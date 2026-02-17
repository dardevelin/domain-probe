mod cli;
mod client;
mod config;
mod grade;
mod probe;
mod render;
mod style;

use anyhow::{Result, anyhow};
use clap::Parser;
use std::collections::HashSet;
use std::time::Instant;

use cli::{Cli, alt_scheme_url, parse_sections, parse_target_url, should_show};
use client::{build_data_client, build_probe_client};
use config::load_config;
use probe::headers::analyze_security_headers;
use probe::http::probe_http;
use probe::redirect::probe_redirect_chain;
use probe::dns::probe_dns;
use probe::rdap::probe_rdap;
use probe::tech::detect_technologies;
use probe::tls::probe_tls;
use render::json::render_json;
use render::quick::render_quick;
use render::report;
use style::{c_bold_red, detect_tty, init_colors, is_tty, make_spinner, set_use_color};

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{} {}", c_bold_red("error:"), err);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let cfg = load_config();

    detect_tty();
    init_colors(&cfg.colors);

    // If piped (not a TTY), disable color and icons automatically
    if !is_tty() {
        set_use_color(false);
    } else {
        set_use_color(!cli.no_color);
    }

    let target = parse_target_url(&cli.target)?;
    let host = target
        .host_str()
        .ok_or_else(|| anyhow!("target URL has no hostname"))?
        .to_string();
    let alt_url = alt_scheme_url(&target);
    let selected_sections = parse_sections(&cli.section)?;
    let is_https = target.scheme() == "https";

    // CLI flags override config values when non-default
    let timeout = if cli.timeout != 10 { cli.timeout } else { cfg.network.timeout };
    let max_redirect_hops = cfg.network.max_redirect_hops;
    let user_agent = cfg.network.user_agent.clone();
    let doh_url = cfg.dns.doh_url.clone();
    let animate = cfg.animation.enabled;

    let probe_client = build_probe_client(timeout, &user_agent)?;
    let data_client = build_data_client(timeout, &user_agent)?;

    let ctx = ProbeContext {
        target,
        host,
        alt_url,
        is_https,
        probe_client,
        data_client,
        selected_sections,
        max_redirect_hops,
        doh_url,
        timeout,
        animate,
    };

    // For JSON/quick mode: run all probes, collect results, render at end
    if cli.json || cli.quick {
        return run_batch(cli, ctx).await;
    }

    // Sequential mode: run probes one at a time
    if cli.sequential {
        return run_sequential(cli, ctx).await;
    }

    // Interactive/streaming mode: render sections as probes complete
    run_streaming(cli, ctx).await
}

struct ProbeContext {
    target: url::Url,
    host: String,
    alt_url: Option<url::Url>,
    is_https: bool,
    probe_client: reqwest::Client,
    data_client: reqwest::Client,
    selected_sections: HashSet<cli::SectionName>,
    max_redirect_hops: usize,
    doh_url: String,
    timeout: u64,
    animate: bool,
}

async fn run_batch(cli: Cli, ctx: ProbeContext) -> Result<()> {
    let ProbeContext {
        target, host, alt_url, is_https, probe_client, data_client,
        selected_sections: _, max_redirect_hops, doh_url, timeout, ..
    } = ctx;
    let spinner = if cli.json || !is_tty() {
        None
    } else {
        Some(make_spinner(&format!("DNS: resolving {}...", &host), cli.no_color))
    };

    let probe_start = Instant::now();
    let dns_result = probe_dns(&host, &data_client, &doh_url).await;

    if let Some(ref sp) = spinner {
        sp.set_message(format!("Probing {} (TLS, HTTP, RDAP, redirects)...", &host));
    }

    let alt_probe_future = async {
        match alt_url {
            Some(url) => {
                let result = probe_redirect_chain(&probe_client, &url, max_redirect_hops).await;
                Some((url, result))
            }
            None => None,
        }
    };

    let tls_future = async {
        if is_https {
            probe_tls(&host, timeout).await
        } else {
            Err(anyhow!("not an HTTPS target"))
        }
    };

    let (http_result, redirect_result, rdap_result, alt_redirect_result, tls_result) = tokio::join!(
        probe_http(&probe_client, &target),
        probe_redirect_chain(&probe_client, &target, max_redirect_hops),
        probe_rdap(&data_client, &host),
        alt_probe_future,
        tls_future,
    );
    let total_elapsed_ms = probe_start.elapsed().as_millis() as u64;
    if let Some(spinner) = spinner {
        spinner.finish_and_clear();
    }

    let security_headers = http_result.as_ref().ok().map(|http| analyze_security_headers(&http.headers));
    let tech_result = http_result.as_ref().ok().map(|http| detect_technologies(&http.headers));

    if cli.json {
        render_json(
            &target, &host, &http_result, &redirect_result,
            alt_redirect_result.as_ref(), &dns_result, &rdap_result,
            &tls_result, security_headers.as_ref(), tech_result.as_ref(),
            total_elapsed_ms,
        );
    } else {
        render_quick(
            &target, &host, &http_result, &redirect_result,
            &dns_result, &rdap_result, &tls_result,
            security_headers.as_ref(), tech_result.as_ref(),
            total_elapsed_ms,
        );
    }

    Ok(())
}

async fn run_sequential(cli: Cli, ctx: ProbeContext) -> Result<()> {
    let ProbeContext {
        target, host, alt_url, is_https, probe_client, data_client,
        selected_sections, max_redirect_hops, doh_url, timeout, animate,
    } = ctx;
    let no_color = cli.no_color;
    let verbose = cli.verbose;

    let probe_start = Instant::now();

    // 1. DNS — run concurrently with the logo animation
    let dns_result = if should_show(&selected_sections, cli::SectionName::Dns) {
        if animate && is_tty() && domain_probe_logo::detect::supports_truecolor() {
            // Spin the logo while DNS resolves; fire signal when done
            let signal = domain_probe_logo::timeline::Signal::new();
            let signal_clone = signal.clone();
            let dns_handle = tokio::spawn({
                let host = host.clone();
                let data_client = data_client.clone();
                let doh_url = doh_url.to_string();
                async move {
                    let result = probe_dns(&host, &data_client, &doh_url).await;
                    signal_clone.fire();
                    result
                }
            });
            tokio::task::spawn_blocking(move || report::print_banner_animated(signal)).await.ok();
            let result = dns_handle.await.map_err(|e| anyhow!("DNS probe failed: {e}"))?;
            report::render_dns_section(&result, None, &selected_sections, verbose);
            Some(result)
        } else {
            report::print_banner_static();
            let sp = spin(&format!("DNS: resolving {}...", &host), no_color);
            let result = probe_dns(&host, &data_client, &doh_url).await;
            sp.finish_and_clear();
            report::render_dns_section(&result, None, &selected_sections, verbose);
            Some(result)
        }
    } else {
        if animate && is_tty() && domain_probe_logo::detect::supports_truecolor() {
            let signal = domain_probe_logo::timeline::Signal::new();
            signal.fire();
            tokio::task::spawn_blocking(move || report::print_banner_animated(signal)).await.ok();
        } else {
            report::print_banner_static();
        }
        None
    };

    // 2. TLS
    let tls_result = if is_https && should_show(&selected_sections, cli::SectionName::Tls) {
        let sp = spin(&format!("TLS: connecting to {}:443...", &host), no_color);
        let result = probe_tls(&host, timeout).await;
        sp.finish_and_clear();
        report::render_tls_section(&result, &selected_sections, verbose);
        Some(result)
    } else {
        None
    };

    // 3. HTTP + headers + tech
    let http_result = if should_show(&selected_sections, cli::SectionName::Target) {
        let sp = spin(&format!("HTTP: HEAD {}...", target.as_str()), no_color);
        let result = probe_http(&probe_client, &target).await;
        sp.finish_and_clear();
        report::render_http_section(&target, &host, &result, &selected_sections, verbose);
        Some(result)
    } else {
        None
    };

    // Compute security headers and tech once from HTTP result
    let security_headers = http_result.as_ref()
        .and_then(|r| r.as_ref().ok())
        .map(|http| analyze_security_headers(&http.headers));
    report::render_headers_section(security_headers.as_ref(), &selected_sections, verbose);
    let tech = http_result.as_ref()
        .and_then(|r| r.as_ref().ok())
        .map(|http| detect_technologies(&http.headers));
    report::render_tech_section(tech.as_ref(), &selected_sections, verbose);

    // 4. Redirects
    let redirect_result = if should_show(&selected_sections, cli::SectionName::Redirects) {
        let sp = spin(&format!("Redirects: following {}...", target.as_str()), no_color);
        let result = probe_redirect_chain(&probe_client, &target, max_redirect_hops).await;
        let alt_redirect_result = match alt_url {
            Some(url) => {
                let result = probe_redirect_chain(&probe_client, &url, max_redirect_hops).await;
                Some((url, result))
            }
            None => None,
        };
        sp.finish_and_clear();
        report::render_redirects_section(&result, alt_redirect_result.as_ref(), &selected_sections, verbose);
        Some(result)
    } else {
        None
    };

    // 5. RDAP
    let rdap_result = if should_show(&selected_sections, cli::SectionName::Whois) {
        let sp = spin(&format!("RDAP: querying registration for {}...", &host), no_color);
        let result = probe_rdap(&data_client, &host).await;
        sp.finish_and_clear();
        report::render_whois_section(&result, &selected_sections, verbose);
        Some(result)
    } else {
        None
    };

    let total_elapsed_ms = probe_start.elapsed().as_millis() as u64;

    // Unwrap results for perf + summary
    let http_r = http_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let redirect_r = redirect_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let dns_r = dns_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let tls_r = tls_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let rdap_r = rdap_result.unwrap_or_else(|| Err(anyhow!("probe not run")));

    report::render_perf_section(
        &http_r, &redirect_r, &dns_r, &tls_r, &rdap_r,
        &selected_sections, total_elapsed_ms, verbose,
    );

    report::render_summary_section(
        &http_r, &redirect_r, &rdap_r, &dns_r, &tls_r,
        security_headers.as_ref(), &selected_sections, total_elapsed_ms, verbose,
    );

    report::render_methodology_section(verbose, true);

    Ok(())
}

fn spin(msg: &str, no_color: bool) -> indicatif::ProgressBar {
    if is_tty() {
        make_spinner(msg, no_color)
    } else {
        let pb = indicatif::ProgressBar::hidden();
        pb.set_message(msg.to_string());
        pb
    }
}

async fn run_streaming(cli: Cli, ctx: ProbeContext) -> Result<()> {
    let ProbeContext {
        target, host, alt_url, is_https, probe_client, data_client,
        selected_sections, max_redirect_hops, doh_url, timeout, animate,
    } = ctx;
    let no_color = cli.no_color;
    let verbose = cli.verbose;

    let probe_start = Instant::now();

    // Phase 1: DNS resolution — animate logo while DNS resolves
    let dns_result = if animate && is_tty() && domain_probe_logo::detect::supports_truecolor() {
        let signal = domain_probe_logo::timeline::Signal::new();
        let signal_clone = signal.clone();
        let dns_handle = tokio::spawn({
            let host = host.clone();
            let data_client = data_client.clone();
            let doh_url = doh_url.to_string();
            async move {
                let result = probe_dns(&host, &data_client, &doh_url).await;
                signal_clone.fire();
                result
            }
        });
        tokio::task::spawn_blocking(move || report::print_banner_animated(signal)).await.ok();
        dns_handle.await.map_err(|e| anyhow!("DNS probe failed: {e}"))?
    } else {
        report::print_banner_static();
        let spinner = if is_tty() {
            Some(make_spinner(&format!("DNS: resolving {}...", &host), no_color))
        } else {
            None
        };
        let result = probe_dns(&host, &data_client, &doh_url).await;
        if let Some(sp) = spinner {
            sp.finish_and_clear();
        }
        result
    };

    // Render DNS section immediately
    report::render_dns_section(&dns_result, None, &selected_sections, verbose);

    // Phase 2: All other probes in parallel with streaming
    let spinner = if is_tty() {
        Some(make_spinner(&format!("Probing {} (TLS, HTTP, RDAP, redirects)...", &host), no_color))
    } else {
        None
    };

    // Spawn all probes as futures
    let http_fut = probe_http(&probe_client, &target);
    let redirect_fut = probe_redirect_chain(&probe_client, &target, max_redirect_hops);
    let rdap_fut = probe_rdap(&data_client, &host);
    let tls_fut = async {
        if is_https {
            probe_tls(&host, timeout).await
        } else {
            Err(anyhow!("not an HTTPS target"))
        }
    };
    let alt_redirect_fut = async {
        match alt_url {
            Some(url) => {
                let result = probe_redirect_chain(&probe_client, &url, max_redirect_hops).await;
                Some((url, result))
            }
            None => None,
        }
    };

    // Pin futures for select!
    tokio::pin!(http_fut, redirect_fut, rdap_fut, tls_fut, alt_redirect_fut);

    let mut http_result: Option<Result<probe::http::HttpProbe>> = None;
    let mut redirect_result: Option<Result<probe::redirect::RedirectProbe>> = None;
    let mut rdap_result: Option<Result<probe::rdap::RdapProbe>> = None;
    let mut tls_result: Option<Result<probe::tls::TlsProbe>> = None;
    let mut alt_redirect_result: Option<Option<(url::Url, Result<probe::redirect::RedirectProbe>)>> = None;

    // Track which sections we've rendered
    let mut tls_rendered = false;
    let mut http_rendered = false;
    let mut headers_rendered = false;
    let mut tech_rendered = false;
    let mut redirects_rendered = false;
    let mut whois_rendered = false;

    let mut remaining = 5; // number of futures still pending

    while remaining > 0 {
        tokio::select! {
            result = &mut http_fut, if http_result.is_none() => {
                http_result = Some(result);
                remaining -= 1;
                if let Some(ref sp) = spinner {
                    sp.set_message(format!("HTTP complete, {} probes remaining...", remaining));
                }
            }
            result = &mut redirect_fut, if redirect_result.is_none() => {
                redirect_result = Some(result);
                remaining -= 1;
                if let Some(ref sp) = spinner {
                    sp.set_message(format!("Redirects complete, {} probes remaining...", remaining));
                }
            }
            result = &mut rdap_fut, if rdap_result.is_none() => {
                rdap_result = Some(result);
                remaining -= 1;
                if let Some(ref sp) = spinner {
                    sp.set_message(format!("RDAP complete, {} probes remaining...", remaining));
                }
            }
            result = &mut tls_fut, if tls_result.is_none() => {
                tls_result = Some(result);
                remaining -= 1;
                if let Some(ref sp) = spinner {
                    sp.set_message(format!("TLS complete, {} probes remaining...", remaining));
                }
            }
            result = &mut alt_redirect_fut, if alt_redirect_result.is_none() => {
                alt_redirect_result = Some(result);
                remaining -= 1;
                if let Some(ref sp) = spinner && remaining > 0 {
                    sp.set_message(format!("Alt scheme complete, {} probes remaining...", remaining));
                }
            }
        }

        // Try to render sections as data becomes available
        // We must clear spinner before printing
        let need_render = (!tls_rendered && tls_result.is_some())
            || (!http_rendered && http_result.is_some())
            || (!redirects_rendered && redirect_result.is_some() && alt_redirect_result.is_some())
            || (!whois_rendered && rdap_result.is_some());

        if need_render {
            if let Some(ref sp) = spinner {
                sp.suspend(|| {
                    render_available_sections(
                        &target, &host, &selected_sections, verbose,
                        &http_result, &redirect_result, &rdap_result,
                        &tls_result, &alt_redirect_result,
                        &mut tls_rendered, &mut http_rendered, &mut headers_rendered,
                        &mut tech_rendered, &mut redirects_rendered, &mut whois_rendered,
                    );
                });
            } else {
                render_available_sections(
                    &target, &host, &selected_sections, verbose,
                    &http_result, &redirect_result, &rdap_result,
                    &tls_result, &alt_redirect_result,
                    &mut tls_rendered, &mut http_rendered, &mut headers_rendered,
                    &mut tech_rendered, &mut redirects_rendered, &mut whois_rendered,
                );
            }
        }
    }

    if let Some(sp) = spinner {
        sp.finish_and_clear();
    }

    // Final render pass for anything not yet rendered
    render_available_sections(
        &target, &host, &selected_sections, verbose,
        &http_result, &redirect_result, &rdap_result,
        &tls_result, &alt_redirect_result,
        &mut tls_rendered, &mut http_rendered, &mut headers_rendered,
        &mut tech_rendered, &mut redirects_rendered, &mut whois_rendered,
    );

    let total_elapsed_ms = probe_start.elapsed().as_millis() as u64;

    // Unwrap results for perf + summary
    let http_r = http_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let redirect_r = redirect_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let rdap_r = rdap_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let tls_r = tls_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let security_headers = http_r.as_ref().ok().map(|http| analyze_security_headers(&http.headers));

    // Performance section
    report::render_perf_section(
        &http_r, &redirect_r, &dns_result, &tls_r, &rdap_r,
        &selected_sections, total_elapsed_ms, verbose,
    );

    // Summary section (composite box)
    report::render_summary_section(
        &http_r, &redirect_r, &rdap_r, &dns_result, &tls_r,
        security_headers.as_ref(), &selected_sections, total_elapsed_ms, verbose,
    );

    report::render_methodology_section(verbose, false);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn render_available_sections(
    target: &url::Url,
    host: &str,
    selected_sections: &std::collections::HashSet<cli::SectionName>,
    verbose: bool,
    http_result: &Option<Result<probe::http::HttpProbe>>,
    redirect_result: &Option<Result<probe::redirect::RedirectProbe>>,
    rdap_result: &Option<Result<probe::rdap::RdapProbe>>,
    tls_result: &Option<Result<probe::tls::TlsProbe>>,
    alt_redirect_result: &Option<Option<(url::Url, Result<probe::redirect::RedirectProbe>)>>,
    tls_rendered: &mut bool,
    http_rendered: &mut bool,
    headers_rendered: &mut bool,
    tech_rendered: &mut bool,
    redirects_rendered: &mut bool,
    whois_rendered: &mut bool,
) {
    // HTTP Target section
    if !*http_rendered
        && let Some(result) = http_result {
            report::render_http_section(target, host, result, selected_sections, verbose);
            *http_rendered = true;
        }

    // TLS section
    if !*tls_rendered
        && let Some(result) = tls_result {
            report::render_tls_section(result, selected_sections, verbose);
            *tls_rendered = true;
        }

    // Security headers (depends on HTTP)
    if !*headers_rendered
        && let Some(http_r) = http_result {
            let security_headers = http_r.as_ref().ok().map(|http| analyze_security_headers(&http.headers));
            report::render_headers_section(security_headers.as_ref(), selected_sections, verbose);
            *headers_rendered = true;
        }

    // Redirects (render when both redirect and alt are available)
    if !*redirects_rendered
        && let (Some(result), Some(alt_result)) = (redirect_result, alt_redirect_result) {
            report::render_redirects_section(result, alt_result.as_ref(), selected_sections, verbose);
            *redirects_rendered = true;
        }

    // Tech fingerprint (depends on HTTP)
    if !*tech_rendered
        && let Some(http_r) = http_result {
            let tech = http_r.as_ref().ok().map(|http| detect_technologies(&http.headers));
            report::render_tech_section(tech.as_ref(), selected_sections, verbose);
            *tech_rendered = true;
        }

    // WHOIS section
    if !*whois_rendered
        && let Some(result) = rdap_result {
            report::render_whois_section(result, selected_sections, verbose);
            *whois_rendered = true;
        }
}
