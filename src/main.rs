mod cli;
mod client;
mod config;
mod grade;
mod probe;
mod render;
#[allow(dead_code)]
mod style;

use anyhow::{Result, anyhow};
use clap::Parser;
use std::time::Instant;

use cli::{Cli, alt_scheme_url, parse_sections, parse_target_url};
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

    let probe_client = build_probe_client(timeout, &user_agent)?;
    let data_client = build_data_client(timeout, &user_agent)?;

    // For JSON/quick mode: run all probes, collect results, render at end
    if cli.json || cli.quick {
        return run_batch(cli, target, host, alt_url, is_https, probe_client, data_client, selected_sections, max_redirect_hops, &doh_url, timeout).await;
    }

    // Sequential mode: run probes one at a time
    if cli.sequential {
        return run_sequential(cli, target, host, alt_url, is_https, probe_client, data_client, selected_sections, max_redirect_hops, &doh_url, timeout).await;
    }

    // Interactive/streaming mode: render sections as probes complete
    run_streaming(cli, target, host, alt_url, is_https, probe_client, data_client, selected_sections, max_redirect_hops, &doh_url, timeout).await
}

#[allow(clippy::too_many_arguments)]
async fn run_batch(
    cli: Cli,
    target: url::Url,
    host: String,
    alt_url: Option<url::Url>,
    is_https: bool,
    probe_client: reqwest::Client,
    data_client: reqwest::Client,
    _selected_sections: std::collections::HashSet<cli::SectionName>,
    max_redirect_hops: usize,
    doh_url: &str,
    timeout: u64,
) -> Result<()> {
    let spinner = if cli.json || !is_tty() {
        None
    } else {
        Some(make_spinner(&format!("DNS: resolving {}...", &host), cli.no_color))
    };

    let probe_start = Instant::now();
    let dns_result = probe_dns(&host, &data_client, doh_url).await;

    if let Some(ref sp) = spinner {
        sp.set_message(format!("Probing {} (TLS, HTTP, RDAP, redirects)...", &host));
    }

    let alt_probe_future = async {
        if let Some(url) = alt_url.clone() {
            Some((url.clone(), probe_redirect_chain(&probe_client, &url, max_redirect_hops).await))
        } else {
            None
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
    let total_elapsed_ms = probe_start.elapsed().as_millis();
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

#[allow(clippy::too_many_arguments)]
async fn run_sequential(
    cli: Cli,
    target: url::Url,
    host: String,
    alt_url: Option<url::Url>,
    is_https: bool,
    probe_client: reqwest::Client,
    data_client: reqwest::Client,
    selected_sections: std::collections::HashSet<cli::SectionName>,
    max_redirect_hops: usize,
    doh_url: &str,
    timeout: u64,
) -> Result<()> {
    let no_color = cli.no_color;
    let verbose = cli.verbose;

    report::print_banner();
    let probe_start = Instant::now();

    // 1. DNS
    let dns_result = if should_run(&selected_sections, cli::SectionName::Dns) {
        let sp = spin(&format!("DNS: resolving {}...", &host), no_color);
        let result = probe_dns(&host, &data_client, doh_url).await;
        sp.finish_and_clear();
        report::render_dns_section(&result, None, &selected_sections, verbose);
        Some(result)
    } else {
        None
    };

    // 2. TLS
    let tls_result = if is_https && should_run(&selected_sections, cli::SectionName::Tls) {
        let sp = spin(&format!("TLS: connecting to {}:443...", &host), no_color);
        let result = probe_tls(&host, timeout).await;
        sp.finish_and_clear();
        report::render_tls_section(&result, &selected_sections, verbose);
        Some(result)
    } else {
        None
    };

    // 3. HTTP + headers + tech
    let http_result = if should_run(&selected_sections, cli::SectionName::Target) {
        let sp = spin(&format!("HTTP: HEAD {}...", target.as_str()), no_color);
        let result = probe_http(&probe_client, &target).await;
        sp.finish_and_clear();
        report::render_http_section(&target, &host, &result, &selected_sections, verbose);
        // Derive headers + tech from HTTP result
        let security_headers = result.as_ref().ok().map(|http| analyze_security_headers(&http.headers));
        report::render_headers_section(security_headers.as_ref(), &selected_sections, verbose);
        let tech = result.as_ref().ok().map(|http| detect_technologies(&http.headers));
        report::render_tech_section(tech.as_ref(), &selected_sections, verbose);
        Some(result)
    } else {
        None
    };

    // 4. Redirects
    let redirect_result = if should_run(&selected_sections, cli::SectionName::Redirects) {
        let sp = spin(&format!("Redirects: following {}...", target.as_str()), no_color);
        let result = probe_redirect_chain(&probe_client, &target, max_redirect_hops).await;
        let alt_redirect_result = if let Some(url) = alt_url.clone() {
            Some((url.clone(), probe_redirect_chain(&probe_client, &url, max_redirect_hops).await))
        } else {
            None
        };
        sp.finish_and_clear();
        report::render_redirects_section(&result, alt_redirect_result.as_ref(), &selected_sections, verbose);
        Some(result)
    } else {
        None
    };

    // 5. RDAP
    let rdap_result = if should_run(&selected_sections, cli::SectionName::Whois) {
        let sp = spin(&format!("RDAP: querying registration for {}...", &host), no_color);
        let result = probe_rdap(&data_client, &host).await;
        sp.finish_and_clear();
        report::render_whois_section(&result, &selected_sections, verbose);
        Some(result)
    } else {
        None
    };

    let total_elapsed_ms = probe_start.elapsed().as_millis();

    // Unwrap results for perf + summary
    let http_r = http_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let redirect_r = redirect_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let dns_r = dns_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let tls_r = tls_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let rdap_r = rdap_result.unwrap_or_else(|| Err(anyhow!("probe not run")));
    let security_headers = http_r.as_ref().ok().map(|http| analyze_security_headers(&http.headers));

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

fn should_run(selected: &std::collections::HashSet<cli::SectionName>, section: cli::SectionName) -> bool {
    selected.is_empty() || selected.contains(&section)
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

#[allow(clippy::too_many_arguments)]
async fn run_streaming(
    cli: Cli,
    target: url::Url,
    host: String,
    alt_url: Option<url::Url>,
    is_https: bool,
    probe_client: reqwest::Client,
    data_client: reqwest::Client,
    selected_sections: std::collections::HashSet<cli::SectionName>,
    max_redirect_hops: usize,
    doh_url: &str,
    timeout: u64,
) -> Result<()> {
    let no_color = cli.no_color;
    let verbose = cli.verbose;

    // Print banner immediately
    report::print_banner();

    // Phase 1: DNS resolution with spinner
    let spinner = if is_tty() {
        Some(make_spinner(&format!("DNS: resolving {}...", &host), no_color))
    } else {
        None
    };

    let probe_start = Instant::now();
    let dns_result = probe_dns(&host, &data_client, doh_url).await;

    if let Some(ref sp) = spinner {
        sp.finish_and_clear();
    }

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
        if let Some(url) = alt_url.clone() {
            Some((url.clone(), probe_redirect_chain(&probe_client, &url, max_redirect_hops).await))
        } else {
            None
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

    let total_elapsed_ms = probe_start.elapsed().as_millis();

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
    if !*http_rendered {
        if let Some(result) = http_result {
            report::render_http_section(target, host, result, selected_sections, verbose);
            *http_rendered = true;
        }
    }

    // TLS section
    if !*tls_rendered {
        if let Some(result) = tls_result {
            report::render_tls_section(result, selected_sections, verbose);
            *tls_rendered = true;
        }
    }

    // Security headers (depends on HTTP)
    if !*headers_rendered {
        if let Some(http_r) = http_result {
            let security_headers = http_r.as_ref().ok().map(|http| analyze_security_headers(&http.headers));
            report::render_headers_section(security_headers.as_ref(), selected_sections, verbose);
            *headers_rendered = true;
        }
    }

    // Redirects (render when both redirect and alt are available)
    if !*redirects_rendered {
        if let (Some(result), Some(alt_result)) = (redirect_result, alt_redirect_result) {
            report::render_redirects_section(result, alt_result.as_ref(), selected_sections, verbose);
            *redirects_rendered = true;
        }
    }

    // Tech fingerprint (depends on HTTP)
    if !*tech_rendered {
        if let Some(http_r) = http_result {
            let tech = http_r.as_ref().ok().map(|http| detect_technologies(&http.headers));
            report::render_tech_section(tech.as_ref(), selected_sections, verbose);
            *tech_rendered = true;
        }
    }

    // WHOIS section
    if !*whois_rendered {
        if let Some(result) = rdap_result {
            report::render_whois_section(result, selected_sections, verbose);
            *whois_rendered = true;
        }
    }
}
