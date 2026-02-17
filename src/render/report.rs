use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashSet;
use url::Url;

use crate::cli::SectionName;
use crate::grade::compute_grade;
use crate::probe::dns::DnsProbe;
use crate::probe::headers::{HeaderStatus, SecurityHeadersProbe};
use crate::probe::http::HttpProbe;
use crate::probe::rdap::RdapProbe;
use crate::probe::redirect::RedirectProbe;
use crate::probe::tech::TechProbe;
use crate::probe::tls::TlsProbe;
use crate::style::*;

use reqwest::{StatusCode, Version};

// ── Banner ──────────────────────────────────────────────────────

pub(crate) fn print_banner() {
    println!();
    println!(
        "  {} {}",
        c_bold_bright("domain-probe"),
        c_muted(format!("v{}", env!("CARGO_PKG_VERSION")))
    );
    let tw = terminal_width().min(72);
    let rule = "\u{2500}".repeat(tw.saturating_sub(2));
    println!("  {}", c_dim(rule));
}

// ── Section header ──────────────────────────────────────────────
// Design: icon + title + horizontal rule extending to terminal width

fn section(icon: &str, title: &str) {
    println!();
    println!("{}", format_section_header(icon, title));
}

// ── Key-value row ───────────────────────────────────────────────
// Key: fg-muted, 22-char min-width (2-space indent + 20 key)

fn row(label: &str, value: impl std::fmt::Display) {
    println!("  {}{}", pad_visible(&c_muted(label), 20, '<'), value);
}

// ── DNS record type row ─────────────────────────────────────────
// Type: purple bold, 6-char min-width

fn row_type(record_type: &str, value: impl std::fmt::Display) {
    println!("  {}{}", pad_visible(&c_bold_purple(record_type), 7, '<'), value);
}

// ── Individual section renderers (for streaming) ────────────────

pub(crate) fn render_http_section(
    target: &Url,
    host: &str,
    http_result: &Result<HttpProbe>,
    selected_sections: &HashSet<SectionName>,
    verbose: bool,
) {
    if !should_show(selected_sections, SectionName::Target) {
        return;
    }
    section("\u{21C4}", "HTTP Target");
    if verbose {
        println!("  {}", c_dim("Sends HEAD request to target URL, captures status code, server, and content-type."));
    }
    row("URL", target.as_str());
    row("Host", host);
    match http_result {
        Ok(http) => {
            let status_label = paint_status(http.status);
            row("HTTP", format!("{status_label} ({})", http_version(http.version)));
            row("Server", http.server.as_deref().unwrap_or("unknown"));
            row("Content-Type", http.content_type.as_deref().unwrap_or("unknown"));
            row(
                "Content-Length",
                http.content_length
                    .map(|v| format!("{} bytes", with_commas(v)))
                    .unwrap_or_else(|| "unknown".to_string()),
            );
            if verbose {
                row("HTTP Probe Time", format!("{} ms", http.elapsed_ms));
            }
        }
        Err(err) => row("HTTP", c_red(format!("probe failed: {err}"))),
    }
}

pub(crate) fn render_tls_section(
    tls_result: &Result<TlsProbe>,
    selected_sections: &HashSet<SectionName>,
    verbose: bool,
) {
    if !should_show(selected_sections, SectionName::Tls) {
        return;
    }
    section("\u{1F512}", "TLS Certificate");
    if verbose {
        println!("  {}", c_dim("Connects to port 443, inspects protocol version, cipher suite, and certificate chain."));
    }
    let now = Utc::now();
    match tls_result {
        Ok(tls) => {
            row("Protocol", c_green(&tls.protocol_version));
            row("Cipher", c_cyan(&tls.cipher_suite));
            if !tls.certificate_chain.is_empty() {
                println!();
                // Certificate chain with tree connectors
                let chain_len = tls.certificate_chain.len();
                for (idx, cert) in tls.certificate_chain.iter().enumerate() {
                    let connector = if chain_len == 1 {
                        "\u{2500}\u{2500}"
                    } else if idx == 0 {
                        "\u{250C}\u{2500}"
                    } else if idx == chain_len - 1 {
                        "\u{2514}\u{2500}"
                    } else {
                        "\u{251C}\u{2500}"
                    };

                    let label = if cert.is_leaf {
                        "(leaf)"
                    } else if idx == chain_len - 1 {
                        "(root)"
                    } else {
                        ""
                    };

                    let name = if cert.subject.is_empty() {
                        &cert.issuer
                    } else {
                        &cert.subject
                    };

                    // Design: leaf=cyan, intermediate=fg, root=fg-muted
                    let name_colored = if cert.is_leaf {
                        c_cyan(name)
                    } else if idx == chain_len - 1 {
                        c_muted(name)
                    } else {
                        c_fg(name)
                    };

                    let label_str = if label.is_empty() {
                        String::new()
                    } else {
                        format!(" {}", c_muted(label))
                    };

                    println!("    {} {}{}",
                        c_dim(connector),
                        name_colored,
                        label_str
                    );
                }
                println!();

                // Leaf certificate details
                if let Some(leaf) = tls.certificate_chain.first() {
                    if let Some(not_after) = leaf.not_after {
                        let days_left = not_after.signed_duration_since(now).num_days();
                        let expiry_text = if days_left >= 0 {
                            format!(
                                "{} ({})",
                                fmt_datetime(not_after),
                                c_green(format!("{days_left} days remaining"))
                            )
                        } else {
                            format!(
                                "{} ({})",
                                fmt_datetime(not_after),
                                c_red(format!("expired {} days ago", -days_left))
                            )
                        };
                        row("Expires", expiry_text);
                    }
                    if !leaf.san.is_empty() {
                        let display_san: Vec<_> = leaf.san.iter().take(5).collect();
                        let san_text = if leaf.san.len() > 5 {
                            format!(
                                "{} (+{} more)",
                                display_san.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                                leaf.san.len() - 5
                            )
                        } else {
                            display_san.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                        };
                        row("SANs", san_text);
                    }
                }
            }
            if verbose {
                row("TLS Probe Time", format!("{} ms", tls.elapsed_ms));
            }
        }
        Err(err) => row("TLS", c_red(format!("probe failed: {err}"))),
    }
}

pub(crate) fn render_headers_section(
    security_headers: Option<&SecurityHeadersProbe>,
    selected_sections: &HashSet<SectionName>,
    verbose: bool,
) {
    if !should_show(selected_sections, SectionName::Headers) {
        return;
    }
    section("\u{1F6E1}", "Security Headers");
    if verbose {
        println!("  {}", c_dim("Checks presence and correctness of 8 security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, COOP, Referrer-Policy, X-XSS-Protection."));
    }
    match security_headers {
        Some(sh) => {
            for check in &sh.checks {
                let badge = match check.status {
                    HeaderStatus::Pass => badge_pass("PASS"),
                    HeaderStatus::Warn => badge_warn("WARN"),
                    HeaderStatus::Fail => badge_fail("FAIL"),
                    HeaderStatus::Info => badge_info("INFO"),
                };
                // Design: badge 4-char + 2 space + header name 30-char + value muted
                println!(
                    "  {:<4}  {:<30} {}",
                    badge,
                    c_fg(&check.name),
                    c_muted(&check.value)
                );
            }
            println!();
            row("Score", score_bar(sh.score, 10));
        }
        None => row("Security Headers", c_muted("unavailable (HTTP probe failed)")),
    }
}

pub(crate) fn render_redirects_section(
    redirect_result: &Result<RedirectProbe>,
    alt_redirect_result: Option<&(Url, Result<RedirectProbe>)>,
    selected_sections: &HashSet<SectionName>,
    verbose: bool,
) {
    if !should_show(selected_sections, SectionName::Redirects) {
        return;
    }
    section("\u{21C4}", "Redirects Chain");
    if verbose {
        println!("  {}", c_dim("Follows HTTP redirects up to max hops, records each hop status and URL."));
    }
    match redirect_result {
        Ok(redirect) => {
            if redirect.hops.is_empty() {
                let status = redirect
                    .final_status
                    .map(|s| paint_status(s))
                    .unwrap_or_else(|| "unknown".to_string());
                println!(
                    "  {} {} ({})",
                    c_green("\u{25CF}"),
                    c_fg(redirect.final_url.as_str()),
                    status
                );
            } else {
                // Timeline rendering with dot + stem
                for hop in &redirect.hops {
                    println!(
                        "  {} {}",
                        c_muted("\u{25CF}"),
                        c_fg(hop.from.as_str())
                    );
                    println!(
                        "  {} \u{2192} {} \u{2192} {}",
                        c_dim("\u{2502}"),
                        c_yellow(hop.status.as_u16()),
                        c_dim(hop.to.as_str())
                    );
                }
                let final_status = redirect
                    .final_status
                    .map(|s| format!(" ({})", paint_status(s)))
                    .unwrap_or_default();
                println!(
                    "  {} {}{}",
                    c_green("\u{25CF}"),
                    c_fg(redirect.final_url.as_str()),
                    final_status
                );
            }

            if redirect.truncated {
                println!("  {}", c_yellow("max redirect hops reached"));
            }
            if verbose {
                row("Redirect Probe", format!("{} ms", redirect.elapsed_ms));
            }
        }
        Err(err) => row("Redirects", c_red(format!("probe failed: {err}"))),
    }

    if let Some((variant_url, variant_result)) = alt_redirect_result {
        println!();
        let label = match variant_url.scheme() {
            "http" => "HTTP variant",
            "https" => "HTTPS variant",
            _ => "Scheme variant",
        };
        match variant_result {
            Ok(redirect) => row(
                label,
                format_redirect_summary(
                    redirect.hops.len(),
                    &redirect.final_url,
                    redirect.final_status,
                ),
            ),
            Err(err) => row(label, c_red(format!("probe failed: {err}"))),
        }
    }
}

pub(crate) fn render_dns_section(
    dns_result: &Result<DnsProbe>,
    http_result: Option<&HttpProbe>,
    selected_sections: &HashSet<SectionName>,
    verbose: bool,
) {
    if !should_show(selected_sections, SectionName::Dns) {
        return;
    }
    section("\u{25C8}", "DNS Records");
    if verbose {
        println!("  {}", c_dim("Resolves A, AAAA, MX, NS, TXT, CAA via system resolver + Cloudflare fallback. DoH used when system resolver fails."));
    }
    match dns_result {
        Ok(dns) => {
            let tw = terminal_width();
            if tw >= 120 {
                render_dns_two_columns(dns, tw);
            } else {
                render_dns_single_column(dns);
            }

            if let Some(http) = http_result {
                if http
                    .server
                    .as_deref()
                    .map(|s| s.to_ascii_lowercase().contains("cloudflare"))
                    .unwrap_or(false)
                {
                    println!();
                    row("Note", c_muted("Cloudflare anycast edge IPs can vary by client location"));
                }
            }
            if verbose {
                row("DNS Probe Time", format!("{} ms", dns.elapsed_ms));
            }
        }
        Err(err) => row("DNS", c_red(format!("lookup failed: {err}"))),
    }
}

fn render_dns_single_column(dns: &DnsProbe) {
    row_type("A", if dns.ipv4.is_empty() { "none".into() } else { dns.ipv4.join(", ") });
    row_type("AAAA", if dns.ipv6.is_empty() { "none".into() } else { dns.ipv6.join(", ") });

    for mx_record in &dns.mx {
        row_type("MX", format!("{} (pri {})", mx_record.exchange, mx_record.priority));
    }

    if !dns.ns.is_empty() {
        row_type("NS", dns.ns.join(", "));
    }

    for txt in &dns.txt {
        let display_txt = if txt.len() > 80 {
            format!("{}...", &txt[..80])
        } else {
            txt.clone()
        };
        row_type("TXT", display_txt);
    }

    for caa in &dns.caa {
        row_type("CAA", caa);
    }
}

fn render_dns_two_columns(dns: &DnsProbe, tw: usize) {
    // Left column: A, AAAA, MX, NS
    let mut left_rows: Vec<(String, String)> = Vec::new();
    left_rows.push(("A".into(), if dns.ipv4.is_empty() { "none".into() } else { dns.ipv4.join(", ") }));
    left_rows.push(("AAAA".into(), if dns.ipv6.is_empty() { "none".into() } else { dns.ipv6.join(", ") }));
    for mx_record in &dns.mx {
        left_rows.push(("MX".into(), format!("{} (pri {})", mx_record.exchange, mx_record.priority)));
    }
    if !dns.ns.is_empty() {
        left_rows.push(("NS".into(), dns.ns.join(", ")));
    }

    // Right column: TXT, CAA
    let mut right_rows: Vec<(String, String)> = Vec::new();
    for txt in &dns.txt {
        right_rows.push(("TXT".into(), txt.clone()));
    }
    for caa in &dns.caa {
        right_rows.push(("CAA".into(), caa.clone()));
    }

    // If either column is empty, fall back to single column
    if left_rows.is_empty() || right_rows.is_empty() {
        render_dns_single_column(dns);
        return;
    }

    let col_width = (tw - 8) / 2; // margins + gutter
    let type_width = 7;
    let val_max = col_width.saturating_sub(type_width + 2);
    let max_rows = left_rows.len().max(right_rows.len());

    for i in 0..max_rows {
        let left = if i < left_rows.len() {
            let (ref rtype, ref val) = left_rows[i];
            let truncated_val = if val.len() > val_max {
                format!("{}...", &val[..val_max.saturating_sub(3)])
            } else {
                val.clone()
            };
            let type_col = pad_visible(&c_bold_purple(rtype), type_width, '<');
            let content = format!("{}{}", type_col, truncated_val);
            pad_visible(&content, col_width, '<')
        } else {
            " ".repeat(col_width)
        };

        let right = if i < right_rows.len() {
            let (ref rtype, ref val) = right_rows[i];
            let truncated_val = if val.len() > val_max {
                format!("{}...", &val[..val_max.saturating_sub(3)])
            } else {
                val.clone()
            };
            let type_col = pad_visible(&c_bold_purple(rtype), type_width, '<');
            format!("{}{}", type_col, truncated_val)
        } else {
            String::new()
        };

        println!("  {}    {}", left, right);
    }
}

pub(crate) fn render_tech_section(
    tech_result: Option<&TechProbe>,
    selected_sections: &HashSet<SectionName>,
    verbose: bool,
) {
    if !should_show(selected_sections, SectionName::Tech) {
        return;
    }
    section("\u{2699}", "Tech Fingerprint");
    if verbose {
        println!("  {}", c_dim("Detects technologies from HTTP response headers (Server, X-Powered-By, etc.)."));
    }
    match tech_result {
        Some(tech) if !tech.technologies.is_empty() => {
            // Design: tech tags as bordered chips
            let tags: Vec<String> = tech
                .technologies
                .iter()
                .map(|t| format!(" {} {} ", t.icon, t.name))
                .collect();
            // Print tags inline, wrapped
            let mut line = String::from("  ");
            for tag in &tags {
                let tag_display = if use_color() {
                    format!(
                        "{}{}{}",
                        c_dim("\u{2502}"),
                        c_fg(tag),
                        c_dim("\u{2502}")
                    )
                } else {
                    format!("[{}]", tag.trim())
                };
                if line.len() + tag.len() + 4 > terminal_width() {
                    println!("{}", line);
                    line = String::from("  ");
                }
                line.push_str(&tag_display);
                line.push(' ');
            }
            if line.trim().len() > 0 {
                println!("{}", line);
            }
        }
        _ => row("Technologies", c_muted("none detected")),
    }
}

pub(crate) fn render_whois_section(
    rdap_result: &Result<RdapProbe>,
    selected_sections: &HashSet<SectionName>,
    verbose: bool,
) {
    if !should_show(selected_sections, SectionName::Whois) {
        return;
    }
    section("\u{1F4CB}", "WHOIS RDAP");
    if verbose {
        println!("  {}", c_dim("Queries RDAP registration data via IANA bootstrap."));
    }
    let now = Utc::now();
    match rdap_result {
        Ok(rdap) => {
            let registrar = match (&rdap.registrar, &rdap.registrar_iana_id) {
                (Some(name), Some(id)) => format!("{name} (IANA Registrar ID: {id})"),
                (Some(name), None) => name.to_string(),
                _ => "unknown".to_string(),
            };
            row("Registrar", registrar);

            if let Some(registered_on) = rdap.registered_on {
                let age = now.signed_duration_since(registered_on);
                row(
                    "Registered On",
                    format!(
                        "{} ({})",
                        fmt_datetime(registered_on),
                        c_green(format!("{} ago", format_duration(age)))
                    ),
                );
            } else {
                row("Registered On", "unknown");
            }

            if let Some(expires_on) = rdap.expires_on {
                let until_expiry = expires_on.signed_duration_since(now);
                row(
                    "Expires On",
                    format!(
                        "{} ({})",
                        fmt_datetime(expires_on),
                        paint_expiry(until_expiry)
                    ),
                );
            } else {
                row("Expires On", "unknown");
            }

            if !rdap.status_codes.is_empty() {
                row("Domain Status", rdap.status_codes.join(", "));
            }

            if let Some(name) = &rdap.registrant_name {
                let display = if name.eq_ignore_ascii_case("data redacted") {
                    c_yellow(name)
                } else {
                    name.to_string()
                };
                row("Registrant", display);
            }

            if let Some(contact_uri) = &rdap.registrant_contact_uri {
                row("Contact URL", contact_uri);
            }

            match (&rdap.abuse_email, &rdap.abuse_phone) {
                (Some(email), Some(phone)) => row("Abuse Contact", format!("{email} | {phone}")),
                (Some(email), None) => row("Abuse Contact", email),
                (None, Some(phone)) => row("Abuse Contact", phone),
                (None, None) => {}
            }

            row("RDAP Source", &rdap.rdap_url);
            if verbose {
                row("RDAP Probe Time", format!("{} ms", rdap.elapsed_ms));
            }
        }
        Err(err) => row("RDAP", c_red(format!("lookup failed: {err}"))),
    }
}

pub(crate) fn render_perf_section(
    http_result: &Result<HttpProbe>,
    redirect_result: &Result<RedirectProbe>,
    dns_result: &Result<DnsProbe>,
    tls_result: &Result<TlsProbe>,
    rdap_result: &Result<RdapProbe>,
    selected_sections: &HashSet<SectionName>,
    total_elapsed_ms: u128,
    verbose: bool,
) {
    if !should_show(selected_sections, SectionName::Performance) {
        return;
    }
    section("\u{26A1}", "Perf Timings");
    if verbose {
        println!("  {}", c_dim("Wall-clock time per probe. Probes run in parallel by default; use --sequential for isolated timings."));
    }

    let mut entries: Vec<(&str, u128)> = Vec::new();
    if let Ok(http) = http_result {
        entries.push(("HTTP", http.elapsed_ms));
    }
    if let Ok(redirect) = redirect_result {
        entries.push(("Redirect", redirect.elapsed_ms));
    }
    if let Ok(dns) = dns_result {
        entries.push(("DNS", dns.elapsed_ms));
    }
    if let Ok(tls) = tls_result {
        entries.push(("TLS", tls.elapsed_ms));
    }
    if let Ok(rdap) = rdap_result {
        entries.push(("RDAP", rdap.elapsed_ms));
    }

    let max_ms = entries.iter().map(|(_, ms)| *ms).max().unwrap_or(1).max(1);

    for (label, ms) in &entries {
        row_perf(label, *ms, max_ms);
    }

    // Separator line before total
    let sep = "\u{2500}".repeat(29);
    println!("  {}", c_dim(&sep));

    // Total row (no bar)
    let label_col = pad_visible(&c_muted("Total"), 20, '<');
    let num_col = pad_visible(&c_fg(total_elapsed_ms), 6, '>');
    println!("  {}{} ms", label_col, num_col);
}

fn row_perf(label: &str, ms: u128, max_ms: u128) {
    let label_col = pad_visible(&c_muted(label), 20, '<');
    let num_col = pad_visible(&c_fg(ms), 6, '>');
    let bar_width = 20;
    let filled = ((ms as f64 / max_ms as f64) * bar_width as f64).round() as usize;
    let empty = bar_width - filled;
    let bar_str = format!(
        "{}{}",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(empty)
    );
    let bar = c_dim(&bar_str);
    println!("  {}{} ms  {}", label_col, num_col, bar);
}

pub(crate) fn render_summary_section(
    http_result: &Result<HttpProbe>,
    redirect_result: &Result<RedirectProbe>,
    rdap_result: &Result<RdapProbe>,
    dns_result: &Result<DnsProbe>,
    tls_result: &Result<TlsProbe>,
    security_headers: Option<&SecurityHeadersProbe>,
    selected_sections: &HashSet<SectionName>,
    total_elapsed_ms: u128,
    verbose: bool,
) {
    if !should_show(selected_sections, SectionName::Summary) {
        return;
    }
    let now = Utc::now();
    section("\u{25C9}", "Summary Grade");
    if verbose {
        println!("  {}", c_dim("Weighted composite: TLS 25%, HTTP 25%, Headers 20%, DNS 15%, Perf 15%. Grades: A+ >=95, A >=85, B >=75, C >=65, D >=50, F <50."));
    }
    let grade_result = compute_grade(
        now,
        http_result,
        redirect_result,
        rdap_result,
        dns_result,
        tls_result,
        security_headers,
        total_elapsed_ms,
    );

    // Composite summary box: large grade + score bars
    // Design: bordered box with grade left, scores right
    let grade_col_width: usize = 12;
    // inner_width = left(grade_col_width+4) + label(14) + bar(~16 visible: "██████████ 10/10") + 2 trailing
    let inner_width = (grade_col_width + 4) + 14 + 16 + 2;
    // Cap by terminal width (6 = 2 indent + 2 border chars + 2 margin)
    let tw = terminal_width().min(72);
    let inner_width = inner_width.min(tw.saturating_sub(6));
    let border_line = "\u{2500}".repeat(inner_width);

    println!();
    println!("  {}{}{}", c_dim("\u{256D}"), c_dim(&border_line), c_dim("\u{256E}"));

    // Grade letter (large, colored)
    let grade_label = match grade_result.grade.as_str() {
        "A+" | "A" => c_bold_green(&grade_result.grade),
        "B" => c_bold_yellow(&grade_result.grade),
        "C" => c_bold_orange(&grade_result.grade),
        _ => c_bold_red(&grade_result.grade),
    };

    // ANSI-aware padding for grade and overall labels
    let grade_display = pad_visible(&grade_label, grade_col_width, '^');
    let overall_label = c_dim("OVERALL");
    let overall_display = pad_visible(&overall_label, grade_col_width, '^');

    // Score rows — fixed: use http_score for HTTP, headers_score for Headers
    let scores = [
        ("HTTP", grade_result.http_score),
        ("TLS", grade_result.tls_score),
        ("Headers", grade_result.headers_score),
        ("DNS", grade_result.dns_score),
        ("Performance", grade_result.perf_score),
    ];

    // Print with grade on left (row 0: grade, row 1: OVERALL), scores on right
    for (i, (label, score)) in scores.iter().enumerate() {
        let left = if i == 0 {
            pad_visible(&format!("  {}", grade_display), grade_col_width + 4, '<')
        } else if i == 1 {
            pad_visible(&format!("  {}", overall_display), grade_col_width + 4, '<')
        } else {
            " ".repeat(grade_col_width + 4)
        };
        let label_col = pad_visible(&c_fg(label), 14, '<');
        let bar = score_bar(*score, 10);
        let content = format!("{}{}{}", left, label_col, bar);
        let padded = pad_visible(&content, inner_width, '<');
        println!("  \u{2502}{}\u{2502}", padded);
    }

    println!("  {}{}{}", c_dim("\u{2570}"), c_dim(&border_line), c_dim("\u{256F}"));
    println!("  {}", c_muted(format!(
        "Performance score reflects total probe time. Use {} for isolated timings, {} for scoring methodology.",
        c_cyan("--sequential"),
        c_cyan("--verbose"),
    )));
    println!();
    row("Completed", format!("{} ms", total_elapsed_ms));
}

pub(crate) fn render_methodology_section(verbose: bool, is_sequential: bool) {
    if !verbose {
        return;
    }

    section("\u{2139}", "Methodology");

    row("Execution Mode", if is_sequential {
        "sequential (--sequential)"
    } else {
        "streaming (parallel probes)"
    });

    println!();
    println!("  {}", c_muted("DNS Resolver"));
    println!("  {}", c_dim("  System nameservers + Cloudflare, parallel per record type"));
    println!("  {}", c_dim("  (A, AAAA, MX, NS, TXT, CAA). DoH fallback for failures."));

    println!();
    println!("  {}", c_muted("Scoring Weights"));
    println!("  {}", c_dim("  TLS ............ 25%   protocol, cipher, cert validity"));
    println!("  {}", c_dim("  HTTP ........... 25%   status, version, redirects, domain health"));
    println!("  {}", c_dim("  Headers ........ 20%   security header presence and correctness"));
    println!("  {}", c_dim("  DNS ............ 15%   record coverage (A, AAAA, MX, NS, TXT, CAA)"));
    println!("  {}", c_dim("  Performance .... 15%   total probe wall-clock time"));

    println!();
    println!("  {}", c_muted("Grade Thresholds"));
    println!("  {}", c_dim("  A+ >= 95 | A >= 85 | B >= 75 | C >= 65 | D >= 50 | F < 50"));
    println!();
}

// ── Helpers ─────────────────────────────────────────────────────

fn should_show(selected_sections: &HashSet<SectionName>, section: SectionName) -> bool {
    selected_sections.is_empty() || selected_sections.contains(&section)
}

pub(crate) fn http_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "h2",
        Version::HTTP_3 => "h3",
        _ => "HTTP/?",
    }
}

pub(crate) fn paint_status(status: StatusCode) -> String {
    let label = format!(
        "{} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("Unknown")
    );
    if status.is_success() {
        c_green(label)
    } else if status.is_redirection() {
        c_yellow(label)
    } else {
        c_red(label)
    }
}

fn format_redirect_summary(
    hops: usize,
    final_url: &Url,
    final_status: Option<StatusCode>,
) -> String {
    if hops == 0 {
        return format!(
            "{} (0 hops, final: {})",
            c_green("No redirect"),
            final_url.as_str()
        );
    }
    let status = final_status
        .map(|s| paint_status(s))
        .unwrap_or_else(|| "unknown".to_string());
    format!(
        "{} ({} hops, final: {}, status: {status})",
        c_yellow("Redirected"),
        hops,
        final_url.as_str()
    )
}

pub(crate) fn fmt_datetime(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

pub(crate) fn format_duration(duration: Duration) -> String {
    let mut secs = duration.num_seconds().abs();
    let days = secs / 86_400;
    secs %= 86_400;
    let hours = secs / 3_600;
    secs %= 3_600;
    let minutes = secs / 60;

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

pub(crate) fn paint_expiry(delta: Duration) -> String {
    if delta.num_seconds() < 0 {
        return c_red(format!("expired {} ago", format_duration(delta)));
    }

    let text = format!("in {}", format_duration(delta));
    if delta.num_days() < 30 {
        c_red(text)
    } else if delta.num_days() < 120 {
        c_yellow(text)
    } else {
        c_green(text)
    }
}
