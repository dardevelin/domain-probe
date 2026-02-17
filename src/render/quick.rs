use anyhow::Result;
use chrono::Utc;
use url::Url;

use crate::grade::compute_grade;
use crate::probe::dns::DnsProbe;
use crate::probe::headers::{HeaderStatus, SecurityHeadersProbe};
use crate::probe::http::HttpProbe;
use crate::probe::rdap::RdapProbe;
use crate::probe::redirect::RedirectProbe;
use crate::probe::tech::TechProbe;
use crate::probe::tls::TlsProbe;
use crate::render::report::{http_version, paint_status, format_duration};
use crate::style::*;

pub(crate) fn render_quick(
    _target: &Url,
    host: &str,
    http_result: &Result<HttpProbe>,
    redirect_result: &Result<RedirectProbe>,
    dns_result: &Result<DnsProbe>,
    rdap_result: &Result<RdapProbe>,
    tls_result: &Result<TlsProbe>,
    security_headers: Option<&SecurityHeadersProbe>,
    tech_result: Option<&TechProbe>,
    total_elapsed_ms: u128,
) {
    let status = match http_result {
        Ok(http) => paint_status(http.status),
        Err(_) => c_red("HTTP error"),
    };
    let proto = match http_result {
        Ok(http) => c_cyan(http_version(http.version)),
        Err(_) => "unknown".to_string(),
    };

    let tls_info = match tls_result {
        Ok(tls) => {
            if is_tty() {
                c_green(format!("\u{1F512} {}", tls.protocol_version))
            } else {
                tls.protocol_version.clone()
            }
        }
        Err(_) => c_muted("no TLS"),
    };

    let grade_result = compute_grade(
        Utc::now(),
        http_result,
        redirect_result,
        rdap_result,
        dns_result,
        tls_result,
        security_headers,
        total_elapsed_ms,
    );
    // Design: grade in bold purple per quick mode spec
    let grade_colored = match grade_result.grade.as_str() {
        "A+" | "A" => c_bold_purple(&grade_result.grade),
        "B" => c_bold_yellow(&grade_result.grade),
        _ => c_bold_red(&grade_result.grade),
    };

    // Line 1: domain in fg-bright bold
    println!("  {}", c_bold_bright(host));

    // Line 2: key metrics with semantic colors
    println!(
        "  {}  {}  {}  {}  {}",
        tls_info,
        proto,
        status,
        c_yellow(format!("{}ms", total_elapsed_ms)),
        grade_colored
    );

    // Line 3: secondary info in fg-muted, · separator
    let mut details = Vec::new();

    // IP
    if let Ok(dns) = dns_result {
        if let Some(ip) = dns.ipv4.first().or(dns.ipv6.first()) {
            details.push(ip.clone());
        }
    }

    // Tech
    if let Some(tech) = tech_result {
        if let Some(first) = tech.technologies.first() {
            details.push(first.name.clone());
        }
    }

    // HSTS check
    if let Some(sh) = security_headers {
        let hsts_pass = sh.checks.iter().any(|c| {
            c.name.contains("Strict-Transport") && c.status == HeaderStatus::Pass
        });
        details.push(if hsts_pass {
            format!("HSTS \u{2713}")
        } else {
            format!("HSTS \u{2717}")
        });

        let csp_pass = sh.checks.iter().any(|c| {
            c.name.contains("Content-Security") && c.status == HeaderStatus::Pass
        });
        details.push(if csp_pass {
            format!("CSP \u{2713}")
        } else {
            format!("CSP \u{2717}")
        });
    }

    // Cert expiry
    if let Ok(tls) = tls_result {
        if let Some(leaf) = tls.certificate_chain.first() {
            if let Some(not_after) = leaf.not_after {
                let days = not_after.signed_duration_since(Utc::now()).num_days();
                details.push(format!("Cert {days}d"));
            }
        }
    } else if let Ok(rdap) = rdap_result {
        if let Some(exp) = rdap.expires_on {
            let delta = exp.signed_duration_since(Utc::now());
            if delta.num_seconds() >= 0 {
                details.push(format!("expires in {}", format_duration(delta)));
            } else {
                details.push(format!("expired {}", format_duration(delta)));
            }
        }
    }

    println!("  {}", c_muted(details.join(" \u{00B7} ")));
}
