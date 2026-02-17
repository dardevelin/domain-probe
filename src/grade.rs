use chrono::{DateTime, Utc};

use crate::probe::dns::DnsProbe;
use crate::probe::headers::SecurityHeadersProbe;
use crate::probe::http::HttpProbe;
use crate::probe::redirect::RedirectProbe;
use crate::probe::rdap::RdapProbe;
use crate::probe::tls::TlsProbe;

use anyhow::Result;

#[derive(Debug)]
pub(crate) struct GradeResult {
    pub grade: String,
    pub overall_score: u32,
    pub tls_score: u32,
    pub headers_score: u32,
    pub dns_score: u32,
    pub http_score: u32,
    pub perf_score: u32,
}

pub(crate) fn compute_grade(
    now: DateTime<Utc>,
    http_result: &Result<HttpProbe>,
    redirect_result: &Result<RedirectProbe>,
    rdap_result: &Result<RdapProbe>,
    dns_result: &Result<DnsProbe>,
    tls_result: &Result<TlsProbe>,
    security_headers: Option<&SecurityHeadersProbe>,
    total_elapsed_ms: u128,
) -> GradeResult {
    // TLS score (0-10)
    let tls_score = match tls_result {
        Ok(tls) => {
            let mut s: u32 = 0;
            // Protocol version
            if tls.protocol_version.contains("1.3") {
                s += 4;
            } else if tls.protocol_version.contains("1.2") {
                s += 2;
            }
            // Cipher suite quality
            let cipher_lower = tls.cipher_suite.to_lowercase();
            if cipher_lower.contains("aes_256") || cipher_lower.contains("chacha20") {
                s += 3;
            } else if cipher_lower.contains("aes_128") {
                s += 2;
            } else {
                s += 1;
            }
            // Certificate validity
            if let Some(leaf) = tls.certificate_chain.first() {
                if let Some(not_after) = leaf.not_after {
                    let days_remaining = not_after.signed_duration_since(now).num_days();
                    if days_remaining > 30 {
                        s += 3;
                    } else if days_remaining > 0 {
                        s += 1;
                    }
                } else {
                    s += 1;
                }
            }
            s.min(10)
        }
        Err(_) => 0,
    };

    // Headers score (0-10) - directly from security headers analysis
    let headers_score = security_headers
        .map(|sh| sh.score)
        .unwrap_or(0);

    // DNS score (0-10)
    let dns_score = match dns_result {
        Ok(dns) => {
            let mut s: u32 = 0;
            if !dns.ipv4.is_empty() { s += 3; }
            if !dns.ipv6.is_empty() { s += 2; }
            if !dns.mx.is_empty() { s += 1; }
            if !dns.ns.is_empty() { s += 1; }
            if !dns.txt.is_empty() { s += 1; }
            if !dns.caa.is_empty() { s += 2; }
            s.min(10)
        }
        Err(_) => 0,
    };

    // HTTP score (0-10)
    let http_score = match http_result {
        Ok(http) => {
            let mut s: u32 = 0;
            if http.status.is_success() {
                s += 5;
            } else if http.status.is_redirection() {
                s += 3;
            }
            // HTTP version bonus
            match http.version {
                reqwest::Version::HTTP_2 => s += 3,
                reqwest::Version::HTTP_3 => s += 4,
                reqwest::Version::HTTP_11 => s += 2,
                _ => s += 1,
            }
            // Redirect chain cleanliness
            if let Ok(redirect) = redirect_result {
                if redirect.hops.len() <= 1 && !redirect.truncated {
                    s += 2;
                } else if !redirect.truncated {
                    s += 1;
                }
            }
            // Domain registration health
            if let Ok(rdap) = rdap_result {
                if let Some(exp) = rdap.expires_on {
                    let days = exp.signed_duration_since(now).num_days();
                    if days < 0 {
                        // expired - already penalized
                    } else if days < 30 {
                        // near expiry
                    } else {
                        s += 1;
                    }
                }
            }
            s.min(10)
        }
        Err(_) => 0,
    };

    // Performance score (0-10)
    let perf_score = {
        let ms = total_elapsed_ms;
        if ms < 500 {
            10
        } else if ms < 1000 {
            9
        } else if ms < 2000 {
            8
        } else if ms < 3000 {
            7
        } else if ms < 5000 {
            5
        } else if ms < 8000 {
            3
        } else {
            1
        }
    };

    // Weighted average: TLS 25%, Headers 20%, DNS 15%, HTTP 25%, Perf 15%
    let weighted = (tls_score as f64 * 0.25)
        + (headers_score as f64 * 0.20)
        + (dns_score as f64 * 0.15)
        + (http_score as f64 * 0.25)
        + (perf_score as f64 * 0.15);

    let overall_score = (weighted * 10.0).round() as u32;

    let grade = if overall_score >= 95 {
        "A+"
    } else if overall_score >= 85 {
        "A"
    } else if overall_score >= 75 {
        "B"
    } else if overall_score >= 65 {
        "C"
    } else if overall_score >= 50 {
        "D"
    } else {
        "F"
    }
    .to_string();

    GradeResult {
        grade,
        overall_score,
        tls_score,
        headers_score,
        dns_score,
        http_score,
        perf_score,
    }
}
