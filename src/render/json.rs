use anyhow::Result;
use chrono::Utc;
use serde_json::{Value, json};
use url::Url;

use crate::grade::compute_grade;
use crate::probe::dns::DnsProbe;
use crate::probe::headers::{HeaderStatus, SecurityHeadersProbe};
use crate::probe::http::HttpProbe;
use crate::probe::rdap::RdapProbe;
use crate::probe::redirect::RedirectProbe;
use crate::probe::tech::TechProbe;
use crate::probe::tls::TlsProbe;
use crate::render::report::http_version;

pub(crate) fn render_json(
    target: &Url,
    host: &str,
    http_result: &Result<HttpProbe>,
    redirect_result: &Result<RedirectProbe>,
    alt_redirect_result: Option<&(Url, Result<RedirectProbe>)>,
    dns_result: &Result<DnsProbe>,
    rdap_result: &Result<RdapProbe>,
    tls_result: &Result<TlsProbe>,
    security_headers: Option<&SecurityHeadersProbe>,
    tech_result: Option<&TechProbe>,
    total_elapsed_ms: u128,
) {
    let http_json = match http_result {
        Ok(http) => json!({
            "status_code": http.status.as_u16(),
            "status_text": http.status.canonical_reason().unwrap_or("Unknown"),
            "http_version": http_version(http.version),
            "server": http.server,
            "content_type": http.content_type,
            "content_length": http.content_length,
            "elapsed_ms": http.elapsed_ms
        }),
        Err(err) => json!({"error": err.to_string()}),
    };

    let redirects_json = match redirect_result {
        Ok(redirect) => json!({
            "hops": redirect.hops.iter().map(|hop| {
                json!({
                    "status_code": hop.status.as_u16(),
                    "from": hop.from.as_str(),
                    "to": hop.to.as_str()
                })
            }).collect::<Vec<_>>(),
            "final_url": redirect.final_url.as_str(),
            "final_status_code": redirect.final_status.map(|s| s.as_u16()),
            "truncated": redirect.truncated,
            "elapsed_ms": redirect.elapsed_ms
        }),
        Err(err) => json!({"error": err.to_string()}),
    };

    let variant_json = alt_redirect_result.map(|(url, result)| match result {
        Ok(redirect) => json!({
            "scheme": url.scheme(),
            "hops": redirect.hops.len(),
            "final_url": redirect.final_url.as_str(),
            "final_status_code": redirect.final_status.map(|s| s.as_u16()),
            "elapsed_ms": redirect.elapsed_ms
        }),
        Err(err) => json!({
            "scheme": url.scheme(),
            "error": err.to_string()
        }),
    });

    let dns_json = match dns_result {
        Ok(dns) => json!({
            "ipv4": dns.ipv4,
            "ipv6": dns.ipv6,
            "mx": dns.mx.iter().map(|r| json!({
                "priority": r.priority,
                "exchange": r.exchange
            })).collect::<Vec<_>>(),
            "ns": dns.ns,
            "txt": dns.txt,
            "caa": dns.caa,
            "elapsed_ms": dns.elapsed_ms
        }),
        Err(err) => json!({"error": err.to_string()}),
    };

    let rdap_json = match rdap_result {
        Ok(rdap) => json!({
            "rdap_url": rdap.rdap_url,
            "registrar": rdap.registrar,
            "registrar_iana_id": rdap.registrar_iana_id,
            "registered_on": rdap.registered_on.map(|d| d.to_rfc3339()),
            "expires_on": rdap.expires_on.map(|d| d.to_rfc3339()),
            "status_codes": rdap.status_codes,
            "registrant_name": rdap.registrant_name,
            "registrant_contact_uri": rdap.registrant_contact_uri,
            "abuse_email": rdap.abuse_email,
            "abuse_phone": rdap.abuse_phone,
            "elapsed_ms": rdap.elapsed_ms
        }),
        Err(err) => json!({"error": err.to_string()}),
    };

    let tls_json: Value = match tls_result {
        Ok(tls) => json!({
            "protocol_version": tls.protocol_version,
            "cipher_suite": tls.cipher_suite,
            "certificate_chain": tls.certificate_chain.iter().map(|cert| json!({
                "subject": cert.subject,
                "issuer": cert.issuer,
                "not_before": cert.not_before.map(|d| d.to_rfc3339()),
                "not_after": cert.not_after.map(|d| d.to_rfc3339()),
                "san": cert.san,
                "is_leaf": cert.is_leaf,
            })).collect::<Vec<_>>(),
            "elapsed_ms": tls.elapsed_ms
        }),
        Err(err) => json!({"error": err.to_string()}),
    };

    let security_json: Value = match security_headers {
        Some(sh) => json!({
            "checks": sh.checks.iter().map(|c| json!({
                "name": c.name,
                "status": match c.status {
                    HeaderStatus::Pass => "pass",
                    HeaderStatus::Warn => "warn",
                    HeaderStatus::Fail => "fail",
                    HeaderStatus::Info => "info",
                },
                "value": c.value,
            })).collect::<Vec<_>>(),
            "score": sh.score,
        }),
        None => json!(null),
    };

    let tech_json: Value = match tech_result {
        Some(tech) => json!(tech.technologies.iter().map(|t| json!({
            "name": t.name,
            "category": t.category,
        })).collect::<Vec<Value>>()),
        None => json!(null),
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

    let out = json!({
        "target": {
            "url": target.as_str(),
            "host": host
        },
        "http": http_json,
        "redirects": redirects_json,
        "scheme_variant": variant_json,
        "dns": dns_json,
        "rdap": rdap_json,
        "tls": tls_json,
        "security_headers": security_json,
        "technology": tech_json,
        "grade": {
            "grade": grade_result.grade,
            "overall_score": grade_result.overall_score,
            "tls_score": grade_result.tls_score,
            "headers_score": grade_result.headers_score,
            "dns_score": grade_result.dns_score,
            "http_score": grade_result.http_score,
            "perf_score": grade_result.perf_score,
        },
        "total_elapsed_ms": total_elapsed_ms
    });

    match serde_json::to_string_pretty(&out) {
        Ok(text) => println!("{text}"),
        Err(err) => println!("{}", json!({ "error": err.to_string() })),
    }
}
