use anyhow::{Context, Result, anyhow};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use reqwest::Client;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct MxRecord {
    pub priority: u16,
    pub exchange: String,
}

#[derive(Debug)]
pub(crate) struct DnsProbe {
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub mx: Vec<MxRecord>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
    pub caa: Vec<String>,
    pub elapsed_ms: u128,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DohResponse {
    #[serde(rename = "Answer")]
    pub answer: Option<Vec<DohAnswer>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DohAnswer {
    pub data: String,
}

pub(crate) async fn probe_dns(host: &str, client: &Client, doh_url: &str) -> Result<DnsProbe> {
    let started = Instant::now();

    // Read system DNS config, then rebuild with trust_negative_responses: true.
    // The system config parser sets trust_negative_responses: false, which causes
    // hickory to cycle through all name servers on NODATA/NXDOMAIN responses
    // (e.g. AAAA on IPv4-only domains) instead of returning immediately.
    let (sys_config, _sys_opts) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|e| anyhow!("failed to read DNS system config: {e}"))?;
    let ips: Vec<_> = sys_config.name_servers().iter().map(|ns| ns.socket_addr.ip()).collect();
    let unique_ips: Vec<_> = {
        let mut seen = std::collections::HashSet::new();
        ips.into_iter().filter(|ip| seen.insert(*ip)).collect()
    };
    // Use system nameservers with trust_negative_responses: true,
    // and merge Cloudflare as a fallback for large responses (TXT etc.)
    // that may fail on macOS DNS proxy (127.0.2.x) with hickory's raw UDP/TCP.
    let mut name_servers = NameServerConfigGroup::from_ips_clear(&unique_ips, 53, true);
    name_servers.merge(NameServerConfigGroup::cloudflare());
    let config = ResolverConfig::from_parts(None, vec![], name_servers);
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 1;
    opts.num_concurrent_reqs = 6;
    opts.try_tcp_on_error = true;
    let mut builder = TokioResolver::builder_with_config(config, Default::default());
    *builder.options_mut() = opts;
    let resolver = builder.build();

    // Phase 1: Parallel system resolver lookups via tokio::spawn for true concurrency
    let host_owned = host.to_string();
    let r = resolver.clone();
    let h = host_owned.clone();
    let ipv4_handle = tokio::spawn(async move { r.ipv4_lookup(&h).await });

    let r = resolver.clone();
    let h = host_owned.clone();
    let ipv6_handle = tokio::spawn(async move { r.ipv6_lookup(&h).await });

    let r = resolver.clone();
    let h = host_owned.clone();
    let mx_handle = tokio::spawn(async move { r.mx_lookup(&h).await });

    let r = resolver.clone();
    let h = host_owned.clone();
    let ns_handle = tokio::spawn(async move { r.ns_lookup(&h).await });

    let r = resolver.clone();
    let h = host_owned.clone();
    let txt_handle = tokio::spawn(async move { r.txt_lookup(&h).await });

    let r = resolver.clone();
    let h = host_owned.clone();
    let caa_handle = tokio::spawn(async move { r.lookup(&h, RecordType::CAA).await });

    let (ipv4_res, ipv6_res, mx_res, ns_res, txt_res, caa_res) = tokio::join!(
        ipv4_handle, ipv6_handle, mx_handle, ns_handle, txt_handle, caa_handle,
    );

    let mut ipv4 = BTreeSet::new();
    if let Ok(Ok(records)) = ipv4_res {
        for ip in records.iter() {
            ipv4.insert(ip.to_string());
        }
    }

    let mut ipv6 = BTreeSet::new();
    if let Ok(Ok(records)) = ipv6_res {
        for ip in records.iter() {
            ipv6.insert(ip.to_string());
        }
    }

    let mut mx = Vec::new();
    if let Ok(Ok(records)) = mx_res {
        for record in records.iter() {
            mx.push(MxRecord {
                priority: record.preference(),
                exchange: record.exchange().to_string().trim_end_matches('.').to_string(),
            });
        }
    }

    let mut ns = BTreeSet::new();
    if let Ok(Ok(records)) = ns_res {
        for record in records.iter() {
            ns.insert(record.to_string().trim_end_matches('.').to_string());
        }
    }

    let mut txt = Vec::new();
    if let Ok(Ok(records)) = txt_res {
        for record in records.iter() {
            txt.push(record.to_string());
        }
    }

    let mut caa = Vec::new();
    if let Ok(Ok(lookup)) = caa_res {
        for record in lookup.iter() {
            caa.push(record.to_string());
        }
    }

    // Phase 2: Parallel DoH fallbacks (only for record types that failed)
    let ipv4_doh = async {
        if ipv4.is_empty() { probe_doh(client, host, "A", doh_url).await.ok() } else { None }
    };
    let ipv6_doh = async {
        if ipv6.is_empty() { probe_doh(client, host, "AAAA", doh_url).await.ok() } else { None }
    };
    let mx_doh = async {
        if mx.is_empty() { probe_doh(client, host, "MX", doh_url).await.ok() } else { None }
    };
    let ns_doh = async {
        if ns.is_empty() { probe_doh(client, host, "NS", doh_url).await.ok() } else { None }
    };
    let txt_doh = async {
        if txt.is_empty() { probe_doh(client, host, "TXT", doh_url).await.ok() } else { None }
    };
    let caa_doh = async {
        if caa.is_empty() { probe_doh(client, host, "CAA", doh_url).await.ok() } else { None }
    };

    let (ipv4_fb, ipv6_fb, mx_fb, ns_fb, txt_fb, caa_fb) = tokio::join!(
        ipv4_doh, ipv6_doh, mx_doh, ns_doh, txt_doh, caa_doh,
    );

    if let Some(records) = ipv4_fb {
        ipv4.extend(records);
    }
    if let Some(records) = ipv6_fb {
        ipv6.extend(records);
    }
    if let Some(doh_records) = mx_fb {
        for entry in doh_records {
            let parts: Vec<&str> = entry.splitn(2, ' ').collect();
            if parts.len() == 2 {
                if let Ok(pri) = parts[0].parse::<u16>() {
                    mx.push(MxRecord {
                        priority: pri,
                        exchange: parts[1].trim_end_matches('.').to_string(),
                    });
                }
            }
        }
    }
    if let Some(doh_records) = ns_fb {
        for entry in doh_records {
            ns.insert(entry.trim_end_matches('.').to_string());
        }
    }
    if let Some(doh_records) = txt_fb {
        txt.extend(doh_records);
    }
    if let Some(doh_records) = caa_fb {
        caa.extend(doh_records);
    }

    mx.sort_by_key(|r| r.priority);

    if ipv4.is_empty() && ipv6.is_empty() {
        return Err(anyhow!("no A or AAAA records returned"));
    }

    Ok(DnsProbe {
        ipv4: ipv4.into_iter().collect(),
        ipv6: ipv6.into_iter().collect(),
        mx,
        ns: ns.into_iter().collect(),
        txt,
        caa,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

pub(crate) async fn probe_doh(client: &Client, host: &str, record_type: &str, doh_url: &str) -> Result<Vec<String>> {
    let response = client
        .get(doh_url)
        .query(&[("name", host), ("type", record_type)])
        .send()
        .await
        .with_context(|| format!("DoH request failed for {record_type} {host}"))?
        .error_for_status()
        .with_context(|| format!("DoH endpoint returned non-success for {record_type} {host}"))?
        .json::<DohResponse>()
        .await
        .context("failed to parse DoH JSON response")?;

    let mut records = Vec::new();
    if let Some(answers) = response.answer {
        for answer in answers {
            let data = answer.data.trim().to_string();
            match record_type {
                "A" => {
                    if data.parse::<std::net::Ipv4Addr>().is_ok() {
                        records.push(data);
                    }
                }
                "AAAA" => {
                    if data.parse::<std::net::Ipv6Addr>().is_ok() {
                        records.push(data);
                    }
                }
                _ => {
                    if !data.is_empty() {
                        records.push(data);
                    }
                }
            }
        }
    }

    Ok(records)
}
