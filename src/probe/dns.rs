use anyhow::{Context, Result, anyhow};
use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RecordType;
use reqwest::Client;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::time::Instant;

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

pub(crate) async fn probe_dns(host: &str, client: &Client) -> Result<DnsProbe> {
    let started = Instant::now();
    let resolver = TokioResolver::builder_tokio()
        .context("failed to read DNS system config")?
        .build();
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();

    if let Ok(records) = resolver.ipv4_lookup(host).await {
        for ip in records.iter() {
            ipv4.insert(ip.to_string());
        }
    }
    if let Ok(records) = resolver.ipv6_lookup(host).await {
        for ip in records.iter() {
            ipv6.insert(ip.to_string());
        }
    }

    if ipv4.is_empty() {
        if let Ok(records) = probe_doh(client, host, "A").await {
            ipv4.extend(records);
        }
    }
    if ipv6.is_empty() {
        if let Ok(records) = probe_doh(client, host, "AAAA").await {
            ipv6.extend(records);
        }
    }

    // Extended DNS: MX records
    let mut mx = Vec::new();
    if let Ok(records) = resolver.mx_lookup(host).await {
        for record in records.iter() {
            mx.push(MxRecord {
                priority: record.preference(),
                exchange: record.exchange().to_string().trim_end_matches('.').to_string(),
            });
        }
    }
    if mx.is_empty() {
        if let Ok(doh_records) = probe_doh(client, host, "MX").await {
            for entry in doh_records {
                // DoH MX data format: "priority exchange"
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
    }
    mx.sort_by_key(|r| r.priority);

    // Extended DNS: NS records
    let mut ns = BTreeSet::new();
    if let Ok(records) = resolver.ns_lookup(host).await {
        for record in records.iter() {
            ns.insert(record.to_string().trim_end_matches('.').to_string());
        }
    }
    if ns.is_empty() {
        if let Ok(doh_records) = probe_doh(client, host, "NS").await {
            for entry in doh_records {
                ns.insert(entry.trim_end_matches('.').to_string());
            }
        }
    }

    // Extended DNS: TXT records
    let mut txt = Vec::new();
    if let Ok(records) = resolver.txt_lookup(host).await {
        for record in records.iter() {
            txt.push(record.to_string());
        }
    }
    if txt.is_empty() {
        if let Ok(doh_records) = probe_doh(client, host, "TXT").await {
            txt.extend(doh_records);
        }
    }

    // Extended DNS: CAA records
    let mut caa = Vec::new();
    if let Ok(lookup) = resolver.lookup(host, RecordType::CAA).await {
        for record in lookup.iter() {
            caa.push(record.to_string());
        }
    }
    if caa.is_empty() {
        if let Ok(doh_records) = probe_doh(client, host, "CAA").await {
            caa.extend(doh_records);
        }
    }

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

pub(crate) async fn probe_doh(client: &Client, host: &str, record_type: &str) -> Result<Vec<String>> {
    let response = client
        .get("https://dns.google/resolve")
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
