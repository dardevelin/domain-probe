use anyhow::{Context, Result, anyhow};
use reqwest::{Client, StatusCode, header};
use std::time::Instant;
use url::Url;

use super::http::request_metadata;

#[derive(Debug)]
pub(crate) struct RedirectHop {
    pub status: StatusCode,
    pub from: Url,
    pub to: Url,
}

#[derive(Debug)]
pub(crate) struct RedirectProbe {
    pub hops: Vec<RedirectHop>,
    pub final_url: Url,
    pub final_status: Option<StatusCode>,
    pub truncated: bool,
    pub elapsed_ms: u128,
}

pub(crate) async fn probe_redirect_chain(
    client: &Client,
    start: &Url,
    max_hops: usize,
) -> Result<RedirectProbe> {
    let started = Instant::now();
    let mut hops = Vec::new();
    let mut current = start.clone();
    let mut final_status = None;

    for _ in 0..max_hops {
        let resp = request_metadata(client, &current).await?;
        let status = resp.status();
        final_status = Some(status);
        if !status.is_redirection() {
            return Ok(RedirectProbe {
                hops,
                final_url: current,
                final_status,
                truncated: false,
                elapsed_ms: started.elapsed().as_millis(),
            });
        }

        let location = resp
            .headers()
            .get(header::LOCATION)
            .ok_or_else(|| anyhow!("redirect response from {} missing Location header", current))?
            .to_str()
            .context("invalid redirect Location header")?;
        let next = current
            .join(location)
            .or_else(|_| Url::parse(location))
            .with_context(|| format!("invalid redirect target `{location}`"))?;

        hops.push(RedirectHop {
            status,
            from: current.clone(),
            to: next.clone(),
        });
        current = next;
    }

    Ok(RedirectProbe {
        hops,
        final_url: current,
        final_status,
        truncated: true,
        elapsed_ms: started.elapsed().as_millis(),
    })
}
