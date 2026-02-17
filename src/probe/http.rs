use anyhow::{Context, Result};
use reqwest::{Client, StatusCode, Version, header};
use std::collections::HashMap;
use std::time::Instant;
use url::Url;

#[derive(Debug)]
pub(crate) struct HttpProbe {
    pub status: StatusCode,
    pub version: Version,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub server: Option<String>,
    pub headers: HashMap<String, String>,
    pub elapsed_ms: u64,
}

pub(crate) async fn request_metadata(client: &Client, url: &Url) -> Result<reqwest::Response> {
    let head_resp = client
        .head(url.clone())
        .send()
        .await
        .with_context(|| format!("HEAD request failed for {}", url.as_str()))?;

    if head_resp.status() == StatusCode::METHOD_NOT_ALLOWED
        || head_resp.status() == StatusCode::FORBIDDEN
    {
        return client
            .get(url.clone())
            .header(header::RANGE, "bytes=0-0")
            .send()
            .await
            .with_context(|| format!("GET fallback failed for {}", url.as_str()));
    }

    Ok(head_resp)
}

pub(crate) async fn probe_http(client: &Client, url: &Url) -> Result<HttpProbe> {
    let started = Instant::now();
    let resp = request_metadata(client, url).await?;
    let resp_headers = resp.headers();

    let content_type = resp_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let mut content_length = resp_headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if content_length.is_none() {
        content_length = resp_headers
            .get(header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_content_range_total);
    }

    if content_length.is_none()
        && let Ok(range_resp) = client
            .get(url.clone())
            .header(header::RANGE, "bytes=0-0")
            .send()
            .await
        {
            let range_headers = range_resp.headers();
            content_length = range_headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .or_else(|| {
                    range_headers
                        .get(header::CONTENT_RANGE)
                        .and_then(|v| v.to_str().ok())
                        .and_then(parse_content_range_total)
                });
        }

    if content_length.is_none()
        && let Ok(get_resp) = client
            .get(url.clone())
            .header(header::ACCEPT_ENCODING, "identity")
            .send()
            .await
    {
        content_length = get_resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
    }

    let server = resp_headers
        .get(header::SERVER)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    // Capture all response headers for security analysis and tech fingerprinting
    let mut headers = HashMap::new();
    for (name, value) in resp_headers.iter() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }

    Ok(HttpProbe {
        status: resp.status(),
        version: resp.version(),
        content_type,
        content_length,
        server,
        headers,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

pub(crate) fn parse_content_range_total(raw: &str) -> Option<u64> {
    let total = raw.rsplit('/').next()?.trim();
    if total == "*" {
        return None;
    }
    total.parse::<u64>().ok()
}
