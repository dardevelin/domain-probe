use anyhow::{Result, anyhow};
use clap::{ArgAction, Parser};
use std::collections::HashSet;
use url::Url;

#[derive(Parser, Debug)]
#[command(
    name = "domain-probe",
    version,
    about = "Probe URL metadata, redirects, public DNS IPs, and RDAP registration details"
)]
pub(crate) struct Cli {
    /// Target URL or hostname (if hostname is passed, https:// is assumed)
    pub target: String,
    /// Compact single-line output
    #[arg(short = 'q', long, conflicts_with = "json")]
    pub quick: bool,
    /// Output as JSON
    #[arg(short = 'j', long, conflicts_with = "quick")]
    pub json: bool,
    /// Show only selected sections (comma-separated): target,whois,redirects,dns,tls,headers,tech,performance,summary
    #[arg(short = 's', long = "section", value_delimiter = ',')]
    pub section: Vec<String>,
    /// Disable colored output
    #[arg(long, action = ArgAction::SetTrue)]
    pub no_color: bool,
    /// Request timeout in seconds
    #[arg(long, default_value_t = 10)]
    pub timeout: u64,
    /// Run probes sequentially (one at a time)
    #[arg(long, action = ArgAction::SetTrue)]
    pub sequential: bool,
    /// Show more details in report output
    #[arg(short = 'v', long, action = ArgAction::SetTrue)]
    pub verbose: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SectionName {
    Target,
    Whois,
    Redirects,
    Dns,
    Tls,
    Headers,
    Tech,
    Performance,
    Summary,
}

impl SectionName {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "target" | "http" => Some(Self::Target),
            "whois" | "rdap" => Some(Self::Whois),
            "redirects" | "redirect" => Some(Self::Redirects),
            "dns" | "ip" => Some(Self::Dns),
            "tls" | "cert" | "certificate" => Some(Self::Tls),
            "headers" | "security" | "security-headers" => Some(Self::Headers),
            "tech" | "technology" | "fingerprint" => Some(Self::Tech),
            "performance" | "perf" => Some(Self::Performance),
            "summary" | "grade" => Some(Self::Summary),
            _ => None,
        }
    }
}

pub(crate) fn parse_target_url(input: &str) -> Result<Url> {
    let parsed = Url::parse(input).or_else(|_| Url::parse(&format!("https://{input}")))?;
    if parsed.host_str().is_none() {
        return Err(anyhow!("unable to parse a hostname from input"));
    }
    Ok(parsed)
}

pub(crate) fn parse_sections(raw_sections: &[String]) -> Result<HashSet<SectionName>> {
    let mut sections = HashSet::new();
    for raw in raw_sections {
        let Some(section) = SectionName::parse(raw) else {
            return Err(anyhow!(
                "unknown section `{raw}` (supported: target, whois, redirects, dns, tls, headers, tech, performance, summary)"
            ));
        };
        sections.insert(section);
    }
    Ok(sections)
}

pub(crate) fn alt_scheme_url(url: &Url) -> Option<Url> {
    let mut alt = url.clone();
    let new_scheme = match url.scheme() {
        "https" => "http",
        "http" => "https",
        _ => return None,
    };
    if alt.set_scheme(new_scheme).is_ok() {
        Some(alt)
    } else {
        None
    }
}
