use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderStatus {
    Pass,
    Warn,
    Fail,
    Info,
}

#[derive(Debug)]
pub(crate) struct HeaderCheck {
    pub name: &'static str,
    pub status: HeaderStatus,
    pub value: String,
}

#[derive(Debug)]
pub(crate) struct SecurityHeadersProbe {
    pub checks: Vec<HeaderCheck>,
    pub score: u32,
}

pub(crate) fn analyze_security_headers(headers: &HashMap<String, String>) -> SecurityHeadersProbe {
    let mut checks = Vec::with_capacity(8);
    let mut score: u32 = 0;
    let max_score: u32 = 10;

    // 1. Strict-Transport-Security (HSTS)
    match headers.get("strict-transport-security") {
        Some(val) => {
            let max_age = val
                .split(';')
                .find_map(|part| {
                    let part = part.trim().to_lowercase();
                    if part.starts_with("max-age=") {
                        part.strip_prefix("max-age=")?.parse::<u64>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if max_age >= 31_536_000 {
                checks.push(HeaderCheck {
                    name: "Strict-Transport-Security",
                    status: HeaderStatus::Pass,
                    value: val.clone(),
                });
                score += 2;
            } else {
                checks.push(HeaderCheck {
                    name: "Strict-Transport-Security",
                    status: HeaderStatus::Warn,
                    value: format!("{val} (max-age too low)"),
                });
                score += 1;
            }
        }
        None => {
            checks.push(HeaderCheck {
                name: "Strict-Transport-Security",
                status: HeaderStatus::Fail,
                value: "not set".into(),
            });
        }
    }

    // 2. Content-Security-Policy
    match headers.get("content-security-policy") {
        Some(val) => {
            checks.push(HeaderCheck {
                name: "Content-Security-Policy",
                status: HeaderStatus::Pass,
                value: truncate(val, 80),
            });
            score += 2;
        }
        None => {
            checks.push(HeaderCheck {
                name: "Content-Security-Policy",
                status: HeaderStatus::Warn,
                value: "not set".into(),
            });
        }
    }

    // 3. X-Frame-Options
    match headers.get("x-frame-options") {
        Some(val) => {
            checks.push(HeaderCheck {
                name: "X-Frame-Options",
                status: HeaderStatus::Pass,
                value: val.clone(),
            });
            score += 1;
        }
        None => {
            checks.push(HeaderCheck {
                name: "X-Frame-Options",
                status: HeaderStatus::Warn,
                value: "not set".into(),
            });
        }
    }

    // 4. X-Content-Type-Options
    match headers.get("x-content-type-options") {
        Some(val) => {
            if val.to_lowercase().contains("nosniff") {
                checks.push(HeaderCheck {
                    name: "X-Content-Type-Options",
                    status: HeaderStatus::Pass,
                    value: val.clone(),
                });
                score += 1;
            } else {
                checks.push(HeaderCheck {
                    name: "X-Content-Type-Options",
                    status: HeaderStatus::Warn,
                    value: format!("{val} (expected nosniff)"),
                });
            }
        }
        None => {
            checks.push(HeaderCheck {
                name: "X-Content-Type-Options",
                status: HeaderStatus::Warn,
                value: "not set".into(),
            });
        }
    }

    // 5. Permissions-Policy
    match headers.get("permissions-policy") {
        Some(val) => {
            checks.push(HeaderCheck {
                name: "Permissions-Policy",
                status: HeaderStatus::Pass,
                value: truncate(val, 80),
            });
            score += 1;
        }
        None => {
            checks.push(HeaderCheck {
                name: "Permissions-Policy",
                status: HeaderStatus::Warn,
                value: "not set".into(),
            });
        }
    }

    // 6. Cross-Origin-Opener-Policy
    match headers.get("cross-origin-opener-policy") {
        Some(val) => {
            checks.push(HeaderCheck {
                name: "Cross-Origin-Opener-Policy",
                status: HeaderStatus::Pass,
                value: val.clone(),
            });
            score += 1;
        }
        None => {
            checks.push(HeaderCheck {
                name: "Cross-Origin-Opener-Policy",
                status: HeaderStatus::Info,
                value: "not set".into(),
            });
        }
    }

    // 7. Referrer-Policy
    match headers.get("referrer-policy") {
        Some(val) => {
            checks.push(HeaderCheck {
                name: "Referrer-Policy",
                status: HeaderStatus::Pass,
                value: val.clone(),
            });
            score += 1;
        }
        None => {
            checks.push(HeaderCheck {
                name: "Referrer-Policy",
                status: HeaderStatus::Warn,
                value: "not set".into(),
            });
        }
    }

    // 8. X-XSS-Protection (deprecated)
    match headers.get("x-xss-protection") {
        Some(val) => {
            checks.push(HeaderCheck {
                name: "X-XSS-Protection",
                status: HeaderStatus::Info,
                value: format!("{val} (deprecated)"),
            });
            score += 1;
        }
        None => {
            checks.push(HeaderCheck {
                name: "X-XSS-Protection",
                status: HeaderStatus::Info,
                value: "not set (deprecated header)".into(),
            });
        }
    }

    // Clamp score to max
    score = score.min(max_score);

    SecurityHeadersProbe { checks, score }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max.saturating_sub(3);
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}
