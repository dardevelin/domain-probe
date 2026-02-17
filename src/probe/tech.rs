use std::collections::HashMap;

#[derive(Debug)]
pub(crate) struct TechMatch {
    pub name: String,
    pub category: String,
    pub icon: &'static str,
}

pub(crate) struct TechProbe {
    pub technologies: Vec<TechMatch>,
}

pub(crate) fn detect_technologies(headers: &HashMap<String, String>) -> TechProbe {
    let mut technologies = Vec::new();

    let server = headers
        .get("server")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let x_powered_by = headers
        .get("x-powered-by")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();
    let via = headers
        .get("via")
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    // Cloudflare
    if server.contains("cloudflare") || headers.contains_key("cf-ray") {
        technologies.push(TechMatch {
            name: "Cloudflare".into(),
            category: "CDN / Security".into(),
            icon: "\u{2601}",
        });
    }

    // Vercel
    if headers.contains_key("x-vercel-id") {
        technologies.push(TechMatch {
            name: "Vercel".into(),
            category: "Hosting".into(),
            icon: "\u{25B2}",
        });
    }

    // Next.js
    if x_powered_by.contains("next.js") {
        technologies.push(TechMatch {
            name: "Next.js".into(),
            category: "Framework".into(),
            icon: "\u{25C8}",
        });
    }

    // Express / Node.js
    if x_powered_by.contains("express") {
        technologies.push(TechMatch {
            name: "Express / Node.js".into(),
            category: "Runtime".into(),
            icon: "\u{2699}",
        });
    }

    // nginx
    if server.contains("nginx") {
        technologies.push(TechMatch {
            name: "nginx".into(),
            category: "Web Server".into(),
            icon: "\u{25C9}",
        });
    }

    // Apache
    if server.contains("apache") {
        technologies.push(TechMatch {
            name: "Apache".into(),
            category: "Web Server".into(),
            icon: "\u{25C9}",
        });
    }

    // CloudFront
    if headers.contains_key("x-amz-cf-id") {
        technologies.push(TechMatch {
            name: "CloudFront".into(),
            category: "CDN".into(),
            icon: "\u{2601}",
        });
    }

    // Fastly
    if headers.contains_key("x-fastly-request-id") {
        technologies.push(TechMatch {
            name: "Fastly".into(),
            category: "CDN".into(),
            icon: "\u{26A1}",
        });
    }

    // Shopify
    if headers.contains_key("x-shopify-stage") {
        technologies.push(TechMatch {
            name: "Shopify".into(),
            category: "E-Commerce".into(),
            icon: "\u{1F6D2}",
        });
    }

    // GitHub Pages
    if headers.contains_key("x-github-request-id") {
        technologies.push(TechMatch {
            name: "GitHub Pages".into(),
            category: "Hosting".into(),
            icon: "\u{2B22}",
        });
    }

    // Varnish
    if via.contains("varnish") {
        technologies.push(TechMatch {
            name: "Varnish".into(),
            category: "Cache".into(),
            icon: "\u{26A1}",
        });
    }

    TechProbe { technologies }
}
