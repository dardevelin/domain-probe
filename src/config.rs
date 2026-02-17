use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub(crate) struct Config {
    pub colors: ColorConfig,
    pub dns: DnsConfig,
    pub network: NetworkConfig,
    pub animation: AnimationConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub(crate) struct ColorConfig {
    pub green: String,
    pub cyan: String,
    pub yellow: String,
    pub red: String,
    pub purple: String,
    pub orange: String,
    pub pink: String,
    pub teal: String,
    pub fg: String,
    pub muted: String,
    pub dim: String,
    pub bright: String,
}

impl Default for ColorConfig {
    fn default() -> Self {
        Self {
            green: "#86EFAC".into(),
            cyan: "#7DD3FC".into(),
            yellow: "#FDE68A".into(),
            red: "#FCA5A5".into(),
            purple: "#C4B5FD".into(),
            orange: "#FDBA74".into(),
            pink: "#F9A8D4".into(),
            teal: "#5EEAD4".into(),
            fg: "#C8C8E0".into(),
            muted: "#6B6B8D".into(),
            dim: "#444466".into(),
            bright: "#EEEEF5".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub(crate) struct DnsConfig {
    pub doh_url: String,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            doh_url: "https://dns.google/resolve".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub(crate) struct NetworkConfig {
    pub timeout: u64,
    pub max_redirect_hops: usize,
    pub user_agent: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            timeout: 10,
            max_redirect_hops: 10,
            user_agent: "domain-probe/0.1".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub(crate) struct AnimationConfig {
    pub enabled: bool,
}

impl Default for AnimationConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

pub(crate) fn load_config() -> Config {
    let config_path = dirs::config_dir()
        .map(|p| p.join("domain-probe").join("config.toml"));

    let Some(path) = config_path else {
        return Config::default();
    };

    if !path.exists() {
        return Config::default();
    }

    match std::fs::read_to_string(&path) {
        Ok(contents) => match toml::from_str::<Config>(&contents) {
            Ok(mut config) => {
                config.network.timeout = config.network.timeout.clamp(1, 120);
                config.network.max_redirect_hops = config.network.max_redirect_hops.clamp(1, 30);
                config
            }
            Err(err) => {
                eprintln!(
                    "warning: failed to parse {}: {err}; using defaults",
                    path.display()
                );
                Config::default()
            }
        },
        Err(err) => {
            eprintln!(
                "warning: failed to read {}: {err}; using defaults",
                path.display()
            );
            Config::default()
        }
    }
}

pub(crate) fn parse_hex_color(hex: &str) -> Option<(u8, u8, u8)> {
    if !hex.is_ascii() {
        return None;
    }
    let hex = hex.trim_start_matches('#');
    if hex.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some((r, g, b))
}
