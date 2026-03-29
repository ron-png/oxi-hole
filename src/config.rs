use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// How blocked domains are responded to.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode", content = "value")]
pub enum BlockingMode {
    /// Adblock-style → 0.0.0.0/::; hosts-style → IP from the rule.
    #[default]
    Default,
    /// Respond with DNS REFUSED rcode.
    Refused,
    /// Respond with DNS NXDOMAIN rcode.
    NxDomain,
    /// Always respond with 0.0.0.0 (A) / :: (AAAA).
    NullIp,
    /// Respond with user-specified IPs.
    CustomIp { ipv4: Ipv4Addr, ipv6: Ipv6Addr },
}

impl std::fmt::Display for BlockingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockingMode::Default => write!(f, "default"),
            BlockingMode::Refused => write!(f, "refused"),
            BlockingMode::NxDomain => write!(f, "nxdomain"),
            BlockingMode::NullIp => write!(f, "null_ip"),
            BlockingMode::CustomIp { ipv4, ipv6 } => write!(f, "custom_ip({}, {})", ipv4, ipv6),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_dns")]
    pub dns: DnsConfig,
    #[serde(default = "default_web")]
    pub web: WebConfig,
    #[serde(default)]
    pub blocking: BlockingConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub system: SystemConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Address to listen on for plain DNS (UDP+TCP)
    #[serde(default = "default_dns_listen")]
    pub listen: String,
    /// Address to listen on for DNS-over-TLS (port 853 typically)
    #[serde(default)]
    pub dot_listen: Option<String>,
    /// Address to listen on for DNS-over-HTTPS
    #[serde(default)]
    pub doh_listen: Option<String>,
    /// Address to listen on for DNS-over-QUIC
    #[serde(default)]
    pub doq_listen: Option<String>,
    /// Upstream DNS servers (supports udp://, tls://, https://, quic:// prefixes)
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<String>,
    /// Timeout for upstream queries in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    /// Address to listen on for the web admin UI
    #[serde(default = "default_web_listen")]
    pub listen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    /// Path to TLS certificate file (PEM). If not set, a self-signed cert is generated.
    #[serde(default)]
    pub cert_path: Option<String>,
    /// Path to TLS private key file (PEM). If not set, a self-signed cert is generated.
    #[serde(default)]
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingConfig {
    /// Whether blocking is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Blocklist URLs or file paths
    #[serde(default)]
    pub blocklists: Vec<String>,
    /// Manually blocked domains
    #[serde(default)]
    pub custom_blocked: Vec<String>,
    /// Allowlisted domains (bypass blocking)
    #[serde(default)]
    pub allowlist: Vec<String>,
    /// How often to refresh blocklists, in minutes (0 = disabled)
    #[serde(default = "default_update_interval")]
    pub update_interval_minutes: u64,
    /// Enabled feature IDs (restored on restart)
    #[serde(default)]
    pub enabled_features: Vec<String>,
    /// How blocked domains are responded to
    #[serde(default)]
    pub blocking_mode: BlockingMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemConfig {
    /// Whether to auto-update the server. Warning: An update could cause unforseeable bugs which could lead to the dns service breaking.
    #[serde(default)]
    pub auto_update: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// How many days to retain query logs (1-90)
    #[serde(default = "default_log_retention_days")]
    pub retention_days: u32,
    /// Whether to anonymize client IPs in the query log
    #[serde(default)]
    pub anonymize_client_ip: bool,
}

fn default_log_retention_days() -> u32 {
    90
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            retention_days: default_log_retention_days(),
            anonymize_client_ip: false,
        }
    }
}

fn default_dns() -> DnsConfig {
    DnsConfig {
        listen: default_dns_listen(),
        dot_listen: None,
        doh_listen: None,
        doq_listen: None,
        upstreams: default_upstreams(),
        timeout_ms: default_timeout_ms(),
    }
}

fn default_web() -> WebConfig {
    WebConfig {
        listen: default_web_listen(),
    }
}

fn default_dns_listen() -> String {
    "0.0.0.0:53".to_string()
}

fn default_web_listen() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_upstreams() -> Vec<String> {
    vec![
        "tls://9.9.9.9:853".to_string(),
        "tls://1.1.1.1:853".to_string(),
    ]
}

fn default_timeout_ms() -> u64 {
    5000
}

fn default_true() -> bool {
    true
}

fn default_update_interval() -> u64 {
    60
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            blocklists: Vec::new(),
            custom_blocked: Vec::new(),
            allowlist: Vec::new(),
            update_interval_minutes: default_update_interval(),
            enabled_features: Vec::new(),
            blocking_mode: BlockingMode::default(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            tracing::warn!(
                "Config file not found at {}, using defaults",
                path.display()
            );
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dns: default_dns(),
            web: default_web(),
            blocking: BlockingConfig::default(),
            tls: TlsConfig::default(),
            system: SystemConfig::default(),
            log: LogConfig::default(),
        }
    }
}
