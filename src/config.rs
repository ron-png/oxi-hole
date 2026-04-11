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
    /// Addresses to listen on for plain DNS (UDP+TCP)
    #[serde(default = "default_dns_listen", deserialize_with = "string_or_vec")]
    pub listen: Vec<String>,
    /// Addresses to listen on for DNS-over-TLS (port 853 typically)
    #[serde(default, deserialize_with = "string_or_vec_opt")]
    pub dot_listen: Option<Vec<String>>,
    /// Addresses to listen on for DNS-over-HTTPS
    #[serde(default, deserialize_with = "string_or_vec_opt")]
    pub doh_listen: Option<Vec<String>>,
    /// Addresses to listen on for DNS-over-QUIC
    #[serde(default, deserialize_with = "string_or_vec_opt")]
    pub doq_listen: Option<Vec<String>>,
    /// Upstream DNS servers (supports udp://, tls://, https://, quic:// prefixes)
    #[serde(default = "default_upstreams")]
    pub upstreams: Vec<String>,
    /// Timeout for upstream queries in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Enable DNS response caching
    #[serde(default = "default_cache_enabled")]
    pub cache_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    /// Addresses to listen on for the web admin UI
    #[serde(default = "default_web_listen", deserialize_with = "string_or_vec")]
    pub listen: Vec<String>,
    /// Addresses to listen on for the HTTPS web admin UI (opt-in)
    #[serde(default, deserialize_with = "string_or_vec_opt")]
    pub https_listen: Option<Vec<String>>,
    /// Force HTTP requests to redirect to HTTPS. Off by default.
    #[serde(default)]
    pub auto_redirect_https: bool,
    /// Set when auto_redirect_https is first enabled; cleared on successful
    /// password change. Drives the dashboard password-rotation banner.
    #[serde(default)]
    pub password_change_recommended: bool,
    /// Trust the X-Forwarded-Proto header from a reverse proxy to determine
    /// whether a request should be treated as HTTPS. ONLY enable if oxi-dns
    /// is ONLY reachable through a trusted TLS-terminating proxy — otherwise
    /// attackers can spoof the header and bypass HTTPS-required checks.
    #[serde(default)]
    pub trust_forwarded_proto: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub email: String,
    /// "cloudflare" or "manual"
    #[serde(default = "default_acme_provider")]
    pub provider: String,
    #[serde(default)]
    pub cloudflare_api_token: String,
    #[serde(default)]
    pub use_staging: bool,
    #[serde(default)]
    pub last_renewed: String,
    #[serde(default)]
    pub last_renewal_error: String,
}

fn default_acme_provider() -> String {
    "cloudflare".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    /// Path to TLS certificate file (PEM). If not set, a self-signed cert is generated.
    #[serde(default)]
    pub cert_path: Option<String>,
    /// Path to TLS private key file (PEM). If not set, a self-signed cert is generated.
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub acme: AcmeConfig,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    /// Whether to automatically check for and apply updates. Updates are health-checked before applying.
    #[serde(default)]
    pub auto_update: bool,
    /// Whether to include AAAA (IPv6) records in DNS responses.
    #[serde(default = "default_true")]
    pub ipv6_enabled: bool,
    /// Release channel for updates (e.g. "stable", "beta").
    #[serde(default = "default_release_channel")]
    pub release_channel: String,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            auto_update: false,
            ipv6_enabled: true,
            release_channel: default_release_channel(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_query_log_retention", alias = "retention_days")]
    pub query_log_retention_days: u32,
    #[serde(default = "default_stats_retention")]
    pub stats_retention_days: u32,
    /// Whether to anonymize client IPs in the query log
    #[serde(default)]
    pub anonymize_client_ip: bool,
}

fn default_query_log_retention() -> u32 {
    7
}

fn default_stats_retention() -> u32 {
    90
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            query_log_retention_days: default_query_log_retention(),
            stats_retention_days: default_stats_retention(),
            anonymize_client_ip: false,
        }
    }
}

/// Deserialize a field that can be either a single string or a list of strings.
fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or list of strings")
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Vec<String>, E> {
            Ok(vec![value.to_string()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut vec = Vec::new();
            while let Some(value) = seq.next_element()? {
                vec.push(value);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

fn string_or_vec_opt<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVecOpt;

    impl<'de> de::Visitor<'de> for StringOrVecOpt {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("null, a string, or list of strings")
        }

        fn visit_none<E: de::Error>(self) -> Result<Option<Vec<String>>, E> {
            Ok(None)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Option<Vec<String>>, E> {
            Ok(None)
        }

        fn visit_str<E: de::Error>(self, value: &str) -> Result<Option<Vec<String>>, E> {
            Ok(Some(vec![value.to_string()]))
        }

        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Option<Vec<String>>, A::Error> {
            let mut vec = Vec::new();
            while let Some(value) = seq.next_element()? {
                vec.push(value);
            }
            Ok(Some(vec))
        }
    }

    deserializer.deserialize_any(StringOrVecOpt)
}

fn default_dns() -> DnsConfig {
    DnsConfig {
        listen: default_dns_listen(),
        dot_listen: None,
        doh_listen: None,
        doq_listen: None,
        upstreams: default_upstreams(),
        timeout_ms: default_timeout_ms(),
        cache_enabled: default_cache_enabled(),
    }
}

fn default_web() -> WebConfig {
    WebConfig {
        listen: default_web_listen(),
        https_listen: None,
        auto_redirect_https: false,
        password_change_recommended: false,
        trust_forwarded_proto: false,
    }
}

fn default_dns_listen() -> Vec<String> {
    vec!["0.0.0.0:53".to_string(), "[::]:53".to_string()]
}

fn default_web_listen() -> Vec<String> {
    vec!["0.0.0.0:9853".to_string(), "[::]:9853".to_string()]
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

fn default_cache_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_release_channel() -> String {
    "stable".to_string()
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
            let mut config: Config = toml::from_str(&content)?;

            // Migrate: add new config fields that didn't exist in older versions.
            // Check the raw TOML to distinguish "field missing" from "explicitly empty".
            let raw: toml::Value = toml::from_str(&content)?;
            let migrated = config.migrate(&raw);
            if migrated {
                if let Err(e) = config.save(path) {
                    tracing::warn!("Failed to save migrated config: {}", e);
                } else {
                    tracing::info!("Config migrated with new defaults and saved");
                }
            }

            Ok(config)
        } else {
            tracing::warn!(
                "Config file not found at {}, using defaults",
                path.display()
            );
            Ok(Self::default())
        }
    }

    /// Apply config migrations for fields added in newer versions.
    /// Returns true if any changes were made.
    fn migrate(&mut self, raw: &toml::Value) -> bool {
        let mut changed = false;

        // v0.5.29+: web.https_listen defaults to port 9854 when missing
        let has_https_listen = raw.get("web").and_then(|w| w.get("https_listen")).is_some();
        if !has_https_listen && self.web.https_listen.is_none() {
            self.web.https_listen = Some(vec!["0.0.0.0:9854".to_string(), "[::]:9854".to_string()]);
            tracing::info!("Config migration: added web.https_listen = [0.0.0.0:9854, [::]:9854]");
            changed = true;
        }

        changed
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, &content)?;
        // Restrict config file permissions — it may contain secrets
        // (e.g. Cloudflare API token in [tls.acme]).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
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

#[cfg(test)]
mod web_config_tests {
    use super::*;

    #[test]
    fn web_config_has_new_https_fields_with_defaults() {
        let toml_str = r#"
listen = ["0.0.0.0:9853"]
https_listen = ["0.0.0.0:9854"]
"#;
        let cfg: WebConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.listen, vec!["0.0.0.0:9853".to_string()]);
        assert_eq!(cfg.https_listen, Some(vec!["0.0.0.0:9854".to_string()]));
        assert!(!cfg.auto_redirect_https, "auto_redirect_https defaults to false");
        assert!(
            !cfg.password_change_recommended,
            "password_change_recommended defaults to false"
        );
    }

    #[test]
    fn web_config_round_trip_preserves_new_fields() {
        let toml_str = r#"
listen = ["0.0.0.0:9853"]
https_listen = ["0.0.0.0:9854"]
auto_redirect_https = true
password_change_recommended = true
"#;
        let cfg: WebConfig = toml::from_str(toml_str).expect("parse");
        assert!(cfg.auto_redirect_https);
        assert!(cfg.password_change_recommended);

        let serialized = toml::to_string(&cfg).expect("serialize");
        let reparsed: WebConfig = toml::from_str(&serialized).expect("reparse");
        assert!(reparsed.auto_redirect_https);
        assert!(reparsed.password_change_recommended);
    }

    #[test]
    fn web_config_missing_new_fields_defaults_false() {
        // Old configs must deserialize without error.
        let toml_str = r#"
listen = ["0.0.0.0:9853"]
"#;
        let cfg: WebConfig = toml::from_str(toml_str).expect("parse");
        assert!(!cfg.auto_redirect_https);
        assert!(!cfg.password_change_recommended);
        assert!(cfg.https_listen.is_none());
    }

    #[test]
    fn web_config_trust_forwarded_proto_defaults_false() {
        let toml_str = r#"
listen = ["0.0.0.0:9853"]
"#;
        let cfg: WebConfig = toml::from_str(toml_str).expect("parse");
        assert!(!cfg.trust_forwarded_proto);
    }
}
