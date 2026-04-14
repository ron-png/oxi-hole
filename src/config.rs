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
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Operator overrides for hardware-adaptive resource limits.
/// Every field is optional — unset fields use values computed from detected CPU/RAM.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Max entries in the DNS response cache.
    #[serde(default)]
    pub dns_cache_entries: Option<usize>,
    /// Max entries in the per-zone NS (delegation) cache used by the iterative resolver.
    #[serde(default)]
    pub ns_cache_entries: Option<usize>,
    /// Max concurrent in-flight UDP query tasks (semaphore cap).
    #[serde(default)]
    pub udp_max_inflight: Option<usize>,
    /// Max concurrent plain-TCP DNS connections.
    #[serde(default)]
    pub tcp_max_connections: Option<usize>,
    /// Max concurrent DNS-over-TLS connections.
    #[serde(default)]
    pub dot_max_connections: Option<usize>,
    /// Max concurrent DNS-over-HTTPS connections.
    #[serde(default)]
    pub doh_max_connections: Option<usize>,
    /// Max concurrent bidirectional streams per DoQ connection.
    #[serde(default)]
    pub doq_max_streams_per_connection: Option<u64>,
    /// Max size for a single downloaded blocklist, in MB.
    #[serde(default)]
    pub blocklist_max_mb: Option<usize>,
    /// Max size for a single web-admin upload (cert/key/p12), in MB.
    #[serde(default)]
    pub web_upload_max_mb: Option<usize>,
    /// When the query log DB grows past this, rotate oldest rows into an
    /// archive DB (rows stay visible in the UI).
    #[serde(default)]
    pub query_log_rotate_mb: Option<u64>,
    /// Minimum free disk to keep on the query log's filesystem.  Below this,
    /// an emergency purge drops the archive then trims the active DB.
    /// Shared floor — also used by the stats DB since they live on the same
    /// filesystem.
    #[serde(default)]
    pub query_log_free_disk_floor_mb: Option<u64>,
    /// When the stats DB grows past this, rotate oldest rows into an archive.
    #[serde(default)]
    pub stats_rotate_mb: Option<u64>,
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
    /// Whether query logging is enabled at all. When false, no entries are
    /// written to the query log database (existing entries are retained).
    #[serde(default = "default_true")]
    pub query_log_enabled: bool,
    /// Retention in days. Legacy field kept for back-compat with hand-edited
    /// configs; the web UI writes to `query_log_retention_minutes` instead.
    /// On startup, if `_minutes` is unset and this is set, we migrate it.
    #[serde(default, alias = "retention_days")]
    pub query_log_retention_days: Option<u32>,
    /// Retention in minutes. Takes precedence over `_days` when set.
    #[serde(default)]
    pub query_log_retention_minutes: Option<u32>,
    /// Whether persistent statistics (hourly aggregates, top domains) are
    /// recorded. When false, new queries are not counted; existing rows
    /// remain and can still be viewed/deleted from the web UI.
    #[serde(default = "default_true")]
    pub stats_enabled: bool,
    /// Legacy: retention in days.  Kept for back-compat.
    #[serde(default)]
    pub stats_retention_days: Option<u32>,
    /// Canonical retention in minutes for persistent stats.  Takes precedence
    /// over `stats_retention_days` when set.
    #[serde(default)]
    pub stats_retention_minutes: Option<u32>,
    /// Whether to anonymize client IPs in the query log
    #[serde(default)]
    pub anonymize_client_ip: bool,
}

impl LogConfig {
    /// Effective query-log retention in minutes.
    pub fn effective_retention_minutes(&self) -> u32 {
        if let Some(m) = self.query_log_retention_minutes {
            return m;
        }
        if let Some(d) = self.query_log_retention_days {
            return d.saturating_mul(1440);
        }
        default_query_log_retention_days().saturating_mul(1440)
    }

    /// Effective stats retention in minutes.
    pub fn effective_stats_retention_minutes(&self) -> u32 {
        if let Some(m) = self.stats_retention_minutes {
            return m;
        }
        if let Some(d) = self.stats_retention_days {
            return d.saturating_mul(1440);
        }
        default_stats_retention_days().saturating_mul(1440)
    }
}

fn default_query_log_retention_days() -> u32 {
    7
}

fn default_stats_retention_days() -> u32 {
    90
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            query_log_enabled: true,
            query_log_retention_days: None,
            query_log_retention_minutes: Some(
                default_query_log_retention_days().saturating_mul(1440),
            ),
            stats_enabled: true,
            stats_retention_days: None,
            stats_retention_minutes: Some(default_stats_retention_days().saturating_mul(1440)),
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

        // v0.6.0+: query_log_retention_days → query_log_retention_minutes.
        // Preserve the intent of hand-edited configs that still use _days.
        if self.log.query_log_retention_minutes.is_none() {
            if let Some(d) = self.log.query_log_retention_days.take() {
                self.log.query_log_retention_minutes = Some(d.saturating_mul(1440));
                tracing::info!(
                    "Config migration: query_log_retention_days={} → query_log_retention_minutes={}",
                    d,
                    d.saturating_mul(1440)
                );
                changed = true;
            }
        }

        // v0.6.5+: stats_retention_days → stats_retention_minutes (same rationale).
        if self.log.stats_retention_minutes.is_none() {
            if let Some(d) = self.log.stats_retention_days.take() {
                self.log.stats_retention_minutes = Some(d.saturating_mul(1440));
                tracing::info!(
                    "Config migration: stats_retention_days={} → stats_retention_minutes={}",
                    d,
                    d.saturating_mul(1440)
                );
                changed = true;
            }
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
            limits: LimitsConfig::default(),
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
        assert!(
            !cfg.auto_redirect_https,
            "auto_redirect_https defaults to false"
        );
    }

    #[test]
    fn web_config_round_trip_preserves_new_fields() {
        let toml_str = r#"
listen = ["0.0.0.0:9853"]
https_listen = ["0.0.0.0:9854"]
auto_redirect_https = true
"#;
        let cfg: WebConfig = toml::from_str(toml_str).expect("parse");
        assert!(cfg.auto_redirect_https);

        let serialized = toml::to_string(&cfg).expect("serialize");
        let reparsed: WebConfig = toml::from_str(&serialized).expect("reparse");
        assert!(reparsed.auto_redirect_https);
    }

    #[test]
    fn web_config_missing_new_fields_defaults_false() {
        // Old configs must deserialize without error.
        let toml_str = r#"
listen = ["0.0.0.0:9853"]
"#;
        let cfg: WebConfig = toml::from_str(toml_str).expect("parse");
        assert!(!cfg.auto_redirect_https);
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
