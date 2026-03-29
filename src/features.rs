use crate::blocklist::BlocklistManager;
use crate::dns::upstream::UpstreamForwarder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Known blocklist URLs for each feature.
pub const BLOCKLIST_ADS_MALWARE: &str =
    "https://raw.githubusercontent.com/ron-png/UltimateDNSBlockList/refs/heads/main/list/UltimateDNSBlockList.txt";
pub const BLOCKLIST_NSFW: &str = "https://nsfw.oisd.nl";
pub const SAFE_SEARCH_LIST_URL: &str =
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/refs/heads/main/assets/engines_safe_search.txt";
pub const YOUTUBE_SAFE_SEARCH_LIST_URL: &str =
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/refs/heads/main/assets/youtube_safe_search.txt";

/// Map a blocklist URL to its feature ID, if it belongs to a known feature.
pub fn url_to_feature_id(url: &str) -> Option<&'static str> {
    match url {
        BLOCKLIST_ADS_MALWARE => Some("ads_malware"),
        BLOCKLIST_NSFW => Some("nsfw"),
        _ => None,
    }
}

/// A safe search DNS rewrite target.
#[derive(Debug, Clone)]
pub enum SafeSearchTarget {
    A(Ipv4Addr),
    Cname(String),
}

/// Feature definition - a named toggle with an associated blocklist URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    pub blocklist_url: Option<String>,
    pub enabled: bool,
}

/// Manages feature toggles and their state.
#[derive(Clone)]
pub struct FeatureManager {
    features: Arc<RwLock<Vec<FeatureDefinition>>>,
    safe_search_enabled: Arc<RwLock<bool>>,
    safe_search_rules: Arc<RwLock<HashMap<String, (SafeSearchTarget, &'static str)>>>,
    blocklist: BlocklistManager,
    upstream: Option<UpstreamForwarder>,
}

impl FeatureManager {
    pub fn new(blocklist: BlocklistManager) -> Self {
        let features = vec![
            FeatureDefinition {
                id: "ads_malware".to_string(),
                name: "Block Ads, Malware & Trackers".to_string(),
                description: "Blocks advertising, malware, and tracking domains using a comprehensive blocklist.".to_string(),
                icon: "shield".to_string(),
                blocklist_url: Some(BLOCKLIST_ADS_MALWARE.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "nsfw".to_string(),
                name: "Block NSFW Content".to_string(),
                description: "Blocks adult and explicit content domains using the OISD NSFW list.".to_string(),
                icon: "eye-off".to_string(),
                blocklist_url: Some(BLOCKLIST_NSFW.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "safe_search".to_string(),
                name: "Enforce Safe Search".to_string(),
                description: "Forces safe search on Google, Bing, and DuckDuckGo via DNS.".to_string(),
                icon: "search".to_string(),
                blocklist_url: None, // Handled via DNS rewriting, not blocklist
                enabled: false,
            },
            FeatureDefinition {
                id: "youtube_safe_search".to_string(),
                name: "YouTube Safe Search".to_string(),
                description: "Enforces YouTube restricted mode via DNS rewriting.".to_string(),
                icon: "search".to_string(),
                blocklist_url: None, // Handled via DNS rewriting, not blocklist
                enabled: false,
            },
            FeatureDefinition {
                id: "root_servers".to_string(),
                name: "Use Root DNS Servers".to_string(),
                description: "Resolve domains directly via root servers instead of third-party resolvers. Maximum privacy — no upstream sees all your queries.".to_string(),
                icon: "globe".to_string(),
                blocklist_url: None,
                enabled: false,
            },
        ];

        Self {
            features: Arc::new(RwLock::new(features)),
            safe_search_enabled: Arc::new(RwLock::new(false)),
            safe_search_rules: Arc::new(RwLock::new(HashMap::new())),
            blocklist,
            upstream: None,
        }
    }

    /// Set the upstream forwarder reference (must be called before toggling root_servers).
    pub fn set_upstream(&mut self, upstream: UpstreamForwarder) {
        self.upstream = Some(upstream);
    }

    pub async fn get_features(&self) -> Vec<FeatureDefinition> {
        self.features.read().await.clone()
    }

    #[allow(dead_code)]
    pub async fn is_safe_search_enabled(&self) -> bool {
        *self.safe_search_enabled.read().await
    }

    /// Toggle a feature on or off. If it has a blocklist, load/unload it.
    pub async fn set_feature(&self, feature_id: &str, enabled: bool) {
        // Update feature state and collect needed info while holding write lock
        let (blocklist_url, name, other_safe_search_enabled) = {
            let mut features = self.features.write().await;
            let feature = match features.iter_mut().find(|f| f.id == feature_id) {
                Some(f) => f,
                None => {
                    warn!("Unknown feature: {}", feature_id);
                    return;
                }
            };

            if feature.enabled == enabled {
                return;
            }

            feature.enabled = enabled;
            let blocklist_url = feature.blocklist_url.clone();
            let name = feature.name.clone();

            // Check if the other safe search feature is enabled (while we hold the lock)
            let other_id = if feature_id == "safe_search" {
                "youtube_safe_search"
            } else {
                "safe_search"
            };
            let other_enabled = features.iter().any(|f| f.id == other_id && f.enabled);

            (blocklist_url, name, other_enabled)
        };
        // Write lock on features is dropped here

        // Handle safe search separately
        if feature_id == "safe_search" {
            if enabled {
                info!("Enabling safe search, loading rules...");
                match Self::fetch_rules(SAFE_SEARCH_LIST_URL, "safe_search").await {
                    Ok(rules) => {
                        info!("Loaded {} safe search rewrite rules", rules.len());
                        let mut all_rules = self.safe_search_rules.write().await;
                        all_rules.extend(rules);
                        *self.safe_search_enabled.write().await = true;
                    }
                    Err(e) => {
                        warn!("Failed to load safe search rules: {}", e);
                    }
                }
            } else {
                let mut all_rules = self.safe_search_rules.write().await;
                all_rules.clear();
                if other_safe_search_enabled {
                    if let Ok(rules) =
                        Self::fetch_rules(YOUTUBE_SAFE_SEARCH_LIST_URL, "youtube_safe_search").await
                    {
                        all_rules.extend(rules);
                    }
                } else {
                    *self.safe_search_enabled.write().await = false;
                }
                info!("Safe search disabled");
            }
            return;
        }

        // Handle YouTube safe search separately
        if feature_id == "youtube_safe_search" {
            if enabled {
                info!("Enabling YouTube safe search, loading rules...");
                match Self::fetch_rules(YOUTUBE_SAFE_SEARCH_LIST_URL, "youtube_safe_search").await {
                    Ok(rules) => {
                        info!("Loaded {} YouTube safe search rewrite rules", rules.len());
                        let mut all_rules = self.safe_search_rules.write().await;
                        all_rules.extend(rules);
                        *self.safe_search_enabled.write().await = true;
                    }
                    Err(e) => {
                        warn!("Failed to load YouTube safe search rules: {}", e);
                    }
                }
            } else {
                let mut all_rules = self.safe_search_rules.write().await;
                all_rules.clear();
                if other_safe_search_enabled {
                    if let Ok(rules) =
                        Self::fetch_rules(SAFE_SEARCH_LIST_URL, "safe_search").await
                    {
                        all_rules.extend(rules);
                    }
                } else {
                    *self.safe_search_enabled.write().await = false;
                }
                info!("YouTube safe search disabled");
            }
            return;
        }

        // Handle root servers toggle
        if feature_id == "root_servers" {
            if let Some(ref upstream) = self.upstream {
                upstream.set_use_root_servers(enabled);
                info!(
                    "Root DNS servers {}",
                    if enabled { "enabled" } else { "disabled" }
                );
            } else {
                warn!("Cannot toggle root servers: upstream forwarder not set");
            }
            return;
        }

        // Handle blocklist-based features
        if let Some(url) = blocklist_url {
            if enabled {
                info!("Enabling feature '{}', loading blocklist...", name);
                let _ = self.blocklist.add_blocklist_source(&url).await;
            } else {
                info!("Disabling feature '{}', removing blocklist...", name);
                self.blocklist.remove_blocklist_source(&url).await;
            }
        }
    }

    /// Get safe search rewrite target for a domain, if safe search is on.
    /// Returns (target, feature_id) where feature_id is "safe_search" or "youtube_safe_search".
    pub async fn get_safe_search_target(
        &self,
        domain: &str,
    ) -> Option<(SafeSearchTarget, &'static str)> {
        if !*self.safe_search_enabled.read().await {
            return None;
        }

        let domain_lower = domain.to_lowercase();
        let domain_trimmed = domain_lower.trim_end_matches('.');

        let rules = self.safe_search_rules.read().await;
        rules.get(domain_trimmed).cloned()
    }

    /// Fetch and parse AdGuard DNS rewrite rules from a URL.
    async fn fetch_rules(
        url: &str,
        feature_id: &'static str,
    ) -> anyhow::Result<HashMap<String, (SafeSearchTarget, &'static str)>> {
        let resp = reqwest::get(url).await?;
        let content = resp.text().await?;
        let raw_rules = parse_safe_search_rules(&content);
        let mut rules: HashMap<String, (SafeSearchTarget, &'static str)> = raw_rules
            .into_iter()
            .map(|(k, v)| (k, (v, feature_id)))
            .collect();

        // The upstream AdGuard list only covers www.youtube.com but not the bare
        // youtube.com domain. Browsers that navigate to youtube.com bypass the
        // rewrite entirely, so add the bare domain (and youtube-ui variants)
        // when we detect YouTube rules are present.
        if url == YOUTUBE_SAFE_SEARCH_LIST_URL {
            let extra = ["youtube.com", "youtubekids.com", "www.youtubekids.com"];
            for domain in extra {
                rules.entry(domain.to_string()).or_insert_with(|| {
                    (
                        SafeSearchTarget::Cname("restrictmoderate.youtube.com".to_string()),
                        feature_id,
                    )
                });
            }
        }

        Ok(rules)
    }
}

/// Parse AdGuard DNS rewrite rules into a domain -> target map.
/// Format: `|domain.com^$dnsrewrite=NOERROR;CNAME;target.com`
///     or: `|domain.com^$dnsrewrite=NOERROR;A;1.2.3.4`
fn parse_safe_search_rules(content: &str) -> HashMap<String, SafeSearchTarget> {
    let mut rules = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        // Parse: |domain^$dnsrewrite=NOERROR;TYPE;VALUE
        let line = match line.strip_prefix('|') {
            Some(l) => l,
            None => continue,
        };

        let (domain_part, rewrite_part) = match line.split_once("^$dnsrewrite=NOERROR;") {
            Some(parts) => parts,
            None => continue,
        };

        let domain = domain_part.to_lowercase();
        let parts: Vec<&str> = rewrite_part.splitn(2, ';').collect();
        if parts.len() != 2 {
            continue;
        }

        let target = match parts[0] {
            "A" => match parts[1].parse::<Ipv4Addr>() {
                Ok(ip) => SafeSearchTarget::A(ip),
                Err(_) => continue,
            },
            "CNAME" => SafeSearchTarget::Cname(parts[1].to_string()),
            _ => continue,
        };

        rules.insert(domain, target);
    }

    rules
}
