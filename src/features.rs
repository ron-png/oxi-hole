use crate::blocklist::{BlocklistManager, RewriteTarget};
use crate::dns::upstream::UpstreamForwarder;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Known list URLs associated with built-in feature toggles.  These stay
/// hard-coded, but the URLs enter the shared source pool at toggle-time —
/// they're refreshed, stored, and displayed uniformly with any user-added
/// source.
pub const BLOCKLIST_ADS_MALWARE: &str =
    "https://raw.githubusercontent.com/ron-png/UltimateDNSBlockList/refs/heads/main/list/UltimateDNSBlockList.txt";
pub const BLOCKLIST_NSFW: &str = "https://nsfw.oisd.nl";
pub const SAFE_SEARCH_LIST_URL: &str =
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/refs/heads/main/assets/engines_safe_search.txt";
pub const YOUTUBE_SAFE_SEARCH_LIST_URL: &str =
    "https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/refs/heads/main/assets/youtube_safe_search.txt";

/// Map a known feature source URL to its feature ID, for UI affordances
/// (e.g. rendering a feature-owned row with a badge).  Returns None for
/// user-added URLs.
pub fn url_to_feature_id(url: &str) -> Option<&'static str> {
    match url {
        BLOCKLIST_ADS_MALWARE => Some("ads_malware"),
        BLOCKLIST_NSFW => Some("nsfw"),
        SAFE_SEARCH_LIST_URL => Some("safe_search"),
        YOUTUBE_SAFE_SEARCH_LIST_URL => Some("youtube_safe_search"),
        _ => None,
    }
}

/// DNS rewrite target.  Thin alias over `RewriteTarget` kept for callers
/// (DNS handler) that used the old name.
pub type SafeSearchTarget = RewriteTarget;

/// Feature definition — a named toggle with an optional external list URL.
/// The list is parsed per-line (blocks / allows / rewrites) just like any
/// user-added source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: String,
    /// External list URL attached to this feature.  None for toggles that
    /// don't touch the source pool (e.g. root_servers).
    #[serde(default)]
    pub list_url: Option<String>,
    pub enabled: bool,
}

/// Manages feature toggles and their state.  Rewrite rules themselves are
/// owned by `BlocklistManager` — this struct only bookkeeps which toggles
/// are on.
#[derive(Clone)]
pub struct FeatureManager {
    features: Arc<RwLock<Vec<FeatureDefinition>>>,
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
                list_url: Some(BLOCKLIST_ADS_MALWARE.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "nsfw".to_string(),
                name: "Block NSFW Content".to_string(),
                description: "Blocks adult and explicit content domains using the OISD NSFW list.".to_string(),
                icon: "eye-off".to_string(),
                list_url: Some(BLOCKLIST_NSFW.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "safe_search".to_string(),
                name: "Enforce Safe Search".to_string(),
                description: "Forces safe search on Google, Bing, and DuckDuckGo via DNS.".to_string(),
                icon: "search".to_string(),
                list_url: Some(SAFE_SEARCH_LIST_URL.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "youtube_safe_search".to_string(),
                name: "YouTube Restricted Mode".to_string(),
                description: "Enforces YouTube restricted mode via DNS rewriting.".to_string(),
                icon: "search".to_string(),
                list_url: Some(YOUTUBE_SAFE_SEARCH_LIST_URL.to_string()),
                enabled: false,
            },
            FeatureDefinition {
                id: "root_servers".to_string(),
                name: "Use Root DNS Servers".to_string(),
                description: "Resolve domains directly via root servers instead of third-party resolvers. Maximum privacy — no upstream sees all your queries.".to_string(),
                icon: "globe".to_string(),
                list_url: None,
                enabled: false,
            },
        ];

        Self {
            features: Arc::new(RwLock::new(features)),
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

    /// Toggle a feature on/off.  Attaches or detaches the feature's list URL
    /// on the shared BlocklistManager.  The parser classifies each line
    /// per-entry, so there's no "kind" to pick.
    pub async fn set_feature(&self, feature_id: &str, enabled: bool) {
        // Update the feature's in-memory state and capture the URL to act
        // on.  No write lock held past this scope.
        let (list_url, name) = {
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
            (feature.list_url.clone(), feature.name.clone())
        };

        // Root-servers is special-cased: no external list, just a flag on
        // the upstream forwarder.
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

        if enabled {
            info!("Enabling feature '{}'", name);
        } else {
            info!("Disabling feature '{}'", name);
        }

        if let Some(url) = list_url {
            if enabled {
                if let Err(e) = self.blocklist.add_source(&url).await {
                    warn!("{}: {}", name, e);
                    // Revert feature state so the UI reflects reality.
                    let mut features = self.features.write().await;
                    if let Some(f) = features.iter_mut().find(|f| f.id == feature_id) {
                        f.enabled = false;
                    }
                }
            } else {
                self.blocklist.remove_source(&url).await;
            }
        }
    }

    /// Delegated to BlocklistManager's unified rewrite-rule table.
    /// Second tuple element is the source URL (used by the DNS handler for
    /// debug-logging / attribution); no longer a feature_id.  Callers that
    /// need the feature id can pipe through `url_to_feature_id`.
    pub async fn get_safe_search_target(&self, domain: &str) -> Option<(SafeSearchTarget, String)> {
        self.blocklist.get_rewrite_target(domain).await
    }
}
