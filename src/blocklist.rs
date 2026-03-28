use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Manages the set of blocked domains loaded from blocklists, custom entries, and allowlist.
#[derive(Clone)]
pub struct BlocklistManager {
    /// All blocked domains (lowercase, normalized)
    blocked: Arc<RwLock<HashSet<String>>>,
    /// Domains loaded per source URL (for add/remove support)
    source_domains: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Custom blocked domains (manually added)
    custom_blocked: Arc<RwLock<HashSet<String>>>,
    /// Allowlisted domains that bypass blocking
    allowlist: Arc<RwLock<HashSet<String>>>,
    /// Whether blocking is globally enabled
    enabled: Arc<RwLock<bool>>,
    /// Blocklist source URLs/paths
    sources: Arc<RwLock<Vec<String>>>,
}

impl BlocklistManager {
    pub fn new(enabled: bool) -> Self {
        Self {
            blocked: Arc::new(RwLock::new(HashSet::new())),
            source_domains: Arc::new(RwLock::new(HashMap::new())),
            custom_blocked: Arc::new(RwLock::new(HashSet::new())),
            allowlist: Arc::new(RwLock::new(HashSet::new())),
            enabled: Arc::new(RwLock::new(enabled)),
            sources: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Load blocklists from URLs/file paths, plus custom blocked/allowed domains.
    pub async fn load(
        &self,
        blocklist_urls: &[String],
        custom_blocked: &[String],
        allowlist: &[String],
    ) {
        let mut all_domains = HashSet::new();
        let mut src_map = HashMap::new();

        for source in blocklist_urls {
            match self.fetch_blocklist(source).await {
                Ok(entries) => {
                    info!("Loaded {} entries from {}", entries.len(), source);
                    let set: HashSet<String> = entries.into_iter().collect();
                    all_domains.extend(set.clone());
                    src_map.insert(source.clone(), set);
                }
                Err(e) => {
                    warn!("Failed to load blocklist {}: {}", source, e);
                }
            }
        }

        let custom: HashSet<String> = custom_blocked.iter().map(|d| normalize_domain(d)).collect();
        all_domains.extend(custom.clone());

        info!("Total blocked domains: {}", all_domains.len());

        *self.blocked.write().await = all_domains;
        *self.source_domains.write().await = src_map;
        *self.custom_blocked.write().await = custom;
        *self.allowlist.write().await = allowlist.iter().map(|d| normalize_domain(d)).collect();
        *self.sources.write().await = blocklist_urls.to_vec();
    }

    /// Dynamically add a blocklist source and load its domains.
    pub async fn add_blocklist_source(&self, url: &str) {
        // Check if already loaded
        {
            let src = self.source_domains.read().await;
            if src.contains_key(url) {
                return;
            }
        }

        match self.fetch_blocklist(url).await {
            Ok(entries) => {
                info!(
                    "Feature blocklist loaded: {} entries from {}",
                    entries.len(),
                    url
                );
                let set: HashSet<String> = entries.into_iter().collect();

                // Add to blocked set
                {
                    let mut blocked = self.blocked.write().await;
                    blocked.extend(set.clone());
                }

                // Track source
                {
                    let mut src_map = self.source_domains.write().await;
                    src_map.insert(url.to_string(), set);
                }

                // Add to sources list
                {
                    let mut sources = self.sources.write().await;
                    if !sources.contains(&url.to_string()) {
                        sources.push(url.to_string());
                    }
                }
            }
            Err(e) => {
                warn!("Failed to load feature blocklist {}: {}", url, e);
            }
        }
    }

    /// Dynamically remove a blocklist source and its domains.
    pub async fn remove_blocklist_source(&self, url: &str) {
        let domains_to_remove = {
            let mut src_map = self.source_domains.write().await;
            src_map.remove(url)
        };

        if let Some(domains) = domains_to_remove {
            // Rebuild blocked set from remaining sources + custom
            let src_map = self.source_domains.read().await;
            let custom = self.custom_blocked.read().await;

            let mut new_blocked = HashSet::new();
            for src_domains in src_map.values() {
                new_blocked.extend(src_domains.clone());
            }
            new_blocked.extend(custom.clone());

            let removed = domains.len();
            let new_total = new_blocked.len();
            *self.blocked.write().await = new_blocked;

            // Remove from sources list
            {
                let mut sources = self.sources.write().await;
                sources.retain(|s| s != url);
            }

            info!(
                "Removed blocklist {}: -{} domains, {} total remaining",
                url, removed, new_total
            );
        }
    }

    /// Fetch and parse a blocklist from a URL or local file path.
    async fn fetch_blocklist(&self, source: &str) -> anyhow::Result<Vec<String>> {
        let content = if source.starts_with("http://") || source.starts_with("https://") {
            let resp = reqwest::get(source).await?;
            resp.text().await?
        } else {
            tokio::fs::read_to_string(source).await?
        };

        Ok(parse_blocklist(&content))
    }

    /// Check if a domain should be blocked.
    pub async fn is_blocked(&self, domain: &str) -> bool {
        if !*self.enabled.read().await {
            return false;
        }

        let normalized = normalize_domain(domain);
        let allowlist = self.allowlist.read().await;

        if allowlist.contains(&normalized) {
            return false;
        }

        let blocked = self.blocked.read().await;

        if blocked.contains(&normalized) {
            return true;
        }

        // Check parent domains
        let parts: Vec<&str> = normalized.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if blocked.contains(&parent) {
                return true;
            }
        }

        false
    }

    pub async fn set_enabled(&self, enabled: bool) {
        *self.enabled.write().await = enabled;
    }

    pub async fn is_enabled(&self) -> bool {
        *self.enabled.read().await
    }

    pub async fn blocked_count(&self) -> usize {
        self.blocked.read().await.len()
    }

    pub async fn get_sources(&self) -> Vec<String> {
        self.sources.read().await.clone()
    }

    pub async fn add_custom_blocked(&self, domain: &str) {
        let d = normalize_domain(domain);
        self.custom_blocked.write().await.insert(d.clone());
        self.blocked.write().await.insert(d);
    }

    pub async fn remove_custom_blocked(&self, domain: &str) {
        let d = normalize_domain(domain);
        self.custom_blocked.write().await.remove(&d);
        self.blocked.write().await.remove(&d);
    }

    pub async fn add_allowlisted(&self, domain: &str) {
        self.allowlist
            .write()
            .await
            .insert(normalize_domain(domain));
    }

    pub async fn remove_allowlisted(&self, domain: &str) {
        self.allowlist
            .write()
            .await
            .remove(&normalize_domain(domain));
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_string()
}

/// Parse a blocklist supporting multiple formats.
fn parse_blocklist(content: &str) -> Vec<String> {
    let mut domains = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        // Wildcard format: *.domain.com -> domain.com
        if let Some(domain) = line.strip_prefix("*.") {
            let domain = domain.trim();
            if is_valid_domain(domain) {
                domains.push(normalize_domain(domain));
                continue;
            }
        }

        // Adblock-style: ||domain.com^
        if let Some(rest) = line.strip_prefix("||") {
            if let Some(domain) = rest.strip_suffix('^') {
                let domain = domain.trim();
                if is_valid_domain(domain) {
                    domains.push(normalize_domain(domain));
                    continue;
                }
            }
        }

        // Hosts file format
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let ip = parts[0];
            if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" || ip == "::0" {
                let domain = parts[1];
                if is_valid_domain(domain) && domain != "localhost" {
                    domains.push(normalize_domain(domain));
                    continue;
                }
            }
        }

        // Domain-only format
        if parts.len() == 1 && is_valid_domain(line) {
            domains.push(normalize_domain(line));
        }
    }

    domains
}

fn is_valid_domain(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('.')
        && !s.starts_with('-')
        && s.contains('.')
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hosts_format() {
        let content = "0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.com\n";
        let domains = parse_blocklist(content);
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_parse_domain_only() {
        let content = "ads.example.com\ntracker.example.com\n";
        let domains = parse_blocklist(content);
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_parse_adblock_style() {
        let content = "||ads.example.com^\n||tracker.example.com^\n";
        let domains = parse_blocklist(content);
        assert_eq!(domains, vec!["ads.example.com", "tracker.example.com"]);
    }

    #[test]
    fn test_parse_comments_and_empty_lines() {
        let content = "# comment\n! another comment\n\nads.example.com\n";
        let domains = parse_blocklist(content);
        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("ADS.Example.COM."), "ads.example.com");
    }

    #[tokio::test]
    async fn test_is_blocked() {
        let mgr = BlocklistManager::new(true);
        mgr.load(&[], &["ads.example.com".to_string()], &[]).await;
        assert!(mgr.is_blocked("ads.example.com").await);
        assert!(mgr.is_blocked("sub.ads.example.com").await);
        assert!(!mgr.is_blocked("example.com").await);
    }

    #[tokio::test]
    async fn test_allowlist_overrides() {
        let mgr = BlocklistManager::new(true);
        mgr.load(
            &[],
            &["ads.example.com".to_string()],
            &["ads.example.com".to_string()],
        )
        .await;
        assert!(!mgr.is_blocked("ads.example.com").await);
    }

    #[tokio::test]
    async fn test_blocking_disabled() {
        let mgr = BlocklistManager::new(false);
        mgr.load(&[], &["ads.example.com".to_string()], &[]).await;
        assert!(!mgr.is_blocked("ads.example.com").await);
    }

    #[tokio::test]
    async fn test_dynamic_add_remove_source() {
        let mgr = BlocklistManager::new(true);
        mgr.load(&[], &["base.example.com".to_string()], &[]).await;

        assert!(mgr.is_blocked("base.example.com").await);
        assert_eq!(mgr.blocked_count().await, 1);

        // add_blocklist_source and remove_blocklist_source can't be fully tested
        // without a URL, but we can test custom blocked add/remove
        mgr.add_custom_blocked("new.example.com").await;
        assert!(mgr.is_blocked("new.example.com").await);

        mgr.remove_custom_blocked("new.example.com").await;
        assert!(!mgr.is_blocked("new.example.com").await);
    }
}
