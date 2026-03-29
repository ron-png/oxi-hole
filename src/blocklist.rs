use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Result of checking whether a domain is blocked.
#[derive(Debug, Clone, PartialEq)]
pub enum BlockResult {
    /// Domain is not blocked.
    Allowed,
    /// Domain is blocked by a blocklist source (URL).
    Blocked { source_url: String },
    /// Domain is blocked by a custom user entry.
    BlockedCustom,
}

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
    /// Returns Ok(count) on success, Err(message) on failure.
    pub async fn add_blocklist_source(&self, url: &str) -> Result<usize, String> {
        // Check if already loaded
        {
            let src = self.source_domains.read().await;
            if src.contains_key(url) {
                let count = src[url].len();
                return Ok(count);
            }
        }

        match self.fetch_blocklist(url).await {
            Ok(entries) => {
                let count = entries.len();
                info!("Blocklist loaded: {} entries from {}", count, url);
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

                Ok(count)
            }
            Err(e) => {
                let msg = format!("Failed to load blocklist {}: {}", url, e);
                warn!("{}", msg);
                Err(msg)
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
    /// Applies per-source `@@` exceptions before returning, so callers
    /// only see the final filtered domain list.
    async fn fetch_blocklist(&self, source: &str) -> anyhow::Result<Vec<String>> {
        let content = if source.starts_with("http://") || source.starts_with("https://") {
            let resp = reqwest::get(source).await?;
            resp.text().await?
        } else {
            tokio::fs::read_to_string(source).await?
        };

        let parsed = parse_blocklist(&content);
        let domains = parsed
            .blocked
            .into_iter()
            .filter(|d| !parsed.exceptions.contains(d))
            .collect();
        Ok(domains)
    }

    /// Check if a domain should be blocked.
    #[allow(dead_code)]
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

    /// Check if a domain is blocked and return which source caused it.
    pub async fn check_domain(&self, domain: &str) -> BlockResult {
        if !*self.enabled.read().await {
            return BlockResult::Allowed;
        }

        let normalized = normalize_domain(domain);
        let allowlist = self.allowlist.read().await;

        // Check exact match and parent domains against the allowlist
        if allowlist.contains(&normalized) {
            return BlockResult::Allowed;
        }
        let parts: Vec<&str> = normalized.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if allowlist.contains(&parent) {
                return BlockResult::Allowed;
            }
        }

        let blocked = self.blocked.read().await;

        // Check exact match and parent-domain matches
        let matched_domain = if blocked.contains(&normalized) {
            Some(normalized.clone())
        } else {
            let parts: Vec<&str> = normalized.split('.').collect();
            let mut found = None;
            for i in 1..parts.len().saturating_sub(1) {
                let parent = parts[i..].join(".");
                if blocked.contains(&parent) {
                    found = Some(parent);
                    break;
                }
            }
            found
        };

        let Some(matched) = matched_domain else {
            return BlockResult::Allowed;
        };

        // Determine which source owns this domain
        let src_map = self.source_domains.read().await;
        for (source_url, domains) in src_map.iter() {
            if domains.contains(&matched) {
                return BlockResult::Blocked {
                    source_url: source_url.clone(),
                };
            }
        }

        if self.custom_blocked.read().await.contains(&matched) {
            return BlockResult::BlockedCustom;
        }

        // In blocked set but source unknown (shouldn't happen normally)
        BlockResult::Blocked {
            source_url: "unknown".to_string(),
        }
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

    /// Re-fetch all current blocklist sources and rebuild the blocked set.
    pub async fn refresh_sources(&self) {
        let sources = self.sources.read().await.clone();
        if sources.is_empty() {
            return;
        }
        info!("Refreshing {} blocklist sources...", sources.len());

        let mut new_src_map = HashMap::new();
        let mut all_domains = HashSet::new();

        for source in &sources {
            match self.fetch_blocklist(source).await {
                Ok(entries) => {
                    info!("Refreshed {} entries from {}", entries.len(), source);
                    let set: HashSet<String> = entries.into_iter().collect();
                    all_domains.extend(set.clone());
                    new_src_map.insert(source.clone(), set);
                }
                Err(e) => {
                    warn!("Failed to refresh blocklist {}: {}", source, e);
                    // Keep existing entries for this source on failure
                    let existing = self.source_domains.read().await;
                    if let Some(existing_set) = existing.get(source) {
                        all_domains.extend(existing_set.clone());
                        new_src_map.insert(source.clone(), existing_set.clone());
                    }
                }
            }
        }

        // Add custom blocked domains
        let custom = self.custom_blocked.read().await;
        all_domains.extend(custom.clone());

        let total = all_domains.len();
        *self.source_domains.write().await = new_src_map;
        *self.blocked.write().await = all_domains;
        info!(
            "Blocklist refresh complete: {} total blocked domains",
            total
        );
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

    pub async fn get_custom_blocked(&self) -> Vec<String> {
        self.custom_blocked.read().await.iter().cloned().collect()
    }

    pub async fn get_allowlist(&self) -> Vec<String> {
        self.allowlist.read().await.iter().cloned().collect()
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_string()
}

/// Result of parsing a blocklist file.
struct ParseResult {
    blocked: Vec<String>,
    exceptions: HashSet<String>,
}

/// Adblock modifiers that are browser-only — rules containing these are skipped.
const BROWSER_ONLY_MODIFIERS: &[&str] = &[
    "script",
    "image",
    "stylesheet",
    "object",
    "xmlhttprequest",
    "xhr",
    "other",
    "subdocument",
    "document",
    "websocket",
    "webrtc",
    "ping",
    "font",
    "media",
    "popup",
    "popunder",
    "inline-script",
    "inline-font",
    "generichide",
    "genericblock",
    "specifichide",
    // Modifier prefixes (checked with starts_with)
    "domain=",
    "csp=",
    "redirect=",
    "redirect-rule=",
    "removeparam=",
    "header=",
];

/// Adblock modifiers that are DNS-safe — silently accepted, domain is still blocked.
const DNS_SAFE_MODIFIERS: &[&str] = &["important", "third-party", "all", "1p", "3p", "dnsrewrite"];

/// Hostnames to skip in hosts-format lines.
const SKIP_HOSTS: &[&str] = &[
    "localhost",
    "broadcasthost",
    "local",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-localnet",
];

/// IPs that mark a line as hosts-format.
const SINKHOLE_IPS: &[&str] = &["0.0.0.0", "127.0.0.1", "::1", "::0", "255.255.255.255"];

/// Parse a blocklist supporting multiple formats in a single universal pass.
///
/// Supported formats:
/// - Hosts file (`0.0.0.0 domain`, multi-hostname, inline comments)
/// - Adblock (`||domain^`, modifiers, `@@` exceptions)
/// - Wildcard (`*.domain.com`)
/// - Dnsmasq (`local=/domain/`, `server=/domain/`, `address=/domain/ip`)
/// - Domain-only (bare `domain.com`)
/// - Comments (`#`, `!`, `;`, `[Adblock` headers)
fn parse_blocklist(content: &str) -> ParseResult {
    let mut blocked = Vec::new();
    let mut exceptions = HashSet::new();

    'line: for raw in content.lines() {
        let line = raw.trim();

        // 1. Skip empty lines and full-line comment starters
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with(';')
            || line.starts_with('[')
        {
            continue;
        }

        // 2. Adblock exception: @@||domain^...
        if let Some(rest) = line.strip_prefix("@@||") {
            if let Some(domain) = parse_adblock_domain(rest) {
                exceptions.insert(normalize_domain(&domain));
            }
            continue;
        }

        // Skip other @@ forms (e.g. @@http://)
        if line.starts_with("@@") {
            continue;
        }

        // 3. Adblock block rule: ||domain^...
        if let Some(rest) = line.strip_prefix("||") {
            if let Some(domain) = parse_adblock_domain(rest) {
                blocked.push(normalize_domain(&domain));
            }
            continue;
        }

        // 4. Wildcard: *.domain.com
        if let Some(rest) = line.strip_prefix("*.") {
            let domain = strip_inline_comment(rest).trim();
            if is_valid_domain(domain) {
                blocked.push(normalize_domain(domain));
            }
            continue;
        }

        // 5. Dnsmasq: local=/domain/, server=/domain/, address=/domain/ip
        if let Some(inner) = line
            .strip_prefix("local=/")
            .or_else(|| line.strip_prefix("server=/"))
            .or_else(|| line.strip_prefix("address=/"))
        {
            if let Some(domain) = inner.split('/').next() {
                let domain = domain.trim();
                if is_valid_domain(domain) {
                    blocked.push(normalize_domain(domain));
                }
            }
            continue;
        }

        // Strip inline comment for remaining formats
        let effective = strip_inline_comment(line);
        let effective = effective.trim();
        if effective.is_empty() {
            continue;
        }

        // 6. Hosts format: <sinkhole_ip> host1 host2 ...
        let parts: Vec<&str> = effective.split_whitespace().collect();
        if parts.len() >= 2 {
            let ip = parts[0];
            if SINKHOLE_IPS.contains(&ip) {
                for &hostname in &parts[1..] {
                    if SKIP_HOSTS.contains(&hostname) {
                        continue;
                    }
                    if is_valid_domain(hostname) {
                        blocked.push(normalize_domain(hostname));
                    }
                }
                continue 'line;
            }
        }

        // 7. Domain-only: single token
        if parts.len() == 1 && is_valid_domain(parts[0]) {
            blocked.push(normalize_domain(parts[0]));
        }
    }

    ParseResult {
        blocked,
        exceptions,
    }
}

/// Extract a domain from the portion after `||` or `@@||` in an adblock rule.
/// Returns None if the rule has a path component, browser-only modifiers,
/// or is otherwise not applicable to DNS-level blocking.
fn parse_adblock_domain(rest: &str) -> Option<String> {
    // Split at '^' — everything before is the domain
    let (domain_part, after_caret) = if let Some(idx) = rest.find('^') {
        (&rest[..idx], Some(&rest[idx + 1..]))
    } else {
        // No caret — bare `||domain` without anchor, treat as domain
        (rest, None)
    };

    let domain = domain_part.trim();

    // Skip rules with path components
    if domain.contains('/') {
        return None;
    }

    // Check modifiers if present
    if let Some(mods) = after_caret {
        // Strip leading `|` (end-of-string anchor, DNS-safe)
        let mods = mods.trim_start_matches('|');

        if !mods.is_empty() {
            if let Some(mod_str) = mods.strip_prefix('$') {
                for part in mod_str.split(',') {
                    let part = part.trim();
                    if part.is_empty() {
                        continue;
                    }
                    if DNS_SAFE_MODIFIERS.contains(&part) {
                        continue;
                    }
                    let is_browser_only = BROWSER_ONLY_MODIFIERS.iter().any(|bm| {
                        if bm.ends_with('=') {
                            part.starts_with(bm)
                        } else {
                            part == *bm
                        }
                    });
                    if is_browser_only {
                        return None;
                    }
                    // Unknown modifier — skip to be safe
                    return None;
                }
            } else if !mods.is_empty() {
                // Non-empty, non-$ content after ^| — not a standard rule, skip
                return None;
            }
        }
    }

    if is_valid_domain(domain) {
        Some(domain.to_string())
    } else {
        None
    }
}

/// Strip inline comments: everything from ` #` (space-hash) onward.
fn strip_inline_comment(s: &str) -> &str {
    s.split(" #").next().unwrap_or(s)
}

fn is_valid_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }

    // Must contain at least one dot
    if !s.contains('.') {
        return false;
    }

    // Reject paths
    if s.contains('/') {
        return false;
    }

    // Reject all-numeric-label strings (IPv4 addresses like 0.0.0.0, 127.0.0.1)
    let all_numeric = s
        .split('.')
        .all(|label| label.chars().all(|c| c.is_ascii_digit()));
    if all_numeric {
        return false;
    }

    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Hosts format ──

    #[test]
    fn test_parse_hosts_format() {
        let content = "0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.com\n";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec!["ads.example.com", "tracker.example.com"]
        );
    }

    #[test]
    fn test_parse_hosts_multi_hostname() {
        let content = "0.0.0.0 ads.example.com tracker.example.com banner.example.com\n";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec![
                "ads.example.com",
                "tracker.example.com",
                "banner.example.com"
            ]
        );
    }

    #[test]
    fn test_parse_hosts_inline_comment() {
        let content = "0.0.0.0 ads.example.com # ad server\n";
        let result = parse_blocklist(content);
        assert_eq!(result.blocked, vec!["ads.example.com"]);
    }

    #[test]
    fn test_parse_hosts_skips_localhost() {
        let content = "127.0.0.1 localhost\n0.0.0.0 broadcasthost\n::1 ip6-localhost\n0.0.0.0 ads.example.com\n";
        let result = parse_blocklist(content);
        assert_eq!(result.blocked, vec!["ads.example.com"]);
    }

    // ── Domain-only format ──

    #[test]
    fn test_parse_domain_only() {
        let content = "ads.example.com\ntracker.example.com\n";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec!["ads.example.com", "tracker.example.com"]
        );
    }

    #[test]
    fn test_parse_domain_only_inline_comment() {
        let content = "ads.example.com # this is blocked\n";
        let result = parse_blocklist(content);
        assert_eq!(result.blocked, vec!["ads.example.com"]);
    }

    // ── Adblock format ──

    #[test]
    fn test_parse_adblock_style() {
        let content = "||ads.example.com^\n||tracker.example.com^\n";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec!["ads.example.com", "tracker.example.com"]
        );
    }

    #[test]
    fn test_parse_adblock_with_dns_safe_modifiers() {
        let content = "||ads.example.com^$third-party\n||tracker.example.com^$important\n||banner.example.com^|\n";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec![
                "ads.example.com",
                "tracker.example.com",
                "banner.example.com"
            ]
        );
    }

    #[test]
    fn test_parse_adblock_browser_only_skipped() {
        let content = "||ads.example.com^$script\n||tracker.example.com^$image\n||font.example.com^$stylesheet\n||ok.example.com^\n";
        let result = parse_blocklist(content);
        assert_eq!(result.blocked, vec!["ok.example.com"]);
    }

    #[test]
    fn test_parse_adblock_mixed_modifiers_skipped() {
        // If ANY modifier is browser-only, the whole rule is skipped
        let content = "||ads.example.com^$third-party,image\n";
        let result = parse_blocklist(content);
        assert!(result.blocked.is_empty());
    }

    #[test]
    fn test_parse_adblock_path_rule_skipped() {
        let content = "||ads.example.com/banner/ad.js^\n||ok.example.com^\n";
        let result = parse_blocklist(content);
        assert_eq!(result.blocked, vec!["ok.example.com"]);
    }

    #[test]
    fn test_parse_adblock_exception() {
        let content = "||ads.example.com^\n@@||ads.example.com^\n||tracker.example.com^\n";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec!["ads.example.com", "tracker.example.com"]
        );
        assert!(result.exceptions.contains("ads.example.com"));
        assert!(!result.exceptions.contains("tracker.example.com"));
    }

    // ── Wildcard format ──

    #[test]
    fn test_parse_wildcard() {
        let content = "*.ads.example.com\n*.tracker.example.com\n";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec!["ads.example.com", "tracker.example.com"]
        );
    }

    // ── Dnsmasq format ──

    #[test]
    fn test_parse_dnsmasq_local() {
        let content = "local=/ads.example.com/\nlocal=/tracker.example.com/\n";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec!["ads.example.com", "tracker.example.com"]
        );
    }

    #[test]
    fn test_parse_dnsmasq_server() {
        let content = "server=/ads.example.com/\n";
        let result = parse_blocklist(content);
        assert_eq!(result.blocked, vec!["ads.example.com"]);
    }

    #[test]
    fn test_parse_dnsmasq_address() {
        let content = "address=/ads.example.com/0.0.0.0\naddress=/tracker.example.com/\n";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec!["ads.example.com", "tracker.example.com"]
        );
    }

    // ── Comments ──

    #[test]
    fn test_parse_comments_and_empty_lines() {
        let content =
            "# comment\n! another comment\n; rpz comment\n[Adblock Plus 2.0]\n\nads.example.com\n";
        let result = parse_blocklist(content);
        assert_eq!(result.blocked, vec!["ads.example.com"]);
    }

    // ── Mixed format list ──

    #[test]
    fn test_parse_mixed_formats() {
        let content = "\
# Mixed blocklist
! Header comment
0.0.0.0 hosts.example.com
||adblock.example.com^
*.wildcard.example.com
local=/dnsmasq.example.com/
domain-only.example.com
";
        let result = parse_blocklist(content);
        assert_eq!(
            result.blocked,
            vec![
                "hosts.example.com",
                "adblock.example.com",
                "wildcard.example.com",
                "dnsmasq.example.com",
                "domain-only.example.com",
            ]
        );
    }

    // ── is_valid_domain ──

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.com"));
        assert!(is_valid_domain("_dmarc.example.com"));
        assert!(is_valid_domain("xn--nxasmq6b.com"));

        // Rejects
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("localhost"));
        assert!(!is_valid_domain(".example.com"));
        assert!(!is_valid_domain("-example.com"));
        assert!(!is_valid_domain("example.com/path"));
        assert!(!is_valid_domain("0.0.0.0"));
        assert!(!is_valid_domain("127.0.0.1"));
        assert!(!is_valid_domain("a..b.com"));
    }

    // ── normalize_domain ──

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("ADS.Example.COM."), "ads.example.com");
    }

    // ── BlocklistManager integration ──

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

        mgr.add_custom_blocked("new.example.com").await;
        assert!(mgr.is_blocked("new.example.com").await);

        mgr.remove_custom_blocked("new.example.com").await;
        assert!(!mgr.is_blocked("new.example.com").await);
    }
}
