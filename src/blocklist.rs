use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// One configured external list.  Stored in `[blocking].sources` in the TOML.
///
/// Lists are no longer tagged by kind — the parser inspects each line and
/// routes it to the right bucket (blocklist, allowlist, or DNS rewrite).
/// A single list can contain any mix of the three.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceEntry {
    pub url: String,
}

/// Per-source counts, returned from `add_source` and used by the web UI to
/// show a breakdown of how a list was classified.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SourceCounts {
    pub blocked: usize,
    pub allowed: usize,
    pub rewrites: usize,
}

impl SourceCounts {
    pub fn total(&self) -> usize {
        self.blocked + self.allowed + self.rewrites
    }
}

/// Target of a DNS rewrite rule.  Previously lived in `features::SafeSearchTarget`.
#[derive(Debug, Clone)]
pub enum RewriteTarget {
    A(Ipv4Addr),
    Cname(String),
}

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

/// Manages the full set of externally-sourced lists — blocklists,
/// allowlists, and DNS rewrite rules — plus manually-entered entries.
#[derive(Clone)]
pub struct BlocklistManager {
    /// All blocked domains (lowercase, normalized), merged from every
    /// source's block entries + `custom_blocked`.
    blocked: Arc<RwLock<HashSet<String>>>,
    /// Block entries contributed by each source URL (for add/remove support).
    source_domains: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Allow entries contributed by each source URL (`@@||domain^` lines).
    source_allowlist: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Aggregated DNS rewrite rules.  Value holds the target + originating
    /// source URL so removals work.
    rewrite_rules: Arc<RwLock<HashMap<String, (RewriteTarget, String)>>>,
    /// Custom blocked domains (manually added — single source, no URL).
    custom_blocked: Arc<RwLock<HashSet<String>>>,
    /// Manual allowlist domains; combined with `source_allowlist` at check time.
    allowlist: Arc<RwLock<HashSet<String>>>,
    /// Whether blocking is globally enabled
    enabled: Arc<RwLock<bool>>,
    /// Configured external list sources (URL-only; parser classifies each line).
    sources: Arc<RwLock<Vec<SourceEntry>>>,
    /// Timestamp of the last completed refresh (manual or auto)
    last_refreshed_at: Arc<RwLock<Option<chrono::DateTime<chrono::Utc>>>>,
    /// Whether a refresh is currently in progress (concurrency guard)
    refreshing: Arc<std::sync::atomic::AtomicBool>,
}

/// Progress event emitted during a streaming blocklist refresh.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum RefreshEvent {
    #[serde(rename = "progress")]
    Progress {
        source: String,
        index: usize,
        total: usize,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        domains: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    #[serde(rename = "done")]
    Done {
        total_domains: usize,
        sources_ok: usize,
        sources_failed: usize,
        refreshed_at: String,
    },
}

impl BlocklistManager {
    pub fn new(enabled: bool) -> Self {
        Self {
            blocked: Arc::new(RwLock::new(HashSet::new())),
            source_domains: Arc::new(RwLock::new(HashMap::new())),
            source_allowlist: Arc::new(RwLock::new(HashMap::new())),
            rewrite_rules: Arc::new(RwLock::new(HashMap::new())),
            custom_blocked: Arc::new(RwLock::new(HashSet::new())),
            allowlist: Arc::new(RwLock::new(HashSet::new())),
            enabled: Arc::new(RwLock::new(enabled)),
            sources: Arc::new(RwLock::new(Vec::new())),
            last_refreshed_at: Arc::new(RwLock::new(None)),
            refreshing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Load all external sources + manual entries at startup.
    pub async fn load(
        &self,
        sources: &[SourceEntry],
        custom_blocked: &[String],
        allowlist: &[String],
    ) {
        let mut blocked_all = HashSet::new();
        let mut block_src: HashMap<String, HashSet<String>> = HashMap::new();
        let mut allow_src: HashMap<String, HashSet<String>> = HashMap::new();
        let mut rewrite_rules: HashMap<String, (RewriteTarget, String)> = HashMap::new();

        for source in sources {
            match self.fetch_source(source).await {
                Ok(parsed) => {
                    info!(
                        "Loaded {} from {} (block={} allow={} rewrite={})",
                        parsed.counts().total(),
                        source.url,
                        parsed.blocked.len(),
                        parsed.allowed.len(),
                        parsed.rewrites.len()
                    );
                    blocked_all.extend(parsed.blocked.iter().cloned());
                    block_src.insert(source.url.clone(), parsed.blocked);
                    allow_src.insert(source.url.clone(), parsed.allowed);
                    for (domain, target) in parsed.rewrites {
                        rewrite_rules.insert(domain, (target, source.url.clone()));
                    }
                }
                Err(e) => {
                    warn!("Failed to load source {}: {}", source.url, e);
                }
            }
        }

        let custom: HashSet<String> = custom_blocked.iter().map(|d| normalize_domain(d)).collect();
        blocked_all.extend(custom.clone());

        info!(
            "Sources loaded: {} block domains, {} allow domains, {} rewrite rules",
            blocked_all.len(),
            allow_src.values().map(|s| s.len()).sum::<usize>(),
            rewrite_rules.len()
        );

        *self.blocked.write().await = blocked_all;
        *self.source_domains.write().await = block_src;
        *self.source_allowlist.write().await = allow_src;
        *self.rewrite_rules.write().await = rewrite_rules;
        *self.custom_blocked.write().await = custom;
        *self.allowlist.write().await = allowlist.iter().map(|d| normalize_domain(d)).collect();
        *self.sources.write().await = sources.to_vec();
    }

    /// Dynamically add a source.  Fetches, auto-classifies every line, and
    /// integrates the results into block / allow / rewrite state.
    pub async fn add_source(&self, url: &str) -> Result<SourceCounts, String> {
        // Already present? Return current counts.
        {
            let sources = self.sources.read().await;
            if sources.iter().any(|s| s.url == url) {
                return Ok(self.source_counts(url).await);
            }
        }

        let entry = SourceEntry {
            url: url.to_string(),
        };
        match self.fetch_source(&entry).await {
            Ok(parsed) => {
                let counts = parsed.counts();
                {
                    let mut blocked = self.blocked.write().await;
                    blocked.extend(parsed.blocked.iter().cloned());
                }
                self.source_domains
                    .write()
                    .await
                    .insert(url.to_string(), parsed.blocked);
                self.source_allowlist
                    .write()
                    .await
                    .insert(url.to_string(), parsed.allowed);
                {
                    let mut all = self.rewrite_rules.write().await;
                    for (domain, target) in parsed.rewrites {
                        all.insert(domain, (target, url.to_string()));
                    }
                }
                self.sources.write().await.push(entry);
                Ok(counts)
            }
            Err(e) => {
                let msg = format!("Failed to load source {}: {}", url, e);
                warn!("{}", msg);
                Err(msg)
            }
        }
    }

    /// Dynamically remove a source and all of its contributed state.
    pub async fn remove_source(&self, url: &str) {
        let present = self.sources.read().await.iter().any(|s| s.url == url);
        if !present {
            return;
        }

        // Pull this source out of all three per-source maps.
        let removed_block = self.source_domains.write().await.remove(url);
        let removed_allow = self.source_allowlist.write().await.remove(url);

        // Rebuild the flat `blocked` set without this source's contribution.
        if let Some(removed) = &removed_block {
            let src_map = self.source_domains.read().await;
            let custom = self.custom_blocked.read().await;
            let mut new_blocked: HashSet<String> = HashSet::new();
            for set in src_map.values() {
                new_blocked.extend(set.iter().cloned());
            }
            new_blocked.extend(custom.iter().cloned());
            *self.blocked.write().await = new_blocked;
            info!("Removed source {}: -{} block entries", url, removed.len());
        }
        if let Some(removed) = &removed_allow {
            if !removed.is_empty() {
                info!("Removed source {}: -{} allow entries", url, removed.len());
            }
        }

        let mut rules = self.rewrite_rules.write().await;
        let before = rules.len();
        rules.retain(|_, (_, owner)| owner != url);
        let removed_rewrites = before.saturating_sub(rules.len());
        if removed_rewrites > 0 {
            info!(
                "Removed source {}: -{} rewrite rules",
                url, removed_rewrites
            );
        }
        drop(rules);

        self.sources.write().await.retain(|s| s.url != url);
    }

    /// Per-source breakdown for UI / API.
    pub async fn source_counts(&self, url: &str) -> SourceCounts {
        let blocked = self
            .source_domains
            .read()
            .await
            .get(url)
            .map(|s| s.len())
            .unwrap_or(0);
        let allowed = self
            .source_allowlist
            .read()
            .await
            .get(url)
            .map(|s| s.len())
            .unwrap_or(0);
        let rewrites = self
            .rewrite_rules
            .read()
            .await
            .values()
            .filter(|(_, owner)| owner == url)
            .count();
        SourceCounts {
            blocked,
            allowed,
            rewrites,
        }
    }

    /// Look up a rewrite target for a domain.  Returns None if no rule
    /// applies or blocking is globally disabled.
    pub async fn get_rewrite_target(&self, domain: &str) -> Option<(RewriteTarget, String)> {
        if !*self.enabled.read().await {
            return None;
        }
        let normalized = normalize_domain(domain);
        let rules = self.rewrite_rules.read().await;
        rules.get(&normalized).cloned()
    }

    /// Download the body for a source URL (or read from disk for file paths),
    /// capped by the `blocklist_max_bytes` resource limit.
    async fn fetch_raw(source: &str) -> anyhow::Result<String> {
        let max_bytes = crate::resources::limits().blocklist_max_bytes;
        if source.starts_with("http://") || source.starts_with("https://") {
            let client = reqwest::Client::new();
            let resp = client
                .get(source)
                .header("Cache-Control", "no-cache")
                .send()
                .await?;
            if let Some(len) = resp.content_length() {
                if len as usize > max_bytes {
                    anyhow::bail!(
                        "Source {} refused: Content-Length {} bytes exceeds limit {} bytes",
                        source,
                        len,
                        max_bytes
                    );
                }
            }
            let mut resp = resp;
            let mut buf: Vec<u8> = Vec::new();
            while let Some(chunk) = resp.chunk().await? {
                if buf.len() + chunk.len() > max_bytes {
                    anyhow::bail!(
                        "Source {} refused: exceeded size limit of {} bytes",
                        source,
                        max_bytes
                    );
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(String::from_utf8(buf)?)
        } else {
            let meta = tokio::fs::metadata(source).await?;
            if meta.len() as usize > max_bytes {
                anyhow::bail!(
                    "Source {} refused: file size {} bytes exceeds limit {} bytes",
                    source,
                    meta.len(),
                    max_bytes
                );
            }
            Ok(tokio::fs::read_to_string(source).await?)
        }
    }

    /// Fetch + parse a source.  Every line is auto-classified into one of
    /// three buckets: block, allow (`@@||…`), or DNS rewrite
    /// (`|…$dnsrewrite=…`).  A single list may mix all three.
    async fn fetch_source(&self, source: &SourceEntry) -> anyhow::Result<ParsedSource> {
        let content = Self::fetch_raw(&source.url).await?;
        let mut parsed = parse_source(&content);

        // The upstream AdGuard list covers www.youtube.com but not the bare
        // youtube.com domain — browsers hitting youtube.com would otherwise
        // bypass the rewrite.  Inject the bare domain when the URL is the
        // known YouTube safe-search list.
        if source.url.contains("youtube_safe_search") {
            for domain in ["youtube.com", "youtubekids.com", "www.youtubekids.com"] {
                parsed
                    .rewrites
                    .entry(domain.to_string())
                    .or_insert_with(|| {
                        RewriteTarget::Cname("restrictmoderate.youtube.com".to_string())
                    });
            }
        }

        Ok(parsed)
    }

    /// Check if a domain is blocked and return which source caused it.
    pub async fn check_domain(&self, domain: &str) -> BlockResult {
        if !*self.enabled.read().await {
            return BlockResult::Allowed;
        }

        let normalized = normalize_domain(domain);

        // Manual allowlist takes precedence over every block source.
        {
            let allowlist = self.allowlist.read().await;
            if Self::matches_self_or_parent(&allowlist, &normalized) {
                return BlockResult::Allowed;
            }
        }
        // URL-sourced allowlists (`@@||…` lines from any source) likewise win.
        {
            let allow_src = self.source_allowlist.read().await;
            for set in allow_src.values() {
                if Self::matches_self_or_parent(set, &normalized) {
                    return BlockResult::Allowed;
                }
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

    /// Total unique domains in every URL-sourced allowlist + manual allowlist.
    pub async fn allowed_count(&self) -> usize {
        let mut all: HashSet<String> = HashSet::new();
        let src = self.source_allowlist.read().await;
        for set in src.values() {
            all.extend(set.iter().cloned());
        }
        drop(src);
        let manual = self.allowlist.read().await;
        all.extend(manual.iter().cloned());
        all.len()
    }

    /// Total active DNS rewrite rules across every source.
    pub async fn rewrite_count(&self) -> usize {
        self.rewrite_rules.read().await.len()
    }

    pub async fn get_sources(&self) -> Vec<SourceEntry> {
        self.sources.read().await.clone()
    }

    /// Helper: does `name` (exactly) or any of its parent domains appear in `set`?
    fn matches_self_or_parent(set: &HashSet<String>, name: &str) -> bool {
        if set.contains(name) {
            return true;
        }
        let parts: Vec<&str> = name.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if set.contains(&parent) {
                return true;
            }
        }
        false
    }

    /// Re-fetch every configured source and rebuild the aggregate state.
    /// Keeps the old per-source data for any entry that fails to re-fetch
    /// so an upstream outage doesn't blank blocking.
    pub async fn refresh_sources(&self) {
        let sources = self.sources.read().await.clone();
        if sources.is_empty() {
            return;
        }
        if !self.try_start_refresh() {
            info!("Sources refresh skipped — another refresh is in progress");
            return;
        }

        info!("Refreshing {} sources...", sources.len());

        let mut block_src: HashMap<String, HashSet<String>> = HashMap::new();
        let mut allow_src: HashMap<String, HashSet<String>> = HashMap::new();
        let mut rewrite_rules: HashMap<String, (RewriteTarget, String)> = HashMap::new();

        for source in &sources {
            match self.fetch_source(source).await {
                Ok(parsed) => {
                    info!(
                        "Refreshed {} entries from {} (block={} allow={} rewrite={})",
                        parsed.counts().total(),
                        source.url,
                        parsed.blocked.len(),
                        parsed.allowed.len(),
                        parsed.rewrites.len()
                    );
                    block_src.insert(source.url.clone(), parsed.blocked);
                    allow_src.insert(source.url.clone(), parsed.allowed);
                    for (domain, target) in parsed.rewrites {
                        rewrite_rules.insert(domain, (target, source.url.clone()));
                    }
                }
                Err(e) => {
                    warn!("Failed to refresh source {}: {}", source.url, e);
                    // Preserve the previous per-source data on failure.
                    self.preserve_previous(
                        source,
                        &mut block_src,
                        &mut allow_src,
                        &mut rewrite_rules,
                    )
                    .await;
                }
            }
        }

        let mut blocked_all: HashSet<String> = HashSet::new();
        for set in block_src.values() {
            blocked_all.extend(set.iter().cloned());
        }
        let custom = self.custom_blocked.read().await;
        blocked_all.extend(custom.iter().cloned());

        let total = blocked_all.len();
        *self.source_domains.write().await = block_src;
        *self.source_allowlist.write().await = allow_src;
        *self.rewrite_rules.write().await = rewrite_rules;
        *self.blocked.write().await = blocked_all;

        self.finish_refresh().await;

        info!("Sources refresh complete: {} total blocked domains", total);
    }

    /// Re-fetch all sources, streaming progress events through the channel.
    /// Caller must have already acquired the refresh lock via `try_start_refresh()`.
    pub async fn refresh_sources_streaming(&self, tx: tokio::sync::mpsc::Sender<RefreshEvent>) {
        let sources = self.sources.read().await.clone();

        let total = sources.len();
        let mut block_src: HashMap<String, HashSet<String>> = HashMap::new();
        let mut allow_src: HashMap<String, HashSet<String>> = HashMap::new();
        let mut rewrite_rules: HashMap<String, (RewriteTarget, String)> = HashMap::new();
        let mut sources_ok: usize = 0;
        let mut sources_failed: usize = 0;

        for (i, source) in sources.iter().enumerate() {
            match self.fetch_source(source).await {
                Ok(parsed) => {
                    let counts = parsed.counts();
                    info!(
                        "Refreshed {} entries from {} (block={} allow={} rewrite={})",
                        counts.total(),
                        source.url,
                        counts.blocked,
                        counts.allowed,
                        counts.rewrites
                    );
                    block_src.insert(source.url.clone(), parsed.blocked);
                    allow_src.insert(source.url.clone(), parsed.allowed);
                    for (domain, target) in parsed.rewrites {
                        rewrite_rules.insert(domain, (target, source.url.clone()));
                    }
                    sources_ok += 1;
                    let _ = tx
                        .send(RefreshEvent::Progress {
                            source: source.url.clone(),
                            index: i + 1,
                            total,
                            status: "ok".to_string(),
                            domains: Some(counts.total()),
                            error: None,
                        })
                        .await;
                }
                Err(e) => {
                    warn!("Failed to refresh source {}: {}", source.url, e);
                    self.preserve_previous(
                        source,
                        &mut block_src,
                        &mut allow_src,
                        &mut rewrite_rules,
                    )
                    .await;
                    sources_failed += 1;
                    let _ = tx
                        .send(RefreshEvent::Progress {
                            source: source.url.clone(),
                            index: i + 1,
                            total,
                            status: "error".to_string(),
                            domains: None,
                            error: Some(e.to_string()),
                        })
                        .await;
                }
            }
        }

        let mut blocked_all: HashSet<String> = HashSet::new();
        for set in block_src.values() {
            blocked_all.extend(set.iter().cloned());
        }
        let custom = self.custom_blocked.read().await;
        blocked_all.extend(custom.iter().cloned());

        let total_domains = blocked_all.len();
        *self.source_domains.write().await = block_src;
        *self.source_allowlist.write().await = allow_src;
        *self.rewrite_rules.write().await = rewrite_rules;
        *self.blocked.write().await = blocked_all;

        let now = Utc::now();
        *self.last_refreshed_at.write().await = Some(now);
        self.refreshing
            .store(false, std::sync::atomic::Ordering::SeqCst);

        let refreshed_at = now.to_rfc3339();
        let _ = tx
            .send(RefreshEvent::Done {
                total_domains,
                sources_ok,
                sources_failed,
                refreshed_at,
            })
            .await;

        info!(
            "Sources refresh complete: {} total blocked domains",
            total_domains
        );
    }

    /// On fetch failure, copy a source's prior entries into the in-progress
    /// refresh maps so the outage doesn't blank its state.
    async fn preserve_previous(
        &self,
        source: &SourceEntry,
        block_src: &mut HashMap<String, HashSet<String>>,
        allow_src: &mut HashMap<String, HashSet<String>>,
        rewrite_rules: &mut HashMap<String, (RewriteTarget, String)>,
    ) {
        if let Some(existing) = self.source_domains.read().await.get(&source.url) {
            block_src.insert(source.url.clone(), existing.clone());
        }
        if let Some(existing) = self.source_allowlist.read().await.get(&source.url) {
            allow_src.insert(source.url.clone(), existing.clone());
        }
        let existing = self.rewrite_rules.read().await;
        for (domain, (target, owner)) in existing.iter() {
            if owner == &source.url {
                rewrite_rules.insert(domain.clone(), (target.clone(), owner.clone()));
            }
        }
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

    /// Get the timestamp of the last completed refresh.
    pub async fn get_last_refreshed_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        *self.last_refreshed_at.read().await
    }

    /// Try to acquire the refresh lock. Returns false if already refreshing.
    pub fn try_start_refresh(&self) -> bool {
        self.refreshing
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Release the refresh lock and set the last_refreshed_at timestamp.
    pub async fn finish_refresh(&self) {
        *self.last_refreshed_at.write().await = Some(Utc::now());
        self.refreshing
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.to_lowercase().trim_end_matches('.').to_string()
}

/// Parsed output of a single source.  Every line is routed to exactly one
/// bucket based on its syntax — operators no longer have to tag lists.
pub struct ParsedSource {
    pub blocked: HashSet<String>,
    pub allowed: HashSet<String>,
    pub rewrites: HashMap<String, RewriteTarget>,
}

impl ParsedSource {
    pub fn counts(&self) -> SourceCounts {
        SourceCounts {
            blocked: self.blocked.len(),
            allowed: self.allowed.len(),
            rewrites: self.rewrites.len(),
        }
    }
}

/// Unified parser: inspects each line and routes it to block / allow /
/// rewrite based on its syntax.  Handles hosts, adblock, wildcard,
/// dnsmasq, plain-domain, AdGuard DNS rewrite, and `@@` exception lines
/// in any mix within one list.
fn parse_source(content: &str) -> ParsedSource {
    let ParseResult {
        blocked,
        exceptions,
    } = parse_blocklist(content);
    let rewrites = parse_rewrite_rules(content);
    ParsedSource {
        blocked: blocked.into_iter().collect(),
        allowed: exceptions,
        rewrites,
    }
}

/// Parse AdGuard DNS rewrite rules into a domain→target map.
/// Format: `|domain.com^$dnsrewrite=NOERROR;CNAME;target.com`
///     or: `|domain.com^$dnsrewrite=NOERROR;A;1.2.3.4`
/// Lines that don't match are silently skipped.
fn parse_rewrite_rules(content: &str) -> HashMap<String, RewriteTarget> {
    let mut rules = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
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
                Ok(ip) => RewriteTarget::A(ip),
                Err(_) => continue,
            },
            "CNAME" => RewriteTarget::Cname(parts[1].to_string()),
            _ => continue,
        };
        rules.insert(domain, target);
    }
    rules
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
        assert!(!matches!(
            mgr.check_domain("ads.example.com").await,
            BlockResult::Allowed
        ));
        assert!(!matches!(
            mgr.check_domain("sub.ads.example.com").await,
            BlockResult::Allowed
        ));
        assert!(matches!(
            mgr.check_domain("example.com").await,
            BlockResult::Allowed
        ));
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
        assert!(matches!(
            mgr.check_domain("ads.example.com").await,
            BlockResult::Allowed
        ));
    }

    #[tokio::test]
    async fn test_blocking_disabled() {
        let mgr = BlocklistManager::new(false);
        mgr.load(&[], &["ads.example.com".to_string()], &[]).await;
        assert!(matches!(
            mgr.check_domain("ads.example.com").await,
            BlockResult::Allowed
        ));
    }

    // ── Unified per-line classification ──

    #[test]
    fn test_parse_source_mixed_list() {
        // A single list contains every kind of entry.  The parser routes each
        // line to the right bucket — operators never have to tag the list.
        let content = "\
# mixed list
0.0.0.0 ads.example.com
||tracker.example.com^
@@||allowed.example.com^
|google.com^$dnsrewrite=NOERROR;CNAME;forcesafesearch.google.com
|pin.it^$dnsrewrite=NOERROR;A;1.2.3.4
";
        let parsed = parse_source(content);
        assert!(parsed.blocked.contains("ads.example.com"));
        assert!(parsed.blocked.contains("tracker.example.com"));
        assert!(parsed.allowed.contains("allowed.example.com"));
        assert_eq!(parsed.rewrites.len(), 2);
        assert!(parsed.rewrites.contains_key("google.com"));
        assert!(parsed.rewrites.contains_key("pin.it"));
    }

    #[test]
    fn test_source_counts_are_independent() {
        let content = "\
||a.example.com^
||b.example.com^
@@||c.example.com^
|d.example.com^$dnsrewrite=NOERROR;CNAME;x.example.com
";
        let parsed = parse_source(content);
        let counts = parsed.counts();
        assert_eq!(counts.blocked, 2);
        assert_eq!(counts.allowed, 1);
        assert_eq!(counts.rewrites, 1);
        assert_eq!(counts.total(), 4);
    }

    #[tokio::test]
    async fn test_dynamic_add_remove_source() {
        let mgr = BlocklistManager::new(true);
        mgr.load(&[], &["base.example.com".to_string()], &[]).await;

        assert!(!matches!(
            mgr.check_domain("base.example.com").await,
            BlockResult::Allowed
        ));
        assert_eq!(mgr.blocked_count().await, 1);

        mgr.add_custom_blocked("new.example.com").await;
        assert!(!matches!(
            mgr.check_domain("new.example.com").await,
            BlockResult::Allowed
        ));

        mgr.remove_custom_blocked("new.example.com").await;
        assert!(matches!(
            mgr.check_domain("new.example.com").await,
            BlockResult::Allowed
        ));
    }
}
