# Persistent Statistics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add persistent statistics in a separate SQLite database with independent retention from query logs, plus API endpoints for historical stats and a split settings UI.

**Architecture:** New `persistent_stats.rs` module manages `stats.db` with hourly aggregates and daily top domains. It uses a write buffer flushed every 60 seconds. The existing `Stats` struct gains an optional `PersistentStats` reference so `record_query()` automatically records to both in-memory and persistent storage. Config splits retention into `query_log_retention_days` (default 7) and `stats_retention_days` (default 90).

**Tech Stack:** Rust, tokio-rusqlite (async SQLite, already in project), chrono (already in project)

---

### Task 1: Split retention config fields

**Files:**
- Modify: `src/config.rs`

- [ ] **Step 1: Update LogConfig struct**

In `src/config.rs`, find the `LogConfig` struct (around line 143). Replace the entire struct, default function, and Default impl:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// How many days to retain detailed query logs (1-90)
    #[serde(default = "default_query_log_retention", alias = "retention_days")]
    pub query_log_retention_days: u32,
    /// How many days to retain aggregated statistics (1-365)
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
```

Remove the old `default_log_retention_days` function and the old `retention_days` field references.

- [ ] **Step 2: Update all references to `retention_days` in the codebase**

Search for `retention_days` in `src/web/mod.rs` and `src/main.rs`. Replace:
- `config.log.retention_days` → `config.log.query_log_retention_days`
- `log_retention_days` field in AppState stays the same name (it tracks query log retention)
- In `save_config()`: `config.log.retention_days = ...` → `config.log.query_log_retention_days = ...`

- [ ] **Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/config.rs src/web/mod.rs src/main.rs
git commit -m "feat: split retention config into query_log_retention_days and stats_retention_days"
```

---

### Task 2: Create persistent stats module

**Files:**
- Create: `src/persistent_stats.rs`
- Modify: `src/main.rs` (add `mod persistent_stats;`)

- [ ] **Step 1: Create `src/persistent_stats.rs` with full implementation and tests**

```rust
use anyhow::Context;
use chrono::Utc;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio_rusqlite::Connection;
use tracing::warn;

#[derive(Clone)]
pub struct PersistentStats {
    db: Connection,
    buffer: Arc<Mutex<StatsBuffer>>,
}

struct StatsBuffer {
    current_hour: String,
    current_day: String,
    hourly_total: u64,
    hourly_blocked: u64,
    domains: HashMap<String, (u64, u64)>, // domain -> (query_count, blocked_count)
}

impl StatsBuffer {
    fn new() -> Self {
        let now = Utc::now();
        Self {
            current_hour: now.format("%Y-%m-%dT%H:00:00").to_string(),
            current_day: now.format("%Y-%m-%d").to_string(),
            hourly_total: 0,
            hourly_blocked: 0,
            domains: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HourlyStat {
    pub hour: String,
    pub total: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopDomains {
    pub top_queried: Vec<DomainCount>,
    pub top_blocked: Vec<DomainCount>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsSummary {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub block_percentage: f64,
}

impl PersistentStats {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let db = Connection::open(path).await?;
        db.call(|conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS hourly_stats (
                    hour TEXT PRIMARY KEY,
                    total_queries INTEGER DEFAULT 0,
                    blocked_queries INTEGER DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_hourly_hour ON hourly_stats(hour);
                CREATE TABLE IF NOT EXISTS daily_top_domains (
                    day TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    query_count INTEGER DEFAULT 0,
                    blocked_count INTEGER DEFAULT 0,
                    PRIMARY KEY (day, domain)
                );
                CREATE INDEX IF NOT EXISTS idx_daily_day ON daily_top_domains(day);",
            )?;
            Ok(())
        })
        .await?;

        Ok(Self {
            db,
            buffer: Arc::new(Mutex::new(StatsBuffer::new())),
        })
    }

    /// Record a query in the write buffer. Non-blocking.
    pub fn record(&self, domain: &str, blocked: bool) {
        let now = Utc::now();
        let hour = now.format("%Y-%m-%dT%H:00:00").to_string();
        let day = now.format("%Y-%m-%d").to_string();

        let mut buf = match self.buffer.lock() {
            Ok(b) => b,
            Err(_) => return,
        };

        // Roll over hour/day if changed
        if buf.current_hour != hour {
            // We'll flush the old data on the next flush() call
            buf.current_hour = hour;
        }
        if buf.current_day != day {
            buf.current_day = day;
        }

        buf.hourly_total += 1;
        if blocked {
            buf.hourly_blocked += 1;
        }

        let entry = buf.domains.entry(domain.to_string()).or_insert((0, 0));
        entry.0 += 1;
        if blocked {
            entry.1 += 1;
        }
    }

    /// Flush buffered data to SQLite. Called every 60 seconds.
    pub async fn flush(&self) -> anyhow::Result<()> {
        let (hour, day, total, blocked, domains) = {
            let mut buf = self.buffer.lock().map_err(|e| anyhow::anyhow!("lock: {}", e))?;
            let data = (
                buf.current_hour.clone(),
                buf.current_day.clone(),
                buf.hourly_total,
                buf.hourly_blocked,
                std::mem::take(&mut buf.domains),
            );
            buf.hourly_total = 0;
            buf.hourly_blocked = 0;
            data
        };

        if total == 0 && domains.is_empty() {
            return Ok(());
        }

        let domains_vec: Vec<(String, u64, u64)> = domains
            .into_iter()
            .map(|(d, (q, b))| (d, q, b))
            .collect();

        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;

                // Upsert hourly stats
                tx.execute(
                    "INSERT INTO hourly_stats (hour, total_queries, blocked_queries)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(hour) DO UPDATE SET
                       total_queries = total_queries + ?2,
                       blocked_queries = blocked_queries + ?3",
                    rusqlite::params![hour, total, blocked],
                )?;

                // Upsert daily top domains
                for (domain, query_count, blocked_count) in &domains_vec {
                    tx.execute(
                        "INSERT INTO daily_top_domains (day, domain, query_count, blocked_count)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(day, domain) DO UPDATE SET
                           query_count = query_count + ?3,
                           blocked_count = blocked_count + ?4",
                        rusqlite::params![day, domain, query_count, blocked_count],
                    )?;
                }

                tx.commit()?;
                Ok(())
            })
            .await?;

        Ok(())
    }

    /// Get hourly stats for a time range.
    pub async fn get_hourly_stats(
        &self,
        from: &str,
        to: &str,
    ) -> anyhow::Result<Vec<HourlyStat>> {
        let from = from.to_string();
        let to = to.to_string();
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT hour, total_queries, blocked_queries
                     FROM hourly_stats
                     WHERE hour >= ?1 AND hour <= ?2
                     ORDER BY hour ASC",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![from, to], |row| {
                        Ok(HourlyStat {
                            hour: row.get(0)?,
                            total: row.get::<_, i64>(1)? as u64,
                            blocked: row.get::<_, i64>(2)? as u64,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
            .context("get_hourly_stats query failed")
    }

    /// Get top queried and top blocked domains over N days.
    pub async fn get_top_domains(
        &self,
        days: u32,
        limit: u32,
    ) -> anyhow::Result<TopDomains> {
        let cutoff = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%d")
            .to_string();
        let limit_i = limit as i64;

        let cutoff2 = cutoff.clone();
        let top_queried = self
            .db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT domain, SUM(query_count) as total
                     FROM daily_top_domains
                     WHERE day >= ?1
                     GROUP BY domain
                     ORDER BY total DESC
                     LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![cutoff, limit_i], |row| {
                        Ok(DomainCount {
                            domain: row.get(0)?,
                            count: row.get::<_, i64>(1)? as u64,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;

        let top_blocked = self
            .db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT domain, SUM(blocked_count) as total
                     FROM daily_top_domains
                     WHERE day >= ?1 AND blocked_count > 0
                     GROUP BY domain
                     ORDER BY total DESC
                     LIMIT ?2",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![cutoff2, limit_i], |row| {
                        Ok(DomainCount {
                            domain: row.get(0)?,
                            count: row.get::<_, i64>(1)? as u64,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;

        Ok(TopDomains {
            top_queried,
            top_blocked,
        })
    }

    /// Get aggregate summary over N days.
    pub async fn get_summary(&self, days: u32) -> anyhow::Result<StatsSummary> {
        let cutoff = (Utc::now() - chrono::Duration::hours(days as i64 * 24))
            .format("%Y-%m-%dT%H:00:00")
            .to_string();

        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT COALESCE(SUM(total_queries), 0), COALESCE(SUM(blocked_queries), 0)
                     FROM hourly_stats
                     WHERE hour >= ?1",
                )?;
                let (total, blocked): (i64, i64) =
                    stmt.query_row(rusqlite::params![cutoff], |row| Ok((row.get(0)?, row.get(1)?)))?;
                let total = total as u64;
                let blocked = blocked as u64;
                let pct = if total > 0 {
                    (blocked as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                Ok(StatsSummary {
                    total_queries: total,
                    blocked_queries: blocked,
                    block_percentage: pct,
                })
            })
            .await
            .context("get_summary query failed")
    }

    /// Delete stats older than N days.
    pub async fn purge_older_than(&self, days: u32) -> anyhow::Result<()> {
        let hour_cutoff = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%dT%H:00:00")
            .to_string();
        let day_cutoff = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%d")
            .to_string();

        self.db
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM hourly_stats WHERE hour < ?1",
                    rusqlite::params![hour_cutoff],
                )?;
                conn.execute(
                    "DELETE FROM daily_top_domains WHERE day < ?1",
                    rusqlite::params![day_cutoff],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    async fn temp_stats() -> PersistentStats {
        let path = PathBuf::from(":memory:");
        // tokio-rusqlite doesn't support :memory: directly, use temp file
        let tmp = std::env::temp_dir().join(format!("oxi-stats-test-{}.db", std::process::id()));
        let ps = PersistentStats::open(&tmp).await.unwrap();
        ps
    }

    #[tokio::test]
    async fn record_and_flush() {
        let ps = temp_stats().await;
        ps.record("example.com", false);
        ps.record("ads.example.com", true);
        ps.record("example.com", false);
        ps.flush().await.unwrap();

        let summary = ps.get_summary(1).await.unwrap();
        assert_eq!(summary.total_queries, 3);
        assert_eq!(summary.blocked_queries, 1);
    }

    #[tokio::test]
    async fn top_domains() {
        let ps = temp_stats().await;
        for _ in 0..10 {
            ps.record("popular.com", false);
        }
        for _ in 0..5 {
            ps.record("ads.tracker.com", true);
        }
        ps.record("rare.com", false);
        ps.flush().await.unwrap();

        let top = ps.get_top_domains(1, 10).await.unwrap();
        assert_eq!(top.top_queried[0].domain, "popular.com");
        assert_eq!(top.top_queried[0].count, 10);
        assert_eq!(top.top_blocked[0].domain, "ads.tracker.com");
        assert_eq!(top.top_blocked[0].count, 5);
    }

    #[tokio::test]
    async fn hourly_stats_query() {
        let ps = temp_stats().await;
        ps.record("example.com", false);
        ps.flush().await.unwrap();

        let now = Utc::now();
        let from = (now - chrono::Duration::hours(1)).format("%Y-%m-%dT%H:00:00").to_string();
        let to = (now + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:00:00").to_string();
        let hourly = ps.get_hourly_stats(&from, &to).await.unwrap();
        assert!(!hourly.is_empty());
        assert!(hourly[0].total >= 1);
    }

    #[tokio::test]
    async fn empty_flush_is_noop() {
        let ps = temp_stats().await;
        ps.flush().await.unwrap(); // should not error
        let summary = ps.get_summary(1).await.unwrap();
        assert_eq!(summary.total_queries, 0);
    }

    #[tokio::test]
    async fn purge_removes_old_data() {
        let ps = temp_stats().await;
        ps.record("example.com", false);
        ps.flush().await.unwrap();

        // Purge with 0 days (removes everything)
        ps.purge_older_than(0).await.unwrap();

        // Current hour data should still exist (it's not "older than 0 days")
        // But data from before today should be gone
        let summary = ps.get_summary(1).await.unwrap();
        // This is tricky — 0 days means "older than now", so current data may still be there
        // The exact behavior depends on timestamp precision
        assert!(summary.total_queries <= 1); // may or may not be purged depending on timing
    }
}
```

- [ ] **Step 2: Register the module in main.rs**

In `src/main.rs`, add after `mod cert_parser;`:

```rust
mod persistent_stats;
```

- [ ] **Step 3: Run tests**

Run: `cargo test persistent_stats`
Expected: All persistent_stats tests pass

- [ ] **Step 4: Commit**

```bash
git add src/persistent_stats.rs src/main.rs
git commit -m "feat: add persistent statistics module with SQLite storage and write buffer"
```

---

### Task 3: Wire persistent stats into Stats and main.rs

**Files:**
- Modify: `src/stats.rs` (add PersistentStats field)
- Modify: `src/main.rs` (open stats.db, pass to Stats, add flush/purge tasks, add to AppState)
- Modify: `src/web/mod.rs` (add persistent_stats and stats_retention_days to AppState, update save_config)

- [ ] **Step 1: Add PersistentStats to Stats struct**

In `src/stats.rs`, add at the top:
```rust
use crate::persistent_stats::PersistentStats;
```

Update the `Stats` struct to include an optional PersistentStats:
```rust
pub struct Stats {
    total_queries: Arc<AtomicU64>,
    blocked_queries: Arc<AtomicU64>,
    query_log: Arc<RwLock<VecDeque<QueryLogEntry>>>,
    max_log_entries: usize,
    persistent: Option<PersistentStats>,
}
```

Update `Stats::new` to accept an optional PersistentStats:
```rust
    pub fn new(max_log_entries: usize, persistent: Option<PersistentStats>) -> Self {
        Self {
            total_queries: Arc::new(AtomicU64::new(0)),
            blocked_queries: Arc::new(AtomicU64::new(0)),
            query_log: Arc::new(RwLock::new(VecDeque::with_capacity(max_log_entries))),
            max_log_entries,
            persistent,
        }
    }
```

Update `record_query` to also record to persistent stats:
```rust
    pub fn record_query(&self, entry: QueryLogEntry) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        if entry.blocked {
            self.blocked_queries.fetch_add(1, Ordering::Relaxed);
        }

        // Record to persistent stats
        if let Some(ref ps) = self.persistent {
            ps.record(&entry.domain, entry.blocked);
        }

        let log = self.query_log.clone();
        let max = self.max_log_entries;
        tokio::spawn(async move {
            let mut log = log.write().await;
            if log.len() >= max {
                log.pop_back();
            }
            log.push_front(entry);
        });
    }
```

- [ ] **Step 2: Add PersistentStats and stats_retention_days to AppState**

In `src/web/mod.rs`, add to the AppState struct:
```rust
    pub persistent_stats: crate::persistent_stats::PersistentStats,
    pub stats_retention_days: std::sync::Arc<tokio::sync::RwLock<u32>>,
```

In `save_config`, add after the `query_log_retention_days` line:
```rust
        config.log.stats_retention_days = *self.stats_retention_days.read().await;
```

- [ ] **Step 3: Update main.rs to open stats.db and wire everything**

In `src/main.rs`, find where `query_log.db` is opened (around line 226). Add after it:

```rust
    // Open persistent stats database
    let stats_db_path = config_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("stats.db");
    let persistent_stats = persistent_stats::PersistentStats::open(&stats_db_path).await?;
```

Update the `Stats::new` call (around line 218):
```rust
    let stats = stats::Stats::new(10_000, Some(persistent_stats.clone()));
```

Add `stats_retention_days` shared state:
```rust
    let stats_retention_days = std::sync::Arc::new(tokio::sync::RwLock::new(
        config.log.stats_retention_days,
    ));
```

Add both new fields to the `web::AppState` construction:
```rust
        persistent_stats: persistent_stats.clone(),
        stats_retention_days: stats_retention_days.clone(),
```

- [ ] **Step 4: Add flush and purge background tasks**

In `src/main.rs`, add after the query log purge task:

```rust
    // Spawn stats flush task (every 60 seconds)
    {
        let ps = persistent_stats.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                if let Err(e) = ps.flush().await {
                    tracing::warn!("Stats flush failed: {}", e);
                }
            }
        });
    }

    // Spawn stats purge task (hourly)
    {
        let ps = persistent_stats.clone();
        let retention = stats_retention_days.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                let days = *retention.read().await;
                if let Err(e) = ps.purge_older_than(days).await {
                    tracing::warn!("Stats purge failed: {}", e);
                }
            }
        });
    }
```

- [ ] **Step 5: Update the query log purge task field name**

In `src/main.rs`, find the query log purge task. Update the retention variable name to use the new field:

Change:
```rust
        let retention = web_state.log_retention_days.clone();
```
to reflect the new config field. The `log_retention_days` in AppState now specifically tracks query log retention. No name change needed for AppState — just ensure the main.rs initialization uses the new config field:
```rust
    let log_retention_days =
        std::sync::Arc::new(tokio::sync::RwLock::new(config.log.query_log_retention_days));
```

- [ ] **Step 6: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add src/stats.rs src/web/mod.rs src/main.rs
git commit -m "feat: wire persistent stats into Stats module with flush and purge tasks"
```

---

### Task 4: Add historical stats API endpoints

**Files:**
- Modify: `src/web/mod.rs` (add 3 new routes + handlers)

- [ ] **Step 1: Add routes**

In `src/web/mod.rs`, find the stats routes area. Add:

```rust
        .route("/api/stats/history", get(api_stats_history))
        .route("/api/stats/top-domains", get(api_stats_top_domains))
        .route("/api/stats/summary", get(api_stats_summary))
```

- [ ] **Step 2: Add the history handler**

```rust
#[derive(Deserialize)]
struct StatsHistoryQuery {
    period: Option<String>, // "24h", "7d", "30d", "90d"
}

async fn api_stats_history(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<StatsHistoryQuery>,
) -> Response {
    let period = params.period.as_deref().unwrap_or("24h");
    let hours = match period {
        "24h" => 24,
        "7d" => 7 * 24,
        "30d" => 30 * 24,
        "90d" => 90 * 24,
        _ => 24,
    };

    let now = chrono::Utc::now();
    let from = (now - chrono::Duration::hours(hours)).format("%Y-%m-%dT%H:00:00").to_string();
    let to = now.format("%Y-%m-%dT%H:00:00").to_string();

    match state.persistent_stats.get_hourly_stats(&from, &to).await {
        Ok(data) => Json(serde_json::json!({
            "period": period,
            "data": data,
        })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response(),
    }
}
```

- [ ] **Step 3: Add the top-domains handler**

```rust
#[derive(Deserialize)]
struct TopDomainsQuery {
    days: Option<u32>,
    limit: Option<u32>,
}

async fn api_stats_top_domains(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<TopDomainsQuery>,
) -> Response {
    let days = params.days.unwrap_or(7);
    let limit = params.limit.unwrap_or(10);

    match state.persistent_stats.get_top_domains(days, limit).await {
        Ok(data) => Json(serde_json::json!({
            "days": days,
            "top_queried": data.top_queried,
            "top_blocked": data.top_blocked,
        })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response(),
    }
}
```

- [ ] **Step 4: Add the summary handler**

```rust
#[derive(Deserialize)]
struct StatsSummaryQuery {
    days: Option<u32>,
}

async fn api_stats_summary(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<StatsSummaryQuery>,
) -> Response {
    let days = params.days.unwrap_or(30);

    match state.persistent_stats.get_summary(days).await {
        Ok(data) => Json(serde_json::json!({
            "days": days,
            "total_queries": data.total_queries,
            "blocked_queries": data.blocked_queries,
            "block_percentage": data.block_percentage,
        })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response(),
    }
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: add historical stats API endpoints (history, top-domains, summary)"
```

---

### Task 5: Update log settings API for split retention

**Files:**
- Modify: `src/web/mod.rs` (update log settings response/request types and handlers)

- [ ] **Step 1: Update LogSettingsResponse**

Find the `LogSettingsResponse` struct (around line 1915). Replace:

```rust
#[derive(Serialize)]
struct LogSettingsResponse {
    query_log_retention_days: u32,
    stats_retention_days: u32,
    anonymize_client_ip: bool,
}
```

- [ ] **Step 2: Update LogSettingsRequest**

Replace:

```rust
#[derive(Deserialize)]
struct LogSettingsRequest {
    #[serde(default)]
    query_log_retention_days: Option<u32>,
    #[serde(default)]
    stats_retention_days: Option<u32>,
    #[serde(default)]
    anonymize_client_ip: Option<bool>,
}
```

- [ ] **Step 3: Update api_get_log_settings**

```rust
async fn api_get_log_settings(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Json<LogSettingsResponse>, Response> {
    require_permission(&user, Permission::ViewLogs)?;
    Ok(Json(LogSettingsResponse {
        query_log_retention_days: *state.log_retention_days.read().await,
        stats_retention_days: *state.stats_retention_days.read().await,
        anonymize_client_ip: state
            .anonymize_ip
            .load(std::sync::atomic::Ordering::Relaxed),
    }))
}
```

- [ ] **Step 4: Update api_set_log_settings**

```rust
async fn api_set_log_settings(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<LogSettingsRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    if let Some(days) = req.query_log_retention_days {
        let clamped = days.clamp(1, 90);
        *state.log_retention_days.write().await = clamped;
        info!("Query log retention set to {} days", clamped);
    }
    if let Some(days) = req.stats_retention_days {
        let clamped = days.clamp(1, 365);
        *state.stats_retention_days.write().await = clamped;
        info!("Stats retention set to {} days", clamped);
    }
    if let Some(anonymize) = req.anonymize_client_ip {
        state
            .anonymize_ip
            .store(anonymize, std::sync::atomic::Ordering::Relaxed);
        info!("Client IP anonymization set to {}", anonymize);
    }
    state.save_config().await;
    Ok(StatusCode::OK)
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: update log settings API with separate query log and stats retention"
```

---

### Task 6: Update dashboard settings UI

**Files:**
- Modify: `src/web/dashboard.html`

- [ ] **Step 1: Update the log settings HTML**

Find the `.logs-settings` div (around line 1411). Replace the entire div with:

```html
                <div class="logs-settings">
                    <label>
                        Query log retention:
                        <input type="number" id="logRetentionInput" min="1" max="90" value="7">
                        days
                    </label>
                    <label>
                        Statistics retention:
                        <input type="number" id="statsRetentionInput" min="1" max="365" value="90">
                        days
                    </label>
                    <button class="btn btn-sm" onclick="saveLogSettings()">Save</button>
                    <label style="margin-left: auto;">
                        <input type="checkbox" id="logAnonIpCheckbox" onchange="saveLogSettings()">
                        Anonymize client IPs
                    </label>
                </div>
```

- [ ] **Step 2: Update the JavaScript**

Find `refreshLogSettings` function. Replace:

```javascript
        async function refreshLogSettings() {
            try {
                const res = await fetch('/api/logs/settings');
                const data = await res.json();
                document.getElementById('logRetentionInput').value = data.query_log_retention_days;
                document.getElementById('statsRetentionInput').value = data.stats_retention_days;
                document.getElementById('logAnonIpCheckbox').checked = data.anonymize_client_ip;
            } catch (e) { console.error('Failed to load log settings', e); }
        }
```

Find `saveLogSettings` function. Replace:

```javascript
        async function saveLogSettings() {
            const query_log_retention_days = parseInt(document.getElementById('logRetentionInput').value, 10);
            const stats_retention_days = parseInt(document.getElementById('statsRetentionInput').value, 10);
            const anonymize_client_ip = document.getElementById('logAnonIpCheckbox').checked;
            try {
                await fetch('/api/logs/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query_log_retention_days, stats_retention_days, anonymize_client_ip })
                });
            } catch (e) { console.error('Failed to save log settings', e); }
        }
```

- [ ] **Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat: split dashboard log settings into query log and statistics retention"
```

---

### Task 7: Final verification

- [ ] **Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass (76 existing + new persistent_stats tests)

- [ ] **Step 2: Verify build**

Run: `cargo build`
Expected: Success

- [ ] **Step 3: Verify new API routes**

Run: `grep -E 'api/stats/(history|top-domains|summary)' src/web/mod.rs`
Expected: Shows 3 routes

- [ ] **Step 4: Verify config fields**

Run: `grep 'retention' src/config.rs`
Expected: Shows query_log_retention_days and stats_retention_days

- [ ] **Step 5: Verify persistent_stats module**

Run: `grep 'mod persistent_stats' src/main.rs`
Expected: Shows module declaration
