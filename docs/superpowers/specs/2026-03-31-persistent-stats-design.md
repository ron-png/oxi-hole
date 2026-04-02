# Persistent Statistics Separated from Query Logs

**Date:** 2026-03-31
**Status:** Approved

## Problem

Statistics (total queries, blocked queries) are in-memory only and reset on every restart. Query logs and stats share a single retention setting. Users can't keep long-term statistics (90 days) while keeping detailed query logs short (7 days) to save space.

## Solution

1. New persistent statistics database (`stats.db`) with hourly aggregates and daily top domains
2. Separate retention settings: `query_log_retention_days` (default 7) and `stats_retention_days` (default 90)
3. New API endpoints for historical stats (time-series, top domains, summary)
4. Dashboard settings split into separate Query Log and Statistics sections

## Persistent Statistics Database

**File:** `stats.db` (SQLite, in the config directory alongside `query_log.db` and `auth.db`)

### Schema

```sql
CREATE TABLE hourly_stats (
    hour TEXT PRIMARY KEY,          -- "2026-03-31T14:00:00"
    total_queries INTEGER DEFAULT 0,
    blocked_queries INTEGER DEFAULT 0
);
CREATE INDEX idx_hourly_stats_hour ON hourly_stats(hour);

CREATE TABLE daily_top_domains (
    day TEXT NOT NULL,               -- "2026-03-31"
    domain TEXT NOT NULL,
    query_count INTEGER DEFAULT 0,
    blocked_count INTEGER DEFAULT 0,
    PRIMARY KEY (day, domain)
);
CREATE INDEX idx_daily_top_day ON daily_top_domains(day);
```

### Write Buffer

To avoid per-query disk I/O, writes are accumulated in memory and flushed every 60 seconds:

- `hourly_buffer: (u64, u64)` — total and blocked for the current hour
- `domain_buffer: HashMap<String, (u64, u64)>` — per-domain query and blocked counts for today
- Protected by `Arc<Mutex<>>`
- Flush writes INSERT OR UPDATE (upsert) into both tables
- Buffer is cleared after successful flush

### Data Flow

```
DNS query arrives
  → stats.record_query()           [in-memory counters for real-time dashboard]
  → persistent_stats.record()      [write buffer, flushed every 60s to stats.db]
  → query_log.insert()             [async insert to query_log.db]
```

The DNS handler calls all three. `persistent_stats.record()` is non-blocking (just updates the in-memory buffer).

## New Module: `src/persistent_stats.rs`

### Public API

```rust
pub struct PersistentStats { ... }

impl PersistentStats {
    pub async fn open(path: &Path) -> anyhow::Result<Self>;
    pub fn record(&self, domain: &str, blocked: bool);
    pub async fn flush(&self) -> anyhow::Result<()>;
    pub async fn get_hourly_stats(&self, from: &str, to: &str) -> anyhow::Result<Vec<HourlyStat>>;
    pub async fn get_top_domains(&self, days: u32, limit: u32) -> anyhow::Result<TopDomains>;
    pub async fn get_summary(&self, days: u32) -> anyhow::Result<StatsSummary>;
    pub async fn purge_older_than(&self, days: u32) -> anyhow::Result<()>;
}

pub struct HourlyStat {
    pub hour: String,
    pub total_queries: u64,
    pub blocked_queries: u64,
}

pub struct TopDomains {
    pub top_queried: Vec<DomainCount>,
    pub top_blocked: Vec<DomainCount>,
}

pub struct DomainCount {
    pub domain: String,
    pub count: u64,
}

pub struct StatsSummary {
    pub total_queries: u64,
    pub blocked_queries: u64,
    pub block_percentage: f64,
}
```

## Config Changes

### LogConfig update

```rust
pub struct LogConfig {
    #[serde(default = "default_query_log_retention", alias = "retention_days")]
    pub query_log_retention_days: u32,    // default 7
    #[serde(default = "default_stats_retention")]
    pub stats_retention_days: u32,         // default 90
    #[serde(default)]
    pub anonymize_client_ip: bool,
}
```

The `alias = "retention_days"` provides backwards compatibility — existing configs with the old `retention_days` field will map to `query_log_retention_days`.

### Defaults

- `query_log_retention_days`: 7 (was 90 as `retention_days`)
- `stats_retention_days`: 90

## API Changes

### New endpoints

`GET /api/stats/history?period=24h|7d|30d|90d`

Returns hourly aggregates for the requested period:
```json
{
    "period": "7d",
    "data": [
        {"hour": "2026-03-25T00:00:00", "total": 1234, "blocked": 456},
        {"hour": "2026-03-25T01:00:00", "total": 987, "blocked": 321},
        ...
    ]
}
```

`GET /api/stats/top-domains?days=7&limit=10`

Returns top queried and blocked domains:
```json
{
    "days": 7,
    "top_queried": [
        {"domain": "google.com", "count": 5432},
        {"domain": "github.com", "count": 3210}
    ],
    "top_blocked": [
        {"domain": "ads.doubleclick.net", "count": 8765},
        {"domain": "tracker.example.com", "count": 4321}
    ]
}
```

`GET /api/stats/summary?days=30`

Returns aggregate totals:
```json
{
    "days": 30,
    "total_queries": 123456,
    "blocked_queries": 45678,
    "block_percentage": 37.0
}
```

### Updated endpoint

`GET /api/logs/settings` — response updated:
```json
{
    "query_log_retention_days": 7,
    "stats_retention_days": 90,
    "anonymize_client_ip": false
}
```

`POST /api/logs/settings` — accepts:
```json
{
    "query_log_retention_days": 7,
    "stats_retention_days": 90,
    "anonymize_client_ip": false
}
```

### Unchanged endpoints

- `GET /api/stats` — still returns in-memory real-time counters (backward compatible)
- `GET /api/queries` — still returns recent queries from in-memory buffer
- `GET /api/logs` — still queries persistent query_log.db with pagination

## Dashboard UI Changes

### Settings panel

The existing single "Log Settings" section splits into two:

**Query Log:**
- "Retention" — number input, 1-90 days, default 7
- "Anonymize client IPs" — checkbox

**Statistics:**
- "Retention" — number input, 1-365 days, default 90

Both share a single "Save" button that POSTs to `/api/logs/settings`.

## Background Tasks in main.rs

### New tasks

- **Stats flush** (every 60 seconds): calls `persistent_stats.flush()`
- **Stats purge** (every hour): calls `persistent_stats.purge_older_than(stats_retention_days)`

### Updated tasks

- **Query log purge** (every hour, existing): uses `query_log_retention_days` instead of `retention_days`

## Scope

### New files
- `src/persistent_stats.rs` — SQLite persistent stats module

### Modified files
- `src/config.rs` — split retention config, add `stats_retention_days`
- `src/stats.rs` — extend `record_query` to call persistent stats
- `src/web/mod.rs` — add `PersistentStats` to AppState, add 3 new API endpoints, update log settings endpoints
- `src/web/dashboard.html` — split log/stats retention settings
- `src/main.rs` — open stats.db, create PersistentStats, add to AppState, spawn flush + purge tasks, update query log purge field name

### Not changed
- `src/query_log.rs` — purge logic unchanged, just called with new field name
- `src/auth/*` — unrelated
- `scripts/*` — unrelated
