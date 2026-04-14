use crate::persistent_stats::PersistentStats;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A single DNS query event, passed to `record_query` so handlers can also
/// feed the persistent query log.  We no longer keep an in-memory ring
/// buffer of recent queries — the web dashboard reads all query history
/// from the SQLite query log instead.
#[derive(Debug, Clone, Serialize)]
pub struct QueryLogEntry {
    pub timestamp: DateTime<Utc>,
    pub domain: String,
    pub query_type: String,
    pub client_ip: String,
    pub blocked: bool,
    pub response_time_ms: u64,
    pub upstream: Option<String>,
}

/// Live counters + delegation to the persistent stats store.
#[derive(Clone)]
pub struct Stats {
    total_queries: Arc<AtomicU64>,
    blocked_queries: Arc<AtomicU64>,
    persistent: Option<PersistentStats>,
}

impl Stats {
    pub fn new(persistent: Option<PersistentStats>) -> Self {
        Self {
            total_queries: Arc::new(AtomicU64::new(0)),
            blocked_queries: Arc::new(AtomicU64::new(0)),
            persistent,
        }
    }

    pub fn record_query(&self, entry: QueryLogEntry) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        if entry.blocked {
            self.blocked_queries.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(ref ps) = self.persistent {
            ps.record(&entry.domain, entry.blocked);
        }
    }

    pub fn total_queries(&self) -> u64 {
        self.total_queries.load(Ordering::Relaxed)
    }

    pub fn blocked_queries(&self) -> u64 {
        self.blocked_queries.load(Ordering::Relaxed)
    }

    pub fn block_percentage(&self) -> f64 {
        let total = self.total_queries() as f64;
        if total == 0.0 {
            return 0.0;
        }
        (self.blocked_queries() as f64 / total) * 100.0
    }

    /// Reset live counters.  Used by the "Delete all stats" web action.
    pub fn reset(&self) {
        self.total_queries.store(0, Ordering::Relaxed);
        self.blocked_queries.store(0, Ordering::Relaxed);
    }
}
