use crate::persistent_stats::PersistentStats;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Query log entry
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

/// Statistics and query log tracker
#[derive(Clone)]
pub struct Stats {
    total_queries: Arc<AtomicU64>,
    blocked_queries: Arc<AtomicU64>,
    query_log: Arc<RwLock<VecDeque<QueryLogEntry>>>,
    max_log_entries: usize,
    persistent: Option<PersistentStats>,
}

impl Stats {
    pub fn new(max_log_entries: usize, persistent: Option<PersistentStats>) -> Self {
        Self {
            total_queries: Arc::new(AtomicU64::new(0)),
            blocked_queries: Arc::new(AtomicU64::new(0)),
            query_log: Arc::new(RwLock::new(VecDeque::with_capacity(max_log_entries))),
            max_log_entries,
            persistent,
        }
    }

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

    pub async fn recent_queries(&self, limit: usize) -> Vec<QueryLogEntry> {
        let log = self.query_log.read().await;
        log.iter().take(limit).cloned().collect()
    }

    /// Reset live counters and drop recent-queries buffer.  Used by the
    /// "Delete all stats" web action so the dashboard cards immediately
    /// reflect the wipe rather than showing stale sums.
    pub async fn reset(&self) {
        self.total_queries.store(0, Ordering::Relaxed);
        self.blocked_queries.store(0, Ordering::Relaxed);
        self.query_log.write().await.clear();
    }
}
