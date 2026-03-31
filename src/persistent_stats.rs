use chrono::Utc;
use rusqlite::params;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing::info;

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

    fn take(&mut self) -> (String, String, u64, u64, HashMap<String, (u64, u64)>) {
        let hour = self.current_hour.clone();
        let day = self.current_day.clone();
        let total = self.hourly_total;
        let blocked = self.hourly_blocked;
        let domains = std::mem::take(&mut self.domains);

        // Reset counters but update time buckets
        let now = Utc::now();
        self.current_hour = now.format("%Y-%m-%dT%H:00:00").to_string();
        self.current_day = now.format("%Y-%m-%d").to_string();
        self.hourly_total = 0;
        self.hourly_blocked = 0;

        (hour, day, total, blocked, domains)
    }
}

/// Persistent statistics store backed by SQLite.
#[derive(Clone)]
pub struct PersistentStats {
    conn: Arc<tokio_rusqlite::Connection>,
    buffer: Arc<Mutex<StatsBuffer>>,
}

impl PersistentStats {
    /// Open or create the stats database at the given path.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = tokio_rusqlite::Connection::open(path).await?;

        conn.call(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;

                 CREATE TABLE IF NOT EXISTS hourly_stats (
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

        info!("Persistent stats database opened at {}", path.display());
        Ok(Self {
            conn: Arc::new(conn),
            buffer: Arc::new(Mutex::new(StatsBuffer::new())),
        })
    }

    /// Record a DNS query. Non-blocking: just updates the in-memory buffer.
    pub fn record(&self, domain: &str, blocked: bool) {
        let mut buf = self.buffer.lock().unwrap();

        // Check if the hour/day rolled over
        let now = Utc::now();
        let current_hour = now.format("%Y-%m-%dT%H:00:00").to_string();
        if buf.current_hour != current_hour {
            buf.current_hour = current_hour;
            buf.current_day = now.format("%Y-%m-%d").to_string();
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

    /// Flush buffered data to SQLite. Called periodically by the background task.
    pub async fn flush(&self) -> anyhow::Result<()> {
        let (hour, day, total, blocked, domains) = {
            let mut buf = self.buffer.lock().unwrap();
            buf.take()
        };

        // Nothing to write
        if total == 0 && domains.is_empty() {
            return Ok(());
        }

        let conn = self.conn.clone();
        conn.call(move |conn| {
            let tx = conn.transaction()?;

            // Upsert hourly stats
            if total > 0 {
                tx.execute(
                    "INSERT INTO hourly_stats (hour, total_queries, blocked_queries)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(hour) DO UPDATE SET
                         total_queries = total_queries + excluded.total_queries,
                         blocked_queries = blocked_queries + excluded.blocked_queries",
                    params![hour, total as i64, blocked as i64],
                )?;
            }

            // Upsert daily domain counts
            for (domain, (query_count, blocked_count)) in &domains {
                tx.execute(
                    "INSERT INTO daily_top_domains (day, domain, query_count, blocked_count)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(day, domain) DO UPDATE SET
                         query_count = query_count + excluded.query_count,
                         blocked_count = blocked_count + excluded.blocked_count",
                    params![day, domain, *query_count as i64, *blocked_count as i64],
                )?;
            }

            tx.commit()?;
            Ok(())
        })
        .await?;

        Ok(())
    }

    /// Return hourly aggregates for a time range (ISO 8601 strings).
    pub async fn get_hourly_stats(&self, from: &str, to: &str) -> anyhow::Result<Vec<HourlyStat>> {
        let from = from.to_string();
        let to = to.to_string();
        let conn = self.conn.clone();

        let stats = conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT hour, total_queries, blocked_queries
                     FROM hourly_stats
                     WHERE hour >= ?1 AND hour <= ?2
                     ORDER BY hour ASC",
                )?;
                let rows = stmt.query_map(params![from, to], |row| {
                    Ok(HourlyStat {
                        hour: row.get(0)?,
                        total: row.get::<_, i64>(1)? as u64,
                        blocked: row.get::<_, i64>(2)? as u64,
                    })
                })?;
                let mut result = Vec::new();
                for row in rows {
                    result.push(row?);
                }
                Ok(result)
            })
            .await?;

        Ok(stats)
    }

    /// Return top queried and top blocked domains over the last N days.
    pub async fn get_top_domains(&self, days: u32, limit: u32) -> anyhow::Result<TopDomains> {
        let cutoff = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%d")
            .to_string();
        let conn = self.conn.clone();

        let result = conn
            .call(move |conn| {
                let mut top_queried_stmt = conn.prepare(
                    "SELECT domain, SUM(query_count) as total
                     FROM daily_top_domains
                     WHERE day >= ?1
                     GROUP BY domain
                     ORDER BY total DESC
                     LIMIT ?2",
                )?;
                let top_queried: Vec<DomainCount> = top_queried_stmt
                    .query_map(params![cutoff, limit as i64], |row| {
                        Ok(DomainCount {
                            domain: row.get(0)?,
                            count: row.get::<_, i64>(1)? as u64,
                        })
                    })?
                    .filter_map(|r| r.ok())
                    .collect();

                let mut top_blocked_stmt = conn.prepare(
                    "SELECT domain, SUM(blocked_count) as total
                     FROM daily_top_domains
                     WHERE day >= ?1 AND blocked_count > 0
                     GROUP BY domain
                     ORDER BY total DESC
                     LIMIT ?2",
                )?;
                let top_blocked: Vec<DomainCount> = top_blocked_stmt
                    .query_map(params![cutoff, limit as i64], |row| {
                        Ok(DomainCount {
                            domain: row.get(0)?,
                            count: row.get::<_, i64>(1)? as u64,
                        })
                    })?
                    .filter_map(|r| r.ok())
                    .collect();

                Ok(TopDomains {
                    top_queried,
                    top_blocked,
                })
            })
            .await?;

        Ok(result)
    }

    /// Return summary statistics over the last N days.
    pub async fn get_summary(&self, days: u32) -> anyhow::Result<StatsSummary> {
        let cutoff = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%dT%H:00:00")
            .to_string();
        let conn = self.conn.clone();

        let summary = conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT COALESCE(SUM(total_queries), 0), COALESCE(SUM(blocked_queries), 0)
                     FROM hourly_stats
                     WHERE hour >= ?1",
                )?;
                let (total, blocked): (i64, i64) =
                    stmt.query_row(params![cutoff], |row| Ok((row.get(0)?, row.get(1)?)))?;

                let total = total as u64;
                let blocked = blocked as u64;
                let block_percentage = if total == 0 {
                    0.0
                } else {
                    (blocked as f64 / total as f64) * 100.0
                };

                Ok(StatsSummary {
                    total_queries: total,
                    blocked_queries: blocked,
                    block_percentage,
                })
            })
            .await?;

        Ok(summary)
    }

    /// Delete data older than the given number of days.
    pub async fn purge_older_than(&self, days: u32) -> anyhow::Result<u64> {
        let hour_cutoff = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%dT%H:00:00")
            .to_string();
        let day_cutoff = (Utc::now() - chrono::Duration::days(days as i64))
            .format("%Y-%m-%d")
            .to_string();

        let conn = self.conn.clone();
        let deleted = conn
            .call(move |conn| {
                let h = conn.execute(
                    "DELETE FROM hourly_stats WHERE hour < ?1",
                    params![hour_cutoff],
                )?;
                let d = conn.execute(
                    "DELETE FROM daily_top_domains WHERE day < ?1",
                    params![day_cutoff],
                )?;
                Ok((h + d) as u64)
            })
            .await?;

        if deleted > 0 {
            info!("Purged {} old persistent stats rows", deleted);
        }
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    async fn open_test_db() -> PersistentStats {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "oxi_dns_test_stats_{}_{}.db",
            std::process::id(),
            id
        ));
        PersistentStats::open(&path).await.unwrap()
    }

    #[tokio::test]
    async fn record_and_flush() {
        let stats = open_test_db().await;

        stats.record("example.com", false);
        stats.record("example.com", true);
        stats.record("other.com", false);

        stats.flush().await.unwrap();

        let summary = stats.get_summary(1).await.unwrap();
        assert_eq!(summary.total_queries, 3);
        assert_eq!(summary.blocked_queries, 1);
        assert!((summary.block_percentage - 33.333).abs() < 1.0);
    }

    #[tokio::test]
    async fn top_domains() {
        let stats = open_test_db().await;

        // Record different domains with different counts
        for _ in 0..5 {
            stats.record("popular.com", false);
        }
        for _ in 0..3 {
            stats.record("medium.com", false);
        }
        stats.record("rare.com", false);

        // Some blocked
        for _ in 0..4 {
            stats.record("ads.example.com", true);
        }
        for _ in 0..2 {
            stats.record("tracker.io", true);
        }

        stats.flush().await.unwrap();

        let top = stats.get_top_domains(1, 10).await.unwrap();

        // Top queried should have popular.com first
        assert!(!top.top_queried.is_empty());
        assert_eq!(top.top_queried[0].domain, "popular.com");
        assert_eq!(top.top_queried[0].count, 5);

        // Top blocked should have ads.example.com first
        assert!(!top.top_blocked.is_empty());
        assert_eq!(top.top_blocked[0].domain, "ads.example.com");
        assert_eq!(top.top_blocked[0].count, 4);
    }

    #[tokio::test]
    async fn hourly_stats_query() {
        let stats = open_test_db().await;

        stats.record("test.com", false);
        stats.record("test.com", true);
        stats.flush().await.unwrap();

        let now = Utc::now();
        let from = (now - chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:00:00")
            .to_string();
        let to = (now + chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:00:00")
            .to_string();

        let hourly = stats.get_hourly_stats(&from, &to).await.unwrap();
        assert!(!hourly.is_empty());
        assert_eq!(hourly[0].total, 2);
        assert_eq!(hourly[0].blocked, 1);
    }

    #[tokio::test]
    async fn empty_flush_is_noop() {
        let stats = open_test_db().await;
        // Flush with no data should not error
        stats.flush().await.unwrap();

        let summary = stats.get_summary(1).await.unwrap();
        assert_eq!(summary.total_queries, 0);
        assert_eq!(summary.blocked_queries, 0);
    }

    #[tokio::test]
    async fn purge_removes_old_data() {
        let stats = open_test_db().await;

        // Insert some data directly with old timestamps
        let old_hour = "2020-01-01T00:00:00";
        let old_day = "2020-01-01";

        let conn = stats.conn.clone();
        conn.call(move |conn| {
            conn.execute(
                "INSERT INTO hourly_stats (hour, total_queries, blocked_queries) VALUES (?1, 10, 5)",
                params![old_hour],
            )?;
            conn.execute(
                "INSERT INTO daily_top_domains (day, domain, query_count, blocked_count) VALUES (?1, 'old.com', 10, 5)",
                params![old_day],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        // Also add current data
        stats.record("new.com", false);
        stats.flush().await.unwrap();

        // Purge anything older than 30 days
        let deleted = stats.purge_older_than(30).await.unwrap();
        assert!(deleted >= 2, "should have purged old rows");

        // Current data should still be there
        let summary = stats.get_summary(1).await.unwrap();
        assert_eq!(summary.total_queries, 1);
    }
}
