use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

/// A persisted query log entry stored in SQLite.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub domain: String,
    pub query_type: String,
    pub client_ip: String,
    pub status: String,
    pub block_source: Option<String>,
    pub block_feature: Option<String>,
    pub response_time_ms: u64,
    pub upstream: Option<String>,
}

/// Parameters for searching the query log.
#[derive(Debug, Default)]
pub struct LogQueryParams {
    pub search: Option<String>,
    pub status: Option<String>,
    pub before_id: Option<i64>,
    pub limit: usize,
}

/// A page of log results with cursor for infinite scroll.
#[derive(Debug, Serialize)]
pub struct LogPage {
    pub entries: Vec<LogEntry>,
    pub next_cursor: Option<i64>,
}

/// Persistent query log backed by SQLite.
#[derive(Clone)]
pub struct QueryLog {
    conn: Arc<tokio_rusqlite::Connection>,
}

impl QueryLog {
    /// Open or create the SQLite database at the given path.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = tokio_rusqlite::Connection::open(path).await?;

        conn.call(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;

                 CREATE TABLE IF NOT EXISTS query_log (
                     id              INTEGER PRIMARY KEY AUTOINCREMENT,
                     timestamp       INTEGER NOT NULL,
                     domain          TEXT NOT NULL,
                     query_type      TEXT NOT NULL,
                     client_ip       TEXT NOT NULL,
                     status          TEXT NOT NULL,
                     block_source    TEXT,
                     block_feature   TEXT,
                     response_time_ms INTEGER NOT NULL,
                     upstream        TEXT
                 );

                 CREATE INDEX IF NOT EXISTS idx_timestamp ON query_log(timestamp DESC);
                 CREATE INDEX IF NOT EXISTS idx_domain ON query_log(domain);
                 CREATE INDEX IF NOT EXISTS idx_status ON query_log(status);",
            )?;
            Ok(())
        })
        .await?;

        info!("Query log database opened at {}", path.display());
        Ok(Self {
            conn: Arc::new(conn),
        })
    }

    /// Insert a log entry. Fire-and-forget — errors are logged, never propagated.
    pub fn insert(&self, entry: LogEntry) {
        let conn = self.conn.clone();
        tokio::spawn(async move {
            let result = conn
                .call(move |conn| {
                    conn.execute(
                        "INSERT INTO query_log (timestamp, domain, query_type, client_ip, status, block_source, block_feature, response_time_ms, upstream)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                        params![
                            entry.timestamp.timestamp_millis(),
                            entry.domain,
                            entry.query_type,
                            entry.client_ip,
                            entry.status,
                            entry.block_source,
                            entry.block_feature,
                            entry.response_time_ms as i64,
                            entry.upstream,
                        ],
                    )?;
                    Ok(())
                })
                .await;

            if let Err(e) = result {
                warn!("Failed to insert query log entry: {}", e);
            }
        });
    }

    /// Search the query log with filters and cursor-based pagination.
    pub async fn search(&self, params: LogQueryParams) -> anyhow::Result<LogPage> {
        let limit = params.limit.clamp(1, 200);

        let conn = self.conn.clone();
        conn.call(move |conn| {
            let mut where_clauses = Vec::new();
            let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            if let Some(ref search) = params.search {
                if !search.is_empty() {
                    let escaped = search
                        .replace('\\', "\\\\")
                        .replace('%', "\\%")
                        .replace('_', "\\_");
                    let pattern = format!("%{}%", escaped);
                    where_clauses.push(
                        "(domain LIKE ?N ESCAPE '\\' OR client_ip LIKE ?N ESCAPE '\\' OR block_source LIKE ?N ESCAPE '\\' OR block_feature LIKE ?N ESCAPE '\\' OR upstream LIKE ?N ESCAPE '\\')"
                            .to_string(),
                    );
                    bind_values.push(Box::new(pattern));
                }
            }

            if let Some(ref status) = params.status {
                if !status.is_empty() {
                    where_clauses.push("status = ?N".to_string());
                    bind_values.push(Box::new(status.clone()));
                }
            }

            if let Some(before_id) = params.before_id {
                where_clauses.push("id < ?N".to_string());
                bind_values.push(Box::new(before_id));
            }

            // Build SQL with numbered parameters
            let where_sql = if where_clauses.is_empty() {
                String::new()
            } else {
                // Replace ?N placeholders with actual numbered params
                let mut param_idx = 1;
                let mut clauses = Vec::new();
                for clause in &where_clauses {
                    let mut c = clause.clone();
                    while c.contains("?N") {
                        c = c.replacen("?N", &format!("?{}", param_idx), 1);
                        param_idx += 1;
                    }
                    clauses.push(c);
                }
                format!("WHERE {}", clauses.join(" AND "))
            };

            // Expand bind_values: search pattern is used 5 times in the LIKE clause
            let mut final_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

            for (value_idx, clause) in where_clauses.iter().enumerate() {
                let count = clause.matches("?N").count();
                for _ in 0..count {
                    let val = &bind_values[value_idx];
                    final_params.push(clone_sql_value(val.as_ref()));
                }
            }

            let sql = format!(
                "SELECT id, timestamp, domain, query_type, client_ip, status, block_source, block_feature, response_time_ms, upstream
                 FROM query_log {} ORDER BY id DESC LIMIT ?",
                where_sql
            );
            final_params.push(Box::new(limit as i64 + 1)); // fetch one extra to detect next page

            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                final_params.iter().map(|p| p.as_ref()).collect();

            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query(param_refs.as_slice())?;

            let mut entries = Vec::new();
            while let Some(row) = rows.next()? {
                let ts_millis: i64 = row.get(1)?;
                let entry = LogEntry {
                    id: row.get(0)?,
                    timestamp: DateTime::from_timestamp_millis(ts_millis)
                        .unwrap_or_default(),
                    domain: row.get(2)?,
                    query_type: row.get(3)?,
                    client_ip: row.get(4)?,
                    status: row.get(5)?,
                    block_source: row.get(6)?,
                    block_feature: row.get(7)?,
                    response_time_ms: row.get::<_, i64>(8)? as u64,
                    upstream: row.get(9)?,
                };
                entries.push(entry);
            }

            let next_cursor = if entries.len() > limit {
                entries.truncate(limit);
                entries.last().map(|e| e.id)
            } else {
                None
            };

            Ok(LogPage {
                entries,
                next_cursor,
            })
        })
        .await
        .map_err(Into::into)
    }

    /// Retroactively anonymize all client IPs in existing log entries.
    pub async fn anonymize_all_ips(&self) -> anyhow::Result<u64> {
        let conn = self.conn.clone();
        let updated = conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT id, client_ip FROM query_log WHERE client_ip != ''")?;
                let rows: Vec<(i64, String)> = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .filter_map(|r| r.ok())
                    .collect();

                let mut count = 0u64;
                let update =
                    conn.prepare_cached("UPDATE query_log SET client_ip = ?1 WHERE id = ?2")?;
                // Need to drop the immutable borrow from prepare_cached before using it mutably
                drop(update);
                for (id, ip) in &rows {
                    let anon = anonymize_ip(ip);
                    if &anon != ip {
                        conn.execute(
                            "UPDATE query_log SET client_ip = ?1 WHERE id = ?2",
                            params![anon, id],
                        )?;
                        count += 1;
                    }
                }
                Ok(count)
            })
            .await?;

        if updated > 0 {
            info!(
                "Retroactively anonymized {} query log entries",
                updated
            );
        }
        Ok(updated)
    }

    /// Delete entries older than the given number of days.
    pub async fn purge_older_than(&self, days: u32) -> anyhow::Result<u64> {
        let cutoff = Utc::now() - chrono::Duration::days(days as i64);
        let cutoff_millis = cutoff.timestamp_millis();

        let conn = self.conn.clone();
        let deleted = conn
            .call(move |conn| {
                let count = conn.execute(
                    "DELETE FROM query_log WHERE timestamp < ?1",
                    params![cutoff_millis],
                )?;
                Ok(count as u64)
            })
            .await?;

        if deleted > 0 {
            info!("Purged {} old query log entries", deleted);
        }
        Ok(deleted)
    }
}

/// Helper to clone a ToSql boxed value (we only use String and i64).
fn clone_sql_value(val: &dyn rusqlite::types::ToSql) -> Box<dyn rusqlite::types::ToSql> {
    use rusqlite::types::{ToSqlOutput, ValueRef};
    let Ok(output) = val.to_sql() else {
        return Box::new(String::new());
    };
    match output {
        ToSqlOutput::Borrowed(ValueRef::Text(s)) => {
            Box::new(std::str::from_utf8(s).unwrap_or("").to_string())
        }
        ToSqlOutput::Owned(rusqlite::types::Value::Text(s)) => Box::new(s),
        ToSqlOutput::Owned(rusqlite::types::Value::Integer(i)) => Box::new(i),
        _ => Box::new(String::new()),
    }
}

/// Anonymize an IP address by zeroing the last octet (IPv4) or last 80 bits (IPv6).
pub fn anonymize_ip(ip: &str) -> String {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        let octets = v4.octets();
        format!("{}.{}.{}.0", octets[0], octets[1], octets[2])
    } else if let Ok(v6) = ip.parse::<std::net::Ipv6Addr>() {
        let segments = v6.segments();
        format!("{:x}:{:x}:{:x}::", segments[0], segments[1], segments[2])
    } else {
        ip.to_string()
    }
}
