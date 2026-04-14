use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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
///
/// Two DB files may coexist:
///   `query_log.db` — active, receives inserts, subject to retention purge
///   `query_log_archive.db` — rotated-out older rows, read-only for the UI
///
/// When the archive file exists at open() it is ATTACHed so searches
/// transparently read from both.  Rotation moves the oldest half of active
/// rows into the archive and VACUUMs the active DB.  Emergency purge drops
/// the archive file entirely, then trims the active DB if still needed.
#[derive(Clone)]
pub struct QueryLog {
    conn: Arc<tokio_rusqlite::Connection>,
    enabled: Arc<AtomicBool>,
    active_path: PathBuf,
    archive_path: PathBuf,
    archive_attached: Arc<AtomicBool>,
}

fn archive_path_for(active: &Path) -> PathBuf {
    let parent = active.parent().unwrap_or_else(|| Path::new("."));
    let stem = active
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("query_log");
    parent.join(format!("{}_archive.db", stem))
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

        let active_path = path.to_path_buf();
        let archive_path = archive_path_for(path);
        let archive_attached = Arc::new(AtomicBool::new(false));

        // If a prior run left an archive behind, ATTACH it so searches see
        // both databases transparently.
        if archive_path.exists() {
            let ap = archive_path.clone();
            let attached = archive_attached.clone();
            let attach_result = conn
                .call(move |conn| {
                    conn.execute_batch(&format!("ATTACH DATABASE '{}' AS archive;", ap.display()))?;
                    Ok(())
                })
                .await;
            match attach_result {
                Ok(()) => {
                    attached.store(true, Ordering::Relaxed);
                    info!("Attached query log archive at {}", archive_path.display());
                }
                Err(e) => warn!("Failed to attach query log archive: {}", e),
            }
        }

        info!("Query log database opened at {}", path.display());
        Ok(Self {
            conn: Arc::new(conn),
            enabled: Arc::new(AtomicBool::new(true)),
            active_path,
            archive_path,
            archive_attached,
        })
    }

    /// Toggle whether new rows are recorded.  Existing rows remain.
    pub fn set_enabled(&self, enabled: bool) {
        let prev = self.enabled.swap(enabled, Ordering::Relaxed);
        if prev != enabled {
            info!(
                "Query logging {}",
                if enabled { "enabled" } else { "disabled" }
            );
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn archive_is_attached(&self) -> bool {
        self.archive_attached.load(Ordering::Relaxed)
    }

    pub fn active_db_path(&self) -> &Path {
        &self.active_path
    }

    /// Return the byte size of the active DB file (best-effort).
    pub fn active_db_size(&self) -> u64 {
        std::fs::metadata(&self.active_path)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    pub fn archive_db_size(&self) -> u64 {
        std::fs::metadata(&self.archive_path)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Insert a log entry. Fire-and-forget — errors are logged, never propagated.
    /// No-ops when query logging is disabled.
    pub fn insert(&self, entry: LogEntry) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
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
        let archive_attached = self.archive_attached.load(Ordering::Relaxed);

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

            // When the archive DB is attached, union it transparently so the
            // UI sees a continuous log despite rotation.
            let source = if archive_attached {
                "(SELECT id, timestamp, domain, query_type, client_ip, status, block_source, block_feature, response_time_ms, upstream FROM query_log
                  UNION ALL
                  SELECT id, timestamp, domain, query_type, client_ip, status, block_source, block_feature, response_time_ms, upstream FROM archive.query_log) AS q"
            } else {
                "query_log"
            };
            let sql = format!(
                "SELECT id, timestamp, domain, query_type, client_ip, status, block_source, block_feature, response_time_ms, upstream
                 FROM {} {} ORDER BY id DESC LIMIT ?",
                source, where_sql
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
            info!("Retroactively anonymized {} query log entries", updated);
        }
        Ok(updated)
    }

    /// Delete entries older than the given number of minutes (both active
    /// and archive DBs when attached).
    pub async fn purge_older_than_minutes(&self, minutes: u32) -> anyhow::Result<u64> {
        let cutoff = Utc::now() - chrono::Duration::minutes(minutes as i64);
        let cutoff_millis = cutoff.timestamp_millis();
        let archive_attached = self.archive_attached.load(Ordering::Relaxed);

        let conn = self.conn.clone();
        let deleted = conn
            .call(move |conn| {
                let mut count = conn.execute(
                    "DELETE FROM query_log WHERE timestamp < ?1",
                    params![cutoff_millis],
                )? as u64;
                if archive_attached {
                    count += conn.execute(
                        "DELETE FROM archive.query_log WHERE timestamp < ?1",
                        params![cutoff_millis],
                    )? as u64;
                }
                Ok(count)
            })
            .await?;

        if deleted > 0 {
            info!("Purged {} old query log entries", deleted);
        }
        Ok(deleted)
    }

    /// Rotate the oldest ~half of rows from the active DB into the archive DB.
    ///
    /// After rotation, the active DB has the newer half of its contents; the
    /// archive gains the older half.  VACUUMs the active DB so the bytes
    /// actually shrink on disk.  Data is preserved, still readable via
    /// `search()`.
    pub async fn rotate_to_archive(&self) -> anyhow::Result<u64> {
        let archive_path = self.archive_path.clone();
        let attached_flag = self.archive_attached.clone();

        let conn = self.conn.clone();
        let moved = conn
            .call(move |conn| {
                // Ensure archive exists with the same schema as active.  If it
                // was already ATTACHed we reuse it; otherwise create it and
                // attach fresh.
                let was_attached = attached_flag.load(Ordering::Relaxed);
                if !was_attached {
                    conn.execute_batch(&format!(
                        "ATTACH DATABASE '{}' AS archive;",
                        archive_path.display()
                    ))?;
                }
                conn.execute_batch(
                    "CREATE TABLE IF NOT EXISTS archive.query_log (
                         id              INTEGER PRIMARY KEY,
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
                     CREATE INDEX IF NOT EXISTS archive.idx_archive_timestamp
                         ON query_log(timestamp DESC);",
                )?;

                // Find the median timestamp via count/2 offset; anything older
                // moves into the archive.  SELECT first to avoid a giant
                // single-statement INSERT..DELETE on a huge DB.
                let total: i64 =
                    conn.query_row("SELECT COUNT(*) FROM query_log", [], |r| r.get(0))?;
                if total <= 1 {
                    return Ok(0u64);
                }
                let half = total / 2;
                let cutoff_id: Option<i64> = conn
                    .query_row(
                        "SELECT id FROM query_log ORDER BY id ASC LIMIT 1 OFFSET ?1",
                        params![half],
                        |r| r.get(0),
                    )
                    .ok();
                let Some(cutoff_id) = cutoff_id else {
                    return Ok(0u64);
                };

                let tx = conn.unchecked_transaction()?;
                tx.execute(
                    "INSERT OR IGNORE INTO archive.query_log
                         (id, timestamp, domain, query_type, client_ip, status,
                          block_source, block_feature, response_time_ms, upstream)
                     SELECT id, timestamp, domain, query_type, client_ip, status,
                            block_source, block_feature, response_time_ms, upstream
                     FROM query_log WHERE id < ?1",
                    params![cutoff_id],
                )?;
                let moved =
                    tx.execute("DELETE FROM query_log WHERE id < ?1", params![cutoff_id])? as u64;
                tx.commit()?;

                // VACUUM the active DB so the file actually shrinks.  Attached
                // databases must be detached for VACUUM, so we detach, vacuum,
                // then reattach.
                conn.execute_batch("DETACH DATABASE archive;")?;
                conn.execute_batch("VACUUM;")?;
                // Truncate the WAL so the on-disk size reflects the post-VACUUM
                // state immediately.
                let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
                conn.execute_batch(&format!(
                    "ATTACH DATABASE '{}' AS archive;",
                    archive_path.display()
                ))?;
                attached_flag.store(true, Ordering::Relaxed);

                Ok(moved)
            })
            .await?;

        if moved > 0 {
            info!(
                "Rotated {} query log rows into archive {}",
                moved,
                self.archive_path.display()
            );
        }
        Ok(moved)
    }

    /// Drop the archive DB entirely and delete its file.  Used by emergency
    /// purge when free disk is below the floor.  Returns the number of bytes
    /// freed (approximate — the file size just before deletion).
    pub async fn drop_archive(&self) -> anyhow::Result<u64> {
        let archive_path = self.archive_path.clone();
        let attached_flag = self.archive_attached.clone();

        let size_before = std::fs::metadata(&archive_path)
            .map(|m| m.len())
            .unwrap_or(0);

        let conn = self.conn.clone();
        conn.call(move |conn| {
            if attached_flag.load(Ordering::Relaxed) {
                let _ = conn.execute_batch("DETACH DATABASE archive;");
                attached_flag.store(false, Ordering::Relaxed);
            }
            Ok(())
        })
        .await?;

        // Remove the main archive file and the WAL / SHM sidecars, if any.
        let _ = std::fs::remove_file(&archive_path);
        let mut sidecar = archive_path.clone().into_os_string();
        sidecar.push("-wal");
        let _ = std::fs::remove_file(std::path::PathBuf::from(&sidecar));
        let mut sidecar = archive_path.clone().into_os_string();
        sidecar.push("-shm");
        let _ = std::fs::remove_file(std::path::PathBuf::from(&sidecar));

        if size_before > 0 {
            warn!(
                "Emergency purge: dropped query log archive ({} MB freed)",
                size_before / (1024 * 1024)
            );
        }
        Ok(size_before)
    }

    /// Delete every row from the active DB and drop the archive file.
    /// Used by the "Delete all query logs" web-UI action.
    pub async fn clear_all(&self) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let attached_flag = self.archive_attached.clone();
        conn.call(move |conn| {
            if attached_flag.load(Ordering::Relaxed) {
                let _ = conn.execute_batch("DETACH DATABASE archive;");
                attached_flag.store(false, Ordering::Relaxed);
            }
            conn.execute("DELETE FROM query_log", [])?;
            // Reset AUTOINCREMENT so the next inserted row starts at id 1 again.
            let _ = conn.execute("DELETE FROM sqlite_sequence WHERE name='query_log'", []);
            conn.execute_batch("VACUUM;")?;
            // Truncate the WAL so the on-disk file sizes reflect the cleared
            // state immediately — without this the main `.db` can stay
            // multi-MB until the next natural checkpoint and operators
            // reasonably conclude nothing happened.
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
            Ok(())
        })
        .await?;

        // Remove archive file + its WAL / SHM sidecars.
        let _ = std::fs::remove_file(&self.archive_path);
        let mut sidecar = self.archive_path.clone().into_os_string();
        sidecar.push("-wal");
        let _ = std::fs::remove_file(std::path::PathBuf::from(&sidecar));
        let mut sidecar = self.archive_path.clone().into_os_string();
        sidecar.push("-shm");
        let _ = std::fs::remove_file(std::path::PathBuf::from(&sidecar));

        warn!("All query log entries cleared by operator request");
        Ok(())
    }

    /// Trim the oldest `fraction` (0.0..=1.0) of rows from the active DB.
    /// Used by emergency purge as a last resort when dropping the archive
    /// wasn't enough to hit the free-disk floor.
    pub async fn trim_active(&self, fraction: f32) -> anyhow::Result<u64> {
        let frac = fraction.clamp(0.0, 1.0);
        if frac == 0.0 {
            return Ok(0);
        }
        let conn = self.conn.clone();
        let deleted = conn
            .call(move |conn| {
                let total: i64 =
                    conn.query_row("SELECT COUNT(*) FROM query_log", [], |r| r.get(0))?;
                if total <= 1 {
                    return Ok(0u64);
                }
                let to_drop = ((total as f32) * frac) as i64;
                if to_drop <= 0 {
                    return Ok(0u64);
                }
                let cutoff_id: Option<i64> = conn
                    .query_row(
                        "SELECT id FROM query_log ORDER BY id ASC LIMIT 1 OFFSET ?1",
                        params![to_drop],
                        |r| r.get(0),
                    )
                    .ok();
                let Some(cutoff_id) = cutoff_id else {
                    return Ok(0u64);
                };
                let deleted =
                    conn.execute("DELETE FROM query_log WHERE id < ?1", params![cutoff_id])? as u64;
                conn.execute_batch("VACUUM;")?;
                let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
                Ok(deleted)
            })
            .await?;

        if deleted > 0 {
            warn!(
                "Emergency purge: trimmed {} oldest rows from active query log",
                deleted
            );
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
