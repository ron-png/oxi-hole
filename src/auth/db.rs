use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use rusqlite::params;
use tracing::info;

use crate::auth::models::{ApiTokenInfo, Permission, User, UserWithHash};

/// Auth database backed by SQLite.
#[derive(Clone)]
pub struct AuthDb {
    conn: Arc<tokio_rusqlite::Connection>,
}

impl AuthDb {
    /// Open or create the SQLite auth database at the given path.
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = tokio_rusqlite::Connection::open(path).await?;

        conn.call(|conn| {
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=NORMAL;
                 PRAGMA foreign_keys=ON;

                 CREATE TABLE IF NOT EXISTS users (
                     id            INTEGER PRIMARY KEY AUTOINCREMENT,
                     username      TEXT UNIQUE NOT NULL,
                     password_hash TEXT NOT NULL,
                     is_active     INTEGER DEFAULT 1,
                     created_at    TEXT,
                     updated_at    TEXT
                 );

                 CREATE TABLE IF NOT EXISTS user_permissions (
                     user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                     permission TEXT NOT NULL,
                     UNIQUE(user_id, permission)
                 );

                 CREATE TABLE IF NOT EXISTS sessions (
                     id         TEXT PRIMARY KEY,
                     user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                     created_at TEXT,
                     expires_at TEXT,
                     ip_address TEXT
                 );

                 CREATE INDEX IF NOT EXISTS idx_sessions_user_id    ON sessions(user_id);
                 CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

                 CREATE TABLE IF NOT EXISTS api_tokens (
                     id          INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                     token_hash  TEXT,
                     name        TEXT,
                     permissions TEXT,
                     created_at  TEXT,
                     last_used_at TEXT,
                     expires_at  TEXT
                 );

                 CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);",
            )?;
            Ok(())
        })
        .await?;

        info!("Auth database opened at {}", path.display());
        Ok(Self {
            conn: Arc::new(conn),
        })
    }

    // -------------------------------------------------------------------------
    // Setup / users
    // -------------------------------------------------------------------------

    /// Returns true when the users table is empty (initial setup needed).
    pub async fn needs_setup(&self) -> anyhow::Result<bool> {
        let conn = self.conn.clone();
        let count: i64 = conn
            .call(|conn| {
                let n: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
                Ok(n)
            })
            .await?;
        Ok(count == 0)
    }

    /// Atomically create the first user (setup). Fails if any users already exist.
    pub async fn create_first_user(
        &self,
        username: String,
        password_hash: String,
        permissions: Vec<Permission>,
    ) -> anyhow::Result<User> {
        let conn = self.conn.clone();
        let user = conn
            .call(move |conn| {
                let count: i64 =
                    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
                if count != 0 {
                    return Err(tokio_rusqlite::Error::Other(
                        anyhow::anyhow!("Setup already completed").into(),
                    ));
                }

                let now = Utc::now().to_rfc3339();
                conn.execute(
                    "INSERT INTO users (username, password_hash, is_active, created_at, updated_at)
                     VALUES (?1, ?2, 1, ?3, ?4)",
                    params![username, password_hash, now, now],
                )?;
                let id = conn.last_insert_rowid();

                for perm in &permissions {
                    conn.execute(
                        "INSERT OR IGNORE INTO user_permissions (user_id, permission) VALUES (?1, ?2)",
                        params![id, perm.as_str()],
                    )?;
                }

                let user = conn.query_row(
                    "SELECT id, username, is_active, created_at, updated_at
                     FROM users WHERE id = ?1",
                    params![id],
                    row_to_user,
                )?;
                Ok(user)
            })
            .await?;
        Ok(user)
    }

    /// Create a new user and insert the given permissions, returning the new User.
    pub async fn create_user(
        &self,
        username: String,
        password_hash: String,
        permissions: Vec<Permission>,
    ) -> anyhow::Result<User> {
        let conn = self.conn.clone();
        let user = conn
            .call(move |conn| {
                let now = Utc::now().to_rfc3339();
                conn.execute(
                    "INSERT INTO users (username, password_hash, is_active, created_at, updated_at)
                     VALUES (?1, ?2, 1, ?3, ?4)",
                    params![username, password_hash, now, now],
                )?;
                let id = conn.last_insert_rowid();

                for perm in &permissions {
                    conn.execute(
                        "INSERT OR IGNORE INTO user_permissions (user_id, permission) VALUES (?1, ?2)",
                        params![id, perm.as_str()],
                    )?;
                }

                let user = conn.query_row(
                    "SELECT id, username, is_active, created_at, updated_at
                     FROM users WHERE id = ?1",
                    params![id],
                    row_to_user,
                )?;
                Ok(user)
            })
            .await?;
        Ok(user)
    }

    /// Look up a user by username, returning the password hash too.
    pub async fn get_user_by_username(
        &self,
        username: String,
    ) -> anyhow::Result<Option<UserWithHash>> {
        let conn = self.conn.clone();
        let result = conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, username, is_active, created_at, updated_at, password_hash
                     FROM users WHERE username = ?1",
                )?;
                let mut rows = stmt.query(params![username])?;
                if let Some(row) = rows.next()? {
                    let user = row_to_user_with_hash(row)?;
                    Ok(Some(user))
                } else {
                    Ok(None)
                }
            })
            .await?;
        Ok(result)
    }

    /// Look up a user by id.
    pub async fn get_user_by_id(&self, user_id: i64) -> anyhow::Result<Option<User>> {
        let conn = self.conn.clone();
        let result = conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, username, is_active, created_at, updated_at
                     FROM users WHERE id = ?1",
                )?;
                let mut rows = stmt.query(params![user_id])?;
                if let Some(row) = rows.next()? {
                    Ok(Some(row_to_user(row)?))
                } else {
                    Ok(None)
                }
            })
            .await?;
        Ok(result)
    }

    /// Get all permissions for a user.
    pub async fn get_user_permissions(&self, user_id: i64) -> anyhow::Result<Vec<Permission>> {
        let conn = self.conn.clone();
        let perms = conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT permission FROM user_permissions WHERE user_id = ?1")?;
                let rows = stmt.query_map(params![user_id], |row| row.get::<_, String>(0))?;
                let mut perms = Vec::new();
                for r in rows {
                    let s = r?;
                    if let Some(p) = Permission::from_str(&s) {
                        perms.push(p);
                    }
                }
                Ok(perms)
            })
            .await?;
        Ok(perms)
    }

    /// List all users.
    pub async fn list_users(&self) -> anyhow::Result<Vec<User>> {
        let conn = self.conn.clone();
        let users = conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, username, is_active, created_at, updated_at
                     FROM users ORDER BY id",
                )?;
                let rows = stmt.query_map([], row_to_user)?;
                let mut users = Vec::new();
                for r in rows {
                    users.push(r?);
                }
                Ok(users)
            })
            .await?;
        Ok(users)
    }

    /// Update a user's is_active flag and replace their permissions.
    pub async fn update_user(
        &self,
        user_id: i64,
        is_active: bool,
        permissions: Vec<Permission>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        conn.call(move |conn| {
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "UPDATE users SET is_active = ?1, updated_at = ?2 WHERE id = ?3",
                params![is_active as i64, now, user_id],
            )?;

            conn.execute(
                "DELETE FROM user_permissions WHERE user_id = ?1",
                params![user_id],
            )?;
            for perm in &permissions {
                conn.execute(
                    "INSERT OR IGNORE INTO user_permissions (user_id, permission) VALUES (?1, ?2)",
                    params![user_id, perm.as_str()],
                )?;
            }
            Ok(())
        })
        .await?;
        Ok(())
    }

    /// Look up a user by id, returning the password hash too.
    pub async fn get_user_with_hash_by_id(
        &self,
        user_id: i64,
    ) -> anyhow::Result<Option<UserWithHash>> {
        let conn = self.conn.clone();
        let result = conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, username, is_active, created_at, updated_at, password_hash
                     FROM users WHERE id = ?1",
                )?;
                let mut rows = stmt.query(params![user_id])?;
                if let Some(row) = rows.next()? {
                    Ok(Some(row_to_user_with_hash(row)?))
                } else {
                    Ok(None)
                }
            })
            .await?;
        Ok(result)
    }

    /// Delete a user (cascades to permissions, sessions, api_tokens).
    pub async fn delete_user(&self, user_id: i64) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        conn.call(move |conn| {
            conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])?;
            Ok(())
        })
        .await?;
        Ok(())
    }

    /// Update the stored password hash for a user.
    pub async fn update_password(&self, user_id: i64, password_hash: String) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        conn.call(move |conn| {
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
                params![password_hash, now, user_id],
            )?;
            Ok(())
        })
        .await?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Sessions
    // -------------------------------------------------------------------------

    /// Create a new session expiring 24 h from now, and clean up expired sessions.
    pub async fn create_session(
        &self,
        token: String,
        user_id: i64,
        ip_address: Option<String>,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        conn.call(move |conn| {
            let now = Utc::now();
            let expires_at = (now + chrono::Duration::hours(24)).to_rfc3339();
            let now_str = now.to_rfc3339();

            // Clean up expired sessions first
            conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?1",
                params![now_str],
            )?;

            conn.execute(
                "INSERT INTO sessions (id, user_id, created_at, expires_at, ip_address)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![token, user_id, now_str, expires_at, ip_address],
            )?;
            Ok(())
        })
        .await?;
        Ok(())
    }

    /// Validate a session token. Returns the user_id if valid (not expired, user active).
    /// Applies sliding expiration: extends by 24 h, capped at 7 days from creation.
    pub async fn validate_session(&self, token: String) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.clone();
        let result = conn
            .call(move |conn| {
                let now = Utc::now();
                let now_str = now.to_rfc3339();

                // Fetch session + check user active
                let row = conn.query_row(
                    "SELECT s.user_id, s.created_at, s.expires_at
                     FROM sessions s
                     JOIN users u ON u.id = s.user_id
                     WHERE s.id = ?1 AND s.expires_at > ?2 AND u.is_active = 1",
                    params![token, now_str],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                );

                match row {
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    Ok((user_id, created_at_str, _expires_at_str)) => {
                        // Sliding expiry: now + 24h, but cap at created_at + 7d
                        let new_expires = now + chrono::Duration::hours(24);
                        let cap = chrono::DateTime::parse_from_rfc3339(&created_at_str)
                            .map(|dt| dt.with_timezone(&Utc) + chrono::Duration::days(7))
                            .unwrap_or(new_expires);
                        let final_expires = new_expires.min(cap);
                        let final_expires_str = final_expires.to_rfc3339();

                        conn.execute(
                            "UPDATE sessions SET expires_at = ?1 WHERE id = ?2",
                            params![final_expires_str, token],
                        )?;
                        Ok(Some(user_id))
                    }
                }
            })
            .await?;
        Ok(result)
    }

    /// Delete a session (logout).
    pub async fn delete_session(&self, token: String) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        conn.call(move |conn| {
            conn.execute("DELETE FROM sessions WHERE id = ?1", params![token])?;
            Ok(())
        })
        .await?;
        Ok(())
    }

    /// Delete all sessions for a user (used on password change/reset).
    pub async fn delete_sessions_for_user(&self, user_id: i64) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        conn.call(move |conn| {
            conn.execute("DELETE FROM sessions WHERE user_id = ?1", params![user_id])?;
            Ok(())
        })
        .await?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // API tokens
    // -------------------------------------------------------------------------

    /// Create an API token and return its new row id.
    pub async fn create_api_token(
        &self,
        user_id: i64,
        token_hash: String,
        name: String,
        permissions: Vec<Permission>,
        expires_at: Option<String>,
    ) -> anyhow::Result<i64> {
        let conn = self.conn.clone();
        let id = conn
            .call(move |conn| {
                let now = Utc::now().to_rfc3339();
                let perms_json = serde_json::to_string(
                    &permissions.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                )
                .unwrap_or_else(|_| "[]".to_string());

                conn.execute(
                    "INSERT INTO api_tokens (user_id, token_hash, name, permissions, created_at, last_used_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
                    params![user_id, token_hash, name, perms_json, now, expires_at],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await?;
        Ok(id)
    }

    /// Validate an API token by its hash. Returns (user_id, permissions) if valid.
    /// Updates last_used_at.
    pub async fn validate_api_token(
        &self,
        token_hash: String,
    ) -> anyhow::Result<Option<(i64, Vec<Permission>)>> {
        let conn = self.conn.clone();
        let result = conn
            .call(move |conn| {
                let now_str = Utc::now().to_rfc3339();

                let row = conn.query_row(
                    "SELECT t.id, t.user_id, t.permissions
                     FROM api_tokens t
                     JOIN users u ON u.id = t.user_id
                     WHERE t.token_hash = ?1
                       AND (t.expires_at IS NULL OR t.expires_at > ?2)
                       AND u.is_active = 1",
                    params![token_hash, now_str],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                );

                match row {
                    Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                    Err(e) => Err(tokio_rusqlite::Error::Rusqlite(e)),
                    Ok((token_id, user_id, perms_json)) => {
                        conn.execute(
                            "UPDATE api_tokens SET last_used_at = ?1 WHERE id = ?2",
                            params![now_str, token_id],
                        )?;

                        let perm_strings: Vec<String> =
                            serde_json::from_str(&perms_json).unwrap_or_default();
                        let perms = perm_strings
                            .iter()
                            .filter_map(|s| Permission::from_str(s))
                            .collect();

                        Ok(Some((user_id, perms)))
                    }
                }
            })
            .await?;
        Ok(result)
    }

    /// List all API tokens for a user (does not return hashes).
    pub async fn list_api_tokens(&self, user_id: i64) -> anyhow::Result<Vec<ApiTokenInfo>> {
        let conn = self.conn.clone();
        let tokens = conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, name, permissions, created_at, last_used_at, expires_at
                     FROM api_tokens WHERE user_id = ?1 ORDER BY id",
                )?;
                let rows = stmt.query_map(params![user_id], |row| {
                    let id: i64 = row.get(0)?;
                    let name: String = row.get(1)?;
                    let perms_json: String = row.get(2).unwrap_or_default();
                    let created_at: String = row.get(3).unwrap_or_default();
                    let last_used_at: Option<String> = row.get(4)?;
                    let expires_at: Option<String> = row.get(5)?;
                    Ok((id, name, perms_json, created_at, last_used_at, expires_at))
                })?;

                let mut tokens = Vec::new();
                for r in rows {
                    let (id, name, perms_json, created_at, last_used_at, expires_at) = r?;
                    let perm_strings: Vec<String> =
                        serde_json::from_str(&perms_json).unwrap_or_default();
                    let permissions = perm_strings
                        .iter()
                        .filter_map(|s| Permission::from_str(s))
                        .collect();
                    tokens.push(ApiTokenInfo {
                        id,
                        name,
                        permissions,
                        created_at,
                        last_used_at,
                        expires_at,
                    });
                }
                Ok(tokens)
            })
            .await?;
        Ok(tokens)
    }

    /// Delete an API token by id, scoped to the owning user. Returns true if deleted.
    pub async fn delete_api_token(&self, token_id: i64, user_id: i64) -> anyhow::Result<bool> {
        let conn = self.conn.clone();
        let count = conn
            .call(move |conn| {
                let n = conn.execute(
                    "DELETE FROM api_tokens WHERE id = ?1 AND user_id = ?2",
                    params![token_id, user_id],
                )?;
                Ok(n)
            })
            .await?;
        Ok(count > 0)
    }
}

// -------------------------------------------------------------------------
// Row helpers
// -------------------------------------------------------------------------

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let is_active: i64 = row.get(2)?;
    Ok(User {
        id: row.get(0)?,
        username: row.get(1)?,
        is_active: is_active != 0,
        created_at: row.get(3).unwrap_or_default(),
        updated_at: row.get(4).unwrap_or_default(),
    })
}

fn row_to_user_with_hash(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserWithHash> {
    let is_active: i64 = row.get(2)?;
    let user = User {
        id: row.get(0)?,
        username: row.get(1)?,
        is_active: is_active != 0,
        created_at: row.get(3).unwrap_or_default(),
        updated_at: row.get(4).unwrap_or_default(),
    };
    let password_hash: String = row.get(5)?;
    Ok(UserWithHash {
        user,
        password_hash,
    })
}
