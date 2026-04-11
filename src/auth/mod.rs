pub mod db;
pub mod middleware;
pub mod models;
pub mod password;

pub use models::{AuthenticatedUser, Permission, User};

use db::AuthDb;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Clone)]
pub struct AuthService {
    db: AuthDb,
}

impl AuthService {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let db = AuthDb::open(path).await?;
        Ok(Self { db })
    }

    pub async fn needs_setup(&self) -> bool {
        self.db.needs_setup().await.unwrap_or(false)
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        permissions: &[Permission],
    ) -> anyhow::Result<User> {
        if password.len() < 8 {
            anyhow::bail!("Password must be at least 8 characters");
        }
        let hash = password::hash_password(password)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
        self.db
            .create_user(username.to_string(), hash, permissions.to_vec())
            .await
    }

    /// Atomically create the first admin user during setup.
    /// Fails if any users already exist (race-safe).
    pub async fn setup_admin(
        &self,
        username: &str,
        password: &str,
        permissions: &[Permission],
    ) -> anyhow::Result<User> {
        if password.len() < 8 {
            anyhow::bail!("Password must be at least 8 characters");
        }
        let hash = password::hash_password(password)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
        self.db
            .create_first_user(username.to_string(), hash, permissions.to_vec())
            .await
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        ip_address: Option<&str>,
    ) -> anyhow::Result<String> {
        let user_with_hash = self
            .db
            .get_user_by_username(username.to_string())
            .await?
            .ok_or_else(|| anyhow::anyhow!("Invalid credentials"))?;

        if !user_with_hash.user.is_active {
            anyhow::bail!("Account is disabled");
        }

        if !password::verify_password(password, &user_with_hash.password_hash) {
            anyhow::bail!("Invalid credentials");
        }

        let token = generate_token();
        let token_hash = hash_token(&token);
        self.db
            .create_session(
                token_hash,
                user_with_hash.user.id,
                ip_address.map(|s| s.to_string()),
            )
            .await?;
        Ok(token)
    }

    pub async fn validate_session(&self, token: &str) -> Option<AuthenticatedUser> {
        let hash = hash_token(token);
        let user_id = self.db.validate_session(hash).await.ok()??;
        let user = self.db.get_user_by_id(user_id).await.ok()??;
        let permissions = self
            .db
            .get_user_permissions(user_id)
            .await
            .unwrap_or_default();
        Some(AuthenticatedUser {
            id: user.id,
            username: user.username,
            permissions,
        })
    }

    pub async fn validate_api_token(&self, token: &str) -> Option<AuthenticatedUser> {
        let hash = hash_token(token);
        let (user_id, scoped_permissions) = self.db.validate_api_token(hash).await.ok()??;
        let user = self.db.get_user_by_id(user_id).await.ok()??;
        Some(AuthenticatedUser {
            id: user.id,
            username: user.username,
            permissions: scoped_permissions,
        })
    }

    pub async fn logout(&self, token: &str) {
        let hash = hash_token(token);
        let _ = self.db.delete_session(hash).await;
    }

    pub async fn create_api_token(
        &self,
        user_id: i64,
        name: &str,
        permissions: &[Permission],
        expires_at: Option<&str>,
    ) -> anyhow::Result<String> {
        let plaintext = generate_token();
        let hash = hash_token(&plaintext);
        self.db
            .create_api_token(
                user_id,
                hash,
                name.to_string(),
                permissions.to_vec(),
                expires_at.map(|s| s.to_string()),
            )
            .await?;
        Ok(plaintext)
    }

    pub async fn list_api_tokens(&self, user_id: i64) -> Vec<models::ApiTokenInfo> {
        self.db.list_api_tokens(user_id).await.unwrap_or_default()
    }

    pub async fn revoke_api_token(&self, token_id: i64, user_id: i64) -> anyhow::Result<bool> {
        self.db.delete_api_token(token_id, user_id).await
    }

    pub async fn list_users(&self) -> Vec<User> {
        self.db.list_users().await.unwrap_or_default()
    }

    pub async fn get_user_permissions(&self, user_id: i64) -> Vec<Permission> {
        self.db
            .get_user_permissions(user_id)
            .await
            .unwrap_or_default()
    }

    pub async fn update_user(
        &self,
        user_id: i64,
        is_active: Option<bool>,
        permissions: Option<&[Permission]>,
    ) -> anyhow::Result<()> {
        // Fetch current values for fields not being updated
        let current_user = self
            .db
            .get_user_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;
        let current_permissions = self.db.get_user_permissions(user_id).await?;

        // The root user is immutable: no permission changes, no
        // deactivation. This guarantees the system always has one account
        // that can recover access.
        if current_user.is_root {
            if matches!(is_active, Some(false)) {
                anyhow::bail!("Cannot deactivate the root user");
            }
            if permissions.is_some() {
                anyhow::bail!("Cannot modify the root user's permissions");
            }
        }

        self.db
            .update_user(
                user_id,
                is_active.unwrap_or(current_user.is_active),
                permissions
                    .map(|p| p.to_vec())
                    .unwrap_or(current_permissions),
            )
            .await
    }

    pub async fn delete_user(&self, user_id: i64) -> anyhow::Result<()> {
        let target = self
            .db
            .get_user_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;
        if target.is_root {
            anyhow::bail!("Cannot delete the root user");
        }
        self.db.delete_user(user_id).await
    }

    pub async fn verify_password(&self, user_id: i64, password: &str) -> bool {
        let user_with_hash = match self.db.get_user_with_hash_by_id(user_id).await {
            Ok(Some(u)) => u,
            _ => return false,
        };
        password::verify_password(password, &user_with_hash.password_hash)
    }

    /// Reset another user's password (admin action). Used by the
    /// `ManageUsers` permission via `POST /api/users/{id}/reset-password`.
    /// This intentionally rejects the root account — otherwise any admin
    /// with `ManageUsers` could change root's password and log in as
    /// root, defeating the "root always exists" guarantee. Root must
    /// change its own password via `change_password_self`.
    pub async fn reset_password(&self, user_id: i64, new_password: &str) -> anyhow::Result<()> {
        let target = self
            .db
            .get_user_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found"))?;
        if target.is_root {
            anyhow::bail!(
                "Cannot reset the root user's password; the root user must change it themselves"
            );
        }
        self.set_password(user_id, new_password).await
    }

    /// Change the authenticated user's own password. Allowed for every
    /// user, including root — this is how root rotates its own password.
    pub async fn change_password_self(
        &self,
        user_id: i64,
        new_password: &str,
    ) -> anyhow::Result<()> {
        self.set_password(user_id, new_password).await
    }

    async fn set_password(&self, user_id: i64, new_password: &str) -> anyhow::Result<()> {
        if new_password.len() < 8 {
            anyhow::bail!("Password must be at least 8 characters");
        }
        let hash = password::hash_password(new_password)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
        self.db.update_password(user_id, hash).await?;
        self.db.delete_sessions_for_user(user_id).await?;
        Ok(())
    }
}

fn generate_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}
