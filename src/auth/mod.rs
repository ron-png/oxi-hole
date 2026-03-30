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
        display_name: Option<&str>,
        permissions: &[Permission],
    ) -> anyhow::Result<User> {
        let hash = password::hash_password(password)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
        self.db
            .create_user(
                username.to_string(),
                hash,
                display_name.map(|s| s.to_string()),
                permissions.to_vec(),
            )
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
        self.db
            .create_session(token.clone(), user_with_hash.user.id, ip_address.map(|s| s.to_string()))
            .await?;
        Ok(token)
    }

    pub async fn validate_session(&self, token: &str) -> Option<AuthenticatedUser> {
        let user_id = self.db.validate_session(token.to_string()).await.ok()??;
        let user = self.db.get_user_by_id(user_id).await.ok()??;
        let permissions = self.db.get_user_permissions(user_id).await.unwrap_or_default();
        Some(AuthenticatedUser {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            permissions,
        })
    }

    pub async fn validate_api_token(&self, token: &str) -> Option<AuthenticatedUser> {
        let hash = hash_token(token);
        let (user_id, scoped_permissions) = self
            .db
            .validate_api_token(hash)
            .await
            .ok()??;
        let user = self.db.get_user_by_id(user_id).await.ok()??;
        Some(AuthenticatedUser {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            permissions: scoped_permissions,
        })
    }

    pub async fn logout(&self, token: &str) {
        let _ = self.db.delete_session(token.to_string()).await;
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
        self.db.get_user_permissions(user_id).await.unwrap_or_default()
    }

    pub async fn update_user(
        &self,
        user_id: i64,
        display_name: Option<&str>,
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

        self.db
            .update_user(
                user_id,
                display_name
                    .map(|s| s.to_string())
                    .or(current_user.display_name),
                is_active.unwrap_or(current_user.is_active),
                permissions.map(|p| p.to_vec()).unwrap_or(current_permissions),
            )
            .await
    }

    pub async fn delete_user(&self, user_id: i64) -> anyhow::Result<()> {
        self.db.delete_user(user_id).await
    }

    pub async fn reset_password(&self, user_id: i64, new_password: &str) -> anyhow::Result<()> {
        let hash = password::hash_password(new_password)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
        self.db.update_password(user_id, hash).await
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
