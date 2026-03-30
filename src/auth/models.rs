use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ViewStats,
    ViewLogs,
    ManageFeatures,
    ManageBlocklists,
    ManageAllowlist,
    ManageUpstreams,
    ManageSystem,
    ManageUsers,
    ManageApiTokens,
}

impl Permission {
    pub const ALL: &[Permission] = &[
        Permission::ViewStats,
        Permission::ViewLogs,
        Permission::ManageFeatures,
        Permission::ManageBlocklists,
        Permission::ManageAllowlist,
        Permission::ManageUpstreams,
        Permission::ManageSystem,
        Permission::ManageUsers,
        Permission::ManageApiTokens,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::ViewStats => "view_stats",
            Permission::ViewLogs => "view_logs",
            Permission::ManageFeatures => "manage_features",
            Permission::ManageBlocklists => "manage_blocklists",
            Permission::ManageAllowlist => "manage_allowlist",
            Permission::ManageUpstreams => "manage_upstreams",
            Permission::ManageSystem => "manage_system",
            Permission::ManageUsers => "manage_users",
            Permission::ManageApiTokens => "manage_api_tokens",
        }
    }

    pub fn from_str(s: &str) -> Option<Permission> {
        match s {
            "view_stats" => Some(Permission::ViewStats),
            "view_logs" => Some(Permission::ViewLogs),
            "manage_features" => Some(Permission::ManageFeatures),
            "manage_blocklists" => Some(Permission::ManageBlocklists),
            "manage_allowlist" => Some(Permission::ManageAllowlist),
            "manage_upstreams" => Some(Permission::ManageUpstreams),
            "manage_system" => Some(Permission::ManageSystem),
            "manage_users" => Some(Permission::ManageUsers),
            "manage_api_tokens" => Some(Permission::ManageApiTokens),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct UserWithHash {
    pub user: User,
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthenticatedUser {
    pub id: i64,
    pub username: String,
    pub permissions: Vec<Permission>,
}

impl AuthenticatedUser {
    pub fn has_permission(&self, perm: Permission) -> bool {
        self.permissions.contains(&perm)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiTokenInfo {
    pub id: i64,
    pub name: String,
    pub permissions: Vec<Permission>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
}
