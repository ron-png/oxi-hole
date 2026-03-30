use crate::auth::middleware::auth_middleware;
use crate::auth::{AuthService, AuthenticatedUser, Permission};
use crate::blocklist::BlocklistManager;
use crate::config::{BlockingMode, Config};
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use crate::update::UpdateChecker;
use axum::extract::{ConnectInfo, State};
use axum::http::header::SET_COOKIE;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub blocklist: BlocklistManager,
    pub stats: Stats,
    pub features: FeatureManager,
    pub upstream: UpstreamForwarder,
    pub auto_update: std::sync::Arc<tokio::sync::RwLock<bool>>,
    pub update_checker: UpdateChecker,
    pub update_status: std::sync::Arc<tokio::sync::RwLock<crate::update::UpdateStatus>>,
    pub blocklist_update_interval: std::sync::Arc<tokio::sync::RwLock<u64>>,
    pub blocking_mode: std::sync::Arc<tokio::sync::RwLock<BlockingMode>>,
    pub config_path: PathBuf,
    pub query_log: QueryLog,
    pub log_retention_days: std::sync::Arc<tokio::sync::RwLock<u32>>,
    pub anonymize_ip: std::sync::Arc<AtomicBool>,
    pub ipv6_enabled: std::sync::Arc<AtomicBool>,
    pub auth: AuthService,
}

impl AppState {
    /// Snapshot current runtime state and write it back to the config file.
    async fn save_config(&self) {
        // Load existing config to preserve fields we don't manage at runtime
        // (dns.listen, web.listen, tls paths, timeout_ms, etc.)
        let mut config = match Config::load(&self.config_path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to load config for save: {}", e);
                return;
            }
        };

        config.dns.upstreams = self.upstream.get_upstream_labels();
        config.blocking.enabled = self.blocklist.is_enabled().await;
        config.blocking.blocklists = self.blocklist.get_sources().await;
        config.blocking.custom_blocked = self.blocklist.get_custom_blocked().await;
        config.blocking.allowlist = self.blocklist.get_allowlist().await;
        config.blocking.update_interval_minutes = *self.blocklist_update_interval.read().await;
        config.blocking.enabled_features = self
            .features
            .get_features()
            .await
            .into_iter()
            .filter(|f| f.enabled)
            .map(|f| f.id)
            .collect();
        config.system.auto_update = *self.auto_update.read().await;
        config.system.ipv6_enabled = self.ipv6_enabled.load(std::sync::atomic::Ordering::Relaxed);
        config.blocking.blocking_mode = self.blocking_mode.read().await.clone();
        config.log.retention_days = *self.log_retention_days.read().await;
        config.log.anonymize_client_ip =
            self.anonymize_ip.load(std::sync::atomic::Ordering::Relaxed);

        if let Err(e) = config.save(&self.config_path) {
            tracing::warn!("Failed to save config: {}", e);
        }
    }
}

pub async fn run_web_server(listen: &[String], state: AppState) -> anyhow::Result<()> {
    let auth_for_middleware = state.auth.clone();
    let app = Router::new()
        // Auth pages (public)
        .route("/login", get(login_page))
        .route("/setup", get(setup_page))
        // Auth API
        .route("/api/auth/login", post(api_auth_login))
        .route("/api/auth/setup", post(api_auth_setup))
        .route("/api/auth/logout", post(api_auth_logout))
        .route("/api/auth/me", get(api_auth_me))
        .route("/api/auth/change-password", post(api_change_password))
        // User management
        .route("/api/users", get(api_list_users).post(api_create_user))
        .route(
            "/api/users/{id}",
            axum::routing::put(api_update_user).delete(api_delete_user),
        )
        .route("/api/users/{id}/reset-password", post(api_reset_password))
        // API tokens
        .route("/api/tokens", get(api_list_tokens).post(api_create_token))
        .route("/api/tokens/{id}", axum::routing::delete(api_revoke_token))
        // Dashboard
        .route("/", get(dashboard))
        // Stats
        .route("/api/stats", get(api_stats))
        .route("/api/queries", get(api_queries))
        // Master blocking
        .route("/api/blocking", get(api_blocking_status))
        .route("/api/blocking/enable", post(api_enable_blocking))
        .route("/api/blocking/disable", post(api_disable_blocking))
        // Feature toggles
        .route("/api/features", get(api_features))
        .route("/api/features/{id}", post(api_toggle_feature))
        // Domain management
        .route("/api/blocklist/custom", get(api_custom_blocked))
        .route("/api/blocklist/add", post(api_add_blocked))
        .route("/api/blocklist/remove", post(api_remove_blocked))
        .route("/api/allowlist", get(api_get_allowlist))
        .route("/api/allowlist/add", post(api_add_allowlisted))
        .route("/api/allowlist/remove", post(api_remove_allowlisted))
        // Blocklist source management
        .route("/api/blocklist-sources", get(api_blocklist_sources))
        .route("/api/blocklist-source/add", post(api_add_blocklist_source))
        .route(
            "/api/blocklist-source/remove",
            post(api_remove_blocklist_source),
        )
        // Blocklist refresh
        .route(
            "/api/blocklist-sources/refresh",
            get(api_blocklist_refresh_sse),
        )
        .route(
            "/api/blocklist-sources/last-refresh",
            get(api_blocklist_last_refresh),
        )
        // Upstream info
        .route("/api/upstreams", get(api_upstreams))
        .route("/api/upstreams/add", post(api_add_upstream))
        .route("/api/upstreams/remove", post(api_remove_upstream))
        // System settings
        .route("/api/system/auto-update", get(api_get_auto_update))
        .route("/api/system/auto-update", post(api_set_auto_update))
        .route("/api/system/ipv6", get(api_get_ipv6))
        .route("/api/system/ipv6", post(api_set_ipv6))
        // Blocklist update interval
        .route(
            "/api/system/blocklist-interval",
            get(api_get_blocklist_interval),
        )
        .route(
            "/api/system/blocklist-interval",
            post(api_set_blocklist_interval),
        )
        // Blocking mode
        .route("/api/blocking/mode", get(api_get_blocking_mode))
        .route("/api/blocking/mode", post(api_set_blocking_mode))
        // Cache stats and flush
        .route("/api/cache/stats", get(api_cache_stats))
        .route("/api/cache/flush", post(api_cache_flush))
        // Version / update
        .route("/api/system/version", get(api_version))
        .route("/api/system/version/check", post(api_version_check))
        .route("/api/system/update", post(api_perform_update))
        .route("/api/system/restart", post(api_restart))
        .route("/api/system/update/status", get(api_update_status))
        .route(
            "/api/system/update/status/dismiss",
            post(api_dismiss_update_status),
        )
        // Query log
        .route("/api/logs", get(api_logs))
        .route("/api/logs/settings", get(api_get_log_settings))
        .route("/api/logs/settings", post(api_set_log_settings))
        // Auth middleware (after all routes, before state)
        .layer(axum::middleware::from_fn_with_state(
            auth_for_middleware,
            auth_middleware,
        ))
        .with_state(state);

    let mut handles = Vec::new();
    for addr in listen {
        let app = app.clone();
        let sock_addr: std::net::SocketAddr = addr.parse()?;
        let domain = if sock_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&sock_addr.into())?;
        socket.listen(1024)?;
        let listener = tokio::net::TcpListener::from_std(socket.into())?;
        let addr = addr.clone();
        info!("Web admin listening on {}", addr);
        handles.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            {
                tracing::error!("Web server error on {}: {}", addr, e);
            }
        }));
    }

    futures::future::join_all(handles).await;
    Ok(())
}

// ==================== Auth Error Response ====================

#[derive(Serialize)]
struct AuthErrorResponse {
    error: String,
}

#[allow(clippy::result_large_err)]
fn require_permission(user: &AuthenticatedUser, perm: Permission) -> Result<(), Response> {
    if user.has_permission(perm) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(AuthErrorResponse {
                error: "Insufficient permissions".to_string(),
            }),
        )
            .into_response())
    }
}

// ==================== Auth Pages ====================

async fn login_page() -> Html<&'static str> {
    Html(include_str!("login.html"))
}

async fn setup_page() -> Html<&'static str> {
    Html(include_str!("setup.html"))
}

// ==================== Auth API ====================

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn api_auth_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Response {
    let ip = addr.ip().to_string();
    match state
        .auth
        .authenticate(&req.username, &req.password, Some(&ip))
        .await
    {
        Ok(session_token) => {
            let cookie = format!(
                "oxi_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800; Secure",
                session_token
            );
            (
                StatusCode::OK,
                [(SET_COOKIE, cookie)],
                Json(serde_json::json!({"success": true})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn api_auth_setup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginRequest>,
) -> Response {
    let all_permissions: Vec<Permission> = Permission::ALL.to_vec();
    match state
        .auth
        .setup_admin(&req.username, &req.password, &all_permissions)
        .await
    {
        Ok(_user) => {
            // Log them in immediately
            let ip = addr.ip().to_string();
            match state
                .auth
                .authenticate(&req.username, &req.password, Some(&ip))
                .await
            {
                Ok(session_token) => {
                    let cookie = format!(
                        "oxi_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800; Secure",
                        session_token
                    );
                    (
                        StatusCode::OK,
                        [(SET_COOKIE, cookie)],
                        Json(serde_json::json!({"success": true})),
                    )
                        .into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuthErrorResponse {
                        error: format!("User created but login failed: {}", e),
                    }),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

async fn api_auth_logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Extract session token from cookie
    if let Some(cookie_header) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for pair in cookie_str.split(';') {
                let pair = pair.trim();
                if let Some(value) = pair.strip_prefix("oxi_session=") {
                    state.auth.logout(value).await;
                }
            }
        }
    }

    let cookie = "oxi_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0; Secure";
    (
        StatusCode::OK,
        [(SET_COOKIE, cookie)],
        Json(serde_json::json!({"success": true})),
    )
        .into_response()
}

async fn api_auth_me(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Json<AuthenticatedUser> {
    Json(user)
}

// ==================== User Management ====================

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    #[serde(default)]
    permissions: Vec<Permission>,
}

#[derive(Deserialize)]
struct UpdateUserRequest {
    #[serde(default)]
    is_active: Option<bool>,
    #[serde(default)]
    permissions: Option<Vec<Permission>>,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct ResetPasswordRequest {
    password: String,
}

#[derive(Serialize)]
struct UserWithPermissions {
    #[serde(flatten)]
    user: crate::auth::User,
    permissions: Vec<Permission>,
}

async fn api_list_users(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Json<Vec<UserWithPermissions>>, Response> {
    require_permission(&user, Permission::ManageUsers)?;
    let users = state.auth.list_users().await;
    let mut result = Vec::new();
    for u in users {
        let perms = state.auth.get_user_permissions(u.id).await;
        result.push(UserWithPermissions {
            user: u,
            permissions: perms,
        });
    }
    Ok(Json(result))
}

async fn api_create_user(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<crate::auth::User>, Response> {
    require_permission(&user, Permission::ManageUsers)?;

    // Cannot grant permissions you don't have
    for perm in &req.permissions {
        if !user.has_permission(*perm) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(AuthErrorResponse {
                    error: format!("Cannot grant permission {:?} that you don't have", perm),
                }),
            )
                .into_response());
        }
    }

    match state
        .auth
        .create_user(&req.username, &req.password, &req.permissions)
        .await
    {
        Ok(new_user) => Ok(Json(new_user)),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response()),
    }
}

async fn api_update_user(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageUsers)?;

    // Cannot deactivate your own account
    if id == user.id {
        if req.is_active == Some(false) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(AuthErrorResponse {
                    error: "Cannot deactivate your own account".to_string(),
                }),
            )
                .into_response());
        }
        if let Some(ref perms) = req.permissions {
            if !perms.contains(&Permission::ManageUsers) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(AuthErrorResponse {
                        error: "Cannot remove your own ManageUsers permission".to_string(),
                    }),
                )
                    .into_response());
            }
        }
    }

    // Cannot grant permissions you don't have
    if let Some(ref perms) = req.permissions {
        for perm in perms {
            if !user.has_permission(*perm) {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(AuthErrorResponse {
                        error: format!("Cannot grant permission {:?} that you don't have", perm),
                    }),
                )
                    .into_response());
            }
        }
    }

    match state
        .auth
        .update_user(id, req.is_active, req.permissions.as_deref())
        .await
    {
        Ok(()) => Ok(StatusCode::OK),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response()),
    }
}

async fn api_delete_user(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageUsers)?;

    if id == user.id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(AuthErrorResponse {
                error: "Cannot delete yourself".to_string(),
            }),
        )
            .into_response());
    }

    match state.auth.delete_user(id).await {
        Ok(()) => Ok(StatusCode::OK),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response()),
    }
}

async fn api_reset_password(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageUsers)?;

    match state.auth.reset_password(id, &req.password).await {
        Ok(()) => Ok(StatusCode::OK),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response()),
    }
}

async fn api_change_password(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, Response> {
    if !state
        .auth
        .verify_password(user.id, &req.current_password)
        .await
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(AuthErrorResponse {
                error: "Current password is incorrect".to_string(),
            }),
        )
            .into_response());
    }

    match state.auth.reset_password(user.id, &req.new_password).await {
        Ok(()) => Ok(StatusCode::OK),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response()),
    }
}

// ==================== API Tokens ====================

#[derive(Deserialize)]
struct CreateTokenRequest {
    name: String,
    #[serde(default)]
    permissions: Vec<Permission>,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    token: String,
}

async fn api_list_tokens(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Json<Vec<crate::auth::models::ApiTokenInfo>> {
    Json(state.auth.list_api_tokens(user.id).await)
}

async fn api_create_token(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>, Response> {
    // Cannot grant permissions you don't have
    for perm in &req.permissions {
        if !user.has_permission(*perm) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(AuthErrorResponse {
                    error: format!("Cannot grant permission {:?} that you don't have", perm),
                }),
            )
                .into_response());
        }
    }

    match state
        .auth
        .create_api_token(
            user.id,
            &req.name,
            &req.permissions,
            req.expires_at.as_deref(),
        )
        .await
    {
        Ok(token) => Ok(Json(CreateTokenResponse { token })),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response()),
    }
}

async fn api_revoke_token(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<StatusCode, Response> {
    match state.auth.revoke_api_token(id, user.id).await {
        Ok(true) => Ok(StatusCode::OK),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(AuthErrorResponse {
                error: "Token not found".to_string(),
            }),
        )
            .into_response()),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response()),
    }
}

// ==================== Dashboard ====================

async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

// ==================== Stats ====================

#[derive(Serialize)]
struct StatsResponse {
    total_queries: u64,
    blocked_queries: u64,
    block_percentage: f64,
    blocklist_size: usize,
    blocking_enabled: bool,
}

async fn api_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    Json(StatsResponse {
        total_queries: state.stats.total_queries(),
        blocked_queries: state.stats.blocked_queries(),
        block_percentage: state.stats.block_percentage(),
        blocklist_size: state.blocklist.blocked_count().await,
        blocking_enabled: state.blocklist.is_enabled().await,
    })
}

async fn api_queries(State(state): State<AppState>) -> Json<Vec<crate::stats::QueryLogEntry>> {
    Json(state.stats.recent_queries(200).await)
}

// ==================== Master Blocking ====================

#[derive(Serialize)]
struct BlockingStatus {
    enabled: bool,
}

async fn api_blocking_status(State(state): State<AppState>) -> Json<BlockingStatus> {
    Json(BlockingStatus {
        enabled: state.blocklist.is_enabled().await,
    })
}

async fn api_enable_blocking(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageFeatures)?;
    state.blocklist.set_enabled(true).await;
    info!("Blocking enabled via web API");
    state.save_config().await;
    Ok(StatusCode::OK)
}

async fn api_disable_blocking(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageFeatures)?;
    state.blocklist.set_enabled(false).await;
    info!("Blocking disabled via web API");
    state.save_config().await;
    Ok(StatusCode::OK)
}

// ==================== Blocking Mode ====================

#[derive(Serialize)]
struct BlockingModeResponse {
    mode: String,
    custom_ipv4: Option<String>,
    custom_ipv6: Option<String>,
}

async fn api_get_blocking_mode(State(state): State<AppState>) -> Json<BlockingModeResponse> {
    let mode = state.blocking_mode.read().await;
    let (mode_str, ipv4, ipv6) = match &*mode {
        BlockingMode::Default => ("default".to_string(), None, None),
        BlockingMode::Refused => ("refused".to_string(), None, None),
        BlockingMode::NxDomain => ("nxdomain".to_string(), None, None),
        BlockingMode::NullIp => ("null_ip".to_string(), None, None),
        BlockingMode::CustomIp { ipv4, ipv6 } => (
            "custom_ip".to_string(),
            Some(ipv4.to_string()),
            Some(ipv6.to_string()),
        ),
    };
    Json(BlockingModeResponse {
        mode: mode_str,
        custom_ipv4: ipv4,
        custom_ipv6: ipv6,
    })
}

#[derive(Deserialize)]
struct BlockingModeRequest {
    mode: String,
    #[serde(default)]
    custom_ipv4: Option<String>,
    #[serde(default)]
    custom_ipv6: Option<String>,
}

async fn api_set_blocking_mode(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<BlockingModeRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    let new_mode = match req.mode.as_str() {
        "default" => BlockingMode::Default,
        "refused" => BlockingMode::Refused,
        "nxdomain" => BlockingMode::NxDomain,
        "null_ip" => BlockingMode::NullIp,
        "custom_ip" => {
            let ipv4 = req
                .custom_ipv4
                .as_deref()
                .unwrap_or("0.0.0.0")
                .parse()
                .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());
            let ipv6 = req
                .custom_ipv6
                .as_deref()
                .unwrap_or("::")
                .parse()
                .unwrap_or_else(|_| "::".parse().unwrap());
            BlockingMode::CustomIp { ipv4, ipv6 }
        }
        _ => return Ok(StatusCode::BAD_REQUEST),
    };
    info!("Blocking mode set to {}", new_mode);
    *state.blocking_mode.write().await = new_mode;
    state.save_config().await;
    Ok(StatusCode::OK)
}

// ==================== Cache Stats & Flush ====================

#[derive(Serialize)]
struct CacheStatsResponse {
    size: usize,
    hits: u64,
    misses: u64,
    hit_rate: f64,
}

async fn api_cache_stats(State(state): State<AppState>) -> Json<CacheStatsResponse> {
    let (size, hits, misses) = state.upstream.cache_stats();
    let total = hits + misses;
    let hit_rate = if total > 0 {
        hits as f64 / total as f64
    } else {
        0.0
    };
    Json(CacheStatsResponse {
        size,
        hits,
        misses,
        hit_rate,
    })
}

async fn api_cache_flush(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    state.upstream.cache_flush();
    info!("DNS cache flushed via API");
    Ok(StatusCode::OK)
}

// ==================== Features ====================

async fn api_features(
    State(state): State<AppState>,
) -> Json<Vec<crate::features::FeatureDefinition>> {
    Json(state.features.get_features().await)
}

#[derive(Deserialize)]
struct FeatureToggleRequest {
    enabled: bool,
}

async fn api_toggle_feature(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<FeatureToggleRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageFeatures)?;
    state.features.set_feature(&id, req.enabled).await;
    state.save_config().await;
    Ok(StatusCode::OK)
}

// ==================== Domain Management ====================

#[derive(Deserialize)]
struct DomainRequest {
    domain: String,
}

async fn api_custom_blocked(State(state): State<AppState>) -> Json<Vec<String>> {
    let mut domains = state.blocklist.get_custom_blocked().await;
    domains.sort();
    Json(domains)
}

async fn api_get_allowlist(State(state): State<AppState>) -> Json<Vec<String>> {
    let mut domains = state.blocklist.get_allowlist().await;
    domains.sort();
    Json(domains)
}

async fn api_add_blocked(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageBlocklists)?;
    state.blocklist.add_custom_blocked(&req.domain).await;
    info!("Added {} to blocklist via web API", req.domain);
    state.save_config().await;
    Ok(StatusCode::OK)
}

async fn api_remove_blocked(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageBlocklists)?;
    state.blocklist.remove_custom_blocked(&req.domain).await;
    info!("Removed {} from blocklist via web API", req.domain);
    state.save_config().await;
    Ok(StatusCode::OK)
}

async fn api_add_allowlisted(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageAllowlist)?;
    state.blocklist.add_allowlisted(&req.domain).await;
    info!("Added {} to allowlist via web API", req.domain);
    state.save_config().await;
    Ok(StatusCode::OK)
}

async fn api_remove_allowlisted(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageAllowlist)?;
    state.blocklist.remove_allowlisted(&req.domain).await;
    info!("Removed {} from allowlist via web API", req.domain);
    state.save_config().await;
    Ok(StatusCode::OK)
}

// ==================== Blocklist Sources ====================

async fn api_blocklist_sources(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(state.blocklist.get_sources().await)
}

#[derive(Deserialize)]
struct UrlRequest {
    url: String,
}

#[derive(Serialize)]
struct BlocklistAddResponse {
    success: bool,
    message: String,
}

async fn api_add_blocklist_source(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<UrlRequest>,
) -> Result<Json<BlocklistAddResponse>, Response> {
    require_permission(&user, Permission::ManageBlocklists)?;
    match state.blocklist.add_blocklist_source(&req.url).await {
        Ok(count) => {
            info!("Added blocklist source: {} ({} entries)", req.url, count);
            state.save_config().await;
            Ok(Json(BlocklistAddResponse {
                success: true,
                message: format!("Loaded {} domains", count),
            }))
        }
        Err(e) => Ok(Json(BlocklistAddResponse {
            success: false,
            message: e,
        })),
    }
}

async fn api_remove_blocklist_source(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<UrlRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageBlocklists)?;
    state.blocklist.remove_blocklist_source(&req.url).await;
    info!("Removed blocklist source: {}", req.url);
    state.save_config().await;
    Ok(StatusCode::OK)
}

// ==================== Blocklist Refresh ====================

#[derive(Serialize)]
struct LastRefreshResponse {
    refreshed_at: Option<String>,
}

async fn api_blocklist_last_refresh(State(state): State<AppState>) -> Json<LastRefreshResponse> {
    let ts = state.blocklist.get_last_refreshed_at().await;
    Json(LastRefreshResponse {
        refreshed_at: ts.map(|t| t.to_rfc3339()),
    })
}

async fn api_blocklist_refresh_sse(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, Response> {
    require_permission(&user, Permission::ManageBlocklists)?;
    // Acquire the refresh lock before spawning to avoid TOCTOU race
    if !state.blocklist.try_start_refresh() {
        return Err(StatusCode::CONFLICT.into_response());
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::blocklist::RefreshEvent>(32);
    let blocklist = state.blocklist.clone();

    tokio::spawn(async move {
        blocklist.refresh_sources_streaming(tx).await;
    });

    let stream = async_stream::stream! {
        while let Some(event) = rx.recv().await {
            let event_type = match &event {
                crate::blocklist::RefreshEvent::Progress { .. } => "progress",
                crate::blocklist::RefreshEvent::Done { .. } => "done",
            };
            let data = serde_json::to_string(&event).unwrap_or_default();
            yield Ok(Event::default().event(event_type).data(data));
        }
    };

    Ok(Sse::new(stream))
}

// ==================== Upstreams ====================

async fn api_upstreams(State(state): State<AppState>) -> Json<Vec<String>> {
    Json(state.upstream.get_upstream_labels())
}

#[derive(Deserialize)]
struct UpstreamRequest {
    upstream: String,
}

async fn api_add_upstream(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<UpstreamRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageUpstreams)?;
    match state.upstream.add_upstream(&req.upstream).await {
        Ok(_) => {
            info!("Added upstream: {}", req.upstream);
            state.save_config().await;
            Ok(StatusCode::OK)
        }
        Err(e) => {
            tracing::warn!("Invalid upstream '{}': {}", req.upstream, e);
            Ok(StatusCode::BAD_REQUEST)
        }
    }
}

async fn api_remove_upstream(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<UpstreamRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageUpstreams)?;
    if state.upstream.remove_upstream(&req.upstream) {
        state.save_config().await;
        Ok(StatusCode::OK)
    } else {
        Ok(StatusCode::NOT_FOUND)
    }
}

// ==================== System Settings ====================

#[derive(Serialize)]
struct AutoUpdateStatus {
    enabled: bool,
}

async fn api_get_auto_update(State(state): State<AppState>) -> Json<AutoUpdateStatus> {
    let enabled = *state.auto_update.read().await;
    Json(AutoUpdateStatus { enabled })
}

#[derive(Deserialize)]
struct AutoUpdateRequest {
    enabled: bool,
}

async fn api_set_auto_update(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<AutoUpdateRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    *state.auto_update.write().await = req.enabled;
    tracing::info!("Auto-update set to {}", req.enabled);
    state.save_config().await;
    Ok(StatusCode::OK)
}

// ==================== IPv6 (AAAA) Toggle ====================

#[derive(Serialize)]
struct Ipv6Status {
    enabled: bool,
}

async fn api_get_ipv6(State(state): State<AppState>) -> Json<Ipv6Status> {
    let enabled = state
        .ipv6_enabled
        .load(std::sync::atomic::Ordering::Relaxed);
    Json(Ipv6Status { enabled })
}

#[derive(Deserialize)]
struct Ipv6Request {
    enabled: bool,
}

async fn api_set_ipv6(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<Ipv6Request>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    state
        .ipv6_enabled
        .store(req.enabled, std::sync::atomic::Ordering::Relaxed);
    tracing::info!("IPv6 (AAAA) set to {}", req.enabled);
    state.save_config().await;
    Ok(StatusCode::OK)
}

// ==================== Blocklist Update Interval ====================

#[derive(Serialize)]
struct BlocklistIntervalResponse {
    interval_minutes: u64,
}

async fn api_get_blocklist_interval(
    State(state): State<AppState>,
) -> Json<BlocklistIntervalResponse> {
    let interval = *state.blocklist_update_interval.read().await;
    Json(BlocklistIntervalResponse {
        interval_minutes: interval,
    })
}

#[derive(Deserialize)]
struct BlocklistIntervalRequest {
    interval_minutes: u64,
}

async fn api_set_blocklist_interval(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<BlocklistIntervalRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    *state.blocklist_update_interval.write().await = req.interval_minutes;
    tracing::info!(
        "Blocklist update interval set to {} minutes",
        req.interval_minutes
    );
    state.save_config().await;
    Ok(StatusCode::OK)
}

// ==================== Version / Update ====================

async fn api_version(
    axum::Extension(_user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Json<crate::update::VersionInfo> {
    Json(state.update_checker.check(false).await)
}

async fn api_version_check(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Json<crate::update::VersionInfo>, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    Ok(Json(state.update_checker.check(true).await))
}

#[derive(Serialize)]
struct UpdateResponse {
    success: bool,
    message: String,
}

async fn api_perform_update(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Json<UpdateResponse>, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    api_perform_update_inner(state).await
}

async fn api_perform_update_inner(state: AppState) -> Result<Json<UpdateResponse>, Response> {
    // Check if an update is already in progress
    {
        let s = state.update_status.read().await;
        if s.state != crate::update::UpdateState::Idle
            && s.state != crate::update::UpdateState::Failed
        {
            return Ok(Json(UpdateResponse {
                success: false,
                message: "An update is already in progress".to_string(),
            }));
        }
    }

    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return Ok(Json(UpdateResponse {
                success: false,
                message: format!("Cannot determine current binary: {}", e),
            }));
        }
    };

    // Spawn the robust update pipeline as a background task.
    // The UI polls /api/system/update/status to track progress.
    let update_checker = state.update_checker.clone();
    let update_status = state.update_status.clone();
    let config_path = state.config_path.clone();
    tokio::spawn(async move {
        crate::update::perform_robust_update(
            &update_checker,
            &update_status,
            &config_path,
            &current_exe,
        )
        .await;
    });

    Ok(Json(UpdateResponse {
        success: true,
        message: "Update started — health-checking and restarting automatically".to_string(),
    }))
}

async fn api_restart(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    info!("Restart requested via web API");
    // Spawn a short delay so the HTTP response can be sent before we exit.
    // The service manager (systemd Restart=always) will restart the process.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });
    Ok(StatusCode::OK)
}

// ==================== Update Status ====================

async fn api_update_status(State(state): State<AppState>) -> Json<crate::update::UpdateStatus> {
    let status = state.update_status.read().await;
    Json(status.to_serializable())
}

async fn api_dismiss_update_status(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    let mut status = state.update_status.write().await;
    *status = crate::update::UpdateStatus::default();
    Ok(StatusCode::OK)
}

// ==================== Query Log ====================

#[derive(Deserialize)]
struct LogsQueryParams {
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    before_id: Option<i64>,
    #[serde(default = "default_log_limit")]
    limit: Option<usize>,
}

fn default_log_limit() -> Option<usize> {
    Some(100)
}

async fn api_logs(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<LogsQueryParams>,
) -> Result<Json<crate::query_log::LogPage>, Response> {
    require_permission(&user, Permission::ViewLogs)?;
    let query_params = crate::query_log::LogQueryParams {
        search: params.search,
        status: params.status,
        before_id: params.before_id,
        limit: params.limit.unwrap_or(100),
    };

    match state.query_log.search(query_params).await {
        Ok(page) => Ok(Json(page)),
        Err(e) => {
            tracing::error!("Log query failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

#[derive(Serialize)]
struct LogSettingsResponse {
    retention_days: u32,
    anonymize_client_ip: bool,
}

async fn api_get_log_settings(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Json<LogSettingsResponse>, Response> {
    require_permission(&user, Permission::ViewLogs)?;
    Ok(Json(LogSettingsResponse {
        retention_days: *state.log_retention_days.read().await,
        anonymize_client_ip: state
            .anonymize_ip
            .load(std::sync::atomic::Ordering::Relaxed),
    }))
}

#[derive(Deserialize)]
struct LogSettingsRequest {
    #[serde(default)]
    retention_days: Option<u32>,
    #[serde(default)]
    anonymize_client_ip: Option<bool>,
}

async fn api_set_log_settings(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<LogSettingsRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    if let Some(days) = req.retention_days {
        let clamped = days.clamp(1, 90);
        *state.log_retention_days.write().await = clamped;
        info!("Log retention set to {} days", clamped);
    }
    if let Some(anonymize) = req.anonymize_client_ip {
        state
            .anonymize_ip
            .store(anonymize, std::sync::atomic::Ordering::Relaxed);
        info!("Client IP anonymization set to {}", anonymize);
    }
    state.save_config().await;
    Ok(StatusCode::OK)
}
