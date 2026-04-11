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
use dashmap::DashMap;
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use tower_service::Service;
use tracing::{info, warn};

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
    pub auth_rate_limiter: RateLimiter,
    pub admin_rate_limiter: RateLimiter,
    pub restart_signal: tokio::sync::watch::Sender<bool>,
    pub release_channel: std::sync::Arc<tokio::sync::RwLock<String>>,
    pub update_check_signal: tokio::sync::watch::Sender<bool>,
    pub persistent_stats: crate::persistent_stats::PersistentStats,
    pub stats_retention_days: std::sync::Arc<tokio::sync::RwLock<u32>>,
    pub acme: std::sync::Arc<crate::acme::AcmeState>,
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
        config.log.query_log_retention_days = *self.log_retention_days.read().await;
        config.log.stats_retention_days = *self.stats_retention_days.read().await;
        config.log.anonymize_client_ip =
            self.anonymize_ip.load(std::sync::atomic::Ordering::Relaxed);
        config.system.release_channel = self.release_channel.read().await.clone();

        if let Err(e) = config.save(&self.config_path) {
            tracing::warn!("Failed to save config: {}", e);
        }
    }
}

#[derive(Clone)]
struct IsHttps;

// ==================== Security Headers Middleware ====================

async fn security_headers_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Check if this is an HTTPS request (set by HTTPS middleware layer)
    let is_https = request.extensions().get::<IsHttps>().is_some();

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(axum::http::header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            .parse()
            .unwrap(),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=()".parse().unwrap(),
    );

    if is_https {
        headers.insert(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }

    response
}

// ==================== Rate Limiter ====================

#[derive(Clone)]
pub struct RateLimiter {
    max_attempts: u32,
    window_secs: u64,
    attempts: Arc<DashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            max_attempts,
            window_secs,
            attempts: Arc::new(DashMap::new()),
        }
    }

    pub fn check_rate_limit(&self, ip: &str) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let mut entry = self.attempts.entry(ip.to_string()).or_insert((0, now));
        let (count, window_start) = entry.value_mut();

        if now.duration_since(*window_start) > window {
            *count = 0;
            *window_start = now;
        }

        *count += 1;
        *count <= self.max_attempts
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs * 2);
        self.attempts
            .retain(|_, (_, window_start)| now.duration_since(*window_start) < window);
    }
}

// ==================== Input Validation ====================

/// Validate a domain name for blocklist/allowlist operations.
fn validate_domain(domain: &str) -> Result<(), &'static str> {
    let domain = domain.trim();
    if domain.is_empty() {
        return Err("Domain cannot be empty");
    }
    if domain.len() > 253 {
        return Err("Domain exceeds maximum length of 253 characters");
    }
    // Each label must be 1-63 chars, alphanumeric or hyphen (not start/end with hyphen)
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("Invalid domain label length");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Domain labels cannot start or end with a hyphen");
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("Domain contains invalid characters");
        }
    }
    Ok(())
}

/// Check if a URL points to an internal/private IP range (SSRF protection).
fn is_ssrf_target(url: &str) -> bool {
    // Extract host from URL
    let host = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .and_then(|rest| rest.split('/').next())
        .and_then(|host_port| {
            // Handle [IPv6]:port and host:port
            if host_port.starts_with('[') {
                host_port.find(']').map(|i| &host_port[1..i])
            } else {
                Some(host_port.split(':').next().unwrap_or(host_port))
            }
        })
        .unwrap_or("");

    if host.is_empty() {
        return true; // No valid host = suspicious
    }

    // Block localhost variants
    let host_lower = host.to_lowercase();
    if host_lower == "localhost" || host_lower == "localhost." || host_lower.ends_with(".localhost")
    {
        return true;
    }

    // Check for private/reserved IP ranges
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        return ipv4.is_loopback()          // 127.0.0.0/8
            || ipv4.is_private()            // 10/8, 172.16/12, 192.168/16
            || ipv4.is_link_local()         // 169.254/16
            || ipv4.is_broadcast()          // 255.255.255.255
            || ipv4.is_unspecified()        // 0.0.0.0
            || ipv4.octets()[0] == 100 && (ipv4.octets()[1] & 0xC0) == 64; // 100.64/10 (CGNAT)
    }

    if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        return ipv6.is_loopback() || ipv6.is_unspecified();
    }

    false
}

async fn https_redirect(
    axum::extract::State(https_port): axum::extract::State<String>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
) -> Response {
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Use the Host header so the redirect preserves the hostname/IP the user typed
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");

    // Strip existing port from Host header, replace with HTTPS port
    let host_without_port = if host.starts_with('[') {
        // IPv6: [::1]:9853 → [::1]
        host.rsplit_once("]:")
            .map(|(h, _)| format!("{}]", h))
            .unwrap_or_else(|| host.to_string())
    } else {
        host.rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| host.to_string())
    };

    let url = format!("https://{}:{}{}", host_without_port, https_port, path);
    axum::response::Redirect::permanent(&url).into_response()
}

async fn mark_https_middleware(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    request.extensions_mut().insert(IsHttps);
    next.run(request).await
}

/// Paths that handle sensitive data (passwords, API tokens, private keys)
/// and must be accessed over HTTPS when it's available.
const SENSITIVE_PATHS: &[&str] = &[
    "/api/system/tls/upload",
    "/api/system/tls/download",
    "/api/system/tls/acme/issue",
    "/api/auth/login",
    "/api/auth/setup",
    "/api/auth/change-password",
];

async fn sensitive_https_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.extensions().get::<IsHttps>().is_none()
        && SENSITIVE_PATHS.iter().any(|p| request.uri().path() == *p)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "This endpoint requires HTTPS. Use https:// to access the dashboard securely.",
                "code": "https_required"
            })),
        )
            .into_response();
    }
    next.run(request).await
}

pub async fn run_web_server(
    listen: &[String],
    https_listen: Option<&[String]>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    auto_redirect_https: bool,
    state: AppState,
) -> anyhow::Result<()> {
    let auth_for_middleware = state.auth.clone();

    // Spawn background cleanup for rate limiters
    let auth_cleanup = state.auth_rate_limiter.clone();
    let admin_cleanup = state.admin_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            auth_cleanup.cleanup();
            admin_cleanup.cleanup();
        }
    });

    let app = Router::new()
        // Auth pages (public)
        .route("/login", get(login_page))
        .route("/setup", get(setup_page))
        // Auth API
        .route("/api/auth/login", post(api_auth_login))
        .route("/api/auth/setup", post(api_auth_setup))
        .route("/api/system/setup-info", get(api_setup_info))
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
        .route("/api/stats/history", get(api_stats_history))
        .route("/api/stats/top-domains", get(api_stats_top_domains))
        .route("/api/stats/summary", get(api_stats_summary))
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
        // Network configuration
        .route(
            "/api/system/network",
            get(api_system_network).post(api_update_network),
        )
        // System settings
        .route(
            "/api/system/release-channel",
            get(api_get_release_channel).post(api_set_release_channel),
        )
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
        // TLS certificate management
        .route("/api/system/tls", get(api_tls_status))
        .route("/api/system/tls/upload", post(api_tls_upload))
        .route("/api/system/tls/remove", post(api_tls_remove))
        // ACME certificate management
        .route("/api/system/tls/acme/issue", post(api_acme_issue))
        .route("/api/system/tls/acme/confirm", post(api_acme_confirm))
        .route("/api/system/tls/acme/status", get(api_acme_status))
        .route("/api/system/tls/acme/renew", post(api_acme_renew))
        .route("/api/system/tls/acme/auto-renew", post(api_acme_auto_renew))
        .route("/api/system/tls/download", post(api_tls_download))
        // Query log
        .route("/api/logs", get(api_logs))
        .route("/api/logs/settings", get(api_get_log_settings))
        .route("/api/logs/settings", post(api_set_log_settings))
        // Auth middleware (after all routes, before state)
        .layer(axum::middleware::from_fn_with_state(
            auth_for_middleware,
            auth_middleware,
        ))
        // Enforce HTTPS on sensitive endpoints
        .layer(axum::middleware::from_fn(sensitive_https_middleware))
        // Security headers on all responses
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(state);

    let mut handles = Vec::new();
    let is_https_active = https_listen.is_some() && tls_config.is_some();

    if is_https_active {
        let tls_cfg = tls_config.unwrap();
        let https_addrs = https_listen.unwrap();

        // HTTPS app: full router + IsHttps marker
        let https_app = app
            .clone()
            .layer(axum::middleware::from_fn(mark_https_middleware));

        for addr in https_addrs {
            let https_app = https_app.clone();
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg.clone());
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
            let tcp_listener = tokio::net::TcpListener::from_std(socket.into())?;
            let addr_str = addr.clone();
            info!("Web admin HTTPS listening on {}", addr_str);

            handles.push(tokio::spawn(async move {
                loop {
                    let (tcp_stream, _peer_addr) = match tcp_listener.accept().await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("HTTPS accept error: {}", e);
                            continue;
                        }
                    };
                    let tls_acceptor = tls_acceptor.clone();
                    let app = https_app.clone();
                    let peer_addr = _peer_addr;
                    tokio::spawn(async move {
                        let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::debug!("TLS handshake failed: {}", e);
                                return;
                            }
                        };
                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        let service = hyper::service::service_fn(
                            move |mut req: hyper::Request<hyper::body::Incoming>| {
                                // Inject ConnectInfo so handlers can access the peer address
                                req.extensions_mut().insert(ConnectInfo(peer_addr));
                                let mut app = app.clone();
                                async move { app.call(req).await }
                            },
                        );
                        if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, service)
                        .await
                        {
                            tracing::debug!("HTTPS connection error: {}", e);
                        }
                    });
                }
            }));
        }

    }

    if is_https_active && auto_redirect_https {
        // HTTP becomes redirect-only when HTTPS is active and auto_redirect_https is enabled.
        // Extract just the port from the HTTPS address — the redirect handler
        // uses the Host header from the request for the hostname.
        let https_addrs = https_listen.unwrap();
        let https_port = https_addrs
            .first()
            .and_then(|addr| addr.rsplit_once(':').map(|(_, p)| p.to_string()))
            .unwrap_or_else(|| "9854".to_string());

        let redirect_app = Router::new()
            .fallback(https_redirect)
            .with_state(https_port);

        for addr in listen {
            let redirect_app = redirect_app.clone();
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
            let addr_str = addr.clone();
            info!("Web admin HTTP (redirect) listening on {}", addr_str);
            handles.push(tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, redirect_app.into_make_service()).await {
                    tracing::error!("HTTP redirect error on {}: {}", addr_str, e);
                }
            }));
        }
    } else {
        // Normal HTTP mode (existing behavior)
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
            let addr_str = addr.clone();
            info!("Web admin listening on {}", addr_str);
            handles.push(tokio::spawn(async move {
                if let Err(e) = axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                {
                    tracing::error!("Web server error on {}: {}", addr_str, e);
                }
            }));
        }
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

async fn setup_page(State(state): State<AppState>) -> Response {
    if !state.auth.needs_setup().await {
        return axum::response::Redirect::to("/").into_response();
    }

    Html(include_str!("setup.html")).into_response()
}

async fn api_setup_info(State(state): State<AppState>) -> Json<serde_json::Value> {
    let config = Config::load(&state.config_path).unwrap_or_default();

    let dns_listen = config
        .dns
        .listen
        .first()
        .cloned()
        .unwrap_or_else(|| "0.0.0.0:53".to_string());

    let web_listen = config
        .web
        .listen
        .first()
        .cloned()
        .unwrap_or_else(|| "0.0.0.0:9853".to_string());

    // Detect server's LAN IP using UDP socket trick (no actual traffic sent)
    let server_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());

    Json(serde_json::json!({
        "dns_listen": dns_listen,
        "web_listen": web_listen,
        "server_ip": server_ip,
    }))
}

async fn api_system_network(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let config = Config::load(&state.config_path).unwrap_or_default();
    let interfaces = get_network_interfaces();

    Json(serde_json::json!({
        "dns_listen": config.dns.listen,
        "web_listen": config.web.listen,
        "dot_listen": config.dns.dot_listen,
        "doh_listen": config.dns.doh_listen,
        "doq_listen": config.dns.doq_listen,
        "interfaces": interfaces,
    }))
    .into_response()
}

#[derive(Serialize)]
struct NetworkInterfaceInfo {
    name: String,
    ip_addresses: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateNetworkRequest {
    dns_listen: Option<serde_json::Value>,
    web_listen: Option<serde_json::Value>,
    dot_listen: Option<serde_json::Value>,
    doh_listen: Option<serde_json::Value>,
    doq_listen: Option<serde_json::Value>,
}

fn parse_optional_listen_value(
    value: &serde_json::Value,
) -> Result<Option<Vec<String>>, &'static str> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(vec![trimmed.to_string()]))
            }
        }
        serde_json::Value::Array(values) => {
            let mut parsed = Vec::new();
            for value in values {
                match value {
                    serde_json::Value::String(s) => {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            parsed.push(trimmed.to_string());
                        }
                    }
                    _ => return Err("listen values must be strings or null"),
                }
            }

            if parsed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(parsed))
            }
        }
        _ => Err("listen values must be a string, an array of strings, or null"),
    }
}

async fn api_update_network(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Json(req): Json<UpdateNetworkRequest>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut config = match Config::load(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("{}", e)})),
            )
                .into_response();
        }
    };

    if req.dns_listen.is_some() || req.web_listen.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "dns_listen and web_listen must be changed with the reconfigure command shown in the dashboard"
            })),
        )
            .into_response();
    }

    if let Some(ref val) = req.dot_listen {
        config.dns.dot_listen = match parse_optional_listen_value(val) {
            Ok(listen) => listen,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": error })),
                )
                    .into_response();
            }
        };
    }
    if let Some(ref val) = req.doh_listen {
        config.dns.doh_listen = match parse_optional_listen_value(val) {
            Ok(listen) => listen,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": error })),
                )
                    .into_response();
            }
        };
    }
    if let Some(ref val) = req.doq_listen {
        config.dns.doq_listen = match parse_optional_listen_value(val) {
            Ok(listen) => listen,
            Err(error) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": error })),
                )
                    .into_response();
            }
        };
    }

    if let Err(e) = config.save(&state.config_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response();
    }

    let _ = state.restart_signal.send(true);

    let interfaces = get_network_interfaces();

    Json(serde_json::json!({
        "dns_listen": config.dns.listen,
        "web_listen": config.web.listen,
        "dot_listen": config.dns.dot_listen,
        "doh_listen": config.dns.doh_listen,
        "doq_listen": config.dns.doq_listen,
        "interfaces": interfaces,
    }))
    .into_response()
}

fn get_network_interfaces() -> Vec<NetworkInterfaceInfo> {
    let mut interfaces = BTreeMap::<String, Vec<String>>::new();

    let Ok(addrs) = get_if_addrs::get_if_addrs() else {
        return Vec::new();
    };

    for iface in addrs {
        let ip = iface.ip();
        if ip.is_unspecified() || ip.is_multicast() {
            continue;
        }

        let ip_addresses = interfaces.entry(iface.name).or_default();
        let ip_text = ip.to_string();
        if !ip_addresses.contains(&ip_text) {
            ip_addresses.push(ip_text);
        }
    }

    interfaces
        .into_iter()
        .filter_map(|(name, mut ip_addresses)| {
            if ip_addresses.is_empty() {
                return None;
            }

            ip_addresses.sort();
            Some(NetworkInterfaceInfo { name, ip_addresses })
        })
        .collect()
}

fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
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

    // Rate limit login attempts per IP
    if !state.auth_rate_limiter.check_rate_limit(&ip) {
        warn!("Login rate limit exceeded for IP {}", ip);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(AuthErrorResponse {
                error: "Too many login attempts. Please try again later.".to_string(),
            }),
        )
            .into_response();
    }

    match state
        .auth
        .authenticate(&req.username, &req.password, Some(&ip))
        .await
    {
        Ok(session_token) => {
            let cookie = format!(
                "oxi_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800",
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
    let ip = addr.ip().to_string();
    if !state.auth_rate_limiter.check_rate_limit(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many attempts. Please try again later."})),
        )
            .into_response();
    }

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
                        "oxi_session={}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800",
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

    let cookie = "oxi_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<crate::auth::User>, Response> {
    let ip = addr.ip().to_string();
    if !state.admin_rate_limiter.check_rate_limit(&ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many requests. Please try again later."})),
        )
            .into_response());
    }

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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Path(id): axum::extract::Path<i64>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<StatusCode, Response> {
    let ip = addr.ip().to_string();
    if !state.admin_rate_limiter.check_rate_limit(&ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many requests. Please try again later."})),
        )
            .into_response());
    }

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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, Response> {
    let ip = addr.ip().to_string();
    if !state.auth_rate_limiter.check_rate_limit(&ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many attempts. Please try again later."})),
        )
            .into_response());
    }

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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<CreateTokenResponse>, Response> {
    let ip = addr.ip().to_string();
    if !state.admin_rate_limiter.check_rate_limit(&ip) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many requests. Please try again later."})),
        )
            .into_response());
    }

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
    state.upstream.cache_flush();
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
    state.upstream.cache_flush();
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
    state.upstream.cache_flush();
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
    state.upstream.cache_flush();
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
    if let Err(e) = validate_domain(&req.domain) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response());
    }
    state.blocklist.add_custom_blocked(&req.domain).await;
    state.upstream.cache_flush();
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
    state.upstream.cache_flush();
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
    if let Err(e) = validate_domain(&req.domain) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(AuthErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response());
    }
    state.blocklist.add_allowlisted(&req.domain).await;
    state.upstream.cache_flush();
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
    state.upstream.cache_flush();
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
    if !req.url.starts_with("http://") && !req.url.starts_with("https://") {
        return Ok(Json(BlocklistAddResponse {
            success: false,
            message: "Only http:// and https:// URLs are allowed".to_string(),
        }));
    }
    if req.url.len() > 2048 {
        return Ok(Json(BlocklistAddResponse {
            success: false,
            message: "URL exceeds maximum length of 2048 characters".to_string(),
        }));
    }
    if is_ssrf_target(&req.url) {
        return Ok(Json(BlocklistAddResponse {
            success: false,
            message: "URLs pointing to internal or private addresses are not allowed".to_string(),
        }));
    }
    match state.blocklist.add_blocklist_source(&req.url).await {
        Ok(count) => {
            info!("Added blocklist source: {} ({} entries)", req.url, count);
            state.upstream.cache_flush();
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
    state.upstream.cache_flush();
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
    let upstream = state.upstream.clone();

    tokio::spawn(async move {
        blocklist.refresh_sources_streaming(tx).await;
        upstream.cache_flush();
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
    state.upstream.cache_flush();
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
    let channel = state.release_channel.read().await.clone();
    Json(state.update_checker.check(false, &channel).await)
}

async fn api_version_check(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Json<crate::update::VersionInfo>, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    let channel = state.release_channel.read().await.clone();
    Ok(Json(state.update_checker.check(true, &channel).await))
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
    let channel = state.release_channel.read().await.clone();
    tokio::spawn(async move {
        crate::update::perform_robust_update(
            &update_checker,
            &update_status,
            &config_path,
            &current_exe,
            &channel,
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
    query_log_retention_days: u32,
    stats_retention_days: u32,
    anonymize_client_ip: bool,
}

async fn api_get_log_settings(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<Json<LogSettingsResponse>, Response> {
    require_permission(&user, Permission::ViewLogs)?;
    Ok(Json(LogSettingsResponse {
        query_log_retention_days: *state.log_retention_days.read().await,
        stats_retention_days: *state.stats_retention_days.read().await,
        anonymize_client_ip: state
            .anonymize_ip
            .load(std::sync::atomic::Ordering::Relaxed),
    }))
}

#[derive(Deserialize)]
struct LogSettingsRequest {
    #[serde(default)]
    query_log_retention_days: Option<u32>,
    #[serde(default)]
    stats_retention_days: Option<u32>,
    #[serde(default)]
    anonymize_client_ip: Option<bool>,
}

async fn api_set_log_settings(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    Json(req): Json<LogSettingsRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageSystem)?;
    if let Some(days) = req.query_log_retention_days {
        let clamped = days.clamp(1, 90);
        *state.log_retention_days.write().await = clamped;
        info!("Query log retention set to {} days", clamped);
    }
    if let Some(days) = req.stats_retention_days {
        let clamped = days.clamp(1, 365);
        *state.stats_retention_days.write().await = clamped;
        info!("Stats retention set to {} days", clamped);
    }
    if let Some(anonymize) = req.anonymize_client_ip {
        state
            .anonymize_ip
            .store(anonymize, std::sync::atomic::Ordering::Relaxed);
        info!("Client IP anonymization set to {}", anonymize);
        if anonymize {
            let ql = state.query_log.clone();
            tokio::spawn(async move {
                if let Err(e) = ql.anonymize_all_ips().await {
                    tracing::warn!("Failed to retroactively anonymize IPs: {}", e);
                }
            });
        }
    }
    state.save_config().await;
    Ok(StatusCode::OK)
}

// ==================== TLS Certificate Management ====================

async fn api_tls_status(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let config = Config::load(&state.config_path).unwrap_or_default();
    let cert_info = crate::cert_parser::get_current_cert_info(&config.tls);

    match cert_info {
        Ok(Some(info)) => Json(serde_json::json!({
            "subject": info.subject,
            "issuer": info.issuer,
            "not_after": info.not_after,
            "self_signed": info.self_signed,
            "cert_path": config.tls.cert_path,
            "key_path": config.tls.key_path,
        }))
        .into_response(),
        _ => Json(serde_json::json!({
            "subject": "Oxi-DNS Server",
            "issuer": "Oxi-DNS Server",
            "not_after": null,
            "self_signed": true,
            "cert_path": null,
            "key_path": null,
        }))
        .into_response(),
    }
}

async fn api_tls_upload(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut multipart: axum::extract::Multipart,
) -> Response {
    let ip = addr.ip().to_string();
    if !state.admin_rate_limiter.check_rate_limit(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many requests. Please try again later."})),
        )
            .into_response();
    }

    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut cert_data: Option<Vec<u8>> = None;
    let mut key_data: Option<Vec<u8>> = None;
    let mut p12_data: Option<Vec<u8>> = None;
    let mut password: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "cert_file" => {
                cert_data = field.bytes().await.ok().map(|b| b.to_vec());
            }
            "key_file" => {
                key_data = field.bytes().await.ok().map(|b| b.to_vec());
            }
            "p12_file" => {
                p12_data = field.bytes().await.ok().map(|b| b.to_vec());
            }
            "password" => {
                password = field.text().await.ok();
            }
            _ => {}
        }
    }

    let parsed = if let Some(ref p12) = p12_data {
        crate::cert_parser::parse_pkcs12(p12, password.as_deref())
    } else if let Some(ref cert) = cert_data {
        crate::cert_parser::parse_pem(cert, key_data.as_deref(), password.as_deref())
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "no certificate file provided"})),
        )
            .into_response();
    };

    let parsed = match parsed {
        Ok(p) => p,
        Err(crate::cert_parser::ParseError::PasswordRequired { cert_type }) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": "password_required",
                    "type": cert_type,
                })),
            )
                .into_response();
        }
        Err(crate::cert_parser::ParseError::Other(e)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{}", e)})),
            )
                .into_response();
        }
    };

    let config_dir = state
        .config_path
        .parent()
        .unwrap_or(std::path::Path::new("/etc/oxi-dns"));
    let cert_path = config_dir.join("cert.pem");
    let key_path = config_dir.join("key.pem");

    if let Err(e) = crate::cert_parser::write_cert_files(&parsed, &cert_path, &key_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response();
    }

    let mut config = Config::load(&state.config_path).unwrap_or_default();
    config.tls.cert_path = Some(cert_path.to_string_lossy().to_string());
    config.tls.key_path = Some(key_path.to_string_lossy().to_string());
    if let Err(e) = config.save(&state.config_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response();
    }

    let _ = state.restart_signal.send(true);

    Json(serde_json::json!({
        "subject": parsed.subject,
        "issuer": parsed.issuer,
        "not_after": parsed.not_after,
        "self_signed": parsed.self_signed,
    }))
    .into_response()
}

async fn api_tls_remove(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let config_dir = state
        .config_path
        .parent()
        .unwrap_or(std::path::Path::new("/etc/oxi-dns"));
    let _ = std::fs::remove_file(config_dir.join("cert.pem"));
    let _ = std::fs::remove_file(config_dir.join("key.pem"));

    let mut config = Config::load(&state.config_path).unwrap_or_default();
    config.tls.cert_path = None;
    config.tls.key_path = None;
    if let Err(e) = config.save(&state.config_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response();
    }

    let _ = state.restart_signal.send(true);

    Json(serde_json::json!({"success": true})).into_response()
}

// ==================== ACME Certificate Management ====================

async fn api_acme_issue(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let domain = match body.get("domain").and_then(|v| v.as_str()) {
        Some(d) if !d.is_empty() => d.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "domain is required"})),
            )
                .into_response()
        }
    };

    let email = match body.get("email").and_then(|v| v.as_str()) {
        Some(e) if !e.is_empty() => e.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "email is required"})),
            )
                .into_response()
        }
    };

    let provider = body
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("manual")
        .to_string();

    let cloudflare_api_token = body
        .get("cloudflare_api_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if provider == "cloudflare" && cloudflare_api_token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "cloudflare_api_token is required for cloudflare provider"})),
        )
            .into_response();
    }

    let use_staging = body
        .get("use_staging")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let acme_config = crate::config::AcmeConfig {
        enabled: true,
        domain: domain.clone(),
        email: email.clone(),
        provider: provider.clone(),
        cloudflare_api_token: cloudflare_api_token.clone(),
        use_staging,
        last_renewed: String::new(),
        last_renewal_error: String::new(),
    };

    // Save ACME config to file
    if let Ok(mut config) = crate::config::Config::load(&state.config_path) {
        config.tls.acme = acme_config.clone();
        config.tls.cert_path = Some(crate::acme::CERT_PATH.to_string());
        config.tls.key_path = Some(crate::acme::KEY_PATH.to_string());
        let _ = config.save(&state.config_path);
    }

    let progress = state.acme.progress.clone();
    let manual_confirm = state.acme.manual_confirm.clone();
    let config_path = state.config_path.clone();
    let restart_signal = state.restart_signal.clone();

    tokio::spawn(async move {
        match crate::acme::issue_certificate(&acme_config, progress.clone(), manual_confirm).await {
            Ok(()) => {
                // Update config timestamps on success
                if let Ok(mut config) = crate::config::Config::load(&config_path) {
                    config.tls.acme.last_renewed = chrono::Utc::now()
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string();
                    config.tls.acme.last_renewal_error = String::new();
                    let _ = config.save(&config_path);
                }
                let _ = restart_signal.send(true);
            }
            Err(e) => {
                // Set progress to Failed
                {
                    let mut p = progress.write().await;
                    p.state = crate::acme::IssuanceState::Failed;
                    p.message = e.to_string();
                }
                // Save error to config
                if let Ok(mut config) = crate::config::Config::load(&config_path) {
                    config.tls.acme.last_renewal_error = e.to_string();
                    let _ = config.save(&config_path);
                }
            }
        }
    });

    Json(serde_json::json!({"status": "started"})).into_response()
}

async fn api_acme_confirm(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    state.acme.manual_confirm.notify_one();

    Json(serde_json::json!({"status": "confirmed"})).into_response()
}

async fn api_acme_status(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let progress = state.acme.progress.read().await.clone();

    let acme_config = crate::config::Config::load(&state.config_path)
        .map(|c| c.tls.acme)
        .unwrap_or_default();

    Json(serde_json::json!({
        "progress": progress,
        "config": {
            "enabled": acme_config.enabled,
            "domain": acme_config.domain,
            "email": acme_config.email,
            "provider": acme_config.provider,
            "use_staging": acme_config.use_staging,
            "last_renewed": acme_config.last_renewed,
            "last_renewal_error": acme_config.last_renewal_error,
        }
    }))
    .into_response()
}

async fn api_acme_renew(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let acme_config = match crate::config::Config::load(&state.config_path) {
        Ok(c) if c.tls.acme.enabled && !c.tls.acme.domain.is_empty() => c.tls.acme,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "ACME is not configured"})),
            )
                .into_response()
        }
    };

    let progress = state.acme.progress.clone();
    let manual_confirm = state.acme.manual_confirm.clone();
    let config_path = state.config_path.clone();
    let restart_signal = state.restart_signal.clone();

    tokio::spawn(async move {
        match crate::acme::issue_certificate(&acme_config, progress.clone(), manual_confirm).await {
            Ok(()) => {
                if let Ok(mut config) = crate::config::Config::load(&config_path) {
                    config.tls.acme.last_renewed = chrono::Utc::now()
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string();
                    config.tls.acme.last_renewal_error = String::new();
                    let _ = config.save(&config_path);
                }
                let _ = restart_signal.send(true);
            }
            Err(e) => {
                {
                    let mut p = progress.write().await;
                    p.state = crate::acme::IssuanceState::Failed;
                    p.message = e.to_string();
                }
                if let Ok(mut config) = crate::config::Config::load(&config_path) {
                    config.tls.acme.last_renewal_error = e.to_string();
                    let _ = config.save(&config_path);
                }
            }
        }
    });

    Json(serde_json::json!({"status": "started"})).into_response()
}

async fn api_acme_auto_renew(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let enabled = match body["enabled"].as_bool() {
        Some(v) => v,
        None => {
            return (StatusCode::BAD_REQUEST, "Missing 'enabled' field").into_response();
        }
    };

    match crate::config::Config::load(&state.config_path) {
        Ok(mut config) => {
            config.tls.acme.enabled = enabled;
            if let Err(e) = config.save(&state.config_path) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to save config: {}", e),
                )
                    .into_response();
            }
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to load config: {}", e),
            )
                .into_response();
        }
    }

    Json(serde_json::json!({"status": "ok", "enabled": enabled})).into_response()
}

async fn api_tls_download(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Require password confirmation
    let password = match body["password"].as_str() {
        Some(p) if !p.is_empty() => p,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Password is required"})),
            )
                .into_response();
        }
    };

    if !state.auth.verify_password(user.id, password).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid password"})),
        )
            .into_response();
    }

    // Load current cert and key paths from config
    let config = match crate::config::Config::load(&state.config_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to load config"})),
            )
                .into_response();
        }
    };

    let cert_path = config
        .tls
        .cert_path
        .as_deref()
        .unwrap_or(crate::acme::CERT_PATH);
    let key_path = config
        .tls
        .key_path
        .as_deref()
        .unwrap_or(crate::acme::KEY_PATH);

    let cert_pem = match std::fs::read_to_string(cert_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "No certificate file found"})),
            )
                .into_response();
        }
    };

    let key_pem = match std::fs::read_to_string(key_path) {
        Ok(k) => k,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "No key file found"})),
            )
                .into_response();
        }
    };

    Json(serde_json::json!({
        "cert_pem": cert_pem,
        "key_pem": key_pem,
    }))
    .into_response()
}

async fn api_get_release_channel(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let channel = state.release_channel.read().await.clone();
    Json(serde_json::json!({"channel": channel})).into_response()
}

#[derive(Deserialize)]
struct SetReleaseChannelRequest {
    channel: String,
}

async fn api_set_release_channel(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Json(req): Json<SetReleaseChannelRequest>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let channel = match req.channel.as_str() {
        "stable" | "development" => req.channel.clone(),
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid channel. Must be 'stable' or 'development'."}))).into_response();
        }
    };

    *state.release_channel.write().await = channel.clone();
    state.save_config().await;

    // Trigger immediate update check
    let _ = state.update_check_signal.send(true);

    Json(serde_json::json!({"channel": channel})).into_response()
}

#[derive(Deserialize)]
struct StatsHistoryQuery {
    period: Option<String>,
}

async fn api_stats_history(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<StatsHistoryQuery>,
) -> Response {
    let period = params.period.as_deref().unwrap_or("24h");
    let hours: i64 = match period {
        "24h" => 24,
        "7d" => 7 * 24,
        "30d" => 30 * 24,
        "90d" => 90 * 24,
        _ => 24,
    };

    let now = chrono::Utc::now();
    let from = (now - chrono::Duration::hours(hours))
        .format("%Y-%m-%dT%H:00:00")
        .to_string();
    let to = now.format("%Y-%m-%dT%H:00:00").to_string();

    match state.persistent_stats.get_hourly_stats(&from, &to).await {
        Ok(data) => Json(serde_json::json!({
            "period": period,
            "data": data,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct TopDomainsQuery {
    days: Option<u32>,
    limit: Option<u32>,
}

async fn api_stats_top_domains(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<TopDomainsQuery>,
) -> Response {
    let days = params.days.unwrap_or(7);
    let limit = params.limit.unwrap_or(10);

    match state.persistent_stats.get_top_domains(days, limit).await {
        Ok(data) => Json(serde_json::json!({
            "days": days,
            "top_queried": data.top_queried,
            "top_blocked": data.top_blocked,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct StatsSummaryQuery {
    days: Option<u32>,
}

async fn api_stats_summary(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<StatsSummaryQuery>,
) -> Response {
    let days = params.days.unwrap_or(30);

    match state.persistent_stats.get_summary(days).await {
        Ok(data) => Json(serde_json::json!({
            "days": days,
            "total_queries": data.total_queries,
            "blocked_queries": data.blocked_queries,
            "block_percentage": data.block_percentage,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        )
            .into_response(),
    }
}
