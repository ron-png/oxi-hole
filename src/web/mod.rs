use crate::blocklist::BlocklistManager;
use crate::config::{BlockingMode, Config};
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use crate::update::UpdateChecker;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
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
    let app = Router::new()
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
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("Web server error on {}: {}", addr, e);
            }
        }));
    }

    futures::future::join_all(handles).await;
    Ok(())
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

async fn api_enable_blocking(State(state): State<AppState>) -> StatusCode {
    state.blocklist.set_enabled(true).await;
    info!("Blocking enabled via web API");
    state.save_config().await;
    StatusCode::OK
}

async fn api_disable_blocking(State(state): State<AppState>) -> StatusCode {
    state.blocklist.set_enabled(false).await;
    info!("Blocking disabled via web API");
    state.save_config().await;
    StatusCode::OK
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
    State(state): State<AppState>,
    Json(req): Json<BlockingModeRequest>,
) -> StatusCode {
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
        _ => return StatusCode::BAD_REQUEST,
    };
    info!("Blocking mode set to {}", new_mode);
    *state.blocking_mode.write().await = new_mode;
    state.save_config().await;
    StatusCode::OK
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
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<FeatureToggleRequest>,
) -> StatusCode {
    state.features.set_feature(&id, req.enabled).await;
    state.save_config().await;
    StatusCode::OK
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
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> StatusCode {
    state.blocklist.add_custom_blocked(&req.domain).await;
    info!("Added {} to blocklist via web API", req.domain);
    state.save_config().await;
    StatusCode::OK
}

async fn api_remove_blocked(
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> StatusCode {
    state.blocklist.remove_custom_blocked(&req.domain).await;
    info!("Removed {} from blocklist via web API", req.domain);
    state.save_config().await;
    StatusCode::OK
}

async fn api_add_allowlisted(
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> StatusCode {
    state.blocklist.add_allowlisted(&req.domain).await;
    info!("Added {} to allowlist via web API", req.domain);
    state.save_config().await;
    StatusCode::OK
}

async fn api_remove_allowlisted(
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> StatusCode {
    state.blocklist.remove_allowlisted(&req.domain).await;
    info!("Removed {} from allowlist via web API", req.domain);
    state.save_config().await;
    StatusCode::OK
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
    State(state): State<AppState>,
    Json(req): Json<UrlRequest>,
) -> Json<BlocklistAddResponse> {
    match state.blocklist.add_blocklist_source(&req.url).await {
        Ok(count) => {
            info!("Added blocklist source: {} ({} entries)", req.url, count);
            state.save_config().await;
            Json(BlocklistAddResponse {
                success: true,
                message: format!("Loaded {} domains", count),
            })
        }
        Err(e) => Json(BlocklistAddResponse {
            success: false,
            message: e,
        }),
    }
}

async fn api_remove_blocklist_source(
    State(state): State<AppState>,
    Json(req): Json<UrlRequest>,
) -> StatusCode {
    state.blocklist.remove_blocklist_source(&req.url).await;
    info!("Removed blocklist source: {}", req.url);
    state.save_config().await;
    StatusCode::OK
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
    State(state): State<AppState>,
    Json(req): Json<UpstreamRequest>,
) -> StatusCode {
    match state.upstream.add_upstream(&req.upstream).await {
        Ok(_) => {
            info!("Added upstream: {}", req.upstream);
            state.save_config().await;
            StatusCode::OK
        }
        Err(e) => {
            tracing::warn!("Invalid upstream '{}': {}", req.upstream, e);
            StatusCode::BAD_REQUEST
        }
    }
}

async fn api_remove_upstream(
    State(state): State<AppState>,
    Json(req): Json<UpstreamRequest>,
) -> StatusCode {
    if state.upstream.remove_upstream(&req.upstream) {
        state.save_config().await;
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
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
    State(state): State<AppState>,
    Json(req): Json<AutoUpdateRequest>,
) -> StatusCode {
    *state.auto_update.write().await = req.enabled;
    tracing::info!("Auto-update set to {}", req.enabled);
    state.save_config().await;
    StatusCode::OK
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

async fn api_set_ipv6(State(state): State<AppState>, Json(req): Json<Ipv6Request>) -> StatusCode {
    state
        .ipv6_enabled
        .store(req.enabled, std::sync::atomic::Ordering::Relaxed);
    tracing::info!("IPv6 (AAAA) set to {}", req.enabled);
    state.save_config().await;
    StatusCode::OK
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
    State(state): State<AppState>,
    Json(req): Json<BlocklistIntervalRequest>,
) -> StatusCode {
    *state.blocklist_update_interval.write().await = req.interval_minutes;
    tracing::info!(
        "Blocklist update interval set to {} minutes",
        req.interval_minutes
    );
    state.save_config().await;
    StatusCode::OK
}

// ==================== Version / Update ====================

async fn api_version(State(state): State<AppState>) -> Json<crate::update::VersionInfo> {
    Json(state.update_checker.check(false).await)
}

async fn api_version_check(State(state): State<AppState>) -> Json<crate::update::VersionInfo> {
    Json(state.update_checker.check(true).await)
}

#[derive(Serialize)]
struct UpdateResponse {
    success: bool,
    message: String,
}

async fn api_perform_update(State(state): State<AppState>) -> Json<UpdateResponse> {
    // Check if an update is already in progress
    {
        let s = state.update_status.read().await;
        if s.state != crate::update::UpdateState::Idle
            && s.state != crate::update::UpdateState::Failed
        {
            return Json(UpdateResponse {
                success: false,
                message: "An update is already in progress".to_string(),
            });
        }
    }

    let current_exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            return Json(UpdateResponse {
                success: false,
                message: format!("Cannot determine current binary: {}", e),
            });
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

    Json(UpdateResponse {
        success: true,
        message: "Update started — health-checking and restarting automatically".to_string(),
    })
}

async fn api_restart() -> StatusCode {
    info!("Restart requested via web API");
    // Spawn a short delay so the HTTP response can be sent before we exit.
    // The service manager (systemd Restart=always) will restart the process.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        std::process::exit(0);
    });
    StatusCode::OK
}

// ==================== Update Status ====================

async fn api_update_status(State(state): State<AppState>) -> Json<crate::update::UpdateStatus> {
    let status = state.update_status.read().await;
    Json(status.to_serializable())
}

async fn api_dismiss_update_status(State(state): State<AppState>) -> StatusCode {
    let mut status = state.update_status.write().await;
    *status = crate::update::UpdateStatus::default();
    StatusCode::OK
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
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<LogsQueryParams>,
) -> Result<Json<crate::query_log::LogPage>, StatusCode> {
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
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Serialize)]
struct LogSettingsResponse {
    retention_days: u32,
    anonymize_client_ip: bool,
}

async fn api_get_log_settings(State(state): State<AppState>) -> Json<LogSettingsResponse> {
    Json(LogSettingsResponse {
        retention_days: *state.log_retention_days.read().await,
        anonymize_client_ip: state
            .anonymize_ip
            .load(std::sync::atomic::Ordering::Relaxed),
    })
}

#[derive(Deserialize)]
struct LogSettingsRequest {
    #[serde(default)]
    retention_days: Option<u32>,
    #[serde(default)]
    anonymize_client_ip: Option<bool>,
}

async fn api_set_log_settings(
    State(state): State<AppState>,
    Json(req): Json<LogSettingsRequest>,
) -> StatusCode {
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
    StatusCode::OK
}
