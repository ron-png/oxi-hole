use crate::blocklist::BlocklistManager;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::stats::Stats;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{get, post};
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub blocklist: BlocklistManager,
    pub stats: Stats,
    pub features: FeatureManager,
    pub upstream: UpstreamForwarder,
    pub auto_update: std::sync::Arc<tokio::sync::RwLock<bool>>,
}

pub async fn run_web_server(listen: &str, state: AppState) -> anyhow::Result<()> {
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
        .route("/api/blocklist/add", post(api_add_blocked))
        .route("/api/blocklist/remove", post(api_remove_blocked))
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
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!("Web admin UI listening on http://{}", listen);
    axum::serve(listener, app).await?;
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
    StatusCode::OK
}

async fn api_disable_blocking(State(state): State<AppState>) -> StatusCode {
    state.blocklist.set_enabled(false).await;
    info!("Blocking disabled via web API");
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
    StatusCode::OK
}

// ==================== Domain Management ====================

#[derive(Deserialize)]
struct DomainRequest {
    domain: String,
}

async fn api_add_blocked(
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> StatusCode {
    state.blocklist.add_custom_blocked(&req.domain).await;
    info!("Added {} to blocklist via web API", req.domain);
    StatusCode::OK
}

async fn api_remove_blocked(
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> StatusCode {
    state.blocklist.remove_custom_blocked(&req.domain).await;
    info!("Removed {} from blocklist via web API", req.domain);
    StatusCode::OK
}

async fn api_add_allowlisted(
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> StatusCode {
    state.blocklist.add_allowlisted(&req.domain).await;
    info!("Added {} to allowlist via web API", req.domain);
    StatusCode::OK
}

async fn api_remove_allowlisted(
    State(state): State<AppState>,
    Json(req): Json<DomainRequest>,
) -> StatusCode {
    state.blocklist.remove_allowlisted(&req.domain).await;
    info!("Removed {} from allowlist via web API", req.domain);
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

async fn api_add_blocklist_source(
    State(state): State<AppState>,
    Json(req): Json<UrlRequest>,
) -> StatusCode {
    state.blocklist.add_blocklist_source(&req.url).await;
    info!("Added blocklist source: {}", req.url);
    StatusCode::OK
}

async fn api_remove_blocklist_source(
    State(state): State<AppState>,
    Json(req): Json<UrlRequest>,
) -> StatusCode {
    state.blocklist.remove_blocklist_source(&req.url).await;
    info!("Removed blocklist source: {}", req.url);
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
    match state.upstream.add_upstream(&req.upstream) {
        Ok(_) => {
            info!("Added upstream: {}", req.upstream);
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
    StatusCode::OK
}
