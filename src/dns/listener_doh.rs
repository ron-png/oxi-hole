use crate::blocklist::BlocklistManager;
use crate::config::BlockingMode;
use crate::dns::handler;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use base64::Engine;
use serde::Deserialize;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::{debug, error, info};

#[derive(Clone)]
struct DohState {
    blocklist: BlocklistManager,
    stats: Stats,
    upstream: UpstreamForwarder,
    features: FeatureManager,
    blocking_mode: Arc<RwLock<BlockingMode>>,
    query_log: QueryLog,
    anonymize_ip: Arc<AtomicBool>,
}

pub async fn run(
    addr: String,
    blocklist: BlocklistManager,
    stats: Stats,
    upstream: UpstreamForwarder,
    features: FeatureManager,
    blocking_mode: Arc<RwLock<BlockingMode>>,
    tls_config: Arc<rustls::ServerConfig>,
    query_log: QueryLog,
    anonymize_ip: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let state = DohState {
        blocklist,
        stats,
        upstream,
        features,
        blocking_mode,
        query_log,
        anonymize_ip,
    };

    let app = Router::new()
        .route("/dns-query", get(doh_get).post(doh_post))
        .with_state(state);

    let tcp_listener = TcpListener::bind(&addr).await?;
    let acceptor = TlsAcceptor::from(tls_config);
    info!("DoH listener ready on https://{}/dns-query", addr);

    loop {
        let (tcp_stream, peer) = match tcp_listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                error!("DoH accept error: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    debug!("DoH TLS handshake failed from {}: {}", peer, e);
                    return;
                }
            };

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            let service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let body = match http_body_util::BodyExt::collect(body).await {
                            Ok(collected) => axum::body::Body::from(collected.to_bytes()),
                            Err(_) => axum::body::Body::empty(),
                        };
                        let req = hyper::Request::from_parts(parts, body);
                        let resp = app.into_service().call(req).await;
                        resp
                    }
                });

            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
            {
                debug!("DoH connection error from {}: {}", peer, e);
            }
        });
    }
}

#[derive(Deserialize)]
struct DohGetParams {
    dns: String,
}

async fn doh_get(
    State(state): State<DohState>,
    Query(params): Query<DohGetParams>,
    req: axum::extract::Request,
) -> impl IntoResponse {
    let client_ip = extract_client_ip(&req);

    let packet = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&params.dns) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64url DNS query").into_response(),
    };

    match handler::process_dns_query(
        &packet,
        &client_ip,
        &state.blocklist,
        &state.upstream,
        &state.stats,
        &state.features,
        &state.blocking_mode,
        &state.query_log,
        &state.anonymize_ip,
    )
    .await
    {
        Ok(response) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/dns-message")],
            response,
        )
            .into_response(),
        Err(e) => {
            debug!("DoH GET error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "DNS query failed").into_response()
        }
    }
}

async fn doh_post(State(state): State<DohState>, req: axum::extract::Request) -> impl IntoResponse {
    let client_ip = extract_client_ip(&req);

    let body = match axum::body::to_bytes(req.into_body(), 65535).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Failed to read body").into_response(),
    };

    match handler::process_dns_query(
        &body,
        &client_ip,
        &state.blocklist,
        &state.upstream,
        &state.stats,
        &state.features,
        &state.blocking_mode,
        &state.query_log,
        &state.anonymize_ip,
    )
    .await
    {
        Ok(response) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/dns-message")],
            response,
        )
            .into_response(),
        Err(e) => {
            debug!("DoH POST error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "DNS query failed").into_response()
        }
    }
}

fn extract_client_ip(req: &axum::extract::Request) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .next()
                .unwrap_or("doh-client")
                .trim()
                .to_string()
        })
        .unwrap_or_else(|| "doh-client".to_string())
}
