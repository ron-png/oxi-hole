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
use hickory_proto::op::ResponseCode;
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::{debug, error, info, warn};

fn bind_tcp_reuse_port(addr: &str) -> anyhow::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock_addr: std::net::SocketAddr = addr.parse()?;
    let domain = if sock_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&sock_addr.into())?;
    socket.listen(128)?;
    Ok(socket.into())
}

#[derive(Clone)]
struct DohState {
    blocklist: BlocklistManager,
    stats: Stats,
    upstream: UpstreamForwarder,
    features: FeatureManager,
    blocking_mode: Arc<RwLock<BlockingMode>>,
    query_log: QueryLog,
    anonymize_ip: Arc<AtomicBool>,
    ipv6_enabled: Arc<AtomicBool>,
}

#[allow(clippy::too_many_arguments)]
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
    ipv6_enabled: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let state = DohState {
        blocklist,
        stats,
        upstream,
        features,
        blocking_mode,
        query_log,
        anonymize_ip,
        ipv6_enabled,
    };

    let app = Router::new()
        .route("/dns-query", get(doh_get).post(doh_post))
        .with_state(state);

    let std_listener = bind_tcp_reuse_port(&addr)?;
    let tcp_listener = TcpListener::from_std(std_listener)?;
    let acceptor = TlsAcceptor::from(tls_config);
    let active_connections = Arc::new(AtomicUsize::new(0));
    let max_connections = crate::resources::limits().doh_max_connections;
    info!(
        "DoH listener ready on https://{}/dns-query (max {} concurrent connections)",
        addr, max_connections
    );

    loop {
        let (tcp_stream, peer) = match tcp_listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                error!("DoH accept error: {}", e);
                continue;
            }
        };

        // Connection cap: increment first then test to avoid TOCTOU races.
        let conn_count = active_connections.clone();
        let prev = conn_count.fetch_add(1, Ordering::AcqRel);
        if prev >= max_connections {
            conn_count.fetch_sub(1, Ordering::AcqRel);
            warn!(
                "DoH connection limit reached ({}), rejecting {}",
                max_connections, peer
            );
            drop(tcp_stream);
            continue;
        }

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
            let service = hyper::service::service_fn(
                move |mut req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        // Inject peer address so handlers can extract real client IP
                        req.extensions_mut().insert(peer);
                        let (parts, body) = req.into_parts();
                        let body = match http_body_util::BodyExt::collect(body).await {
                            Ok(collected) => axum::body::Body::from(collected.to_bytes()),
                            Err(_) => axum::body::Body::empty(),
                        };
                        let req = hyper::Request::from_parts(parts, body);
                        let resp = app.into_service().call(req).await;
                        resp
                    }
                },
            );

            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
            {
                debug!("DoH connection error from {}: {}", peer, e);
            }
            conn_count.fetch_sub(1, Ordering::AcqRel);
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
    // RFC 8484 §4.1: validate Accept header if present
    if let Some(accept) = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
    {
        if !accept.contains("application/dns-message") && !accept.contains("*/*") {
            return StatusCode::NOT_ACCEPTABLE.into_response();
        }
    }

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
        &state.ipv6_enabled,
    )
    .await
    {
        Ok(response) => build_doh_response(response),
        Err(e) => {
            debug!("DoH GET error: {}", e);
            match e {
                // RFC 8484 §4.2.1: DNS errors are returned as DNS messages in the HTTP body,
                // not as HTTP error status codes.
                handler::DnsError::ParseError(_) => {
                    build_dns_error_response(&packet, ResponseCode::FormErr)
                }
                handler::DnsError::ServerError(_) => {
                    build_dns_error_response(&packet, ResponseCode::ServFail)
                }
            }
        }
    }
}

async fn doh_post(State(state): State<DohState>, req: axum::extract::Request) -> impl IntoResponse {
    // RFC 8484 §4.1: validate Accept header if present
    if let Some(accept) = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
    {
        if !accept.contains("application/dns-message") && !accept.contains("*/*") {
            return StatusCode::NOT_ACCEPTABLE.into_response();
        }
    }

    let client_ip = extract_client_ip(&req);

    // Validate Content-Type per RFC 8484 §4.1
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/dns-message") {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/dns-message",
        )
            .into_response();
    }

    // RFC 8484 §6: DNS-over-HTTPS messages are bounded by DNS message size
    // (~64KB max). Cap here so a rogue client can't stream MB of junk.
    let body = match axum::body::to_bytes(req.into_body(), 65535).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "body too large").into_response(),
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
        &state.ipv6_enabled,
    )
    .await
    {
        Ok(response) => build_doh_response(response),
        Err(e) => {
            debug!("DoH POST error: {}", e);
            match e {
                // RFC 8484 §4.2.1: DNS errors are returned as DNS messages in the HTTP body,
                // not as HTTP error status codes.
                handler::DnsError::ParseError(_) => {
                    build_dns_error_response(&body, ResponseCode::FormErr)
                }
                handler::DnsError::ServerError(_) => {
                    build_dns_error_response(&body, ResponseCode::ServFail)
                }
            }
        }
    }
}

/// Build a DNS error response for DoH (RFC 8484 §4.2.1: DNS errors go in the body, not HTTP status).
fn build_dns_error_response(packet: &[u8], rcode: ResponseCode) -> axum::response::Response {
    let bytes = handler::build_error_response(packet, rcode);
    build_doh_response(bytes)
}

/// Build a DoH HTTP response with proper Content-Type and Cache-Control headers (RFC 8484 §5.1).
fn build_doh_response(response: Vec<u8>) -> axum::response::Response {
    use hickory_proto::serialize::binary::BinDecodable;

    // Extract minimum TTL for Cache-Control max-age (RFC 8484 §5.1)
    let max_age = hickory_proto::op::Message::from_bytes(&response)
        .ok()
        .map(|msg| {
            msg.answers()
                .iter()
                .chain(msg.name_servers().iter())
                .map(|r| r.ttl())
                .min()
                // For locally-synthesized responses with no records (blocked NXDOMAIN/REFUSED,
                // IPv6-suppressed empty), use a reasonable TTL instead of 0 to avoid
                // forcing clients to re-query on every request.
                .unwrap_or(300)
        })
        .unwrap_or(0);

    // RFC 8484 §5.1: set max-age to minimum TTL from answer/authority sections
    let cache_control = format!("max-age={}", max_age);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/dns-message".to_string()),
            (header::CACHE_CONTROL, cache_control),
        ],
        response,
    )
        .into_response()
}

fn extract_client_ip(req: &axum::extract::Request) -> String {
    // Use actual peer address from TCP connection.
    // X-Forwarded-For is NOT trusted because any client can set it to spoof their IP
    // without a trusted proxy verification mechanism.
    if let Some(addr) = req.extensions().get::<std::net::SocketAddr>() {
        return addr.ip().to_string();
    }
    "doh-client".to_string()
}
