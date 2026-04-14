use crate::blocklist::BlocklistManager;
use crate::config::BlockingMode;
use crate::dns::handler;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

/// Idle timeout for DoT connections in seconds (RFC 7858 §3.4).
const DOT_IDLE_TIMEOUT_SECS: u64 = 30;

/// Maximum DNS message size over DoT. Cap at 4096 to limit memory allocation
/// from untrusted clients (legitimate DNS queries are far smaller).
const MAX_DOT_MESSAGE_LEN: usize = 4096;

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
    let std_listener = bind_tcp_reuse_port(&addr)?;
    let listener = TcpListener::from_std(std_listener)?;
    let acceptor = TlsAcceptor::from(tls_config);
    let active_connections = Arc::new(AtomicUsize::new(0));
    let max_connections = crate::resources::limits().dot_max_connections;
    info!(
        "DoT listener ready on {} (max {} concurrent connections)",
        addr, max_connections
    );

    loop {
        let (tcp_stream, peer) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                error!("DoT accept error: {}", e);
                continue;
            }
        };

        // Enforce connection limit (RFC 7858 §3.4)
        // Increment first, then check — avoids TOCTOU race where a burst of accepts
        // all see count < MAX and all pass the guard.
        let conn_count = active_connections.clone();
        let prev = conn_count.fetch_add(1, Ordering::AcqRel);
        if prev >= max_connections {
            conn_count.fetch_sub(1, Ordering::AcqRel);
            warn!(
                "DoT connection limit reached ({}), rejecting {}",
                max_connections, peer
            );
            drop(tcp_stream);
            continue;
        }

        let acceptor = acceptor.clone();
        let bl = blocklist.clone();
        let st = stats.clone();
        let up = upstream.clone();
        let ft = features.clone();
        let bm = blocking_mode.clone();
        let ql = query_log.clone();
        let anon = anonymize_ip.clone();
        let ipv6 = ipv6_enabled.clone();

        tokio::spawn(async move {
            let result = async {
                match acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        if let Err(e) = handle_dot_connection(
                            tls_stream,
                            &peer.ip().to_string(),
                            &bl,
                            &st,
                            &up,
                            &ft,
                            &bm,
                            &ql,
                            &anon,
                            &ipv6,
                        )
                        .await
                        {
                            debug!("DoT connection error from {}: {}", peer, e);
                        }
                    }
                    Err(e) => debug!("TLS handshake failed from {}: {}", peer, e),
                }
            }
            .await;
            conn_count.fetch_sub(1, Ordering::AcqRel);
            result
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_dot_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    client_ip: &str,
    blocklist: &BlocklistManager,
    stats: &Stats,
    upstream: &UpstreamForwarder,
    features: &FeatureManager,
    blocking_mode: &Arc<RwLock<BlockingMode>>,
    query_log: &QueryLog,
    anonymize_ip: &Arc<AtomicBool>,
    ipv6_enabled: &Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let idle_timeout = Duration::from_secs(DOT_IDLE_TIMEOUT_SECS);

    loop {
        // Apply idle timeout when waiting for next query (RFC 7858 §3.4)
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(idle_timeout, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("DoT connection idle timeout for {}", client_ip);
                return Ok(());
            }
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > MAX_DOT_MESSAGE_LEN {
            anyhow::bail!("DoT message length out of range: {}", msg_len);
        }

        // Apply timeout on body read to prevent partial-send connection exhaustion (RFC 7858 §3.4)
        let mut msg_buf = vec![0u8; msg_len];
        match tokio::time::timeout(idle_timeout, stream.read_exact(&mut msg_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("DoT body read timeout for {}", client_ip);
                return Ok(());
            }
        }

        let response = match handler::process_dns_query(
            &msg_buf,
            client_ip,
            blocklist,
            upstream,
            stats,
            features,
            blocking_mode,
            query_log,
            anonymize_ip,
            ipv6_enabled,
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => {
                use hickory_proto::op::ResponseCode;
                let rcode = match &e {
                    handler::DnsError::ParseError(_) => ResponseCode::FormErr,
                    handler::DnsError::ServerError(_) => ResponseCode::ServFail,
                };
                debug!("DoT query error ({}): {}", rcode, e);
                handler::build_error_response(&msg_buf, rcode)
            }
        };

        let resp_len = u16::try_from(response.len()).map_err(|_| {
            anyhow::anyhow!(
                "DNS response too large for DoT framing: {} bytes",
                response.len()
            )
        })?;
        // Write length prefix + body as single buffer to avoid packet fragmentation
        let mut framed = Vec::with_capacity(2 + response.len());
        framed.extend_from_slice(&resp_len.to_be_bytes());
        framed.extend_from_slice(&response);
        stream.write_all(&framed).await?;
        stream.flush().await?;
    }
}
