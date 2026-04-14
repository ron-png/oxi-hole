use crate::blocklist::BlocklistManager;
use crate::config::BlockingMode;
use crate::dns::handler;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

/// Idle timeout for plain TCP DNS connections in seconds (RFC 7766 §6.2.3).
const TCP_IDLE_TIMEOUT_SECS: u64 = 30;

/// Hard cap on total TCP DNS connection lifetime.  Prevents a constant-
/// keepalive client from squatting on a connection slot forever.
const TCP_MAX_CONNECTION_LIFETIME_SECS: u64 = 300;

/// Maximum DNS message size over TCP. DNS messages can be at most 65535 bytes
/// (limited by the 2-byte length prefix), but legitimate queries are far smaller.
/// Cap at 4096 to limit memory allocation from untrusted clients.
const MAX_DNS_TCP_MESSAGE_LEN: usize = 4096;

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
    query_log: QueryLog,
    anonymize_ip: Arc<AtomicBool>,
    ipv6_enabled: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let std_listener = bind_tcp_reuse_port(&addr)?;
    let listener = TcpListener::from_std(std_listener)?;
    let max_connections = crate::resources::limits().tcp_max_connections;
    let semaphore = Arc::new(Semaphore::new(max_connections));
    info!(
        "Plain TCP DNS listener ready on {} (max {} concurrent connections)",
        addr, max_connections
    );

    loop {
        let (tcp_stream, peer) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                error!("TCP DNS accept error: {}", e);
                continue;
            }
        };

        // Backpressure: drop under flood rather than spawning unbounded tasks.
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(
                    "TCP DNS connection limit reached ({}), dropping {}",
                    max_connections, peer
                );
                drop(tcp_stream);
                continue;
            }
        };

        let bl = blocklist.clone();
        let st = stats.clone();
        let up = upstream.clone();
        let ft = features.clone();
        let bm = blocking_mode.clone();
        let ql = query_log.clone();
        let anon = anonymize_ip.clone();
        let ipv6 = ipv6_enabled.clone();

        tokio::spawn(async move {
            let _permit = permit; // hold permit for task lifetime
            let peer_ip = peer.ip().to_string();
            let handler = handle_tcp_connection(
                tcp_stream, &peer_ip, &bl, &st, &up, &ft, &bm, &ql, &anon, &ipv6,
            );
            match tokio::time::timeout(
                Duration::from_secs(TCP_MAX_CONNECTION_LIFETIME_SECS),
                handler,
            )
            .await
            {
                Ok(Err(e)) => debug!("TCP DNS connection error from {}: {}", peer, e),
                Err(_) => debug!(
                    "TCP DNS connection from {} hit max-lifetime cap ({}s), closing",
                    peer, TCP_MAX_CONNECTION_LIFETIME_SECS
                ),
                Ok(Ok(())) => {}
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_connection(
    mut stream: tokio::net::TcpStream,
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
    let idle_timeout = Duration::from_secs(TCP_IDLE_TIMEOUT_SECS);

    loop {
        // RFC 1035 §4.2.2: 2-byte big-endian length prefix for TCP DNS
        // Apply idle timeout when waiting for next query (RFC 7766 §6.2.3)
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(idle_timeout, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("TCP DNS connection idle timeout for {}", client_ip);
                return Ok(());
            }
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > MAX_DNS_TCP_MESSAGE_LEN {
            anyhow::bail!("DNS TCP message length out of range: {}", msg_len);
        }

        // Apply timeout on body read to prevent partial-send connection exhaustion
        let mut msg_buf = vec![0u8; msg_len];
        match tokio::time::timeout(idle_timeout, stream.read_exact(&mut msg_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("TCP DNS body read timeout for {}", client_ip);
                return Ok(());
            }
        }

        let response = match handler::process_dns_query_bounded(
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
                handler::build_error_response(&msg_buf, rcode)
            }
        };

        let resp_len = u16::try_from(response.len()).map_err(|_| {
            anyhow::anyhow!(
                "DNS response too large for TCP framing: {} bytes",
                response.len()
            )
        })?;
        // Write length prefix + body as single buffer to avoid packet fragmentation (RFC 7766 §8)
        let mut framed = Vec::with_capacity(2 + response.len());
        framed.extend_from_slice(&resp_len.to_be_bytes());
        framed.extend_from_slice(&response);
        stream.write_all(&framed).await?;
        stream.flush().await?;
    }
}
