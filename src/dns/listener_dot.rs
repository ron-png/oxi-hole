use crate::blocklist::BlocklistManager;
use crate::config::BlockingMode;
use crate::dns::handler;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info};

/// Bind a TCP socket, optionally with SO_REUSEPORT for zero-downtime takeover.
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
    reuse_port: bool,
) -> anyhow::Result<()> {
    let listener = if reuse_port {
        let std_listener = bind_tcp_reuse_port(&addr)?;
        TcpListener::from_std(std_listener)?
    } else {
        TcpListener::bind(&addr).await?
    };
    let acceptor = TlsAcceptor::from(tls_config);
    info!("DoT listener ready on {}", addr);

    loop {
        let (tcp_stream, peer) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                error!("DoT accept error: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let bl = blocklist.clone();
        let st = stats.clone();
        let up = upstream.clone();
        let ft = features.clone();
        let bm = blocking_mode.clone();
        let ql = query_log.clone();
        let anon = anonymize_ip.clone();

        tokio::spawn(async move {
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
                    )
                    .await
                    {
                        debug!("DoT connection error from {}: {}", peer, e);
                    }
                }
                Err(e) => debug!("TLS handshake failed from {}: {}", peer, e),
            }
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
) -> anyhow::Result<()> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            anyhow::bail!("Invalid DNS message length: {}", msg_len);
        }

        let mut msg_buf = vec![0u8; msg_len];
        stream.read_exact(&mut msg_buf).await?;

        let response = handler::process_dns_query(
            &msg_buf,
            client_ip,
            blocklist,
            upstream,
            stats,
            features,
            blocking_mode,
            query_log,
            anonymize_ip,
        )
        .await?;

        let resp_len = (response.len() as u16).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}
