use crate::blocklist::BlocklistManager;
use crate::config::BlockingMode;
use crate::dns::handler;
use crate::dns::upstream::UpstreamForwarder;
use crate::features::FeatureManager;
use crate::query_log::QueryLog;
use crate::stats::Stats;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error};

/// Bind a UDP socket, optionally with SO_REUSEPORT for zero-downtime takeover.
fn bind_udp_reuse_port(addr: &str) -> anyhow::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock_addr: std::net::SocketAddr = addr.parse()?;
    let domain = if sock_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&sock_addr.into())?;
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
    ready_tx: Option<tokio::sync::oneshot::Sender<()>>,
    query_log: QueryLog,
    anonymize_ip: Arc<AtomicBool>,
    reuse_port: bool,
) -> anyhow::Result<()> {
    let socket = if reuse_port {
        let std_socket = bind_udp_reuse_port(&addr)?;
        Arc::new(UdpSocket::from_std(std_socket)?)
    } else {
        Arc::new(UdpSocket::bind(&addr).await?)
    };
    if let Some(tx) = ready_tx {
        let _ = tx.send(());
    }
    let mut buf = vec![0u8; 4096];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                error!("UDP recv error: {}", e);
                continue;
            }
        };

        let packet = buf[..len].to_vec();
        let sock = socket.clone();
        let bl = blocklist.clone();
        let st = stats.clone();
        let up = upstream.clone();
        let ft = features.clone();
        let bm = blocking_mode.clone();
        let ql = query_log.clone();
        let anon = anonymize_ip.clone();

        tokio::spawn(async move {
            let client_ip = src.ip().to_string();
            match handler::process_dns_query(
                &packet, &client_ip, &bl, &up, &st, &ft, &bm, &ql, &anon,
            )
            .await
            {
                Ok(response) => {
                    if let Err(e) = sock.send_to(&response, src).await {
                        debug!("Failed to send UDP response to {}: {}", src, e);
                    }
                }
                Err(e) => debug!("Error handling UDP query from {}: {}", src, e),
            }
        });
    }
}
