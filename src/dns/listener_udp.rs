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
) -> anyhow::Result<()> {
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
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
