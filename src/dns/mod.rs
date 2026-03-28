pub mod handler;
pub mod upstream;

mod listener_doh;
mod listener_doq;
mod listener_dot;
mod listener_udp;

use crate::blocklist::BlocklistManager;
use crate::config::DnsConfig;
use crate::features::FeatureManager;
use crate::stats::Stats;
use std::sync::Arc;
use tracing::info;
use upstream::UpstreamForwarder;

/// Central DNS server that manages all listener protocols.
pub struct DnsServer {
    config: DnsConfig,
    blocklist: BlocklistManager,
    stats: Stats,
    upstream: UpstreamForwarder,
    features: FeatureManager,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    quic_config: Option<quinn::ServerConfig>,
}

impl DnsServer {
    pub fn new(
        config: DnsConfig,
        blocklist: BlocklistManager,
        stats: Stats,
        upstream: UpstreamForwarder,
        features: FeatureManager,
        tls_config: Option<Arc<rustls::ServerConfig>>,
        quic_config: Option<quinn::ServerConfig>,
    ) -> Self {
        Self {
            config,
            blocklist,
            stats,
            upstream,
            features,
            tls_config,
            quic_config,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let mut handles = Vec::new();

        // Always start plain UDP listener
        {
            let addr = self.config.listen.clone();
            let bl = self.blocklist.clone();
            let st = self.stats.clone();
            let up = self.upstream.clone();
            let ft = self.features.clone();
            info!("Starting plain DNS (UDP) on {}", addr);
            handles.push(tokio::spawn(async move {
                if let Err(e) = listener_udp::run(addr, bl, st, up, ft).await {
                    tracing::error!("UDP DNS listener error: {}", e);
                }
            }));
        }

        // DNS-over-TLS listener
        if let (Some(dot_addr), Some(tls_config)) = (&self.config.dot_listen, &self.tls_config) {
            let addr = dot_addr.clone();
            let bl = self.blocklist.clone();
            let st = self.stats.clone();
            let up = self.upstream.clone();
            let ft = self.features.clone();
            let tls = tls_config.clone();
            info!("Starting DNS-over-TLS on {}", addr);
            handles.push(tokio::spawn(async move {
                if let Err(e) = listener_dot::run(addr, bl, st, up, ft, tls).await {
                    tracing::error!("DoT listener error: {}", e);
                }
            }));
        }

        // DNS-over-HTTPS listener
        if let (Some(doh_addr), Some(tls_config)) = (&self.config.doh_listen, &self.tls_config) {
            let addr = doh_addr.clone();
            let bl = self.blocklist.clone();
            let st = self.stats.clone();
            let up = self.upstream.clone();
            let ft = self.features.clone();
            let tls = tls_config.clone();
            info!("Starting DNS-over-HTTPS on {}", addr);
            handles.push(tokio::spawn(async move {
                if let Err(e) = listener_doh::run(addr, bl, st, up, ft, tls).await {
                    tracing::error!("DoH listener error: {}", e);
                }
            }));
        }

        // DNS-over-QUIC listener
        if let Some(doq_addr) = &self.config.doq_listen {
            if let Some(quic_config) = self.quic_config {
                let addr = doq_addr.clone();
                let bl = self.blocklist.clone();
                let st = self.stats.clone();
                let up = self.upstream.clone();
                let ft = self.features.clone();
                info!("Starting DNS-over-QUIC on {}", addr);
                handles.push(tokio::spawn(async move {
                    if let Err(e) = listener_doq::run(addr, bl, st, up, ft, quic_config).await {
                        tracing::error!("DoQ listener error: {}", e);
                    }
                }));
            } else {
                tracing::warn!("DoQ listen address configured but no TLS config available");
            }
        }

        let results = futures::future::join_all(handles).await;
        for result in results {
            if let Err(e) = result {
                tracing::error!("Listener task error: {}", e);
            }
        }

        Ok(())
    }
}
