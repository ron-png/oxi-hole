mod blocklist;
mod config;
mod dns;
mod features;
mod stats;
mod tls;
mod update;
mod web;

use config::Config;
use std::path::PathBuf;
use tracing::info;

const VERSION: &str = match option_env!("OXI_HOLE_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Handle --version before anything else
    if let Some(arg) = std::env::args().nth(1) {
        if arg == "--version" || arg == "-V" {
            println!("oxi-hole {}", VERSION);
            return Ok(());
        }
    }

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "oxi_hole=info".into()),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    let config = Config::load(&config_path)?;

    info!("Starting Oxi-Hole DNS server v{}", VERSION);
    info!("DNS (UDP) listen: {}", config.dns.listen);
    if let Some(ref dot) = config.dns.dot_listen {
        info!("DNS-over-TLS listen: {}", dot);
    }
    if let Some(ref doh) = config.dns.doh_listen {
        info!("DNS-over-HTTPS listen: https://{}/dns-query", doh);
    }
    if let Some(ref doq) = config.dns.doq_listen {
        info!("DNS-over-QUIC listen: {}", doq);
    }
    info!("Web admin: http://{}", config.web.listen);
    info!("Upstreams: {:?}", config.dns.upstreams);
    info!(
        "Blocking: {} ({} blocklists, {} custom entries)",
        if config.blocking.enabled {
            "enabled"
        } else {
            "disabled"
        },
        config.blocking.blocklists.len(),
        config.blocking.custom_blocked.len(),
    );

    // Build TLS configs
    let needs_tls = config.dns.dot_listen.is_some()
        || config.dns.doh_listen.is_some()
        || config.dns.doq_listen.is_some();

    let server_tls_config = if needs_tls {
        Some(tls::build_server_config(&config.tls)?)
    } else {
        None
    };

    let quic_server_config = if config.dns.doq_listen.is_some() {
        Some(tls::build_quic_server_config(&config.tls)?)
    } else {
        None
    };

    let client_tls_config = tls::build_client_config()?;
    let quic_client_config = tls::build_quic_client_config()?;

    // Initialize blocklist manager
    let blocklist_manager = blocklist::BlocklistManager::new(config.blocking.enabled);
    blocklist_manager
        .load(
            &config.blocking.blocklists,
            &config.blocking.custom_blocked,
            &config.blocking.allowlist,
        )
        .await;

    // Build upstream forwarder
    let upstream = dns::upstream::UpstreamForwarder::new(
        &config.dns.upstreams,
        config.dns.timeout_ms,
        client_tls_config,
        quic_client_config,
    )?;

    // Initialize features (with upstream reference for root servers toggle)
    let mut feature_manager = features::FeatureManager::new(blocklist_manager.clone());
    feature_manager.set_upstream(upstream.clone());

    // Initialize stats
    let stats = stats::Stats::new(10_000);

    // Start DNS server (all protocols)
    let upstream_for_web = upstream.clone();
    let dns_server = dns::DnsServer::new(
        config.dns.clone(),
        blocklist_manager.clone(),
        stats.clone(),
        upstream,
        feature_manager.clone(),
        server_tls_config,
        quic_server_config,
    );

    let dns_handle = tokio::spawn(async move {
        if let Err(e) = dns_server.run().await {
            tracing::error!("DNS server error: {}", e);
        }
    });

    // Initialize update checker
    let update_checker = update::UpdateChecker::new();

    // Blocklist refresh interval (shared so web UI can change it)
    let blocklist_update_interval = std::sync::Arc::new(tokio::sync::RwLock::new(
        config.blocking.update_interval_minutes,
    ));

    // Spawn background blocklist refresh task
    {
        let bm = blocklist_manager.clone();
        let interval_lock = blocklist_update_interval.clone();
        tokio::spawn(async move {
            loop {
                let minutes = *interval_lock.read().await;
                if minutes == 0 {
                    // Disabled — check again in 60s to see if user re-enabled
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    continue;
                }
                tokio::time::sleep(std::time::Duration::from_secs(minutes * 60)).await;
                bm.refresh_sources().await;
            }
        });
    }

    // Restore enabled features from config
    for feature_id in &config.blocking.enabled_features {
        info!("Restoring feature: {}", feature_id);
        feature_manager.set_feature(feature_id, true).await;
    }

    // Start web server
    let web_state = web::AppState {
        blocklist: blocklist_manager,
        stats,
        features: feature_manager,
        upstream: upstream_for_web,
        auto_update: std::sync::Arc::new(tokio::sync::RwLock::new(config.system.auto_update)),
        update_checker,
        blocklist_update_interval,
        config_path: config_path.clone(),
    };

    let web_listen = config.web.listen.clone();
    let web_handle = tokio::spawn(async move {
        if let Err(e) = web::run_web_server(&web_listen, web_state).await {
            tracing::error!("Web server error: {}", e);
        }
    });

    let (dns_result, web_result) = tokio::join!(dns_handle, web_handle);
    if let Err(e) = dns_result {
        tracing::error!("DNS server task error: {}", e);
    }
    if let Err(e) = web_result {
        tracing::error!("Web server task error: {}", e);
    }

    Ok(())
}
