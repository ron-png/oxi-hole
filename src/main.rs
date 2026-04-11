#[cfg(not(unix))]
compile_error!(
    "oxi-dns only supports Unix platforms (Linux, macOS, FreeBSD). Use Docker for other platforms."
);

mod acme;
mod auth;
mod blocklist;
mod cert_parser;
mod config;
mod dns;
mod features;
mod persistent_stats;
mod query_log;
mod reconfigure;
mod stats;
mod tls;
mod update;
mod web;

use config::Config;
use std::path::PathBuf;
use tracing::{info, warn};

const VERSION: &str = env!("OXIDNS_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI arguments
    let args: Vec<String> = std::env::args().collect();
    let mut health_check = false;
    let mut ready_file: Option<PathBuf> = None;
    let mut config_arg: Option<String> = None;
    let mut reconfigure_args: Vec<String> = Vec::new();
    let mut is_reconfigure = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => {
                println!("oxi-dns {}", VERSION);
                return Ok(());
            }
            "--health-check" => health_check = true,
            "--takeover" => {} // SO_REUSEPORT is always enabled; readiness signaled via --ready-file
            "--ready-file" => {
                i += 1;
                ready_file =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        anyhow::anyhow!("--ready-file requires a path")
                    })?));
            }
            "--reconfigure" => {
                is_reconfigure = true;
            }
            other => {
                if is_reconfigure && other.contains('=') {
                    reconfigure_args.push(other.to_string());
                } else if config_arg.is_none() && !other.starts_with('-') {
                    config_arg = Some(other.to_string());
                }
            }
        }
        i += 1;
    }

    let config_path = config_arg
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/oxi-dns/config.toml"));

    // Handle --reconfigure before any server initialization
    if is_reconfigure {
        if let Err(e) = reconfigure::run(&config_path, &reconfigure_args) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        return Ok(());
    }

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "oxi_dns=info".into()),
        )
        .init();

    let config = Config::load(&config_path)?;

    info!("Starting Oxi-DNS server v{}", VERSION);
    info!("DNS (UDP) listen: {:?}", config.dns.listen);
    if let Some(ref dot) = config.dns.dot_listen {
        info!("DNS-over-TLS listen: {:?}", dot);
    }
    if let Some(ref doh) = config.dns.doh_listen {
        info!("DNS-over-HTTPS listen: {:?}", doh);
    }
    if let Some(ref doq) = config.dns.doq_listen {
        info!("DNS-over-QUIC listen: {:?}", doq);
    }
    info!("Web admin: {:?}", config.web.listen);
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

    // Health-check mode: verify config loads, upstreams resolve, DNS works, then exit
    if health_check {
        info!("Running health check...");

        // Build TLS configs (needed for upstream)
        let client_tls_config = tls::build_client_config(vec![b"dot".to_vec()])?;
        let quic_client_config = tls::build_quic_client_config()?;

        // Build upstream forwarder (tests hostname resolution)
        let upstream = dns::upstream::UpstreamForwarder::new(
            &config.dns.upstreams,
            config.dns.timeout_ms,
            client_tls_config,
            quic_client_config,
        )?;
        upstream.set_cache_enabled(config.dns.cache_enabled);
        info!("Health check: upstreams OK");

        // Send a test DNS query through the upstream pipeline.
        // Uses example.com (RFC 2606 reserved — designed for testing, no tracking concerns).
        use hickory_proto::op::{Header, Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};

        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1234);
        header.set_message_type(MessageType::Query);
        header.set_op_code(OpCode::Query);
        header.set_recursion_desired(true);
        msg.set_header(header);
        let mut query = Query::new();
        query.set_name(Name::from_ascii("example.com.")?);
        query.set_query_type(RecordType::A);
        msg.add_query(query);
        let packet = msg.to_vec()?;

        // Retry transient network failures. Auto-update can fire during boot or
        // brief connectivity flaps — a single upstream blip shouldn't fail the
        // whole health check. Backoff grows: 300ms, 900ms.
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err: Option<anyhow::Error> = None;
        let mut resolved: Option<(Vec<u8>, String)> = None;
        for attempt in 1..=MAX_ATTEMPTS {
            match upstream.forward(&packet).await {
                Ok(r) => {
                    resolved = Some(r);
                    break;
                }
                Err(e) => {
                    warn!(
                        "Health check: test query attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, e
                    );
                    last_err = Some(e);
                    if attempt < MAX_ATTEMPTS {
                        let backoff = std::time::Duration::from_millis(300 * 3u64.pow(attempt - 1));
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }

        let (response_bytes, upstream_label) = resolved.ok_or_else(|| {
            last_err.unwrap_or_else(|| anyhow::anyhow!("test query failed"))
        })?;
        info!(
            "Health check: test query resolved via {} ({} bytes)",
            upstream_label,
            response_bytes.len()
        );

        info!("Health check passed");
        return Ok(());
    }

    // Build per-protocol TLS configs with correct ALPN
    let dot_tls_config = if config.dns.dot_listen.is_some() {
        // RFC 8310 / RFC 7858: advertise "dot" ALPN token
        Some(tls::build_server_config(
            &config.tls,
            vec![b"dot".to_vec()],
        )?)
    } else {
        None
    };

    let doh_tls_config = if config.dns.doh_listen.is_some() {
        // RFC 8484 §5.2: DoH MUST use HTTP/2 — only advertise h2
        Some(tls::build_server_config(&config.tls, vec![b"h2".to_vec()])?)
    } else {
        None
    };

    let quic_server_config = if config.dns.doq_listen.is_some() {
        Some(tls::build_quic_server_config(&config.tls)?)
    } else {
        None
    };

    // RFC 7858 §3.3: advertise "dot" ALPN for upstream DoT connections
    let client_tls_config = tls::build_client_config(vec![b"dot".to_vec()])?;
    let quic_client_config = tls::build_quic_client_config()?;

    // Initialize blocklist manager (loaded after DNS is ready to avoid bootstrap issues)
    let blocklist_manager = blocklist::BlocklistManager::new(config.blocking.enabled);

    // Build upstream forwarder
    let upstream = dns::upstream::UpstreamForwarder::new(
        &config.dns.upstreams,
        config.dns.timeout_ms,
        client_tls_config,
        quic_client_config,
    )?;
    upstream.set_cache_enabled(config.dns.cache_enabled);

    // Initialize features (with upstream reference for root servers toggle)
    let mut feature_manager = features::FeatureManager::new(blocklist_manager.clone());
    feature_manager.set_upstream(upstream.clone());

    // Open persistent stats database
    let stats_db_path = config_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("stats.db");
    let persistent_stats = persistent_stats::PersistentStats::open(&stats_db_path).await?;

    // Initialize stats
    let stats = stats::Stats::new(10_000, Some(persistent_stats.clone()));

    // Shared blocking mode (so web UI can change it at runtime)
    let blocking_mode = std::sync::Arc::new(tokio::sync::RwLock::new(
        config.blocking.blocking_mode.clone(),
    ));

    // Open persistent query log database
    let db_path = config_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("query_log.db");
    let query_log = query_log::QueryLog::open(&db_path).await?;

    // Open auth database
    let auth_db_path = config_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("auth.db");
    let auth_service = auth::AuthService::open(&auth_db_path).await?;

    // Shared log settings
    let anonymize_ip = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        config.log.anonymize_client_ip,
    ));
    let log_retention_days = std::sync::Arc::new(tokio::sync::RwLock::new(
        config.log.query_log_retention_days,
    ));
    let ipv6_enabled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        config.system.ipv6_enabled,
    ));
    let stats_retention_days =
        std::sync::Arc::new(tokio::sync::RwLock::new(config.log.stats_retention_days));

    // Start DNS server (all protocols)
    let upstream_for_web = upstream.clone();
    let (dns_ready_tx, dns_ready_rx) = tokio::sync::oneshot::channel::<()>();
    let dns_server = dns::DnsServer::new(
        config.dns.clone(),
        blocklist_manager.clone(),
        stats.clone(),
        upstream,
        feature_manager.clone(),
        blocking_mode.clone(),
        dot_tls_config,
        doh_tls_config,
        quic_server_config,
        Some(dns_ready_tx),
        query_log.clone(),
        anonymize_ip.clone(),
        ipv6_enabled.clone(),
    );

    let dns_handle = tokio::spawn(async move {
        if let Err(e) = dns_server.run().await {
            tracing::error!("DNS server error: {}", e);
        }
    });

    // Wait for DNS server to be ready before loading blocklists, so that
    // machines using oxi-dns as their own resolver can fetch remote lists.
    let _ = dns_ready_rx.await;

    // In takeover mode, signal readiness via ready file
    if let Some(ref path) = ready_file {
        if let Err(e) = std::fs::write(path, "ready") {
            tracing::error!("Failed to write ready file: {}", e);
        } else {
            info!("Takeover ready — wrote {}", path.display());
        }
    }

    // Load blocklists now that DNS is available
    blocklist_manager
        .load(
            &config.blocking.blocklists,
            &config.blocking.custom_blocked,
            &config.blocking.allowlist,
        )
        .await;

    // Mark initial load as a refresh so the timer starts from startup
    if !config.blocking.blocklists.is_empty() {
        blocklist_manager.finish_refresh().await;
    }

    // Initialize update checker
    let update_checker = update::UpdateChecker::new();

    // Blocklist refresh interval (shared so web UI can change it)
    let blocklist_update_interval = std::sync::Arc::new(tokio::sync::RwLock::new(
        config.blocking.update_interval_minutes,
    ));

    // Graceful restart signal (for web API to trigger zero-downtime restart)
    let (restart_tx, mut restart_rx) = tokio::sync::watch::channel(false);

    let release_channel = std::sync::Arc::new(tokio::sync::RwLock::new(
        config.system.release_channel.clone(),
    ));
    let (update_check_tx, mut update_check_rx) = tokio::sync::watch::channel(false);

    // Construct web_state early so background tasks can clone from it
    let web_state = web::AppState {
        blocklist: blocklist_manager,
        stats,
        features: feature_manager,
        upstream: upstream_for_web,
        auto_update: std::sync::Arc::new(tokio::sync::RwLock::new(config.system.auto_update)),
        update_checker,
        update_status: std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::update::UpdateStatus::default(),
        )),
        blocklist_update_interval,
        blocking_mode,
        config_path: config_path.clone(),
        query_log,
        log_retention_days,
        anonymize_ip,
        ipv6_enabled,
        auth: auth_service,
        auth_rate_limiter: web::RateLimiter::new(5, 60),
        admin_rate_limiter: web::RateLimiter::new(20, 60),
        restart_signal: restart_tx,
        release_channel: release_channel.clone(),
        update_check_signal: update_check_tx,
        persistent_stats: persistent_stats.clone(),
        stats_retention_days: stats_retention_days.clone(),
        acme: std::sync::Arc::new(crate::acme::AcmeState::new()),
    };

    // Spawn background blocklist refresh task
    {
        let bm = web_state.blocklist.clone();
        let interval_lock = web_state.blocklist_update_interval.clone();
        let upstream = web_state.upstream.clone();
        tokio::spawn(async move {
            // Track when the last refresh happened so interval changes take effect promptly
            let mut last_refresh = tokio::time::Instant::now();
            loop {
                // Check every 30 seconds whether a refresh is due
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let minutes = *interval_lock.read().await;
                if minutes == 0 {
                    // Disabled — reset timer so refresh triggers promptly when re-enabled
                    last_refresh = tokio::time::Instant::now();
                    continue;
                }
                let interval = std::time::Duration::from_secs(minutes * 60);
                if last_refresh.elapsed() >= interval {
                    bm.refresh_sources().await;
                    upstream.cache_flush();
                    last_refresh = tokio::time::Instant::now();
                }
            }
        });
    }

    // Spawn background log retention cleanup task (runs hourly)
    {
        let ql = web_state.query_log.clone();
        let retention = web_state.log_retention_days.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                let days = *retention.read().await;
                if let Err(e) = ql.purge_older_than(days).await {
                    tracing::warn!("Log retention purge failed: {}", e);
                }
            }
        });
    }

    // Spawn stats flush task (every 60 seconds)
    {
        let ps = persistent_stats.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(e) = ps.flush().await {
                    tracing::warn!("Stats flush failed: {}", e);
                }
            }
        });
    }

    // Spawn stats purge task (hourly)
    {
        let ps = persistent_stats.clone();
        let retention = stats_retention_days.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                let days = *retention.read().await;
                if let Err(e) = ps.purge_older_than(days).await {
                    tracing::warn!("Stats purge failed: {}", e);
                }
            }
        });
    }

    // Spawn background auto-update task
    {
        let auto_update_flag = web_state.auto_update.clone();
        let update_checker = web_state.update_checker.clone();
        let update_status = web_state.update_status.clone();
        let current_exe = std::env::current_exe().ok();
        let config_path_for_update = config_path.clone();
        let channel_lock = release_channel.clone();

        tokio::spawn(async move {
            loop {
                let channel = channel_lock.read().await.clone();
                let version_info = update_checker.check(true, &channel).await;

                if version_info.update_available {
                    if let Some(ref latest) = version_info.latest_version {
                        if *auto_update_flag.read().await {
                            let current_exe_path = match &current_exe {
                                Some(p) => p.clone(),
                                None => {
                                    tracing::warn!(
                                        "Auto-update: cannot determine current binary path"
                                    );
                                    tokio::time::sleep(crate::update::CHECK_INTERVAL).await;
                                    continue;
                                }
                            };

                            crate::update::perform_robust_update(
                                &update_checker,
                                &update_status,
                                &config_path_for_update,
                                &current_exe_path,
                                &channel,
                            )
                            .await;
                        } else {
                            info!(
                                "Update available: v{} (current: v{}). Enable auto-update or visit {} to update manually.",
                                latest,
                                version_info.current_version,
                                version_info.release_url.as_deref().unwrap_or("GitHub"),
                            );
                        }
                    }
                }

                // Wait for either the check interval OR an immediate check signal
                tokio::select! {
                    _ = tokio::time::sleep(crate::update::CHECK_INTERVAL) => {}
                    _ = update_check_rx.changed() => {
                        info!("Immediate update check triggered by channel change");
                    }
                }
            }
        });
    }

    // Spawn cache eviction task (every 60 seconds)
    {
        let upstream = web_state.upstream.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let removed = upstream.evict_expired();
                if removed > 0 {
                    tracing::debug!("Cache eviction: removed {} expired entries", removed);
                }
            }
        });
    }

    // Spawn ACME certificate renewal task (daily check)
    {
        let config_path = web_state.config_path.clone();
        let progress = web_state.acme.progress.clone();
        let manual_confirm = web_state.acme.manual_confirm.clone();
        let restart_signal = web_state.restart_signal.clone();
        tokio::spawn(async move {
            crate::acme::renewal_loop(config_path, progress, manual_confirm, restart_signal).await;
        });
    }

    // Spawn graceful restart watcher (triggered by web API for config changes)
    {
        let config_path_for_restart = config_path.clone();
        tokio::spawn(async move {
            loop {
                restart_rx.changed().await.ok();
                if !*restart_rx.borrow() {
                    continue;
                }

                info!("Graceful restart triggered by web API");
                let current_exe = match std::env::current_exe() {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!("Cannot determine binary path for restart: {}", e);
                        continue;
                    }
                };

                let ready_path = std::env::temp_dir().join("oxi-dns-restart.ready");
                let _ = std::fs::remove_file(&ready_path);

                let mut child = match tokio::process::Command::new(&current_exe)
                    .arg("--takeover")
                    .arg("--ready-file")
                    .arg(ready_path.to_str().unwrap())
                    .arg(
                        config_path_for_restart
                            .to_str()
                            .unwrap_or("/etc/oxi-dns/config.toml"),
                    )
                    .spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("Failed to spawn restart process: {}", e);
                        continue;
                    }
                };

                let mut ready = false;
                for _ in 0..120 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    match child.try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) => {}
                        Err(_) => break,
                    }
                    if ready_path.exists() {
                        ready = true;
                        break;
                    }
                }

                if ready {
                    info!("New process ready — shutting down for graceful restart");
                    let _ = std::fs::remove_file(&ready_path);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    std::process::exit(0);
                } else {
                    tracing::error!("Restart: new process failed to become ready within 60s");
                    let _ = child.kill().await;
                }
            }
        });
    }

    // Restore enabled features from config
    for feature_id in &config.blocking.enabled_features {
        info!("Restoring feature: {}", feature_id);
        web_state.features.set_feature(feature_id, true).await;
    }

    let web_listen = config.web.listen.clone();
    let web_https_listen = config.web.https_listen.clone();
    let auto_redirect_https = config.web.auto_redirect_https;
    let trust_forwarded_proto = config.web.trust_forwarded_proto;

    let web_tls_config = if web_https_listen.is_some() {
        match tls::build_server_config(&config.tls, vec![b"h2".to_vec(), b"http/1.1".to_vec()]) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                tracing::warn!("Failed to build web TLS config: {}. HTTPS disabled.", e);
                None
            }
        }
    } else {
        None
    };

    let web_handle = tokio::spawn(async move {
        if let Err(e) = web::run_web_server(
            &web_listen,
            web_https_listen.as_deref(),
            web_tls_config,
            auto_redirect_https,
            trust_forwarded_proto,
            web_state,
        )
        .await
        {
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
