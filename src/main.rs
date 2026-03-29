mod blocklist;
mod config;
mod dns;
mod features;
mod query_log;
mod stats;
mod tls;
mod update;
mod web;

use config::Config;
use std::path::PathBuf;
use tracing::info;

const VERSION: &str = env!("OXIHOLE_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI arguments
    let args: Vec<String> = std::env::args().collect();
    let mut health_check = false;
    let mut takeover = false;
    let mut ready_file: Option<PathBuf> = None;
    let mut config_arg: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => {
                println!("oxi-hole {}", VERSION);
                return Ok(());
            }
            "--health-check" => health_check = true,
            "--takeover" => takeover = true,
            "--ready-file" => {
                i += 1;
                ready_file = Some(PathBuf::from(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--ready-file requires a path"))?,
                ));
            }
            other => {
                if config_arg.is_none() && !other.starts_with('-') {
                    config_arg = Some(other.to_string());
                }
            }
        }
        i += 1;
    }

    let config_path = config_arg
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "oxi_hole=info".into()),
        )
        .init();

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

    // Health-check mode: verify config loads, upstreams resolve, DNS works, then exit
    if health_check {
        info!("Running health check...");

        // Build TLS configs (needed for upstream)
        let client_tls_config = tls::build_client_config()?;
        let quic_client_config = tls::build_quic_client_config()?;

        // Build upstream forwarder (tests hostname resolution)
        let upstream = dns::upstream::UpstreamForwarder::new(
            &config.dns.upstreams,
            config.dns.timeout_ms,
            client_tls_config,
            quic_client_config,
        )?;
        info!("Health check: upstreams OK");

        // Send a test DNS query through the upstream pipeline
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
        query.set_name(Name::from_ascii("dns.google.")?);
        query.set_query_type(RecordType::A);
        msg.add_query(query);
        let packet = msg.to_vec()?;

        let (response_bytes, upstream_label) = upstream.forward(&packet).await?;
        info!(
            "Health check: test query resolved via {} ({} bytes)",
            upstream_label,
            response_bytes.len()
        );

        info!("Health check passed");
        return Ok(());
    }

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

    // Initialize blocklist manager (loaded after DNS is ready to avoid bootstrap issues)
    let blocklist_manager = blocklist::BlocklistManager::new(config.blocking.enabled);

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

    // Shared log settings
    let anonymize_ip = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
        config.log.anonymize_client_ip,
    ));
    let log_retention_days =
        std::sync::Arc::new(tokio::sync::RwLock::new(config.log.retention_days));

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
        server_tls_config,
        quic_server_config,
        Some(dns_ready_tx),
        query_log.clone(),
        anonymize_ip.clone(),
    );

    let dns_handle = tokio::spawn(async move {
        if let Err(e) = dns_server.run().await {
            tracing::error!("DNS server error: {}", e);
        }
    });

    // Wait for DNS server to be ready before loading blocklists, so that
    // machines using oxi-hole as their own resolver can fetch remote lists.
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

    // Initialize update checker
    let update_checker = update::UpdateChecker::new();

    // Blocklist refresh interval (shared so web UI can change it)
    let blocklist_update_interval = std::sync::Arc::new(tokio::sync::RwLock::new(
        config.blocking.update_interval_minutes,
    ));

    // Construct web_state early so background tasks can clone from it
    let web_state = web::AppState {
        blocklist: blocklist_manager,
        stats,
        features: feature_manager,
        upstream: upstream_for_web,
        auto_update: std::sync::Arc::new(tokio::sync::RwLock::new(config.system.auto_update)),
        update_checker,
        update_status: std::sync::Arc::new(tokio::sync::RwLock::new(crate::update::UpdateStatus::default())),
        blocklist_update_interval,
        blocking_mode,
        config_path: config_path.clone(),
        query_log,
        log_retention_days,
        anonymize_ip,
    };

    // Spawn background blocklist refresh task
    {
        let bm = web_state.blocklist.clone();
        let interval_lock = web_state.blocklist_update_interval.clone();
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

    // Spawn background auto-update task
    {
        let auto_update_flag = web_state.auto_update.clone();
        let update_checker = web_state.update_checker.clone();
        let update_status = web_state.update_status.clone();
        let current_exe = std::env::current_exe().ok();
        let config_path_for_update = config_path.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(crate::update::CHECK_INTERVAL).await;

                if !*auto_update_flag.read().await {
                    continue;
                }

                info!("Auto-update: checking for updates...");
                {
                    let mut s = update_status.write().await;
                    s.state = crate::update::UpdateState::Checking;
                    s.last_attempt = Some(std::time::Instant::now());
                }

                // Check for update
                let info = update_checker.check(true).await;
                if !info.update_available {
                    let mut s = update_status.write().await;
                    s.state = crate::update::UpdateState::Idle;
                    continue;
                }

                let latest_version = match info.latest_version {
                    Some(v) => v,
                    None => {
                        let mut s = update_status.write().await;
                        s.state = crate::update::UpdateState::Idle;
                        continue;
                    }
                };

                info!("Auto-update: v{} available, downloading...", latest_version);
                {
                    let mut s = update_status.write().await;
                    s.state = crate::update::UpdateState::Downloading;
                }

                // Download to temp path
                let (tmp_path, version) = match update_checker.download_update().await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("Auto-update: download failed: {}", e);
                        let mut s = update_status.write().await;
                        s.state = crate::update::UpdateState::Failed;
                        s.message = Some(format!("Download failed: {}", e));
                        continue;
                    }
                };

                // Health check
                info!("Auto-update: running health check on v{}...", version);
                {
                    let mut s = update_status.write().await;
                    s.state = crate::update::UpdateState::HealthChecking;
                }

                let mut health_child = match tokio::process::Command::new(&tmp_path)
                    .arg("--health-check")
                    .arg(config_path_for_update.to_str().unwrap_or("config.toml"))
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                {
                    Ok(child) => child,
                    Err(e) => {
                        tracing::warn!("Auto-update: health check failed to run: {}", e);
                        let mut s = update_status.write().await;
                        s.state = crate::update::UpdateState::Failed;
                        s.message = Some(format!("Health check failed to run: {}", e));
                        s.logs = Some(e.to_string());
                        continue;
                    }
                };

                let health_output = match tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    health_child.wait_with_output(),
                )
                .await
                {
                    Ok(Ok(output)) => output,
                    Ok(Err(e)) => {
                        tracing::warn!("Auto-update: health check failed: {}", e);
                        let _ = health_child.kill().await;
                        let mut s = update_status.write().await;
                        s.state = crate::update::UpdateState::Failed;
                        s.message = Some(format!("Health check failed: {}", e));
                        s.logs = Some(e.to_string());
                        continue;
                    }
                    Err(_) => {
                        tracing::warn!("Auto-update: health check timed out (30s), killing child process");
                        let _ = health_child.kill().await;
                        let mut s = update_status.write().await;
                        s.state = crate::update::UpdateState::Failed;
                        s.message =
                            Some("Health check timed out after 30 seconds".to_string());
                        continue;
                    }
                };

                let health_logs = format!(
                    "stdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&health_output.stdout),
                    String::from_utf8_lossy(&health_output.stderr)
                );

                if !health_output.status.success() {
                    tracing::warn!(
                        "Auto-update: health check failed (exit code {:?})",
                        health_output.status.code()
                    );
                    let mut s = update_status.write().await;
                    s.state = crate::update::UpdateState::Failed;
                    s.message = Some(format!(
                        "Health check failed with exit code {}",
                        health_output.status.code().unwrap_or(-1)
                    ));
                    s.logs = Some(health_logs);
                    continue;
                }

                info!("Auto-update: health check passed, replacing binary...");

                // Replace current binary
                let current_exe_path = match &current_exe {
                    Some(p) => p.clone(),
                    None => {
                        let mut s = update_status.write().await;
                        s.state = crate::update::UpdateState::Failed;
                        s.message =
                            Some("Cannot determine current binary path".to_string());
                        continue;
                    }
                };

                let binary_bytes = match std::fs::read(&tmp_path) {
                    Ok(b) => b,
                    Err(e) => {
                        let mut s = update_status.write().await;
                        s.state = crate::update::UpdateState::Failed;
                        s.message = Some(format!("Failed to read temp binary: {}", e));
                        continue;
                    }
                };

                if let Err(e) =
                    crate::update::try_replace_binary(&current_exe_path, &binary_bytes)
                {
                    let mut s = update_status.write().await;
                    s.state = crate::update::UpdateState::Failed;
                    s.message = Some(format!("Failed to replace binary: {}", e));
                    continue;
                }

                // Clean up temp binary
                let _ = std::fs::remove_file(&tmp_path);

                // Start new binary with --takeover
                info!("Auto-update: starting v{} with --takeover...", version);
                {
                    let mut s = update_status.write().await;
                    s.state = crate::update::UpdateState::Restarting;
                }

                let ready_path = std::path::PathBuf::from("/tmp/oxi-hole.ready");
                let _ = std::fs::remove_file(&ready_path);

                let child = tokio::process::Command::new(&current_exe_path)
                    .arg("--takeover")
                    .arg("--ready-file")
                    .arg(ready_path.to_str().unwrap())
                    .arg(config_path_for_update.to_str().unwrap_or("config.toml"))
                    .spawn();

                let mut child = match child {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(
                            "Auto-update: failed to start new process: {}",
                            e
                        );
                        let mut s = update_status.write().await;
                        s.state = crate::update::UpdateState::Failed;
                        s.message =
                            Some(format!("Failed to start new process: {}", e));
                        continue;
                    }
                };

                // Wait for ready file (poll every 500ms, up to 60s)
                let mut ready = false;
                for _ in 0..120 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                    match child.try_wait() {
                        Ok(Some(status)) => {
                            tracing::warn!(
                                "Auto-update: new process exited early with {:?}",
                                status
                            );
                            let mut s = update_status.write().await;
                            s.state = crate::update::UpdateState::Failed;
                            s.message =
                                Some(format!("New process exited with {:?}", status));
                            break;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::warn!(
                                "Auto-update: failed to check child: {}",
                                e
                            );
                            break;
                        }
                    }

                    if ready_path.exists() {
                        ready = true;
                        break;
                    }
                }

                if ready {
                    tracing::warn!(
                        "Auto-update: v{} is ready, handing off — goodbye!",
                        version
                    );
                    let _ = std::fs::remove_file(&ready_path);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    std::process::exit(0);
                } else {
                    tracing::warn!(
                        "Auto-update: new process failed to become ready within 60s"
                    );
                    let _ = child.kill().await;
                    let mut s = update_status.write().await;
                    if s.state != crate::update::UpdateState::Failed {
                        s.state = crate::update::UpdateState::Failed;
                        s.message = Some(
                            "New process failed to become ready within 60 seconds"
                                .to_string(),
                        );
                    }
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
