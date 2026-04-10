# Certificate Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ACME/Let's Encrypt certificate issuance with DNS-01 challenge support (Cloudflare + manual), auto-renewal, and a consolidated certificate management modal in the Advanced tab.

**Architecture:** A new `src/acme.rs` module handles ACME protocol interactions using `instant-acme`. DNS provider logic (Cloudflare API, manual polling) lives in `src/acme/providers.rs`. A background tokio task checks cert expiry daily and auto-renews. The dashboard modal consolidates all cert management (status, ACME, manual upload) behind a single button in the Advanced tab.

**Tech Stack:** `instant-acme` (ACME protocol), `reqwest` (Cloudflare API calls), existing `cert_parser` + `tls` modules for cert persistence and reload.

**Spec:** `docs/superpowers/specs/2026-04-10-certificate-management-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `Cargo.toml` | Modify | Add `instant-acme` dependency |
| `src/config.rs` | Modify | Add `AcmeConfig` struct nested in `TlsConfig` |
| `src/acme/mod.rs` | Create | ACME orchestration: issue, renew, challenge coordination |
| `src/acme/providers.rs` | Create | Cloudflare DNS API + manual challenge polling |
| `src/main.rs` | Modify | Register `acme` module, spawn renewal background task |
| `src/web/mod.rs` | Modify | Add ACME API endpoints, add ACME state to `AppState` |
| `src/web/dashboard.html` | Modify | Remove TLS section from System Settings, add button + modal in Advanced tab |

---

### Task 1: Add `instant-acme` dependency and `AcmeConfig`

**Files:**
- Modify: `Cargo.toml:36` (after `rcgen`)
- Modify: `src/config.rs:85-93` (extend `TlsConfig`)

- [ ] **Step 1: Add instant-acme to Cargo.toml**

In `Cargo.toml`, after the `rcgen = "0.13"` line (line 36), add:

```toml
instant-acme = "0.8"
```

- [ ] **Step 2: Add AcmeConfig struct to config.rs**

In `src/config.rs`, add the `AcmeConfig` struct just before the existing `TlsConfig` struct (before line 85):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub email: String,
    /// "cloudflare" or "manual"
    #[serde(default = "default_acme_provider")]
    pub provider: String,
    #[serde(default)]
    pub cloudflare_api_token: String,
    #[serde(default)]
    pub use_staging: bool,
    #[serde(default)]
    pub last_renewed: String,
    #[serde(default)]
    pub last_renewal_error: String,
}

fn default_acme_provider() -> String {
    "cloudflare".to_string()
}
```

- [ ] **Step 3: Add acme field to TlsConfig**

Modify the existing `TlsConfig` struct to include the new field:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub acme: AcmeConfig,
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check`
Expected: Compiles successfully (AcmeConfig is Default, so existing configs without `[tls.acme]` will work)

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/config.rs
git commit -m "feat: add instant-acme dependency and AcmeConfig struct"
```

---

### Task 2: Create ACME providers module (Cloudflare + manual)

**Files:**
- Create: `src/acme/providers.rs`

- [ ] **Step 1: Create src/acme directory**

```bash
mkdir -p src/acme
```

- [ ] **Step 2: Write providers.rs**

Create `src/acme/providers.rs`:

```rust
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::time::Duration;
use tracing::{info, warn};

// ── Cloudflare DNS-01 Provider ──────────────────────────────────────────

const CF_API: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareProvider {
    token: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    errors: Vec<CfError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct CfError {
    message: String,
}

#[derive(Deserialize)]
struct CfZone {
    id: String,
}

#[derive(Deserialize)]
struct CfDnsRecord {
    id: String,
}

impl CloudflareProvider {
    pub fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Find the Cloudflare zone ID for the given domain.
    /// Walks up the domain labels to find the zone (e.g. sub.example.com → example.com).
    async fn find_zone_id(&self, domain: &str) -> Result<String> {
        let mut labels: Vec<&str> = domain.split('.').collect();
        while labels.len() >= 2 {
            let zone_name = labels.join(".");
            let url = format!("{}/zones?name={}", CF_API, zone_name);
            let resp: CfResponse<Vec<CfZone>> = self
                .client
                .get(&url)
                .bearer_auth(&self.token)
                .send()
                .await?
                .json()
                .await?;

            if !resp.success {
                let msgs: Vec<String> = resp.errors.iter().map(|e| e.message.clone()).collect();
                bail!("Cloudflare API error: {}", msgs.join(", "));
            }

            if let Some(zones) = resp.result {
                if let Some(zone) = zones.into_iter().next() {
                    return Ok(zone.id);
                }
            }
            labels.remove(0);
        }
        bail!("No Cloudflare zone found for domain: {}", domain)
    }

    /// Create the _acme-challenge TXT record. Returns the record ID for cleanup.
    pub async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        let zone_id = self.find_zone_id(domain).await?;
        let record_name = format!("_acme-challenge.{}", domain);

        let url = format!("{}/zones/{}/dns_records", CF_API, zone_id);
        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120,
        });

        let resp: CfResponse<CfDnsRecord> = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            let msgs: Vec<String> = resp.errors.iter().map(|e| e.message.clone()).collect();
            bail!("Cloudflare create TXT failed: {}", msgs.join(", "));
        }

        let record = resp.result.context("Cloudflare returned no record")?;
        info!(
            "Created Cloudflare TXT record {} = {}",
            record_name, value
        );
        Ok(record.id)
    }

    /// Delete the TXT record after validation.
    pub async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()> {
        let zone_id = self.find_zone_id(domain).await?;
        let url = format!("{}/zones/{}/dns_records/{}", CF_API, zone_id, record_id);

        let resp: CfResponse<serde_json::Value> = self
            .client
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .json()
            .await?;

        if !resp.success {
            let msgs: Vec<String> = resp.errors.iter().map(|e| e.message.clone()).collect();
            warn!("Cloudflare delete TXT failed: {}", msgs.join(", "));
        }
        Ok(())
    }
}

// ── Manual DNS-01 Challenge ─────────────────────────────────────────────

/// Poll DNS for the expected TXT record using the system resolver.
/// Returns true if the record was found.
pub async fn poll_dns_txt_record(domain: &str, expected_value: &str) -> bool {
    let record_name = format!("_acme-challenge.{}", domain);
    // Use a simple DNS lookup via the system resolver (tokio's built-in)
    match tokio::net::lookup_host(format!("{}:0", record_name)).await {
        // lookup_host resolves A/AAAA, not TXT. Use hickory for TXT lookup.
        _ => {}
    }

    // Use hickory-proto to do a proper TXT query
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::net::UdpSocket;

    let name = match Name::from_ascii(&format!("{}.", record_name)) {
        Ok(n) => n,
        Err(_) => return false,
    };

    let mut msg = Message::new();
    msg.set_id(rand::random::<u16>());
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, RecordType::TXT));

    let packet = match msg.to_vec() {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Query well-known public resolvers to check propagation
    let resolvers = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
    ];

    for resolver in &resolvers {
        let sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => continue,
        };

        if sock.send_to(&packet, resolver).await.is_err() {
            continue;
        }

        let mut buf = vec![0u8; 4096];
        let result = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await;

        if let Ok(Ok((len, _))) = result {
            if let Ok(response) = Message::from_vec(&buf[..len]) {
                for record in response.answers() {
                    if let RData::TXT(ref txt) = *record.data() {
                        let txt_str = txt
                            .iter()
                            .map(|b| String::from_utf8_lossy(b).to_string())
                            .collect::<Vec<_>>()
                            .join("");
                        if txt_str == expected_value {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check`
Expected: Will not compile yet — needs `mod.rs` (next task)

- [ ] **Step 4: Commit**

```bash
git add src/acme/providers.rs
git commit -m "feat: add Cloudflare DNS provider and manual TXT polling"
```

---

### Task 3: Create ACME orchestration module

**Files:**
- Create: `src/acme/mod.rs`
- Modify: `src/main.rs` (add `mod acme;`)

- [ ] **Step 1: Write src/acme/mod.rs**

Create `src/acme/mod.rs`:

```rust
pub mod providers;

use anyhow::{bail, Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, KeyAuthorization, NewAccount,
    NewOrder, OrderStatus,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::cert_parser;
use crate::config::{AcmeConfig, Config};

/// Tracks the progress of an active ACME issuance.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IssuanceProgress {
    pub state: IssuanceState,
    pub message: String,
    /// For manual mode: the TXT record name and value to create.
    pub challenge_record_name: Option<String>,
    pub challenge_record_value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssuanceState {
    Idle,
    CreatingAccount,
    PlacingOrder,
    WaitingForChallenge,
    Validating,
    Downloading,
    Installing,
    Complete,
    Failed,
}

impl Default for IssuanceProgress {
    fn default() -> Self {
        Self {
            state: IssuanceState::Idle,
            message: String::new(),
            challenge_record_name: None,
            challenge_record_value: None,
        }
    }
}

/// Shared ACME state for the web server.
pub struct AcmeState {
    pub progress: Arc<RwLock<IssuanceProgress>>,
    /// Signal set when the manual user confirms TXT record creation.
    pub manual_confirm: Arc<tokio::sync::Notify>,
}

impl AcmeState {
    pub fn new() -> Self {
        Self {
            progress: Arc::new(RwLock::new(IssuanceProgress::default())),
            manual_confirm: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

const CERT_PATH: &str = "/etc/oxi-dns/cert.pem";
const KEY_PATH: &str = "/etc/oxi-dns/key.pem";

/// Run the full ACME issuance flow.
pub async fn issue_certificate(
    acme_config: &AcmeConfig,
    progress: Arc<RwLock<IssuanceProgress>>,
    manual_confirm: Arc<tokio::sync::Notify>,
) -> Result<()> {
    let domain = &acme_config.domain;
    if domain.is_empty() {
        bail!("Domain is required");
    }
    if acme_config.email.is_empty() {
        bail!("Email is required");
    }

    // Step 1: Create ACME account
    set_progress(&progress, IssuanceState::CreatingAccount, "Creating ACME account...").await;

    let directory_url = if acme_config.use_staging {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    } else {
        "https://acme-v02.api.letsencrypt.org/directory"
    };

    let (account, _credentials) = Account::create(
        &NewAccount {
            contact: &[&format!("mailto:{}", acme_config.email)],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        directory_url,
        None,
    )
    .await
    .context("Failed to create ACME account")?;

    // Step 2: Place order
    set_progress(&progress, IssuanceState::PlacingOrder, "Placing certificate order...").await;

    let identifier = Identifier::Dns(domain.clone());
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .await
        .context("Failed to create order")?;

    let authorizations = order
        .authorizations()
        .await
        .context("Failed to get authorizations")?;

    // Step 3: Handle DNS-01 challenge
    set_progress(
        &progress,
        IssuanceState::WaitingForChallenge,
        "Setting up DNS challenge...",
    )
    .await;

    let mut challenge_url = String::new();
    let mut key_auth_value = String::new();
    let mut cf_record_id: Option<String> = None;

    for auth in &authorizations {
        if matches!(auth.status, AuthorizationStatus::Valid) {
            continue;
        }

        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .context("No DNS-01 challenge available")?;

        challenge_url = challenge.url.clone();
        let key_authorization = order.key_authorization(challenge);
        key_auth_value = key_authorization.dns_value();

        let record_name = format!("_acme-challenge.{}", domain);

        match acme_config.provider.as_str() {
            "cloudflare" => {
                if acme_config.cloudflare_api_token.is_empty() {
                    bail!("Cloudflare API token is required");
                }
                let cf = providers::CloudflareProvider::new(&acme_config.cloudflare_api_token);
                let rid = cf
                    .create_txt_record(domain, &key_auth_value)
                    .await
                    .context("Failed to create Cloudflare TXT record")?;
                cf_record_id = Some(rid);

                // Wait for DNS propagation
                set_progress(
                    &progress,
                    IssuanceState::WaitingForChallenge,
                    "Waiting for DNS propagation...",
                )
                .await;
                wait_for_dns_propagation(domain, &key_auth_value).await;
            }
            "manual" | _ => {
                // Show challenge details to user and wait
                {
                    let mut p = progress.write().await;
                    p.state = IssuanceState::WaitingForChallenge;
                    p.message =
                        "Create this DNS TXT record at your DNS provider:".to_string();
                    p.challenge_record_name = Some(record_name.clone());
                    p.challenge_record_value = Some(key_auth_value.clone());
                }

                // Wait for either manual confirm or DNS polling detection
                let confirm = manual_confirm.clone();
                let poll_domain = domain.clone();
                let poll_value = key_auth_value.clone();

                tokio::select! {
                    _ = confirm.notified() => {
                        info!("ACME: Manual confirmation received");
                    }
                    _ = async {
                        loop {
                            tokio::time::sleep(Duration::from_secs(15)).await;
                            if providers::poll_dns_txt_record(&poll_domain, &poll_value).await {
                                info!("ACME: TXT record detected via polling");
                                break;
                            }
                        }
                    } => {}
                    _ = tokio::time::sleep(Duration::from_secs(600)) => {
                        bail!("Timeout: TXT record not detected after 10 minutes");
                    }
                }
            }
        }
    }

    // Step 4: Notify ACME server challenge is ready
    set_progress(&progress, IssuanceState::Validating, "Validating challenge...").await;

    order
        .set_challenge_ready(&challenge_url)
        .await
        .context("Failed to set challenge ready")?;

    // Poll order status until ready
    let mut tries = 0u8;
    let order_state = loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let state = order.refresh().await.context("Failed to refresh order")?;
        if matches!(state.status, OrderStatus::Ready | OrderStatus::Valid) {
            break state;
        }
        if matches!(state.status, OrderStatus::Invalid) {
            bail!("ACME order became invalid — check domain and DNS records");
        }
        tries += 1;
        if tries > 30 {
            bail!("ACME order validation timed out");
        }
    };

    // Step 5: Finalize order and download certificate
    set_progress(&progress, IssuanceState::Downloading, "Downloading certificate...").await;

    let mut params = rcgen::CertificateParams::new(vec![domain.clone()])?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain.as_str());
    let private_key = rcgen::KeyPair::generate()?;
    let csr = params.serialize_request(&private_key)?;

    order
        .finalize(csr.der())
        .await
        .context("Failed to finalize order")?;

    // Wait for certificate to be available
    let cert_chain_pem = loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let state = order.refresh().await?;
        if matches!(state.status, OrderStatus::Valid) {
            break order
                .certificate()
                .await
                .context("Failed to download certificate")?
                .context("Certificate not available")?;
        }
        if matches!(state.status, OrderStatus::Invalid) {
            bail!("Order became invalid during finalization");
        }
    };

    // Step 6: Install certificate
    set_progress(&progress, IssuanceState::Installing, "Installing certificate...").await;

    let cert_path = Path::new(CERT_PATH);
    let key_path = Path::new(KEY_PATH);

    // Ensure parent directory exists
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write certificate chain PEM
    std::fs::write(cert_path, &cert_chain_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644))?;
    }

    // Write private key PEM
    let key_pem = private_key.serialize_pem();
    std::fs::write(key_path, &key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    // Cleanup Cloudflare record
    if let Some(record_id) = cf_record_id {
        if acme_config.provider == "cloudflare" && !acme_config.cloudflare_api_token.is_empty() {
            let cf = providers::CloudflareProvider::new(&acme_config.cloudflare_api_token);
            let _ = cf.delete_txt_record(domain, &record_id).await;
        }
    }

    set_progress(&progress, IssuanceState::Complete, "Certificate installed successfully!").await;
    info!("ACME: Certificate for {} installed successfully", domain);

    Ok(())
}

/// Check if the current cert expires within `days` days.
pub fn cert_expires_within_days(cert_path: &str, days: u64) -> Result<bool> {
    let info = cert_parser::get_current_cert_info(
        &Some(cert_path.to_string()),
        &None,
    )?;
    if let Some(info) = info {
        if let Ok(expiry) = chrono::NaiveDateTime::parse_from_str(&info.not_after, "%Y-%m-%d %H:%M:%S UTC") {
            let now = chrono::Utc::now().naive_utc();
            let remaining = expiry - now;
            return Ok(remaining.num_days() < days as i64);
        }
    }
    Ok(false)
}

/// Background renewal task: checks daily, renews if cert expires within 30 days.
pub async fn renewal_loop(
    config_path: PathBuf,
    progress: Arc<RwLock<IssuanceProgress>>,
    manual_confirm: Arc<tokio::sync::Notify>,
    restart_signal: tokio::sync::watch::Sender<bool>,
) {
    // Wait 60 seconds after startup before first check
    tokio::time::sleep(Duration::from_secs(60)).await;

    loop {
        let config = match Config::load(&config_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("ACME renewal: failed to load config: {}", e);
                tokio::time::sleep(Duration::from_secs(86400)).await;
                continue;
            }
        };

        let acme = &config.tls.acme;
        if acme.enabled && !acme.domain.is_empty() && acme.provider == "cloudflare" {
            // Only auto-renew for Cloudflare (manual requires user interaction)
            let cert_path = config
                .tls
                .cert_path
                .as_deref()
                .unwrap_or(CERT_PATH);

            match cert_expires_within_days(cert_path, 30) {
                Ok(true) => {
                    info!("ACME renewal: cert expires within 30 days, renewing...");
                    match issue_certificate(acme, progress.clone(), manual_confirm.clone()).await {
                        Ok(()) => {
                            // Update config with renewal timestamp
                            if let Ok(mut cfg) = Config::load(&config_path) {
                                cfg.tls.acme.last_renewed =
                                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
                                cfg.tls.acme.last_renewal_error = String::new();
                                let _ = cfg.save(&config_path);
                            }
                            let _ = restart_signal.send(true);
                        }
                        Err(e) => {
                            warn!("ACME renewal failed: {}", e);
                            if let Ok(mut cfg) = Config::load(&config_path) {
                                cfg.tls.acme.last_renewal_error = e.to_string();
                                let _ = cfg.save(&config_path);
                            }
                        }
                    }
                }
                Ok(false) => {
                    info!("ACME renewal: cert still valid, skipping");
                }
                Err(e) => {
                    warn!("ACME renewal: failed to check cert expiry: {}", e);
                }
            }
        }

        // Check once daily
        tokio::time::sleep(Duration::from_secs(86400)).await;
    }
}

async fn set_progress(progress: &Arc<RwLock<IssuanceProgress>>, state: IssuanceState, message: &str) {
    let mut p = progress.write().await;
    p.state = state;
    p.message = message.to_string();
}

async fn wait_for_dns_propagation(domain: &str, expected_value: &str) {
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if providers::poll_dns_txt_record(domain, expected_value).await {
            info!("ACME: DNS propagation confirmed for {}", domain);
            return;
        }
    }
    warn!("ACME: DNS propagation not confirmed after 200s, proceeding anyway");
}
```

- [ ] **Step 2: Register acme module in main.rs**

In `src/main.rs`, add the module declaration near the top with the other `mod` statements:

```rust
mod acme;
```

- [ ] **Step 3: Add Config::save method if not present**

Check `src/config.rs` for a `save` method. If missing, add to the `Config` impl block:

```rust
impl Config {
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let toml_str = toml::to_string_pretty(self)?;
        std::fs::write(path, toml_str)?;
        Ok(())
    }
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check`
Expected: Compiles (the module is registered but not yet wired into AppState)

- [ ] **Step 5: Commit**

```bash
git add src/acme/mod.rs src/acme/providers.rs src/main.rs src/config.rs
git commit -m "feat: add ACME orchestration module with issuance and renewal"
```

---

### Task 4: Wire ACME into AppState and add API endpoints

**Files:**
- Modify: `src/web/mod.rs` (AppState, routes, handlers)

- [ ] **Step 1: Add AcmeState to AppState**

In `src/web/mod.rs`, add to the `AppState` struct (after line 54):

```rust
pub acme: std::sync::Arc<crate::acme::AcmeState>,
```

- [ ] **Step 2: Initialize AcmeState where AppState is constructed**

In `src/main.rs`, where `AppState` is constructed (look for the struct literal), add:

```rust
acme: std::sync::Arc::new(crate::acme::AcmeState::new()),
```

- [ ] **Step 3: Spawn ACME renewal background task**

In `src/main.rs`, after the existing background task spawns (after the cache eviction task), add:

```rust
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
```

- [ ] **Step 4: Add ACME routes**

In `src/web/mod.rs`, after the existing TLS routes (line 401), add:

```rust
// ACME certificate management
.route("/api/system/tls/acme/issue", post(api_acme_issue))
.route("/api/system/tls/acme/confirm", post(api_acme_confirm))
.route("/api/system/tls/acme/status", get(api_acme_status))
.route("/api/system/tls/acme/renew", post(api_acme_renew))
```

- [ ] **Step 5: Implement ACME API handlers**

Add these handler functions in `src/web/mod.rs` (after the existing `api_tls_remove` function):

```rust
async fn api_acme_issue(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    if !user.has_permission(Permission::ManageSystem) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let domain = body["domain"].as_str().unwrap_or("").trim().to_string();
    let email = body["email"].as_str().unwrap_or("").trim().to_string();
    let provider = body["provider"].as_str().unwrap_or("cloudflare").to_string();
    let cloudflare_api_token = body["cloudflare_api_token"].as_str().unwrap_or("").to_string();
    let use_staging = body["use_staging"].as_bool().unwrap_or(false);

    if domain.is_empty() || email.is_empty() {
        return (StatusCode::BAD_REQUEST, "Domain and email are required").into_response();
    }

    if provider == "cloudflare" && cloudflare_api_token.is_empty() {
        return (StatusCode::BAD_REQUEST, "Cloudflare API token is required").into_response();
    }

    let acme_config = crate::config::AcmeConfig {
        enabled: true,
        domain: domain.clone(),
        email: email.clone(),
        provider: provider.clone(),
        cloudflare_api_token: cloudflare_api_token.clone(),
        use_staging,
        last_renewed: String::new(),
        last_renewal_error: String::new(),
    };

    // Save ACME config
    if let Ok(mut config) = crate::config::Config::load(&state.config_path) {
        config.tls.acme = acme_config.clone();
        config.tls.cert_path = Some(crate::acme::CERT_PATH.to_string());
        config.tls.key_path = Some(crate::acme::KEY_PATH.to_string());
        let _ = config.save(&state.config_path);
    }

    let progress = state.acme.progress.clone();
    let manual_confirm = state.acme.manual_confirm.clone();
    let config_path = state.config_path.clone();
    let restart_signal = state.restart_signal.clone();

    // Run issuance in background
    tokio::spawn(async move {
        match crate::acme::issue_certificate(&acme_config, progress.clone(), manual_confirm).await {
            Ok(()) => {
                // Update config with success timestamp
                if let Ok(mut cfg) = crate::config::Config::load(&config_path) {
                    cfg.tls.acme.last_renewed =
                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
                    cfg.tls.acme.last_renewal_error = String::new();
                    let _ = cfg.save(&config_path);
                }
                let _ = restart_signal.send(true);
            }
            Err(e) => {
                tracing::warn!("ACME issuance failed: {}", e);
                let mut p = progress.write().await;
                p.state = crate::acme::IssuanceState::Failed;
                p.message = e.to_string();
                // Save error to config
                if let Ok(mut cfg) = crate::config::Config::load(&config_path) {
                    cfg.tls.acme.last_renewal_error = e.to_string();
                    let _ = cfg.save(&config_path);
                }
            }
        }
    });

    axum::Json(serde_json::json!({ "status": "started" })).into_response()
}

async fn api_acme_confirm(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.has_permission(Permission::ManageSystem) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    state.acme.manual_confirm.notify_one();
    axum::Json(serde_json::json!({ "status": "confirmed" })).into_response()
}

async fn api_acme_status(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.has_permission(Permission::ManageSystem) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let progress = state.acme.progress.read().await;
    let config = crate::config::Config::load(&state.config_path).ok();

    let acme_config = config.as_ref().map(|c| &c.tls.acme);

    axum::Json(serde_json::json!({
        "progress": *progress,
        "config": {
            "enabled": acme_config.map(|a| a.enabled).unwrap_or(false),
            "domain": acme_config.map(|a| a.domain.as_str()).unwrap_or(""),
            "email": acme_config.map(|a| a.email.as_str()).unwrap_or(""),
            "provider": acme_config.map(|a| a.provider.as_str()).unwrap_or("cloudflare"),
            "use_staging": acme_config.map(|a| a.use_staging).unwrap_or(false),
            "last_renewed": acme_config.map(|a| a.last_renewed.as_str()).unwrap_or(""),
            "last_renewal_error": acme_config.map(|a| a.last_renewal_error.as_str()).unwrap_or(""),
        }
    }))
    .into_response()
}

async fn api_acme_renew(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.has_permission(Permission::ManageSystem) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let config = match crate::config::Config::load(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load config: {}", e))
                .into_response();
        }
    };

    if !config.tls.acme.enabled || config.tls.acme.domain.is_empty() {
        return (StatusCode::BAD_REQUEST, "ACME is not configured").into_response();
    }

    let acme_config = config.tls.acme.clone();
    let progress = state.acme.progress.clone();
    let manual_confirm = state.acme.manual_confirm.clone();
    let config_path = state.config_path.clone();
    let restart_signal = state.restart_signal.clone();

    tokio::spawn(async move {
        match crate::acme::issue_certificate(&acme_config, progress.clone(), manual_confirm).await {
            Ok(()) => {
                if let Ok(mut cfg) = crate::config::Config::load(&config_path) {
                    cfg.tls.acme.last_renewed =
                        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
                    cfg.tls.acme.last_renewal_error = String::new();
                    let _ = cfg.save(&config_path);
                }
                let _ = restart_signal.send(true);
            }
            Err(e) => {
                tracing::warn!("ACME renewal failed: {}", e);
                let mut p = progress.write().await;
                p.state = crate::acme::IssuanceState::Failed;
                p.message = e.to_string();
            }
        }
    });

    axum::Json(serde_json::json!({ "status": "started" })).into_response()
}
```

- [ ] **Step 6: Make CERT_PATH and KEY_PATH public in acme/mod.rs**

Change the const visibility:

```rust
pub const CERT_PATH: &str = "/etc/oxi-dns/cert.pem";
pub const KEY_PATH: &str = "/etc/oxi-dns/key.pem";
```

- [ ] **Step 7: Verify it compiles**

Run: `cargo check`
Expected: Compiles successfully

- [ ] **Step 8: Commit**

```bash
git add src/web/mod.rs src/main.rs src/acme/mod.rs
git commit -m "feat: add ACME API endpoints and wire into AppState"
```

---

### Task 5: Dashboard UI — Remove old TLS section, add button and modal

**Files:**
- Modify: `src/web/dashboard.html`

- [ ] **Step 1: Remove TLS Certificate section from System Settings**

Delete the entire TLS section from System Settings (lines 2433-2484, the `<div class="tls-section manage-system-only">` block through its closing `</div>`).

- [ ] **Step 2: Add Certificates section in Advanced tab**

Insert between the Upstream DNS Servers section end (line 2260 `</div>`) and the User Management section (line 2262 comment):

```html
            <!-- Certificate Management -->
            <div class="section manage-system-only">
                <h2>TLS Certificate</h2>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                    <span style="font-size: 13px; color: var(--text-muted);" id="certSummary">Loading certificate info...</span>
                    <button type="button" class="btn btn-accent btn-sm" onclick="showCertModal()">Manage Certificates</button>
                </div>
            </div>
```

- [ ] **Step 3: Add certificate modal CSS**

Add in the `<style>` section (after the existing modal CSS around line 1857):

```css
.cert-tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 16px; }
.cert-tab { padding: 8px 16px; cursor: pointer; border: none; background: none; color: var(--text-muted); font-size: 13px; border-bottom: 2px solid transparent; }
.cert-tab.active { color: var(--text); border-bottom-color: var(--accent); }
.cert-tab-content { display: none; }
.cert-tab-content.active { display: block; }
.cert-info-grid { display: grid; grid-template-columns: auto 1fr; gap: 6px 12px; font-size: 13px; margin-bottom: 16px; }
.cert-info-label { color: var(--text-muted); }
.cert-info-value { color: var(--text); word-break: break-all; }
.acme-progress { margin: 16px 0; }
.acme-step { display: flex; align-items: center; gap: 8px; padding: 6px 0; font-size: 13px; color: var(--text-muted); }
.acme-step.active { color: var(--text); font-weight: 500; }
.acme-step.done { color: var(--text-muted); }
.acme-step-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--border); flex-shrink: 0; }
.acme-step.active .acme-step-dot { background: var(--accent); }
.acme-step.done .acme-step-dot { background: var(--text-muted); }
.acme-challenge-box { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 12px; margin: 12px 0; font-size: 12px; font-family: monospace; word-break: break-all; }
.acme-challenge-label { font-size: 11px; color: var(--text-muted); margin-bottom: 4px; font-family: var(--font); }
```

- [ ] **Step 4: Add certificate modal JavaScript**

Replace the existing TLS JavaScript functions (lines 3537-3620) with the new certificate management code:

```javascript
// ---- Certificate Management ----
let certModalTab = 'status';
let acmePollTimer = null;

function showCertModal() {
    const html = `
        <h3>Certificate Management</h3>
        <div class="cert-tabs">
            <button class="cert-tab active" onclick="switchCertTab('status')">Status</button>
            <button class="cert-tab" onclick="switchCertTab('acme')">Let's Encrypt</button>
            <button class="cert-tab" onclick="switchCertTab('upload')">Manual Upload</button>
        </div>
        <div class="cert-tab-content active" id="certTabStatus">
            <div class="cert-info-grid" id="certInfoGrid">Loading...</div>
            <div id="certRenewalInfo" style="font-size:13px;color:var(--text-muted);margin-bottom:16px;"></div>
            <div class="modal-actions">
                <button class="btn btn-sm" style="background:var(--danger);color:#fff;" onclick="removeTlsCert()">Remove &amp; use self-signed</button>
            </div>
        </div>
        <div class="cert-tab-content" id="certTabAcme">
            <div class="form-group">
                <label>Domain</label>
                <input type="text" id="acmeDomain" placeholder="example.com" />
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" id="acmeEmail" placeholder="admin@example.com" />
            </div>
            <div class="form-group">
                <label>DNS Provider</label>
                <select id="acmeProvider" onchange="onAcmeProviderChange()">
                    <option value="cloudflare">Cloudflare</option>
                    <option value="manual">Manual DNS</option>
                </select>
                <a href="https://github.com/ron-png/oxi-dns/issues/new" target="_blank" rel="noopener" style="font-size:12px;display:block;margin-top:4px;">Suggest a provider</a>
            </div>
            <div class="form-group" id="cfTokenGroup">
                <label>Cloudflare API Token</label>
                <input type="password" id="acmeCfToken" placeholder="API token with Zone:DNS:Edit permission" />
            </div>
            <div class="form-group" style="display:flex;align-items:center;gap:8px;">
                <input type="checkbox" id="acmeStaging" />
                <label for="acmeStaging" style="margin:0;font-size:13px;">Use staging environment (for testing)</label>
            </div>
            <div id="acmeProgressArea" style="display:none;">
                <div class="acme-progress" id="acmeProgressSteps"></div>
                <div id="acmeChallengeDetails" style="display:none;">
                    <div class="acme-challenge-box">
                        <div class="acme-challenge-label">TXT Record Name</div>
                        <div id="acmeChallengeName"></div>
                        <div class="acme-challenge-label" style="margin-top:8px;">TXT Record Value</div>
                        <div id="acmeChallengeValue"></div>
                    </div>
                    <button class="btn btn-accent btn-sm" onclick="confirmAcmeChallenge()">I've created the record</button>
                </div>
            </div>
            <div id="acmeMsg" style="font-size:13px;margin-top:8px;"></div>
            <div class="modal-actions" id="acmeActions">
                <button class="btn btn-accent" onclick="startAcmeIssuance()">Issue Certificate</button>
            </div>
        </div>
        <div class="cert-tab-content" id="certTabUpload">
            <div class="tls-tabs" style="display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:12px;">
                <button class="cert-tab active" onclick="switchUploadTab('pem')">PEM</button>
                <button class="cert-tab" onclick="switchUploadTab('p12')">PKCS12</button>
            </div>
            <div id="uploadPemTab">
                <div class="form-group"><label>Certificate (.pem)</label><input type="file" id="uploadCertFile" accept=".pem,.crt,.cer" /></div>
                <div class="form-group"><label>Private Key (.pem)</label><input type="file" id="uploadKeyFile" accept=".pem,.key" /></div>
            </div>
            <div id="uploadP12Tab" style="display:none;">
                <div class="form-group"><label>PKCS12 File (.p12/.pfx)</label><input type="file" id="uploadP12File" accept=".p12,.pfx" /></div>
            </div>
            <div class="form-group" id="uploadPasswordGroup" style="display:none;">
                <label>Password</label>
                <input type="password" id="uploadPassword" placeholder="Certificate password" />
            </div>
            <div id="uploadMsg" style="font-size:13px;margin-top:8px;"></div>
            <div class="modal-actions">
                <button class="btn btn-accent" onclick="uploadTlsCert()">Upload Certificate</button>
            </div>
        </div>
    `;
    openModal(html);
    refreshCertStatus();
    loadAcmeConfig();
}

function switchCertTab(tab) {
    certModalTab = tab;
    document.querySelectorAll('.cert-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.cert-tab-content').forEach(c => c.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById('certTab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('active');
}

function switchUploadTab(tab) {
    document.querySelectorAll('#certTabUpload .cert-tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    document.getElementById('uploadPemTab').style.display = tab === 'pem' ? '' : 'none';
    document.getElementById('uploadP12Tab').style.display = tab === 'p12' ? '' : 'none';
}

function onAcmeProviderChange() {
    const provider = document.getElementById('acmeProvider').value;
    document.getElementById('cfTokenGroup').style.display = provider === 'cloudflare' ? '' : 'none';
}

async function refreshCertStatus() {
    try {
        const res = await fetch('/api/system/tls');
        if (!res.ok) return;
        const data = await res.json();
        const grid = document.getElementById('certInfoGrid');
        if (!grid) return;
        const certType = data.self_signed ? 'Self-signed' : (data.issuer?.includes("Let's Encrypt") ? "Let's Encrypt" : 'Custom');
        grid.innerHTML = `
            <span class="cert-info-label">Type</span><span class="cert-info-value">${escapeHtml(certType)}</span>
            <span class="cert-info-label">Subject</span><span class="cert-info-value">${escapeHtml(data.subject || 'N/A')}</span>
            <span class="cert-info-label">Issuer</span><span class="cert-info-value">${escapeHtml(data.issuer || 'N/A')}</span>
            <span class="cert-info-label">Expires</span><span class="cert-info-value">${escapeHtml(data.not_after || 'N/A')}</span>
        `;
        // Update summary in advanced tab
        const summary = document.getElementById('certSummary');
        if (summary) summary.textContent = `${certType} — expires ${data.not_after || 'N/A'}`;
    } catch (_) {}

    // Load renewal info
    try {
        const res = await fetch('/api/system/tls/acme/status');
        if (!res.ok) return;
        const data = await res.json();
        const info = document.getElementById('certRenewalInfo');
        if (info && data.config.enabled) {
            let text = '';
            if (data.config.last_renewed) text += `Last renewed: ${escapeHtml(data.config.last_renewed)}`;
            if (data.config.last_renewal_error) text += `<br>Last error: <span style="color:var(--danger)">${escapeHtml(data.config.last_renewal_error)}</span>`;
            info.innerHTML = text;
        }
    } catch (_) {}
}

async function loadAcmeConfig() {
    try {
        const res = await fetch('/api/system/tls/acme/status');
        if (!res.ok) return;
        const data = await res.json();
        const c = data.config;
        if (c.domain) document.getElementById('acmeDomain').value = c.domain;
        if (c.email) document.getElementById('acmeEmail').value = c.email;
        if (c.provider) document.getElementById('acmeProvider').value = c.provider;
        if (c.use_staging) document.getElementById('acmeStaging').checked = true;
        onAcmeProviderChange();
    } catch (_) {}
}

async function startAcmeIssuance() {
    const body = {
        domain: document.getElementById('acmeDomain').value.trim(),
        email: document.getElementById('acmeEmail').value.trim(),
        provider: document.getElementById('acmeProvider').value,
        cloudflare_api_token: document.getElementById('acmeCfToken')?.value || '',
        use_staging: document.getElementById('acmeStaging').checked,
    };
    if (!body.domain || !body.email) { showAcmeMsg('Domain and email are required', 'error'); return; }

    document.getElementById('acmeActions').style.display = 'none';
    document.getElementById('acmeProgressArea').style.display = '';
    showAcmeMsg('');

    try {
        const res = await fetch('/api/system/tls/acme/issue', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!res.ok) { const text = await res.text(); showAcmeMsg(text, 'error'); document.getElementById('acmeActions').style.display = ''; return; }
        startAcmePolling();
    } catch (e) { showAcmeMsg('Request failed: ' + e.message, 'error'); document.getElementById('acmeActions').style.display = ''; }
}

function startAcmePolling() {
    if (acmePollTimer) return;
    acmePollTimer = setInterval(pollAcmeStatus, 2000);
    pollAcmeStatus();
}

function stopAcmePolling() {
    if (acmePollTimer) { clearInterval(acmePollTimer); acmePollTimer = null; }
}

const ACME_STEPS = ['creating_account', 'placing_order', 'waiting_for_challenge', 'validating', 'downloading', 'installing', 'complete'];
const ACME_STEP_LABELS = { creating_account: 'Creating ACME account', placing_order: 'Placing order', waiting_for_challenge: 'DNS challenge', validating: 'Validating', downloading: 'Downloading certificate', installing: 'Installing', complete: 'Complete' };

async function pollAcmeStatus() {
    try {
        const res = await fetch('/api/system/tls/acme/status');
        if (!res.ok) return;
        const data = await res.json();
        const p = data.progress;
        const stepsEl = document.getElementById('acmeProgressSteps');
        if (!stepsEl) { stopAcmePolling(); return; }

        const currentIdx = ACME_STEPS.indexOf(p.state);
        let html = '';
        for (let i = 0; i < ACME_STEPS.length; i++) {
            const cls = i < currentIdx ? 'done' : i === currentIdx ? 'active' : '';
            html += `<div class="acme-step ${cls}"><span class="acme-step-dot"></span>${ACME_STEP_LABELS[ACME_STEPS[i]]}</div>`;
        }
        stepsEl.innerHTML = html;

        // Show challenge details for manual mode
        const challengeEl = document.getElementById('acmeChallengeDetails');
        if (p.state === 'waiting_for_challenge' && p.challenge_record_name) {
            document.getElementById('acmeChallengeName').textContent = p.challenge_record_name;
            document.getElementById('acmeChallengeValue').textContent = p.challenge_record_value;
            challengeEl.style.display = '';
        } else if (challengeEl) {
            challengeEl.style.display = 'none';
        }

        if (p.state === 'complete') {
            stopAcmePolling();
            showAcmeMsg('Certificate installed! The service will restart.', 'success');
            document.getElementById('acmeActions').style.display = '';
            setTimeout(() => { refreshCertStatus(); }, 3000);
        } else if (p.state === 'failed') {
            stopAcmePolling();
            showAcmeMsg(p.message || 'Issuance failed', 'error');
            document.getElementById('acmeActions').style.display = '';
            document.getElementById('acmeProgressArea').style.display = 'none';
        } else if (p.state === 'idle') {
            stopAcmePolling();
        }
    } catch (_) {}
}

async function confirmAcmeChallenge() {
    try {
        await fetch('/api/system/tls/acme/confirm', { method: 'POST' });
    } catch (_) {}
}

function showAcmeMsg(msg, type) {
    const el = document.getElementById('acmeMsg');
    if (!el) return;
    el.textContent = msg;
    el.style.color = type === 'error' ? 'var(--danger)' : type === 'success' ? 'var(--success, #4caf50)' : 'var(--text-muted)';
}

async function uploadTlsCert() {
    const form = new FormData();
    const certFile = document.getElementById('uploadCertFile')?.files[0];
    const keyFile = document.getElementById('uploadKeyFile')?.files[0];
    const p12File = document.getElementById('uploadP12File')?.files[0];
    const password = document.getElementById('uploadPassword')?.value || '';

    if (p12File) { form.append('p12_file', p12File); }
    else if (certFile) { form.append('cert_file', certFile); if (keyFile) form.append('key_file', keyFile); }
    else { showUploadMsg('Select a certificate file', 'error'); return; }
    if (password) form.append('password', password);

    try {
        const res = await fetch('/api/system/tls/upload', { method: 'POST', body: form });
        if (res.status === 422) {
            document.getElementById('uploadPasswordGroup').style.display = '';
            showUploadMsg('Password required for this certificate', 'error');
            return;
        }
        if (!res.ok) { const text = await res.text(); showUploadMsg(text, 'error'); return; }
        showUploadMsg('Certificate uploaded! Restarting...', 'success');
        setTimeout(() => { refreshCertStatus(); }, 3000);
    } catch (e) { showUploadMsg('Upload failed: ' + e.message, 'error'); }
}

async function removeTlsCert() {
    if (!confirm('Remove the current certificate and revert to self-signed?')) return;
    try {
        await fetch('/api/system/tls/remove', { method: 'POST' });
        setTimeout(() => { refreshCertStatus(); closeModal(); }, 3000);
    } catch (_) {}
}

function showUploadMsg(msg, type) {
    const el = document.getElementById('uploadMsg');
    if (!el) return;
    el.textContent = msg;
    el.style.color = type === 'error' ? 'var(--danger)' : type === 'success' ? 'var(--success, #4caf50)' : 'var(--text-muted)';
}
```

- [ ] **Step 5: Update the init/refresh calls**

Find the existing `refreshTlsStatus()` call in the initialization code (search for `refreshTlsStatus`) and replace it with `refreshCertStatus()`. Also update any references like the `setMode` function or tab initialization that calls `refreshTlsStatus`.

- [ ] **Step 6: Remove old TLS CSS**

Remove the `.tls-section`, `.tls-status`, `.tls-tabs`, `.tls-upload` CSS classes and related rules that were only used by the removed TLS section.

- [ ] **Step 7: Verify it compiles and renders**

Run: `cargo check`
Expected: Compiles. Open the dashboard in a browser and verify:
- Advanced tab has "TLS Certificate" section with "Manage Certificates" button
- Button opens modal with three tabs: Status, Let's Encrypt, Manual Upload
- Status tab shows current cert info
- Let's Encrypt tab shows form with provider dropdown
- Manual Upload tab has file upload form

- [ ] **Step 8: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat: add certificate management modal with ACME and manual upload"
```

---

### Task 6: Integration testing and cleanup

**Files:**
- All modified files

- [ ] **Step 1: Full compile check**

Run: `cargo check`
Expected: Clean compilation

- [ ] **Step 2: Run all tests**

Run: `cargo test`
Expected: All existing tests pass

- [ ] **Step 3: Test config round-trip**

Verify that a config file without `[tls.acme]` loads correctly (AcmeConfig defaults). Create a temp config and test:

```bash
cargo run -- --help
```

Expected: No panics, help output shown. The `AcmeConfig::default()` fills in all fields.

- [ ] **Step 4: Verify ACME status endpoint**

Start the server locally and test the status endpoint:

```bash
curl -s http://localhost:9853/api/system/tls/acme/status | python3 -m json.tool
```

Expected: JSON response with `progress` and `config` fields

- [ ] **Step 5: Commit final state**

```bash
git add -A
git commit -m "feat: complete ACME certificate management implementation"
```
