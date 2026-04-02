# Encrypted DNS Toggles + Certificate Upload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dashboard toggles for DoT/DoH/DoQ protocols with zero-downtime restarts, and certificate upload (PEM + PKCS12) with flexible parsing.

**Architecture:** A graceful restart signal channel in `AppState` lets the web API trigger zero-downtime restarts (reusing the existing `--takeover` + `--ready-file` mechanism from auto-update). The cert parser module handles any cert format. The dashboard gets protocol toggles and a TLS certificate management section.

**Tech Stack:** Rust/Axum (API + multipart upload), rustls-pemfile (PEM parsing), p12 (PKCS12), x509-parser (cert inspection), vanilla HTML/CSS/JS (dashboard)

---

### Task 1: Add dependencies

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add new dependencies**

In `Cargo.toml`, in the `[dependencies]` section, add:

```toml
# Certificate parsing
x509-parser = "0.16"
p12 = "0.6"
pkcs8 = { version = "0.10", features = ["encryption", "pem"] }
```

Also update the axum dependency to enable multipart:

```toml
axum = { version = "0.8", features = ["multipart"] }
```

- [ ] **Step 2: Verify compilation**

Run: `cargo check`
Expected: Success

- [ ] **Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add cert parsing and multipart upload dependencies"
```

---

### Task 2: Create cert parser module

**Files:**
- Create: `src/cert_parser.rs`
- Modify: `src/main.rs` (add `mod cert_parser;`)

The flexible cert parser that handles PEM (single/chain/combined cert+key, encrypted keys) and PKCS12 bundles.

- [ ] **Step 1: Create `src/cert_parser.rs` with tests and implementation**

```rust
use anyhow::{anyhow, bail, Context};
use rustls_pemfile::Item;
use std::io::BufReader;

#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    pub certs: Vec<Vec<u8>>,   // DER-encoded certificates, leaf first
    pub key: Vec<u8>,          // DER-encoded private key (decrypted)
    pub subject: String,       // CN from leaf cert
    pub issuer: String,        // Issuer CN from leaf cert
    pub not_after: String,     // Expiry as ISO 8601
    pub self_signed: bool,     // subject == issuer
}

#[derive(Debug)]
pub enum ParseError {
    PasswordRequired { cert_type: String },
    Other(anyhow::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::PasswordRequired { cert_type } => {
                write!(f, "password required for {} file", cert_type)
            }
            ParseError::Other(e) => write!(f, "{}", e),
        }
    }
}

impl From<anyhow::Error> for ParseError {
    fn from(e: anyhow::Error) -> Self {
        ParseError::Other(e)
    }
}

/// Parse PEM data from one or two byte slices (cert_data and optional key_data).
/// Extracts all certificates and exactly one private key.
pub fn parse_pem(
    cert_data: &[u8],
    key_data: Option<&[u8]>,
    password: Option<&str>,
) -> Result<ParsedCertificate, ParseError> {
    let mut certs: Vec<Vec<u8>> = Vec::new();
    let mut key: Option<Vec<u8>> = None;
    let mut found_encrypted = false;

    // Parse cert_data (may contain certs + key)
    extract_pem_items(cert_data, &mut certs, &mut key, &mut found_encrypted)?;

    // Parse optional key_data
    if let Some(kd) = key_data {
        extract_pem_items(kd, &mut certs, &mut key, &mut found_encrypted)?;
    }

    // Handle encrypted key
    if found_encrypted && key.is_none() {
        if let Some(pw) = password {
            // Try to decrypt from cert_data
            if let Some(k) = try_decrypt_pem_key(cert_data, pw)? {
                key = Some(k);
            }
            // Try from key_data
            if key.is_none() {
                if let Some(kd) = key_data {
                    if let Some(k) = try_decrypt_pem_key(kd, pw)? {
                        key = Some(k);
                    }
                }
            }
        }
        if key.is_none() {
            return Err(ParseError::PasswordRequired {
                cert_type: "encrypted_pem".to_string(),
            });
        }
    }

    let key_der = key.ok_or_else(|| ParseError::Other(anyhow!("no private key found")))?;
    if certs.is_empty() {
        return Err(ParseError::Other(anyhow!("no certificates found")));
    }

    build_result(certs, key_der)
}

/// Parse a PKCS12 (.p12/.pfx) bundle.
pub fn parse_pkcs12(data: &[u8], password: Option<&str>) -> Result<ParsedCertificate, ParseError> {
    let pw = password.unwrap_or("");

    let p12 = p12::PFX::parse(data)
        .map_err(|e| {
            if pw.is_empty() {
                ParseError::PasswordRequired {
                    cert_type: "pkcs12".to_string(),
                }
            } else {
                ParseError::Other(anyhow!("failed to parse PKCS12: {:?}", e))
            }
        })?;

    let certs_der = p12.cert_x509_bags(pw)
        .map_err(|e| {
            if pw.is_empty() {
                ParseError::PasswordRequired {
                    cert_type: "pkcs12".to_string(),
                }
            } else {
                ParseError::Other(anyhow!("failed to extract certificates: {:?}", e))
            }
        })?;

    let key_bags = p12.key_bags(pw)
        .map_err(|e| ParseError::Other(anyhow!("failed to extract private key: {:?}", e)))?;

    if certs_der.is_empty() {
        return Err(ParseError::Other(anyhow!("no certificates found in PKCS12")));
    }
    if key_bags.is_empty() {
        return Err(ParseError::Other(anyhow!("no private key found in PKCS12")));
    }

    let certs: Vec<Vec<u8>> = certs_der.into_iter().map(|c| c.to_der()).collect();
    let key_der = key_bags.into_iter().next().unwrap();

    build_result(certs, key_der)
}

/// Detect whether data looks like PKCS12 (binary) or PEM (text).
pub fn is_pkcs12(data: &[u8]) -> bool {
    // PKCS12 files start with ASN.1 SEQUENCE tag (0x30) and are binary
    !data.is_empty() && data[0] == 0x30 && !data.starts_with(b"-----")
}

fn extract_pem_items(
    data: &[u8],
    certs: &mut Vec<Vec<u8>>,
    key: &mut Option<Vec<u8>>,
    found_encrypted: &mut bool,
) -> Result<(), ParseError> {
    let mut reader = BufReader::new(data);

    // Check for encrypted PEM key marker before rustls parsing
    let data_str = String::from_utf8_lossy(data);
    if data_str.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        *found_encrypted = true;
    }

    for item in rustls_pemfile::read_all(&mut reader) {
        match item {
            Ok(Item::X509Certificate(cert)) => {
                certs.push(cert.to_vec());
            }
            Ok(Item::Pkcs1Key(key_data)) => {
                *key = Some(key_data.secret_pkcs1_der().to_vec());
            }
            Ok(Item::Pkcs8Key(key_data)) => {
                *key = Some(key_data.secret_pkcs8_der().to_vec());
            }
            Ok(Item::Sec1Key(key_data)) => {
                *key = Some(key_data.secret_sec1_der().to_vec());
            }
            Ok(_) => {} // skip CRLs, etc
            Err(_) => {} // skip unparseable items (may be encrypted key)
        }
    }
    Ok(())
}

fn try_decrypt_pem_key(data: &[u8], password: &str) -> Result<Option<Vec<u8>>, ParseError> {
    let pem_str = String::from_utf8_lossy(data);

    // Find encrypted PKCS8 PEM block
    if let Some(start) = pem_str.find("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
        if let Some(end) = pem_str[start..].find("-----END ENCRYPTED PRIVATE KEY-----") {
            let pem_block = &pem_str[start..start + end + "-----END ENCRYPTED PRIVATE KEY-----".len()];

            use pkcs8::DecodePrivateKey;
            match pkcs8::PrivateKeyInfo::from_pem(pem_block) {
                Ok(_info) => {
                    // Unencrypted despite the header — unlikely but handle it
                    // Re-encode as DER
                    let der = pkcs8::PrivateKeyInfo::from_pem(pem_block)
                        .map_err(|e| ParseError::Other(anyhow!("PEM decode failed: {}", e)))?;
                    return Ok(Some(der.to_der().map_err(|e| ParseError::Other(anyhow!("{}", e)))?));
                }
                Err(_) => {
                    // Try with password
                    use pkcs8::pkcs5::pbes2;
                    let encrypted = pkcs8::EncryptedPrivateKeyInfo::from_pem(pem_block)
                        .map_err(|e| ParseError::Other(anyhow!("failed to parse encrypted key: {}", e)))?;
                    let decrypted = encrypted.decrypt(password)
                        .map_err(|e| ParseError::Other(anyhow!("wrong password or decryption failed: {}", e)))?;
                    return Ok(Some(decrypted.to_der().map_err(|e| ParseError::Other(anyhow!("{}", e)))?));
                }
            }
        }
    }
    Ok(None)
}

fn build_result(certs: Vec<Vec<u8>>, key_der: Vec<u8>) -> Result<ParsedCertificate, ParseError> {
    // Extract cert info from leaf (first) cert
    let (subject, issuer, not_after) = extract_cert_info(&certs[0])?;
    let self_signed = subject == issuer;

    Ok(ParsedCertificate {
        certs,
        key: key_der,
        subject,
        issuer,
        not_after,
        self_signed,
    })
}

fn extract_cert_info(der: &[u8]) -> Result<(String, String, String), ParseError> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| ParseError::Other(anyhow!("failed to parse X.509 certificate: {}", e)))?;

    let subject = cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let issuer = cert.issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let not_after = cert.validity().not_after.to_rfc2822()
        .unwrap_or_else(|_| "Unknown".to_string());

    Ok((subject, issuer, not_after))
}

/// Write parsed certificate to PEM files on disk.
pub fn write_cert_files(
    parsed: &ParsedCertificate,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<()> {
    use std::io::Write;

    // Write cert chain as PEM
    let mut cert_file = std::fs::File::create(cert_path)
        .context("failed to create cert file")?;
    for cert_der in &parsed.certs {
        let encoded = pem_encode("CERTIFICATE", cert_der);
        cert_file.write_all(encoded.as_bytes())?;
    }

    // Write private key as PEM (unencrypted PKCS8)
    let mut key_file = std::fs::File::create(key_path)
        .context("failed to create key file")?;
    let encoded = pem_encode("PRIVATE KEY", &parsed.key);
    key_file.write_all(encoded.as_bytes())?;

    // Set permissions: cert 644, key 600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644))?;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    use std::fmt::Write;
    let b64 = base64_encode(der);
    let mut out = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    write!(out, "-----END {}-----\n", label).unwrap();
    out
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Get info about the currently active TLS certificate.
pub fn get_current_cert_info(
    tls_config: &crate::config::TlsConfig,
) -> Option<ParsedCertificate> {
    match (&tls_config.cert_path, &tls_config.key_path) {
        (Some(cert_path), Some(key_path)) => {
            let cert_data = std::fs::read(cert_path).ok()?;
            let key_data = std::fs::read(key_path).ok()?;
            parse_pem(&cert_data, Some(&key_data), None).ok()
        }
        _ => None, // self-signed, no file to inspect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generate a self-signed test cert for tests
    fn make_test_cert() -> (Vec<u8>, Vec<u8>) {
        let mut params = rcgen::CertificateParams::new(vec!["test.local".to_string()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "Test Cert");
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_pem = cert.pem().as_bytes().to_vec();
        let key_pem = key_pair.serialize_pem().as_bytes().to_vec();
        (cert_pem, key_pem)
    }

    #[test]
    fn parse_separate_pem_files() {
        let (cert_pem, key_pem) = make_test_cert();
        let result = parse_pem(&cert_pem, Some(&key_pem), None).unwrap();
        assert_eq!(result.certs.len(), 1);
        assert!(!result.key.is_empty());
        assert_eq!(result.subject, "Test Cert");
        assert!(result.self_signed);
    }

    #[test]
    fn parse_combined_pem() {
        let (cert_pem, key_pem) = make_test_cert();
        let mut combined = cert_pem.clone();
        combined.extend_from_slice(&key_pem);
        let result = parse_pem(&combined, None, None).unwrap();
        assert_eq!(result.certs.len(), 1);
        assert!(!result.key.is_empty());
    }

    #[test]
    fn parse_no_key_fails() {
        let (cert_pem, _) = make_test_cert();
        let result = parse_pem(&cert_pem, None, None);
        assert!(matches!(result, Err(ParseError::Other(_))));
    }

    #[test]
    fn parse_no_cert_fails() {
        let (_, key_pem) = make_test_cert();
        let result = parse_pem(&key_pem, None, None);
        assert!(matches!(result, Err(ParseError::Other(_))));
    }

    #[test]
    fn is_pkcs12_detects_binary() {
        assert!(is_pkcs12(&[0x30, 0x82, 0x01]));
        assert!(!is_pkcs12(b"-----BEGIN CERTIFICATE-----"));
        assert!(!is_pkcs12(&[]));
    }

    #[test]
    fn extract_cert_info_works() {
        let (cert_pem, _) = make_test_cert();
        let parsed = parse_pem(&cert_pem, None, None);
        // This will fail (no key) but we test extract_cert_info separately
        let mut reader = BufReader::new(&cert_pem[..]);
        let items: Vec<_> = rustls_pemfile::read_all(&mut reader)
            .filter_map(|i| i.ok())
            .collect();
        if let Some(Item::X509Certificate(cert_der)) = items.first() {
            let (subj, issuer, _expiry) = extract_cert_info(cert_der).unwrap();
            assert_eq!(subj, "Test Cert");
            assert_eq!(issuer, "Test Cert"); // self-signed
        } else {
            panic!("expected certificate");
        }
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn pem_encode_format() {
        let data = b"test";
        let pem = pem_encode("TEST", data);
        assert!(pem.starts_with("-----BEGIN TEST-----\n"));
        assert!(pem.ends_with("-----END TEST-----\n"));
    }
}
```

- [ ] **Step 2: Register the module in main.rs**

In `src/main.rs`, add after `mod reconfigure;`:

```rust
mod cert_parser;
```

- [ ] **Step 3: Run tests**

Run: `cargo test cert_parser`
Expected: All cert_parser tests pass

- [ ] **Step 4: Commit**

```bash
git add src/cert_parser.rs src/main.rs
git commit -m "feat: add flexible cert parser supporting PEM, PKCS12, and encrypted keys"
```

---

### Task 3: Add graceful restart signal to AppState

**Files:**
- Modify: `src/web/mod.rs` (add restart_signal to AppState)
- Modify: `src/main.rs` (create channel, add to AppState, spawn watcher)

- [ ] **Step 1: Add restart signal to AppState**

In `src/web/mod.rs`, add to the `AppState` struct (after `login_rate_limiter`):

```rust
    pub restart_signal: tokio::sync::watch::Sender<bool>,
```

- [ ] **Step 2: Create the channel in main.rs and add to AppState**

In `src/main.rs`, find the `web_state` construction (around line 296). Add before it:

```rust
    // Graceful restart signal (for web API to trigger zero-downtime restart)
    let (restart_tx, mut restart_rx) = tokio::sync::watch::channel(false);
```

Then add to the `AppState` struct construction:

```rust
        restart_signal: restart_tx,
```

- [ ] **Step 3: Spawn restart watcher background task**

In `src/main.rs`, after the cache eviction task spawn block (around line 421) and before the feature restoration, add:

```rust
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
                    .arg(config_path_for_restart.to_str().unwrap_or("/etc/oxi-dns/config.toml"))
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
```

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/web/mod.rs src/main.rs
git commit -m "feat: add graceful restart signal channel for zero-downtime config changes"
```

---

### Task 4: Add POST /api/system/network endpoint

**Files:**
- Modify: `src/web/mod.rs` (add route + handler)

This endpoint updates encrypted DNS protocol listen addresses and triggers a graceful restart.

- [ ] **Step 1: Add the route**

In `src/web/mod.rs`, find the existing network GET route:
```rust
        .route("/api/system/network", get(api_system_network))
```

Change to:
```rust
        .route("/api/system/network", get(api_system_network).post(api_update_network))
```

- [ ] **Step 2: Add the request type and handler**

In `src/web/mod.rs`, add near the `api_system_network` handler:

```rust
#[derive(Deserialize)]
struct UpdateNetworkRequest {
    dot_listen: Option<serde_json::Value>,  // string or null
    doh_listen: Option<serde_json::Value>,
    doq_listen: Option<serde_json::Value>,
}

async fn api_update_network(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Json(req): Json<UpdateNetworkRequest>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Load current config
    let mut config = match Config::load(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response();
        }
    };

    // Apply changes — serde_json::Value::Null means disable, String means enable/change
    if let Some(ref val) = req.dot_listen {
        config.dns.dot_listen = match val {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) if s.is_empty() => None,
            serde_json::Value::String(s) => Some(vec![s.clone()]),
            _ => config.dns.dot_listen.clone(),
        };
    }
    if let Some(ref val) = req.doh_listen {
        config.dns.doh_listen = match val {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) if s.is_empty() => None,
            serde_json::Value::String(s) => Some(vec![s.clone()]),
            _ => config.dns.doh_listen.clone(),
        };
    }
    if let Some(ref val) = req.doq_listen {
        config.dns.doq_listen = match val {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) if s.is_empty() => None,
            serde_json::Value::String(s) => Some(vec![s.clone()]),
            _ => config.dns.doq_listen.clone(),
        };
    }

    // Save config
    if let Err(e) = config.save(&state.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response();
    }

    // Trigger graceful restart
    let _ = state.restart_signal.send(true);

    Json(serde_json::json!({
        "dns_listen": config.dns.listen,
        "web_listen": config.web.listen,
        "dot_listen": config.dns.dot_listen,
        "doh_listen": config.dns.doh_listen,
        "doq_listen": config.dns.doq_listen,
    }))
    .into_response()
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: add POST /api/system/network for encrypted DNS protocol changes"
```

---

### Task 5: Add TLS certificate API endpoints

**Files:**
- Modify: `src/web/mod.rs` (add 3 routes + handlers)

Three endpoints: GET status, POST upload, POST remove.

- [ ] **Step 1: Add routes**

In `src/web/mod.rs`, find the system settings routes. Add:

```rust
        // TLS certificate management
        .route("/api/system/tls", get(api_tls_status))
        .route("/api/system/tls/upload", post(api_tls_upload))
        .route("/api/system/tls/remove", post(api_tls_remove))
```

- [ ] **Step 2: Add the TLS status handler**

```rust
async fn api_tls_status(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let config = Config::load(&state.config_path).unwrap_or_default();

    let cert_info = crate::cert_parser::get_current_cert_info(&config.tls);

    match cert_info {
        Some(info) => Json(serde_json::json!({
            "subject": info.subject,
            "issuer": info.issuer,
            "not_after": info.not_after,
            "self_signed": info.self_signed,
            "cert_path": config.tls.cert_path,
            "key_path": config.tls.key_path,
        })).into_response(),
        None => Json(serde_json::json!({
            "subject": "Oxi-DNS Server",
            "issuer": "Oxi-DNS Server",
            "not_after": null,
            "self_signed": true,
            "cert_path": null,
            "key_path": null,
        })).into_response(),
    }
}
```

- [ ] **Step 3: Add the TLS upload handler**

```rust
async fn api_tls_upload(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    mut multipart: axum::extract::Multipart,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let mut cert_data: Option<Vec<u8>> = None;
    let mut key_data: Option<Vec<u8>> = None;
    let mut p12_data: Option<Vec<u8>> = None;
    let mut password: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "cert_file" => { cert_data = field.bytes().await.ok().map(|b| b.to_vec()); }
            "key_file" => { key_data = field.bytes().await.ok().map(|b| b.to_vec()); }
            "p12_file" => { p12_data = field.bytes().await.ok().map(|b| b.to_vec()); }
            "password" => { password = field.text().await.ok(); }
            _ => {}
        }
    }

    // Parse certificate
    let parsed = if let Some(ref p12) = p12_data {
        crate::cert_parser::parse_pkcs12(p12, password.as_deref())
    } else if let Some(ref cert) = cert_data {
        crate::cert_parser::parse_pem(cert, key_data.as_deref(), password.as_deref())
    } else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "no certificate file provided"}))).into_response();
    };

    let parsed = match parsed {
        Ok(p) => p,
        Err(crate::cert_parser::ParseError::PasswordRequired { cert_type }) => {
            return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
                "error": "password_required",
                "type": cert_type,
            }))).into_response();
        }
        Err(crate::cert_parser::ParseError::Other(e)) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("{}", e)}))).into_response();
        }
    };

    // Write cert files
    let config_dir = state.config_path.parent().unwrap_or(std::path::Path::new("/etc/oxi-dns"));
    let cert_path = config_dir.join("cert.pem");
    let key_path = config_dir.join("key.pem");

    if let Err(e) = crate::cert_parser::write_cert_files(&parsed, &cert_path, &key_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response();
    }

    // Update config
    let mut config = Config::load(&state.config_path).unwrap_or_default();
    config.tls.cert_path = Some(cert_path.to_string_lossy().to_string());
    config.tls.key_path = Some(key_path.to_string_lossy().to_string());
    if let Err(e) = config.save(&state.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response();
    }

    // Trigger graceful restart
    let _ = state.restart_signal.send(true);

    Json(serde_json::json!({
        "subject": parsed.subject,
        "issuer": parsed.issuer,
        "not_after": parsed.not_after,
        "self_signed": parsed.self_signed,
    })).into_response()
}
```

- [ ] **Step 4: Add the TLS remove handler**

```rust
async fn api_tls_remove(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let config_dir = state.config_path.parent().unwrap_or(std::path::Path::new("/etc/oxi-dns"));
    let _ = std::fs::remove_file(config_dir.join("cert.pem"));
    let _ = std::fs::remove_file(config_dir.join("key.pem"));

    let mut config = Config::load(&state.config_path).unwrap_or_default();
    config.tls.cert_path = None;
    config.tls.key_path = None;
    if let Err(e) = config.save(&state.config_path) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("{}", e)}))).into_response();
    }

    let _ = state.restart_signal.send(true);

    Json(serde_json::json!({"success": true})).into_response()
}
```

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: add TLS certificate upload, status, and remove API endpoints"
```

---

### Task 6: Add protocol toggles to dashboard Network section

**Files:**
- Modify: `src/web/dashboard.html`

Update the existing DoT/DoH/DoQ fields in the Network section to add toggle switches and change the behavior from `--reconfigure` command generation to direct API calls.

- [ ] **Step 1: Add toggle CSS**

In `src/web/dashboard.html`, find the `.network-field input` CSS. Add after the `.network-field input::placeholder` rule:

```css
        .network-field .proto-toggle { display: flex; align-items: center; gap: 8px; }
        .network-field .proto-toggle label.toggle-switch { flex-shrink: 0; }
        .network-field .proto-toggle input[type="text"] { flex: 1; }
        .network-field .proto-toggle input[type="text"]:disabled {
            opacity: 0.4; cursor: not-allowed;
        }
```

- [ ] **Step 2: Update the DoT/DoH/DoQ HTML fields**

Find the three encrypted protocol fields in the Network section. Replace them:

```html
                    <div class="network-field">
                        <label>DNS-over-TLS</label>
                        <div class="proto-toggle">
                            <label class="toggle-switch"><input type="checkbox" id="toggle-dot" onchange="toggleProtocol('dot', this.checked)"><span class="toggle-slider"></span></label>
                            <input type="text" id="net-dot" placeholder="0.0.0.0:853" disabled oninput="checkNetworkChanges()">
                        </div>
                    </div>
                    <div class="network-field">
                        <label>DNS-over-HTTPS</label>
                        <div class="proto-toggle">
                            <label class="toggle-switch"><input type="checkbox" id="toggle-doh" onchange="toggleProtocol('doh', this.checked)"><span class="toggle-slider"></span></label>
                            <input type="text" id="net-doh" placeholder="0.0.0.0:443" disabled oninput="checkNetworkChanges()">
                        </div>
                    </div>
                    <div class="network-field">
                        <label>DNS-over-QUIC</label>
                        <div class="proto-toggle">
                            <label class="toggle-switch"><input type="checkbox" id="toggle-doq" onchange="toggleProtocol('doq', this.checked)"><span class="toggle-slider"></span></label>
                            <input type="text" id="net-doq" placeholder="0.0.0.0:853" disabled oninput="checkNetworkChanges()">
                        </div>
                    </div>
```

- [ ] **Step 3: Update the JavaScript**

Find the `// ---- Network Settings ----` section. Replace the `refreshNetworkSettings` and `checkNetworkChanges` functions, and add new functions:

```javascript
        const PROTO_DEFAULTS = { dot: '0.0.0.0:853', doh: '0.0.0.0:443', doq: '0.0.0.0:853' };

        async function refreshNetworkSettings() {
            try {
                const res = await fetch('/api/system/network');
                if (!res.ok) return;
                serverNetworkState = await res.json();
                document.getElementById('net-dns').value = (serverNetworkState.dns_listen || [])[0] || '';
                document.getElementById('net-web').value = (serverNetworkState.web_listen || [])[0] || '';

                // Set toggle + input state for each protocol
                for (const proto of ['dot', 'doh', 'doq']) {
                    const key = proto === 'dot' ? 'dot_listen' : proto === 'doh' ? 'doh_listen' : 'doq_listen';
                    const val = (serverNetworkState[key] || [])?.[0] || '';
                    const toggle = document.getElementById('toggle-' + proto);
                    const input = document.getElementById('net-' + proto);
                    if (val) {
                        toggle.checked = true;
                        input.disabled = false;
                        input.value = val;
                    } else {
                        toggle.checked = false;
                        input.disabled = true;
                        input.value = '';
                    }
                }
            } catch (_) {}
        }

        function toggleProtocol(proto, enabled) {
            const input = document.getElementById('net-' + proto);
            if (enabled) {
                input.disabled = false;
                if (!input.value) input.value = PROTO_DEFAULTS[proto];
                saveProtocolChange();
            } else {
                input.disabled = true;
                input.value = '';
                saveProtocolChange();
            }
        }

        async function saveProtocolChange() {
            const body = {};
            for (const proto of ['dot', 'doh', 'doq']) {
                const key = proto === 'dot' ? 'dot_listen' : proto === 'doh' ? 'doh_listen' : 'doq_listen';
                const toggle = document.getElementById('toggle-' + proto);
                const input = document.getElementById('net-' + proto);
                if (toggle.checked && input.value.trim()) {
                    body[key] = input.value.trim();
                } else {
                    body[key] = null;
                }
            }

            try {
                const res = await fetch('/api/system/network', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                });
                if (res.ok) {
                    // Refresh after a short delay to let restart complete
                    setTimeout(refreshNetworkSettings, 3000);
                }
            } catch (_) {}
        }

        function checkNetworkChanges() {
            // Only generate --reconfigure banner for dns.listen and web.listen changes
            const fields = [
                { id: 'net-dns', key: 'dns.listen', server: (serverNetworkState.dns_listen || [])[0] || '' },
                { id: 'net-web', key: 'web.listen', server: (serverNetworkState.web_listen || [])[0] || '' },
            ];

            const changes = [];
            for (const f of fields) {
                const val = document.getElementById(f.id).value.trim();
                if (val !== f.server) {
                    changes.push(f.key + '=' + val);
                }
            }

            const banner = document.getElementById('reconfigBanner');
            if (changes.length > 0) {
                const cmd = 'sudo oxi-dns --reconfigure ' + changes.join(' ');
                document.getElementById('reconfigCmd').textContent = cmd;
                if (!bannerDismissed) {
                    banner.classList.add('visible');
                    startNetworkPolling();
                }
            } else {
                banner.classList.remove('visible');
                bannerDismissed = false;
                stopNetworkPolling();
            }
        }
```

Remove the old `oninput="checkNetworkChanges()"` from the DoT/DoH/DoQ inputs (they now use toggle + `saveProtocolChange`). Keep `oninput="checkNetworkChanges()"` on `net-dns` and `net-web` only.

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat: add protocol toggle switches for DoT/DoH/DoQ in dashboard"
```

---

### Task 7: Add TLS Certificate section to dashboard

**Files:**
- Modify: `src/web/dashboard.html`

Add the TLS Certificate management subsection with upload UI and cert status.

- [ ] **Step 1: Add CSS for TLS section**

In the CSS, add after the `.reconfig-btn-dismiss:hover` rule:

```css
        .tls-section { margin-top: 24px; padding-top: 20px; border-top: 1px solid var(--border); }
        .tls-section h3 { font-size: 15px; margin-bottom: 12px; color: var(--text-primary); }
        .tls-status { padding: 12px 14px; background: var(--bg-page); border-radius: 8px; margin-bottom: 12px; }
        .tls-status .tls-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .tls-status .tls-value { font-size: 14px; color: var(--text-primary); margin-top: 2px; }
        .tls-status-row { display: flex; gap: 16px; flex-wrap: wrap; }
        .tls-status-item { flex: 1; min-width: 120px; }
        .tls-upload { margin-top: 12px; }
        .tls-tabs { display: flex; gap: 4px; margin-bottom: 12px; }
        .tls-tab {
            padding: 6px 14px; border-radius: 6px; font-size: 12px; cursor: pointer;
            border: 1px solid var(--border); background: transparent; color: var(--text-muted);
        }
        .tls-tab.active { border-color: var(--accent); color: var(--accent); background: rgba(138,100,229,0.06); }
        .tls-file-input { margin-bottom: 8px; }
        .tls-file-input label { font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px; }
        .tls-file-input input[type="file"] { font-size: 13px; color: var(--text-secondary); }
        .tls-password { margin-bottom: 10px; display: none; }
        .tls-password.visible { display: block; }
        .tls-password input {
            width: 100%; background: var(--bg-page); border: 1px solid var(--border); border-radius: 6px;
            padding: 7px 10px; font-size: 13px; color: var(--text-primary); outline: none;
        }
        .tls-password input:focus { border-color: var(--accent); }
        .tls-actions { display: flex; gap: 8px; margin-top: 10px; }
        .tls-msg { margin-top: 10px; font-size: 13px; padding: 8px 12px; border-radius: 6px; display: none; }
        .tls-msg.visible { display: block; }
        .tls-msg.success { background: rgba(34,197,94,0.08); color: #22c55e; border: 1px solid rgba(34,197,94,0.2); }
        .tls-msg.error { background: rgba(248,113,113,0.08); color: #f87171; border: 1px solid rgba(248,113,113,0.25); }
```

- [ ] **Step 2: Add TLS HTML section**

In the dashboard HTML, find the closing `</div>` of the `.network-settings` div (after the reconfig banner). Add after it, before the auto-update setting-row:

```html
                <div class="tls-section manage-system-only">
                    <h3>TLS Certificate</h3>
                    <div class="tls-status" id="tlsStatus">
                        <div class="tls-status-row">
                            <div class="tls-status-item">
                                <div class="tls-label">Status</div>
                                <div class="tls-value" id="tlsCertType">Loading...</div>
                            </div>
                            <div class="tls-status-item">
                                <div class="tls-label">Subject</div>
                                <div class="tls-value" id="tlsSubject">—</div>
                            </div>
                            <div class="tls-status-item">
                                <div class="tls-label">Expires</div>
                                <div class="tls-value" id="tlsExpiry">—</div>
                            </div>
                        </div>
                    </div>
                    <div class="tls-upload">
                        <div class="tls-tabs">
                            <button class="tls-tab active" onclick="switchTlsTab('pem')">PEM</button>
                            <button class="tls-tab" onclick="switchTlsTab('p12')">PKCS12</button>
                        </div>
                        <div id="tls-pem-fields">
                            <div class="tls-file-input">
                                <label>Certificate file (chain)</label>
                                <input type="file" id="tlsCertFile" accept=".pem,.crt,.cer">
                            </div>
                            <div class="tls-file-input">
                                <label>Private key file (optional if in cert file)</label>
                                <input type="file" id="tlsKeyFile" accept=".pem,.key">
                            </div>
                        </div>
                        <div id="tls-p12-fields" style="display:none;">
                            <div class="tls-file-input">
                                <label>PKCS12 file (.pfx / .p12)</label>
                                <input type="file" id="tlsP12File" accept=".pfx,.p12">
                            </div>
                        </div>
                        <div class="tls-password" id="tlsPasswordField">
                            <label style="font-size:12px;color:var(--text-secondary);display:block;margin-bottom:4px;">Password</label>
                            <input type="password" id="tlsPassword" placeholder="Certificate password">
                        </div>
                        <div class="tls-actions">
                            <button class="btn btn-sm" onclick="uploadTlsCert()">Upload</button>
                            <button class="btn btn-sm" id="tlsRemoveBtn" onclick="removeTlsCert()" style="display:none;">Remove &amp; use self-signed</button>
                        </div>
                        <div class="tls-msg" id="tlsMsg"></div>
                    </div>
                </div>
```

- [ ] **Step 3: Add TLS JavaScript**

Add before the `// ---- Network Settings ----` comment:

```javascript
        // ---- TLS Certificate ----
        let currentTlsTab = 'pem';

        function switchTlsTab(tab) {
            currentTlsTab = tab;
            document.querySelectorAll('.tls-tab').forEach(t => t.classList.remove('active'));
            document.querySelector('.tls-tab[onclick*="' + tab + '"]').classList.add('active');
            document.getElementById('tls-pem-fields').style.display = tab === 'pem' ? '' : 'none';
            document.getElementById('tls-p12-fields').style.display = tab === 'p12' ? '' : 'none';
        }

        async function refreshTlsStatus() {
            try {
                const res = await fetch('/api/system/tls');
                if (!res.ok) return;
                const data = await res.json();
                document.getElementById('tlsCertType').textContent = data.self_signed ? 'Self-signed' : 'Custom';
                document.getElementById('tlsSubject').textContent = data.subject || '—';
                document.getElementById('tlsExpiry').textContent = data.not_after || '—';
                document.getElementById('tlsRemoveBtn').style.display = data.self_signed ? 'none' : '';
            } catch (_) {}
        }

        function showTlsMsg(msg, type) {
            const el = document.getElementById('tlsMsg');
            el.textContent = msg;
            el.className = 'tls-msg visible ' + type;
            setTimeout(() => { el.classList.remove('visible'); }, 5000);
        }

        async function uploadTlsCert() {
            const form = new FormData();
            const password = document.getElementById('tlsPassword').value;

            if (currentTlsTab === 'p12') {
                const file = document.getElementById('tlsP12File').files[0];
                if (!file) { showTlsMsg('Please select a PKCS12 file.', 'error'); return; }
                form.append('p12_file', file);
            } else {
                const certFile = document.getElementById('tlsCertFile').files[0];
                if (!certFile) { showTlsMsg('Please select a certificate file.', 'error'); return; }
                form.append('cert_file', certFile);
                const keyFile = document.getElementById('tlsKeyFile').files[0];
                if (keyFile) form.append('key_file', keyFile);
            }
            if (password) form.append('password', password);

            try {
                const res = await fetch('/api/system/tls/upload', { method: 'POST', body: form });
                const data = await res.json();

                if (res.status === 422 && data.error === 'password_required') {
                    document.getElementById('tlsPasswordField').classList.add('visible');
                    showTlsMsg('This file is password-protected. Enter the password and try again.', 'error');
                    return;
                }

                if (!res.ok) {
                    showTlsMsg(data.error || 'Upload failed.', 'error');
                    return;
                }

                showTlsMsg('Certificate uploaded. Service restarting...', 'success');
                document.getElementById('tlsPasswordField').classList.remove('visible');
                document.getElementById('tlsPassword').value = '';
                setTimeout(refreshTlsStatus, 3000);
            } catch (_) {
                showTlsMsg('Upload failed. Check your connection.', 'error');
            }
        }

        async function removeTlsCert() {
            try {
                const res = await fetch('/api/system/tls/remove', { method: 'POST' });
                if (res.ok) {
                    showTlsMsg('Reverted to self-signed certificate. Service restarting...', 'success');
                    setTimeout(refreshTlsStatus, 3000);
                }
            } catch (_) {
                showTlsMsg('Failed to remove certificate.', 'error');
            }
        }
```

- [ ] **Step 4: Add init call for TLS status**

Find where `refreshNetworkSettings()` is called on page load. Add after it:

```javascript
                refreshTlsStatus();
```

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat: add TLS certificate management section to dashboard"
```

---

### Task 8: Final verification

**Files:**
- Verify: all modified files

- [ ] **Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass (68 existing + new cert_parser tests)

- [ ] **Step 2: Verify build**

Run: `cargo build`
Expected: Successful build

- [ ] **Step 3: Verify new routes exist**

Run: `grep -E 'api/system/(network|tls)' src/web/mod.rs`
Expected: Shows all 5 routes (network GET+POST, tls GET, tls/upload POST, tls/remove POST)

- [ ] **Step 4: Verify cert parser module registered**

Run: `grep 'mod cert_parser' src/main.rs`
Expected: Shows the module declaration

- [ ] **Step 5: Verify multipart feature enabled**

Run: `grep 'multipart' Cargo.toml`
Expected: Shows axum with multipart feature
