# Encrypted DNS Protocol Toggles + Certificate Upload

**Date:** 2026-03-31
**Status:** Approved

## Problem

Users cannot enable/disable encrypted DNS protocols (DoT, DoH, DoQ) or upload custom TLS certificates from the web dashboard. These require manual config.toml editing and a service restart.

## Solution

1. Dashboard toggles for DoT/DoH/DoQ that apply changes via a zero-downtime graceful restart (no terminal commands needed)
2. Certificate upload UI supporting PEM and PKCS12 formats with password handling
3. A flexible cert parser that handles any combination of cert files (full chain, partial chain, combined cert+key, separate files, encrypted keys)

## Encrypted DNS Protocol Toggles

### Dashboard UI

In the existing Network section of System Settings, each encrypted protocol field (DoT, DoH, DoQ) gets a toggle switch next to its address input:
- Toggle on: populates a default address (`0.0.0.0:853` for DoT, `0.0.0.0:443` for DoH, `0.0.0.0:853` for DoQ) and the input becomes editable for custom addresses
- Toggle off: clears the listen address (protocol disabled)
- DNS and Web listen fields remain as-is (editable text inputs with `--reconfigure` banner for privileged changes)

### API: `POST /api/system/network`

Authenticated, requires `ManageSystem` permission.

Request body:
```json
{
  "dot_listen": "0.0.0.0:853",
  "doh_listen": null,
  "doq_listen": "0.0.0.0:853"
}
```

Only includes the encrypted protocol fields being changed. `null` disables a protocol. String value enables/changes the listen address.

The endpoint:
1. Loads current config from disk
2. Updates the `dns.dot_listen`, `dns.doh_listen`, `dns.doq_listen` fields
3. Saves config.toml to disk
4. Triggers a zero-downtime graceful restart
5. Returns `200 OK` with the updated network config

### Graceful Restart Mechanism

Uses the existing zero-downtime restart infrastructure from `src/update.rs`:
- `main.rs` creates a `tokio::sync::watch::Sender<bool>` restart signal channel
- The sender is stored in `AppState`
- When the API triggers a restart, it sends `true` on the channel
- A background task in `main.rs` watches this channel and spawns a new oxi-dns process with `--takeover` and `--ready-file`
- The new process loads fresh config, binds to the new ports with `SO_REUSEPORT`, writes the readiness file
- The old process detects readiness and exits gracefully
- DNS is never interrupted

### What still uses `--reconfigure`

The `dns.listen` and `web.listen` fields remain with the existing `--reconfigure` command banner, because:
- Changing DNS listen to/from port 53 may require systemd-resolved reconfiguration (root privilege)
- The `--reconfigure` infrastructure already handles this correctly

## Certificate Upload

### Dashboard UI

New "TLS Certificate" subsection in System Settings, below Network, above auto-update toggles.

**Display:**
- Current cert status: "Self-signed" or custom cert info (subject CN, issuer, expiry date)
- If custom cert: a "Remove" button to revert to self-signed

**Upload area:**
- Format selector: PEM / PKCS12 tabs
- PEM tab: two file inputs — "Certificate file" (cert chain) and "Private key file" (optional if key is in cert file)
- PKCS12 tab: one file input for .pfx/.p12 file
- Password field: hidden by default, shown when the backend reports the uploaded file is password-protected
- "Upload" button

### API: `POST /api/system/tls/upload`

Authenticated, requires `ManageSystem` permission. Accepts `multipart/form-data`.

Form fields:
- `cert_file` — PEM certificate file (may contain full chain + key)
- `key_file` — PEM private key file (optional if key is in cert_file)
- `p12_file` — PKCS12 bundle (alternative to cert_file + key_file)
- `password` — passphrase for encrypted PEM key or PKCS12 (optional, included on retry)

**Flow:**
1. Parse the uploaded file(s) using the cert parser
2. If encrypted and no password provided: return `422` with `{"error": "password_required", "type": "pkcs12"|"encrypted_pem"}`
3. Validate: at least one certificate present, exactly one private key present, key matches the first certificate's public key
4. Write cert chain to `/etc/oxi-dns/cert.pem` (PEM format, mode `644`)
5. Write private key to `/etc/oxi-dns/key.pem` (unencrypted PEM, mode `600`)
6. Set ownership to `oxi-dns:oxi-dns` on both files
7. Update config: `tls.cert_path = "/etc/oxi-dns/cert.pem"`, `tls.key_path = "/etc/oxi-dns/key.pem"`
8. Save config.toml and trigger graceful restart
9. Return `200 OK` with cert details:

```json
{
  "subject": "example.com",
  "issuer": "Let's Encrypt Authority X3",
  "not_after": "2026-06-30T00:00:00Z",
  "self_signed": false
}
```

### API: `GET /api/system/tls`

Authenticated, requires `ManageSystem` permission.

Returns current TLS certificate info:
```json
{
  "subject": "Oxi-DNS Server",
  "issuer": "Oxi-DNS Server",
  "not_after": "2027-03-31T00:00:00Z",
  "self_signed": true,
  "cert_path": null,
  "key_path": null
}
```

When `cert_path` and `key_path` are `null`, it means the self-signed cert is in use (no user-uploaded cert).

### API: `POST /api/system/tls/remove`

Authenticated, requires `ManageSystem` permission.

Removes user-uploaded cert, reverts to self-signed:
1. Deletes `/etc/oxi-dns/cert.pem` and `/etc/oxi-dns/key.pem` (if they exist)
2. Sets `tls.cert_path = null`, `tls.key_path = null` in config
3. Saves config.toml and triggers graceful restart
4. Returns `200 OK`

## Certificate Parser (`src/cert_parser.rs`)

A flexible parser that accepts any combination of cert-related files and extracts a cert chain + private key.

### Supported inputs

| Input | Handling |
|-------|----------|
| PEM cert chain (one or multiple `CERTIFICATE` blocks) | Extracts all certs in order |
| PEM with cert + key in same file | Extracts both |
| Separate PEM cert file + PEM key file | Merges from both |
| Encrypted PEM private key (`ENCRYPTED PRIVATE KEY`) | Decrypts with provided password |
| PKCS12 / PFX binary bundle | Extracts cert chain + key, decrypts with password |
| Full chain (leaf + intermediates + root) | Stores all certs |
| Partial chain (leaf + intermediates, no root) | Stores as-is (normal for production) |
| Leaf cert only | Stores as-is |

### Validation

- At least one certificate must be present
- Exactly one private key must be present
- The private key must match the first (leaf) certificate's public key
- If password-protected content detected and no password provided, return a specific error

### Output

```rust
pub struct ParsedCertificate {
    pub certs: Vec<Vec<u8>>,     // DER-encoded certificates, leaf first
    pub key: Vec<u8>,            // DER-encoded private key (decrypted)
    pub subject: String,         // CN from leaf cert
    pub issuer: String,          // Issuer CN from leaf cert
    pub not_after: String,       // Expiry as ISO 8601
    pub self_signed: bool,       // subject == issuer
}
```

### Dependencies

- `rustls-pemfile` (already in project) — PEM parsing
- `p12` crate — PKCS12 parsing
- `x509-parser` crate — cert inspection (subject, issuer, expiry, public key extraction)
- `pkcs8` crate — encrypted PEM key decryption

## Scope

### New files
- `src/cert_parser.rs` — flexible cert/key parser

### Modified files
- `src/web/mod.rs` — add `POST /api/system/network`, `POST /api/system/tls/upload`, `GET /api/system/tls`, `POST /api/system/tls/remove`
- `src/web/dashboard.html` — protocol toggles in Network section, TLS Certificate subsection
- `src/main.rs` — add restart signal channel, background restart watcher task
- `src/web/mod.rs` (`AppState`) — add restart signal sender to shared state
- `Cargo.toml` — add `p12`, `x509-parser`, `pkcs8`, `axum-multipart` or use axum's built-in multipart

### Not changed
- `src/config.rs` — TlsConfig struct already has `cert_path` and `key_path` fields
- `src/tls.rs` — load_or_generate_certs already handles both user-provided and self-signed paths
- `src/auth/middleware.rs` — all new endpoints are behind auth
- `scripts/install.sh`, `scripts/uninstall.sh` — no changes
