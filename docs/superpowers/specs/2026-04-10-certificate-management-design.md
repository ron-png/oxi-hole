# Certificate Management with Let's Encrypt

## Overview

Add ACME/Let's Encrypt certificate issuance and auto-renewal to oxi-dns. Consolidate all certificate management (ACME + manual upload + status) into a single modal accessible from the Advanced tab, replacing the existing TLS section in System Settings.

## Architecture

A new `src/acme.rs` module handles ACME protocol interactions: account creation, order placement, DNS-01 challenges, and certificate download. Uses `instant-acme` for the ACME protocol and `reqwest` (already a dependency) for DNS provider API calls.

A background renewal task runs daily. When the current certificate is within 30 days of expiry and ACME config is saved, it auto-renews using stored provider credentials.

## Modal UI

Opened via a "Manage Certificates" button in the Advanced tab. The existing TLS Certificate section in System Settings is removed.

### Tab 1: Status

- Current certificate info: subject, issuer, expiry, type (Self-signed / Let's Encrypt / Custom)
- Auto-renewal status: last success/failure timestamp, next scheduled check
- "Remove & use self-signed" button

### Tab 2: Let's Encrypt

- Domain input field
- Email input field (for Let's Encrypt registration)
- Provider selection dropdown:
  - **Cloudflare** — shows API token input field
  - **Manual** — no extra fields; challenge details shown during issuance
  - **Suggest a provider** — link to https://github.com/ron-png/oxi-dns/issues/new
- Staging environment toggle (for testing)
- "Issue Certificate" button

During issuance, the tab shows progress steps:

1. Creating ACME account
2. Placing order
3. Waiting for DNS challenge (Cloudflare: automatic; Manual: shows TXT record name + value, confirm button + background polling every 15s)
4. Downloading certificate
5. Installing and restarting

### Tab 3: Manual Upload

The existing PEM/PKCS12 upload UI relocated here. Same functionality: file inputs, password field for encrypted keys, upload button.

## DNS Providers

### Cloudflare

Requires an API token with `Zone:DNS:Edit` permission. Uses Cloudflare API v4:

- `GET /zones?name=<domain>` to find zone ID
- `POST /zones/<id>/dns_records` to create `_acme-challenge.<domain>` TXT record
- `DELETE /zones/<id>/dns_records/<record_id>` to clean up after validation

### Manual

Displays the TXT record name (`_acme-challenge.<domain>`) and value. The user creates this record at their DNS provider. Two completion triggers — whichever fires first:

- User clicks "I've created the record" confirm button
- Background polling every 15 seconds detects the TXT record via DNS lookup

### Suggest a Provider

A link styled as a dropdown option that opens `https://github.com/ron-png/oxi-dns/issues/new` in a new tab.

## Auto-Renewal

- Background tokio task spawned at server startup
- Checks once daily whether the current cert expires within 30 days
- Only renews if ACME config is saved and enabled
- Uses stored provider credentials (Cloudflare token or manual mode)
- Manual mode auto-renewal: attempts DNS lookup for existing `_acme-challenge` TXT record; if not found, logs warning and skips (user must renew manually)
- Persists renewal status: last attempt timestamp, success/failure, error message
- Failed renewals log at WARN level and set a status flag visible in the modal

## Configuration

Added to `config.toml` under `[tls]`:

```toml
[tls]
cert_path = "/etc/oxi-dns/cert.pem"
key_path = "/etc/oxi-dns/key.pem"

[tls.acme]
enabled = false
domain = ""
email = ""
provider = "cloudflare"  # "cloudflare" or "manual"
cloudflare_api_token = ""
use_staging = false
last_renewed = ""
last_renewal_error = ""
```

The `cloudflare_api_token` field is stored in the config file. The config file should have restricted permissions (600) since it contains secrets.

## API Endpoints

All require `ManageSystem` permission.

### New Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/system/tls/acme/issue` | Start certificate issuance. Body: `{ domain, email, provider, cloudflare_api_token?, use_staging }`. Returns challenge details for manual mode or completes automatically for Cloudflare. |
| `POST` | `/api/system/tls/acme/confirm` | Manual mode: user confirms TXT record is created. Triggers challenge validation and certificate download. |
| `GET` | `/api/system/tls/acme/status` | Poll issuance progress during active issuance. Also returns renewal status (last_renewed, last_error, next_check). |
| `POST` | `/api/system/tls/acme/renew` | Trigger immediate renewal using saved ACME config. |

### Existing Endpoints (unchanged)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/system/tls` | Get current certificate info |
| `POST` | `/api/system/tls/upload` | Upload PEM/PKCS12 certificate |
| `POST` | `/api/system/tls/remove` | Revert to self-signed |

## New Dependencies

- `instant-acme` — async ACME protocol client

## UI Changes

### Removed

- TLS Certificate section from System Settings (dashboard.html lines 2433-2484)
- Associated CSS (`.tls-section`, `.tls-status`, `.tls-tabs`, `.tls-upload`)

### Added

- "Manage Certificates" button in Advanced tab (after Upstream DNS Servers section, before User Management)
- Certificate management modal with three tabs (Status, Let's Encrypt, Manual Upload)
- Progress stepper UI for ACME issuance flow
- Renewal status indicator

### Moved

- PEM/PKCS12 upload form from System Settings into the modal's Manual Upload tab

## Files Modified

| File | Change |
|------|--------|
| `Cargo.toml` | Add `instant-acme` dependency |
| `src/acme.rs` | New: ACME client, DNS providers, renewal task |
| `src/config.rs` | Add `AcmeConfig` struct to `TlsConfig` |
| `src/main.rs` | Spawn renewal background task |
| `src/web/mod.rs` | Add ACME API endpoints, remove old TLS section routes (keep upload/remove/status) |
| `src/web/dashboard.html` | Remove TLS section from System Settings, add button + modal in Advanced tab |

## ACME Directory

Let's Encrypt only:
- Production: `https://acme-v02.api.letsencrypt.org/directory`
- Staging: `https://acme-staging-v02.api.letsencrypt.org/directory`

## Error Handling

- Invalid Cloudflare token: surface API error message in the modal
- DNS propagation timeout (manual mode): after 10 minutes of polling, show timeout message with option to retry
- ACME rate limits: surface Let's Encrypt error message; suggest using staging for testing
- Renewal failure: log warning, store error in config, show in Status tab
- Network errors: retry up to 3 times with exponential backoff for ACME and Cloudflare API calls
