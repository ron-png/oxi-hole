# Security Hardening: HTTPS, HSTS, Rate Limiting, CSP Nonce

**Date:** 2026-03-31
**Status:** Approved

## Problem

A security audit identified four gaps in frontend-backend communication:
1. Web dashboard runs plain HTTP by default — no transport encryption
2. No HSTS header even when TLS is available
3. Rate limiting only on login — password change, setup, and admin endpoints unprotected
4. CSP allows `unsafe-inline` for scripts — weakens XSS protection

## Solution

1. Optional HTTPS binding for the web dashboard (activated when user uploads a cert + configures `https_listen`)
2. HSTS header on HTTPS responses
3. Tiered rate limiting: strict on auth endpoints, looser on admin endpoints
4. Per-request CSP nonce for inline scripts (remove `unsafe-inline` from `script-src`)

## 1. HTTPS for Web Dashboard

### Config

New optional field in `WebConfig`:
```toml
[web]
listen = "0.0.0.0:9853"
https_listen = "0.0.0.0:9443"  # optional
```

`https_listen` defaults to `None`. HTTPS only activates when ALL three conditions are met:
- `web.https_listen` is set
- `tls.cert_path` is set (user-uploaded cert, not self-signed)
- `tls.key_path` is set

### Behavior

**When HTTPS is active (cert uploaded + https_listen configured):**
- HTTPS listener serves the dashboard on `https_listen` address
- HTTP listener on `web.listen` responds with `301 Moved Permanently` redirecting to the HTTPS address
- HSTS header is sent on all HTTPS responses

**When HTTPS is not active (default — no cert or no https_listen):**
- HTTP listener serves the dashboard normally on `web.listen`
- No redirects, no HSTS
- Self-signed certs do NOT trigger HTTPS for the web UI (they cause browser warnings)

**Dashboard hint:** When a cert is uploaded but `https_listen` is not configured, the Network settings section shows a suggestion banner: "TLS certificate is available. Enable HTTPS for the dashboard by setting an HTTPS listen address." This uses the same `--reconfigure` command pattern.

### Startup flow in main.rs

1. Always start HTTP web server on `config.web.listen`
2. Check if `config.tls.cert_path` + `config.tls.key_path` + `config.web.https_listen` are all set
3. If yes: build a rustls `ServerConfig` using the same `tls::build_server_config()` with `["h2", "http/1.1"]` ALPN, bind HTTPS on `config.web.https_listen`, set HTTP to redirect mode
4. If no: HTTP serves normally

### HTTP redirect mode

When HTTPS is active, the HTTP listener serves a minimal redirect handler instead of the full app router:
```
HTTP/1.1 301 Moved Permanently
Location: https://{host}:{https_port}{path}
```

The redirect preserves the request path and query string.

### Config field

```rust
// In WebConfig
#[serde(default, deserialize_with = "string_or_vec_opt")]
pub https_listen: Option<Vec<String>>,
```

## 2. HSTS Header

Added to `security_headers_middleware` conditionally.

**Logic:** A shared flag (`is_https: bool`) is set based on which listener is serving the request. The HTTPS listener sets it to `true` via request extensions. When `true`, the middleware adds:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

The HTTP listener never sets HSTS (as per RFC 6797 — HSTS must only be sent over secure transport).

**Implementation:** The HTTPS app router wraps the shared router with an additional middleware layer that inserts an `IsHttps(true)` extension. The `security_headers_middleware` checks for this extension.

## 3. Tiered Rate Limiting

### Generalized RateLimiter

The existing `LoginRateLimiter` is renamed to `RateLimiter` and parameterized:

```rust
pub struct RateLimiter {
    max_attempts: u32,
    window_secs: u64,
    attempts: DashMap<String, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self { ... }
    pub fn check_rate_limit(&self, key: &str) -> bool { ... }
    pub fn cleanup(&self) { ... }
}
```

### Two tiers in AppState

```rust
pub struct AppState {
    // ...
    pub auth_rate_limiter: RateLimiter,   // 5 requests / 60s per IP
    pub admin_rate_limiter: RateLimiter,  // 20 requests / 60s per IP
}
```

The old `login_rate_limiter` field is replaced by `auth_rate_limiter`.

### Endpoint mapping

**Auth tier (5/60s per IP):**
- `POST /api/auth/login` (existing, updated to use `auth_rate_limiter`)
- `POST /api/auth/setup` (new rate limiting)
- `POST /api/auth/change-password` (new rate limiting)

**Admin tier (20/60s per IP):**
- `POST /api/tokens` (new rate limiting)
- `POST /api/system/tls/upload` (new rate limiting)
- `POST /api/users` (new rate limiting)
- `POST /api/users/{id}/reset-password` (new rate limiting)

### Cleanup

The existing background cleanup task (every 60 seconds) is updated to clean both rate limiters.

## 4. CSP Nonce for Scripts

### Nonce generation

The `security_headers_middleware` generates a 16-byte random nonce per request, base64-encoded. This nonce is:
1. Stored as a request extension: `request.extensions_mut().insert(CspNonce(nonce_string))`
2. Used in the CSP header: `script-src 'self' 'nonce-{nonce}'`

### CSP header change

Before:
```
script-src 'self' 'unsafe-inline'
```

After:
```
script-src 'self' 'nonce-{per-request-random}'
```

`style-src 'self' 'unsafe-inline'` stays unchanged (inline styles are low-risk).

### HTML injection

The three HTML-serving handlers (`dashboard`, `login_page`, `setup_page`) extract the nonce from the request extension and inject it into script tags:

```rust
async fn dashboard(nonce: Option<axum::Extension<CspNonce>>) -> Html<String> {
    let html = include_str!("dashboard.html");
    let nonce_val = nonce.map(|n| n.0.0.clone()).unwrap_or_default();
    Html(html.replace("<script>", &format!("<script nonce=\"{}\">", nonce_val)))
}
```

The `str::replace` approach works because:
- Each HTML file has a small number of `<script>` tags (1-2 per file)
- The replacement is a simple string operation, very fast
- No templating engine needed

### CspNonce type

```rust
#[derive(Clone)]
struct CspNonce(String);
```

Inserted by the middleware, extracted by HTML handlers.

## Scope

### Modified files
- `src/config.rs` — add `https_listen: Option<Vec<String>>` to `WebConfig`
- `src/web/mod.rs` — HTTPS redirect handler, HSTS in security headers, generalized `RateLimiter`, CSP nonce generation + injection, updated HTML handlers to return `Html<String>` with nonce, `CspNonce` type
- `src/main.rs` — spawn HTTPS listener alongside HTTP when conditions met, update rate limiter construction, update cleanup task

### Not changed
- `src/web/dashboard.html` — nonce injected at serve time, no HTML changes
- `src/web/login.html` — same
- `src/web/setup.html` — same
- `src/tls.rs` — `build_server_config` already supports custom ALPN, reused for web HTTPS
- `src/auth/middleware.rs` — no changes
- `scripts/install.sh`, `scripts/uninstall.sh` — no changes
