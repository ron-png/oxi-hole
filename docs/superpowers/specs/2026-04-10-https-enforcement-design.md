# HTTPS enforcement & sensitive-feature gating

**Date:** 2026-04-10
**Status:** Design approved, pending implementation plan

## Problem

The oxi-dns web dashboard currently has these gaps in its HTTPS story:

1. **HTTPS port is invisible in the UI.** `web.https_listen` exists in config and defaults to `9854` via migration, but there's no way to edit it from the Network tab — users must hand-edit `config.toml` or use the CLI `--reconfigure` command. All other listener ports (DoT, DoH, DoQ) are editable in the Network tab.
2. **HTTP → HTTPS redirect is all-or-nothing.** When HTTPS is active (cert + `https_listen` both set), HTTP is *unconditionally* force-redirected. There's no way for an admin to keep HTTP accessible for read-only/LAN use while still having HTTPS available for sensitive operations.
3. **Sensitive writes aren't gated when HTTPS is off.** The existing `sensitive_https_middleware` only kicks in when HTTPS is active. A user on a fresh install with no `https_listen` configured can happily POST their Cloudflare API token, cert files, and passwords over plain HTTP.
4. **No nudge to rotate passwords after enabling HTTPS.** A user who has been logging in over plain HTTP, then enables HTTPS, has no indication that their old password may have been sniffed and should be rotated.

A self-signed cert is auto-generated on startup (`src/tls.rs` fallback), so HTTPS is *always* reachable from day one — the user just has to know to go there. That fact unlocks a simple design: gate sensitive features on the request protocol, not on any config state.

## Goals

- Add a **HTTPS Web Dashboard** port row to the Network tab, editable with the same UX as DoT/DoH/DoQ.
- Add an **Auto-redirect HTTP → HTTPS** toggle, **off by default**, editable in the Network tab.
- **Always block** sensitive API endpoints over plain HTTP, regardless of toggle state or HTTPS activation state.
- Surface the block in the UI via a **global banner** + **per-form inline replacement** so users understand why a feature is disabled before hitting a 403.
- When the admin first flips auto-redirect ON, show a **persistent password-change recommendation banner** until any user changes their password.

## Non-goals

- Per-user password-change tracking. The recommendation flag is system-wide — any successful password change clears it for everyone.
- Auth-log inspection to detect "user X logged in over HTTP in the past" as a trigger. Too much state, not enough value.
- Making `web.https_listen` editable only via CLI `--reconfigure` (like `web.listen` and `dns.listen`). HTTPS is a new binding, not a change to the system-resolver-owned port, so it's safe to web-edit with the standard restart signal.
- Changing HSTS behavior.
- Preventing the user from clearing `https_listen` entirely. If they do, HTTPS is off and sensitive features become unreachable — that's their call, and a one-line config fix recovers them.

## Design

### Config schema (`src/config.rs`)

Two new fields on `WebConfig`:

```rust
pub struct WebConfig {
    pub listen: Vec<String>,
    pub https_listen: Option<Vec<String>>,
    #[serde(default)]
    pub auto_redirect_https: bool,           // NEW — default false
    #[serde(default)]
    pub password_change_recommended: bool,   // NEW — default false, transient
}
```

- Both use `#[serde(default)]` so old configs deserialize cleanly. No migration needed beyond the existing `https_listen` default.
- `auto_redirect_https` lives under `[web]` because it's web-server behavior.
- `password_change_recommended` is a transient admin-state flag, not user preference. Stored in `[web]` to co-locate with the toggle that sets it. A restart is not needed when it changes — the frontend polls it.

### Backend: middleware changes (`src/web/mod.rs:309`)

`sensitive_https_middleware` drops its state dependency:

```rust
// Before:
//   if https_active && !has IsHttps ext && path in SENSITIVE_PATHS → 403
// After:
//   if !has IsHttps ext && path in SENSITIVE_PATHS → 403
```

The `State<bool>` input goes away entirely. The middleware becomes a pure function of the request extensions. `SENSITIVE_PATHS` is unchanged. The response body stays a 403 with a JSON hint so the frontend can distinguish it from other 403s:

```json
{ "error": "This endpoint requires HTTPS. Use https:// to access the dashboard securely." }
```

Security headers middleware, auth middleware, and all other layers are untouched.

### Backend: HTTP listener behavior (`src/web/mod.rs:481`)

`run_web_server` gains one more boolean and a branch:

```
is_https_active = https_listen.is_some() && tls_config.is_some()

if is_https_active:
    serve HTTPS app on https_listen addrs  (unchanged)
    if auto_redirect_https:
        HTTP listener → redirect-only app  (unchanged current behavior)
    else:
        HTTP listener → full app            (NEW — normally serves everything,
                                              but sensitive paths get 403 from
                                              middleware due to missing IsHttps ext)
else:
    HTTP listener → full app                (unchanged — no HTTPS at all)
```

The function signature gains `auto_redirect_https: bool`. `main.rs` passes it in from the loaded config. On reconfigure, the restart signal tears down and rebuilds listeners with the new value.

### Backend: Network API (`src/web/mod.rs:687`)

`api_system_network` response adds two fields:

```json
{
  "dns_listen": [...],
  "web_listen": [...],
  "https_listen": [...],              // NEW
  "dot_listen": [...],
  "doh_listen": [...],
  "doq_listen": [...],
  "auto_redirect_https": false,       // NEW
  "interfaces": [...]
}
```

`UpdateNetworkRequest` gains `https_listen: Option<serde_json::Value>` and `auto_redirect_https: Option<bool>`. Handling:

- `https_listen`: parsed via existing `parse_optional_listen_value`, assigned to `config.web.https_listen`. Accepts string, array, or null (clears).
- `auto_redirect_https`:
  - If `true` and `config.web.https_listen.is_none()` → **400 Bad Request** with `{"error": "HTTPS must be configured before enabling auto-redirect"}`. The frontend disables the toggle in that state, but the backend enforces.
  - If transitioning `false` → `true`, set `config.web.password_change_recommended = true`.
  - If transitioning `true` → `false`, leave `password_change_recommended` alone (it's cleared only by a successful password change).

Save config, send restart signal, return the same JSON shape as GET.

### Backend: password-change hook

`api_change_password` (existing handler, wherever it lives under the auth module):

- On successful password change, load config, set `config.web.password_change_recommended = false`, save. Swallow save failures with a warn log — the password change itself succeeded and that's what matters.
- No restart signal needed — the change only affects a frontend banner poll, not any listener state.

### Backend: security-status endpoint

New `GET /api/system/security-status`:

```rust
async fn api_security_status(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Json<serde_json::Value> {
    let is_https = request.extensions().get::<IsHttps>().is_some();
    // ... load config, build response ...
}
```

Returns:
```json
{
  "is_https_request": true,           // present IsHttps ext?
  "password_change_recommended": false,
  "https_available": true              // https_listen.is_some()
}
```

Behind the existing auth middleware — returns 401 for unauthenticated users. No special permission required; every logged-in user needs to know whether to show the banner. Placed alongside the other `/api/system/*` read endpoints.

Frontend polls this on dashboard load and after any password/network change.

### Frontend: Network tab additions (`src/web/dashboard.html`)

**HTTPS Web Dashboard row.** Append to `NETWORK_LISTENERS` around line 3800:

```js
{ prefix: 'net-web-https', key: 'web.https_listen', serverKey: 'https_listen',
  label: 'Web Dashboard (HTTPS)', required: false, toggleId: 'toggle-web-https',
  proto: 'https', defaultPort: '9854' },
```

The generic rendering loop builds a toggle + IPv4 port + IPv6 port row. Reuses `getFamilyBindings`, `setPortInputValue`, save handler, restart notification. No new rendering code.

**Auto-redirect switch.** A new standalone control below the HTTPS row (not in `NETWORK_LISTENERS` because it's a boolean). Mirrors the existing toggle switch styling used by IPv6, auto-update, etc. Wired to the same `POST /api/system/network` endpoint as the listener edits. Disabled with a tooltip when `https_listen` is unset/empty.

### Frontend: Global banners

Two banners injected at the top of the dashboard `<main>`, above all existing content. Both are state-driven (no dismiss button — they disappear automatically when the state clears).

**HTTP warning banner** — visible when `window.location.protocol === 'http:'`:

> ⚠ **You're connected over plain HTTP.**
> Sensitive settings (certificates, ACME tokens, password changes) are disabled.
> [**Switch to HTTPS →**]

The button builds `https://${location.hostname}:${httpsPort}${location.pathname}${location.search}` using the HTTPS port from the `/api/system/network` response. On click, `window.location.href = ...`.

**Password-change recommendation banner** — visible when `security_status.password_change_recommended === true` AND `window.location.protocol === 'https:'`:

> 🔑 **HTTPS is now active.**
> Your account password may have been transmitted in plaintext before HTTPS was enabled. We recommend changing it now.
> [**Change password →**]

The button navigates to the existing password-change UI (scroll-to or modal-open, whichever the current dashboard uses).

Both banners share a simple CSS class — styled like the existing warning/info banners in the dashboard.

### Frontend: Inline form disable

Three forms get the treatment: cert upload, ACME provider-token entry, password change.

Wrap each form's content in a container with a data attribute:

```html
<div class="sensitive-form" data-requires-https>
  <!-- original form contents -->
</div>
```

On dashboard init, if `location.protocol === 'http:'`, for every `.sensitive-form` element, replace its inner HTML with:

```html
<div class="sensitive-warning">
  🔒 This feature requires HTTPS.
  <a href="..." class="btn">Switch to HTTPS →</a>
</div>
```

The link uses the same HTTPS URL builder as the banner. One function handles all three forms — no per-form code.

On HTTPS, the forms render normally; no JS work.

### Interactions & edge cases

- **User clears `https_listen` while auto-redirect is on:** backend should auto-flip `auto_redirect_https` to `false` at the same time. Any later attempt to turn it back on while `https_listen` is unset gets the 400 error.
- **User changes HTTPS port:** restart signal rebinds the HTTPS listener. Current HTTPS sessions are dropped — same behavior as today for DoT/DoH/DoQ port changes. Frontend shows a "saved, rebinding..." message.
- **Multi-user environment:** first user to change their password clears `password_change_recommended` for everyone. Acceptable simplification — the point of the nudge is to remind *someone* to rotate, not to track each user.
- **Staleness:** frontend polls `/api/system/security-status` on dashboard load and after any auth/network action. No websocket push — polling on navigation is enough.
- **Self-signed cert warnings:** browsers will balk at the self-signed cert when users first switch to HTTPS. That's expected and out of scope — the ACME flow handles real certs.

## Components & files

### New
- `GET /api/system/security-status` — new handler in `src/web/mod.rs`
- `docs/superpowers/specs/2026-04-10-https-enforcement-design.md` — this file

### Modified
- `src/config.rs` — add two fields to `WebConfig`, add tests
- `src/web/mod.rs`:
  - `sensitive_https_middleware` — drop state dependency, simplify condition
  - `run_web_server` — branch on `auto_redirect_https`, accept new parameter
  - `api_system_network` — return `https_listen` + `auto_redirect_https`
  - `UpdateNetworkRequest` — two new fields
  - `api_update_network` — parse, validate (400 if enabling without https_listen), set `password_change_recommended` on false→true transition
  - `api_change_password` — clear `password_change_recommended` on success
  - Router — register `/api/system/security-status`
- `src/main.rs` — pass `auto_redirect_https` into `run_web_server`
- `src/web/dashboard.html`:
  - `NETWORK_LISTENERS` array — add HTTPS row
  - Network tab markup — add HTTPS port inputs + auto-redirect toggle
  - Global banner markup + CSS
  - Sensitive-form wrapping + init-time replacement logic
  - `loadNetwork` / `saveNetwork` handlers — include new fields
  - Security-status polling on init + after relevant actions

## Testing

### Unit tests
- `config.rs`: round-trip load/save with new fields; defaults match; old config without either field deserializes fine.
- `reconfigure.rs`: guard test — `web.https_listen` is **not** in the CLI-reconfigure key allow-list.

### Integration tests (handler-level)
- `api_update_network` accepts `https_listen` + `auto_redirect_https`, persists, triggers restart signal.
- `api_update_network` with `auto_redirect_https: true` when `https_listen` is `None` → 400.
- `api_update_network` false → true transition sets `password_change_recommended = true`.
- `api_change_password` success clears `password_change_recommended`.
- `sensitive_https_middleware`: plain-HTTP POST to `/api/system/tls/upload` → 403 regardless of config state; HTTPS POST (IsHttps extension present) → passes through.
- `GET /api/system/security-status` returns correct `is_https_request` based on which listener served the request.

### Manual browser verification
1. Fresh server, self-signed cert auto-generated, hit `http://host:9853` → HTTP banner visible, cert-upload/ACME/password-change forms replaced with warning cards.
2. Click "Switch to HTTPS" → `https://host:9854` → accept self-signed warning → HTTP banner gone, forms visible, functional.
3. Network tab: change HTTPS port 9854 → 9855 → save → verify rebind on new port.
4. Flip auto-redirect ON → `http://host:9853/` returns 301 to HTTPS. On HTTPS dashboard, password-change banner is now visible.
5. Change password → banner disappears, `config.toml` shows `password_change_recommended = false`.
6. Flip auto-redirect OFF → HTTP serves the dashboard again, sensitive forms still disabled (correctly).
7. `curl -X POST http://host:9853/api/system/tls/upload` → 403 with the warning JSON.

## Out of scope

- Per-user password-change tracking.
- Changing HSTS header values.
- Auth-log inspection for "was this user ever logged in over HTTP" triggers.
- Automatic TLS cert rotation beyond what ACME already provides.
- Blocking *read* APIs over HTTP (only writes to sensitive paths are blocked; stats and dashboard remain HTTP-visible).
