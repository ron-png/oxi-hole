# Setup Wizard

**Date:** 2026-03-31
**Status:** Approved

## Problem

Oxi-dns currently handles DNS configuration (systemd-resolved conflict resolution) entirely in the install script with a simple yes/no prompt, giving users no choice between replacing systemd-resolved or running alongside it. The web setup page only creates an admin account. Users who want oxi-dns to coexist with systemd-resolved on a different port/interface have no supported path.

## Solution

A two-part setup flow:

1. **Install script** — interactive prompts for web dashboard port and DNS mode (replace vs. coexist with systemd-resolved), since these require root privileges
2. **Web setup wizard** — multi-step first-run wizard replacing the current `/setup` page, handling account creation and showing a configuration summary

## Scope

### Modified files

- `scripts/install.sh` — web port prompt, DNS mode choice replacing `fix_systemd_resolved()`
- `scripts/uninstall.sh` + embedded copy in install.sh — update `restore_dns()` to handle coexist mode
- `src/web/setup.html` — replace single form with 3-step wizard
- `src/web/mod.rs` — add `GET /api/system/setup-info` endpoint
- `src/config.rs` — change default web port from `8080` to `9853`
- `config.toml` (repo root) — update default web port

### Not changed

- `src/main.rs` — startup flow unchanged
- `src/auth/*` — auth middleware and `needs_setup()` detection unchanged
- DNS listener logic — already reads listen address from config

## Install Script Changes

### Web dashboard port prompt

After binary installation, before writing `config.toml`, the script prompts:

```
Web dashboard port [9853]:
```

- Pressing Enter uses the default `9853`
- Validates input is a number between 1-65535
- The value is written into `config.toml` as `[web] listen = "0.0.0.0:<port>"`
- Shown on all platforms (not conditional)

### DNS mode choice

Replaces the current `fix_systemd_resolved()` yes/no prompt. Only shown when systemd-resolved is detected on port 53 (same detection as today via `check_port53()`).

**Prompt:**

```
systemd-resolved is using port 53. How should Oxi-DNS handle this?

  1) Replace systemd-resolved (recommended for whole-network ad blocking)
     Disables the stub listener, Oxi-DNS becomes your system DNS on port 53

  2) Run alongside systemd-resolved
     Oxi-DNS listens on a different address/port, point clients to it directly

Choice [1]:
```

- Default: 1 (replace) — matches current behavior
- Pressing Enter selects replace mode

**If choice 1 (replace):** Existing `fix_systemd_resolved()` logic runs as before — creates resolved drop-in config, rewrites resolv.conf, restarts systemd-resolved.

**If choice 2 (coexist):** Follow-up prompt:

```
Choose a listen configuration:

  1) All interfaces, alternate port (0.0.0.0:5353)
  2) LAN IP only, standard port (<detected-ip>:53)
  3) Custom (enter address:port)

Choice [1]:
```

- Option 1: Sets `[dns] listen = "0.0.0.0:5353"` — no systemd-resolved changes needed
- Option 2: Auto-detects the primary LAN IP (via `hostname -I` or `ifconfig`), sets `[dns] listen = "<ip>:53"` — no resolved changes if the detected IP isn't 127.0.0.53
- Option 3: Prompts `Enter listen address (ip:port):` — user types e.g. `192.168.1.10:53`
- In all coexist cases, systemd-resolved is left untouched

**Non-systemd systems:** No DNS mode prompt. Current behavior continues — if nothing is on port 53, oxi-dns uses `0.0.0.0:53`. If something else conflicts (dnsmasq, BIND), existing prompts handle it.

### Config writing

The install script writes `config.toml` with the user's choices. The `create_default_config()` function is updated to accept the web port and DNS listen address as parameters instead of downloading a static file (for fresh installs) or using hardcoded defaults.

For reinstalls (`-r` flag) that pre-download config, the downloaded config is patched with the user's port/address choices before writing.

## Uninstall Script Changes

`restore_dns()` is updated to handle coexist mode: if no resolved drop-in files exist (`/etc/systemd/resolved.conf.d/oxi-dns.conf` not present), the uninstall script skips resolved restoration since systemd-resolved was never modified. This already works correctly with the current implementation — the `RESOLVED_CHANGED` flag only triggers restoration when drop-in files are found.

No functional changes needed — the current logic already handles both modes. The uninstall script is already correct.

## Web Setup Wizard

### Detection

Same as today: `AuthService::needs_setup()` checks if the `users` table is empty. All requests redirect to `/setup` until an admin account is created.

### Step 1 — Create Admin Account

Same functionality as current setup page:
- Username input
- Password input (minimum 8 characters)
- Confirm password input
- Client-side validation (matching passwords, minimum length)
- POSTs to existing `POST /api/auth/setup`
- On success: auto-login via session cookie, advance to step 2
- On failure: show error message inline

### Step 2 — DNS Configuration Summary

Informational, read-only step. Fetches `GET /api/system/setup-info` and displays:

- DNS listen address (e.g., `0.0.0.0:53` or `0.0.0.0:5353`)
- DNS mode description (e.g., "Replaced systemd-resolved" or "Running alongside systemd-resolved")
- Web dashboard address
- Server's LAN IP address

Shows a tip box: "Point your devices' DNS settings to `<server-ip>` to start blocking ads."

Navigation: Back button, Next button, "Skip to dashboard" link.

### Step 3 — Done

Summary card with:
- Admin username
- DNS listen address
- Dashboard URL (clickable)

"Open Dashboard" button that navigates to `/`.

### UI Design

- Dark theme matching existing oxi-dns dashboard (#0f0f1a background, #1a1a2e cards, #8a64e5 purple accent)
- Step indicator dots at the top (3 dots: active, completed, pending states)
- Centered card layout, max-width 560px
- Vanilla JavaScript, no framework (matches existing codebase)
- Embedded via `include_str!()` in `src/web/mod.rs` (matches existing pattern)

## New API Endpoint

### `GET /api/system/setup-info`

Accessible during setup (before auth is complete — whitelisted in auth middleware alongside `/setup` and `/api/auth/setup`).

**Response:**
```json
{
  "dns_listen": "0.0.0.0:53",
  "web_listen": "0.0.0.0:9853",
  "server_ip": "192.168.1.10"
}
```

- `dns_listen`: read from current config's `dns.listen`
- `web_listen`: read from current config's `web.listen`
- `server_ip`: detected at runtime — first non-loopback IPv4 address from network interfaces

## Default Port Change

The default web dashboard port changes from `8080` to `9853` across:
- `src/config.rs` — `WebConfig` default
- `config.toml` — repo root default config file
- `scripts/install.sh` — install completion message, prompt default
- Any documentation or comments referencing port 8080
