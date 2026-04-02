# Privileged Reconfigure via CLI + Dashboard Command Generation

**Date:** 2026-03-31
**Status:** Approved

## Problem

The oxi-dns service runs as a restricted user (`oxi-dns`) with `NoNewPrivileges=yes` and `ProtectSystem=strict`. Changing network listen addresses (DNS, web, DoT, DoH, DoQ) requires modifying config.toml (owned by oxi-dns, writable) and potentially reconfiguring systemd-resolved (requires root). The web dashboard cannot perform these privileged actions itself.

## Solution

Two parts:
1. A `--reconfigure` CLI flag on the oxi-dns binary that applies config changes and handles system-level reconfiguration (run with sudo)
2. A dashboard UI section that shows current network config, lets users edit values, and generates the exact `sudo oxi-dns --reconfigure ...` command to copy and run

## CLI: `--reconfigure` Flag

### Usage

```bash
sudo oxi-dns --reconfigure dns.listen=0.0.0.0:5353
sudo oxi-dns --reconfigure web.listen=0.0.0.0:9853
sudo oxi-dns --reconfigure dns.listen=0.0.0.0:53 dns.dot_listen=0.0.0.0:853
sudo oxi-dns /etc/oxi-dns/config.toml --reconfigure dns.listen=0.0.0.0:5353
```

Multiple key-value pairs in a single command to batch changes. Config path is the first positional arg (defaults to `/etc/oxi-dns/config.toml`).

### Supported Keys

| Key | Config Field | Description |
|-----|-------------|-------------|
| `dns.listen` | `dns.listen` | Plain DNS listen address (UDP+TCP) |
| `dns.dot_listen` | `dns.dot_listen` | DNS-over-TLS listen address |
| `dns.doh_listen` | `dns.doh_listen` | DNS-over-HTTPS listen address |
| `dns.doq_listen` | `dns.doq_listen` | DNS-over-QUIC listen address |
| `web.listen` | `web.listen` | Web dashboard listen address |

### Execution Flow

1. Parse args — extract key=value pairs after `--reconfigure`
2. Check running as root — exit with error if not (`euid != 0`)
3. Load config from config path
4. Apply changes to config struct
5. Handle systemd-resolved if `dns.listen` changed and involves port 53:
   - Switching TO port 53 on 0.0.0.0 or 127.0.0.1: disable systemd-resolved stub listener (create `/etc/systemd/resolved.conf.d/oxi-dns.conf` with `DNSStubListener=no`, update `/etc/resolv.conf` to `127.0.0.1`, restart systemd-resolved)
   - Switching FROM port 53: re-enable systemd-resolved (remove drop-in config, restore resolv.conf symlink to stub-resolv.conf, restart systemd-resolved)
   - No systemd-resolved on system: skip silently
6. Save config to disk
7. Restart oxi-dns service (detect init system: systemctl/launchctl/rc-service)
8. Print success message and exit

### systemd-resolved Handling

Implemented in Rust by shelling out to system commands — mirrors the install/uninstall scripts' proven logic:
- `mkdir -p /etc/systemd/resolved.conf.d`
- Write/remove `/etc/systemd/resolved.conf.d/oxi-dns.conf`
- `systemctl restart systemd-resolved`
- Update `/etc/resolv.conf` (remove and symlink or write)

### Error Handling

- Not root: print `Error: --reconfigure requires root privileges. Run with sudo.` and exit 1
- Invalid key: print `Error: unknown config key '<key>'. Valid keys: dns.listen, dns.dot_listen, dns.doh_listen, dns.doq_listen, web.listen` and exit 1
- Invalid format (no `=`): print `Error: expected key=value format, got '<arg>'` and exit 1
- Config load failure: print error and exit 1
- Config save failure: print error and exit 1

## Dashboard UI: Network Settings Section

### New API Endpoint

`GET /api/system/network` — authenticated, requires `ManageSystem` permission.

Response:
```json
{
  "dns_listen": ["0.0.0.0:53"],
  "web_listen": ["0.0.0.0:9853"],
  "dot_listen": null,
  "doh_listen": null,
  "doq_listen": null
}
```

Returns the full listen address arrays from config. Null means the protocol is not configured.

### UI Layout

New "Network" subsection added to the System Settings tab in the dashboard, before the existing auto-update and IPv6 toggles.

Each protocol shown as a row with label and editable input field:
- DNS Server: `0.0.0.0:53`
- Web Dashboard: `0.0.0.0:9853`
- DNS-over-TLS: (empty, with "Enable" placeholder)
- DNS-over-HTTPS: (empty, with "Enable" placeholder)
- DNS-over-QUIC: (empty, with "Enable" placeholder)

Unconfigured protocols show a subtle input with placeholder text. Clearing a configured value disables that protocol.

### Pending Command Banner

When the user edits any network field, the dashboard compares the current input values against the server-reported values. If they differ, a yellow/amber inline banner appears below the Network section:

```
⚠ System command required

This change requires root privileges. Run this command in your terminal:

  sudo oxi-dns --reconfigure dns.listen=0.0.0.0:5353

The service will restart automatically.                    [Copy] [Dismiss]
```

**Banner behavior:**
- Appears when any field value differs from server state
- Updates dynamically as the user edits more fields (combines into single command)
- "Copy" button copies the command to clipboard
- "Dismiss" button hides the banner (reappears if user edits again)
- Banner also disappears if the dashboard polls and detects the server config now matches the edited values (meaning the user ran the command)
- Polling interval: every 5 seconds while banner is visible, via `GET /api/system/network`

**Multiple changes combined:**
```
sudo oxi-dns --reconfigure dns.listen=0.0.0.0:5353 web.listen=0.0.0.0:3000
```

**No server-side state:** The banner is purely client-side JavaScript. It tracks input values vs last-known server values.

## Scope

### New files
- `src/reconfigure.rs` — reconfigure logic (parse args, update config, systemd-resolved handling, service restart)

### Modified files
- `src/main.rs` — add `--reconfigure` CLI flag, call reconfigure module before server startup
- `src/web/mod.rs` — add `GET /api/system/network` endpoint handler
- `src/web/dashboard.html` — add Network subsection with editable fields and command banner
- `src/lib.rs` or `main.rs` — add `mod reconfigure`

### Not changed
- `src/config.rs` — config struct already has all listen fields
- `src/auth/middleware.rs` — new endpoint is behind auth (not a setup-mode endpoint)
- `scripts/install.sh` — no changes
- `scripts/uninstall.sh` — no changes
