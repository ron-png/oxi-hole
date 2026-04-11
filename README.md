# Oxi-DNS — DNS Ad Blocker & Sinkhole Written in Rust

A fast, memory-safe DNS sinkhole that blocks ads, trackers, and malware at the network level. A modern alternative to Pi-hole and AdGuard Home, built from the ground up in Rust with encrypted DNS support.

Supports plain DNS (UDP), DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ). Ships as a single static binary with a built-in web dashboard — no dependencies, no containers required.

> [!NOTE]
> **Still in Beta** I do not recommend using this in any environment other than testing/development. If you're looking for a more battle-tested solution, check out [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome).


<img width="934" height="881" alt="SCR-20260402-pajz" src="https://github.com/user-attachments/assets/ba57edf1-308a-49bd-8f1c-0191a32d6939" />



## Quick Start

Get Oxi-DNS running in under a minute:


**Install (Linux, macOS, FreeBSD [amd64 only], OpenBSD [amd64 only])**
```sh
URL="https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh"; \
  (curl -fsSL "$URL" 2>/dev/null || wget -qO- "$URL" 2>/dev/null || \
   fetch -qo- "$URL" 2>/dev/null || ftp -Vo - "$URL" 2>/dev/null) | sh
```

**Or run with Docker**
```bash
docker run -d --name oxi-dns \
  -p 53:53/udp -p 53:53/tcp -p 9853:9853 \
  -v oxi-dns-config:/etc/oxi-dns \
  ghcr.io/ron-png/oxi-dns:latest
```

Then open the dashboard at **http://<host>:9853** and point a device's DNS at the server's IP. That's it — ads and trackers are blocked network-wide. See [Installation](#installation) and [Configuration](#configuration) for details.

## Why Oxi-DNS?

- **Single binary, zero dependencies** — no Python, no PHP, no database server to maintain
- **Encrypted DNS out of the box** — DoT, DoH, and DoQ alongside plain DNS
- **Written in Rust** — memory-safe, no garbage collector, minimal resource usage
- **Zero-downtime updates** — automatic self-updates with health checks and seamless binary replacement
- **Runtime configuration** — change any setting from the web dashboard without restarting
- **Root servers** — option to use the root servers as upstream DNS

## Features

### DNS Protocol Support

- **Plain DNS** (UDP, port 53)
- **DNS-over-TLS** (DoT, port 853)
- **DNS-over-HTTPS** (DoH, port 443)
- **DNS-over-QUIC** (DoQ, port 853/UDP)
- Dual-stack IPv4/IPv6 listening on all protocols
- Multiple listen addresses per protocol

### Network-Wide Ad & Tracker Blocking

- Block ads, trackers, and malware for every device on your network
- Supports hosts-file, Adblock, and AdGuard filter syntax
- Multiple blocklist sources (URLs or local files)
- Custom blocked domains and allowlist
- Automatic blocklist refresh on a configurable interval
- One-click feature toggles:
  - Ads, malware & trackers
  - NSFW content
  - Safe search enforcement (Google, Bing, DuckDuckGo)
  - YouTube restricted mode
  - Root server resolution (queries root DNS directly, bypassing third-party upstreams)

### DNS Blocking Modes

Choose how blocked queries are answered:

| Mode | Behavior |
|------|----------|
| Default | 0.0.0.0 / :: (adblock-style) |
| Refused | DNS REFUSED response |
| NxDomain | NXDOMAIN (domain does not exist) |
| NullIp | Always 0.0.0.0 / :: |
| CustomIp | User-specified IPv4/IPv6 address |

All modes are changeable at runtime without restart.

### IPv6 Support

- AAAA response filtering toggle — disable to strip IPv6 records from DNS answers
- Dual-stack listen addresses by default (`0.0.0.0` + `[::]`)
- IPv6 root server fallback resolution

### Reliable Auto-Update

Updates are designed to never leave you with a broken DNS server:

1. **Download** the new binary for your platform
2. **Health-check** — the new binary is started with `--health-check`, which verifies config loading, upstream resolution, and end-to-end DNS queries. A 30-second timeout kills stalled checks.
3. **Replace** — on Linux, the old binary inode is unlinked (safe while running) and the new binary is written. A `.bak` backup is created.
4. **Zero-downtime takeover** — the new process starts with `SO_REUSEPORT`, binding the same port alongside the old process. Once it writes a readiness file, the old process exits. DNS never goes down.

If any step fails, the old binary keeps running and the failure is reported in the dashboard. Checks run every 8 hours when auto-update is enabled. Manual updates from the dashboard use the same pipeline.

### Web Dashboard

Available at `http://<host>:9853`:

- Real-time query stats (total, blocked, block rate)
- Searchable query log with status/domain/client filters
- Blocklist and allowlist management
- Upstream DNS server configuration
- Feature toggles and system settings
- Update status and manual trigger
- All changes take effect immediately — no restart needed

### Query Logging & Statistics

- SQLite-backed persistent query log (WAL mode) — configurable retention (default 7 days)
- Separate persistent statistics database — hourly aggregates and top domains (default 90 days)
- Search by domain, client IP, status, block source, feature, upstream
- Historical stats API: time-series charts, top queried/blocked domains, summaries
- Optional client IP anonymization

## Installation

### Install Script

Works on Linux, macOS, FreeBSD (amd64 only), and OpenBSD (amd64 only). The script auto-detects your init system (systemd, launchd, OpenRC, rc.d) and privilege tool (`sudo` or `doas`).

```sh
URL="https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh"; \
  (curl -fsSL "$URL" 2>/dev/null || wget -qO- "$URL" 2>/dev/null || \
   fetch -qo- "$URL" 2>/dev/null || ftp -Vo - "$URL" 2>/dev/null) | sh
```

Installs the binary to `/opt/oxi-dns/`, config to `/etc/oxi-dns/config.toml`, and creates a service using the native init system.

**Options** (pass via `sh -s -- <flags>`):

| Flag | Description |
|------|-------------|
| `-c <channel>` | Release channel: `stable` (default) or `development` (pre-releases). `beta` and `edge` are accepted as aliases for `development`. |
| `-V <version>` | Install a specific version (e.g. `v0.4.0.9-dev`). Skips version detection. |
| `-r` | Reinstall — purge all files and install fresh |
| `-U` | Update — download latest binary and restart service (preserves config) |
| `-u` | Uninstall Oxi-DNS |
| `-v` | Verbose output |
| `-h` | Show help message |

`-r`, `-u`, and `-U` are mutually exclusive.

During a fresh install, the script interactively prompts for:
- **Web dashboard port** (default 9853)
- **DNS mode** (when systemd-resolved is detected): replace systemd-resolved or run alongside it on a different address/port

Examples:
```bash
# Install latest stable
URL="https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh"; \
  (curl -fsSL "$URL" 2>/dev/null || wget -qO- "$URL" 2>/dev/null || \
   fetch -qo- "$URL" 2>/dev/null || ftp -Vo - "$URL" 2>/dev/null) | sh

# Install latest development (pre-release)
URL="https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh"; \
  (curl -fsSL "$URL" 2>/dev/null || wget -qO- "$URL" 2>/dev/null || \
   fetch -qo- "$URL" 2>/dev/null || ftp -Vo - "$URL" 2>/dev/null) | sh -s -- -c development

# Install a specific version
URL="https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh"; \
  (curl -fsSL "$URL" 2>/dev/null || wget -qO- "$URL" 2>/dev/null || \
   fetch -qo- "$URL" 2>/dev/null || ftp -Vo - "$URL" 2>/dev/null) | sh -s -- -V v0.4.0.9-dev
```

### Docker / Podman

Images are published to GHCR for `linux/amd64` and `linux/arm64`.

```bash
docker run -d \
  --name oxi-dns \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 9853:9853 \
  -v oxi-dns-config:/etc/oxi-dns \
  ghcr.io/ron-png/oxi-dns:latest
```

Docker Compose:

```yaml
services:
  oxi-dns:
    image: ghcr.io/ron-png/oxi-dns:latest
    container_name: oxi-dns
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "9853:9853"
      # Uncomment for encrypted DNS:
      # - "853:853/tcp"   # DoT
      # - "443:443/tcp"   # DoH
      # - "853:853/udp"   # DoQ
    volumes:
      - oxi-dns-config:/etc/oxi-dns

volumes:
  oxi-dns-config:
```

## Configuration

Default config (`config.toml`):

```toml
[dns]
listen = "0.0.0.0:53"
upstreams = [
    "tls://9.9.9.10:853",
    "tls://149.112.112.10:853",
]

[web]
listen = "0.0.0.0:9853"
```

Most settings are configurable at runtime through the web dashboard. The full set of config sections:

| Section | Key settings |
|---------|-------------|
| `[dns]` | `listen`, `dot_listen`, `doh_listen`, `doq_listen`, `upstreams`, `timeout_ms`, `cache_enabled` |
| `[web]` | `listen`, `https_listen` (optional, enables HTTPS for dashboard) |
| `[blocking]` | `enabled`, `blocklists`, `custom_blocked`, `allowlist`, `blocking_mode`, `update_interval_minutes`, `enabled_features` |
| `[tls]` | `cert_path`, `key_path` (auto-generates self-signed if omitted) |
| `[system]` | `auto_update`, `ipv6_enabled`, `release_channel` |
| `[log]` | `query_log_retention_days`, `stats_retention_days`, `anonymize_client_ip` |

Upstream formats: `udp://`, `tls://`, `https://`, `quic://` — defaults to UDP if no prefix.

## Reconfigure

Change network listen addresses from the command line (requires root):

```bash
sudo oxi-dns --reconfigure dns.listen=0.0.0.0:5353
sudo oxi-dns --reconfigure web.listen=0.0.0.0:3000
sudo oxi-dns --reconfigure dns.listen=0.0.0.0:53 dns.dot_listen=0.0.0.0:853
```

Handles systemd-resolved automatically when switching to/from port 53. The dashboard also generates these commands for you when you edit network settings.

## Uninstall

A standalone uninstall script is installed alongside the binary at `/opt/oxi-dns/uninstall.sh`. It works offline with no network access required:

```bash
sudo /opt/oxi-dns/uninstall.sh
```

Alternatively, via the install script:

```bash
URL="https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh"; \
  (curl -fsSL "$URL" 2>/dev/null || wget -qO- "$URL" 2>/dev/null || \
   fetch -qo- "$URL" 2>/dev/null || ftp -Vo - "$URL" 2>/dev/null) | sh -s -- -u
```

## API Reference

All endpoints are served on the web dashboard port (default `9853`). Authentication is via API token (`Authorization: Bearer <token>` header). Create tokens in the dashboard under **Advanced > API Tokens**, or via the API itself.

### Authentication

```bash
# Set your API token (create one in the dashboard, or via POST /api/tokens)
export OXI_TOKEN="your-api-token"

# Use it with any request
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/stats
```

Session cookies (from `/api/auth/login`) are also supported but API tokens are recommended for scripts and automation — they're scoped to specific permissions and can be revoked individually.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Login with username/password |
| `POST` | `/api/auth/logout` | End session |
| `GET` | `/api/auth/me` | Current user info and permissions |
| `POST` | `/api/auth/change-password` | Change own password |
| `POST` | `/api/auth/setup` | Initial admin account setup |

### Stats & Queries

```bash
# Get current stats
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/stats

# Get query log (with search and filtering)
curl -H "Authorization: Bearer $OXI_TOKEN" 'http://localhost:9853/api/logs?search=google.com&status=blocked&limit=50'

# Get historical stats (time-series)
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/stats/history

# Top queried/blocked domains
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/stats/top-domains

# Stats summary
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/stats/summary
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/stats` | Current query statistics |
| `GET` | `/api/stats/history` | Historical time-series data |
| `GET` | `/api/stats/top-domains` | Top queried and blocked domains |
| `GET` | `/api/stats/summary` | Aggregated stats summary |
| `GET` | `/api/queries` | Query log (supports `search`, `status`, `before_id`, `limit` params) |
| `GET` | `/api/logs` | Query log (same as `/api/queries`) |
| `GET` | `/api/logs/settings` | Log retention settings |
| `POST` | `/api/logs/settings` | Update log/stats retention and anonymization |

### Blocking

```bash
# Check blocking status
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/blocking

# Disable blocking (e.g., for 5 minutes)
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/blocking/disable

# Re-enable blocking
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/blocking/enable

# Get blocking mode
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/blocking/mode

# Set blocking mode
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/blocking/mode \
  -H 'Content-Type: application/json' \
  -d '{"mode": "refused"}'
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/blocking` | Current blocking status |
| `POST` | `/api/blocking/enable` | Enable blocking |
| `POST` | `/api/blocking/disable` | Disable blocking |
| `GET` | `/api/blocking/mode` | Get blocking mode |
| `POST` | `/api/blocking/mode` | Set mode (`default`, `refused`, `nxdomain`, `null_ip`, `custom_ip`) |

### Domain Management

```bash
# List custom blocked domains
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/blocklist/custom

# Block a domain
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/blocklist/add \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com"}'

# Unblock a domain
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/blocklist/remove \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com"}'

# List allowlisted domains
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/allowlist

# Add to allowlist
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/allowlist/add \
  -H 'Content-Type: application/json' \
  -d '{"domain": "safe.example.com"}'

# Remove from allowlist
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/allowlist/remove \
  -H 'Content-Type: application/json' \
  -d '{"domain": "safe.example.com"}'
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/blocklist/custom` | List custom blocked domains |
| `POST` | `/api/blocklist/add` | Add domain to blocklist |
| `POST` | `/api/blocklist/remove` | Remove domain from blocklist |
| `GET` | `/api/allowlist` | List allowlisted domains |
| `POST` | `/api/allowlist/add` | Add domain to allowlist |
| `POST` | `/api/allowlist/remove` | Remove domain from allowlist |

### Blocklist Sources

```bash
# List blocklist sources
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/blocklist-sources

# Add a blocklist source
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/blocklist-source/add \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"}'

# Remove a blocklist source
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/blocklist-source/remove \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"}'
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/blocklist-sources` | List all blocklist sources |
| `POST` | `/api/blocklist-source/add` | Add blocklist URL |
| `POST` | `/api/blocklist-source/remove` | Remove blocklist URL |
| `GET` | `/api/blocklist-sources/refresh` | Trigger refresh (SSE stream) |
| `GET` | `/api/blocklist-sources/last-refresh` | Last refresh timestamp |

### Feature Toggles

```bash
# List all features
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/features

# Enable root server resolution
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/features/root_servers \
  -H 'Content-Type: application/json' \
  -d '{"enabled": true}'
```

Available feature IDs: `ads_malware`, `nsfw`, `safe_search`, `youtube_safe_search`, `root_servers`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/features` | List all features with status |
| `POST` | `/api/features/{id}` | Toggle feature on/off |

### Upstream DNS

```bash
# List configured upstreams
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/upstreams

# Add an upstream (supports udp://, tls://, https://, quic://)
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/upstreams/add \
  -H 'Content-Type: application/json' \
  -d '{"upstream": "tls://1.1.1.1"}'

# Remove an upstream
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/upstreams/remove \
  -H 'Content-Type: application/json' \
  -d '{"upstream": "tls://1.1.1.1"}'
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/upstreams` | List upstream DNS servers |
| `POST` | `/api/upstreams/add` | Add upstream server |
| `POST` | `/api/upstreams/remove` | Remove upstream server |

### Cache

```bash
# Cache statistics
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/cache/stats

# Flush the cache
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/cache/flush
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/cache/stats` | Cache hit/miss statistics |
| `POST` | `/api/cache/flush` | Clear all cached DNS responses |

### Network Configuration

```bash
# Get current network listen addresses and interfaces
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/system/network

# Update optional protocol listeners (DoT, DoH, DoQ)
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/network \
  -H 'Content-Type: application/json' \
  -d '{"dot_listen": ["0.0.0.0:853", "[::]:853"]}'
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/system/network` | Current listen addresses and network interfaces |
| `POST` | `/api/system/network` | Update DoT/DoH/DoQ listen addresses (DNS and web require `--reconfigure`) |

### TLS Certificate Management

```bash
# Get current certificate info
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/system/tls

# Upload PEM certificate
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/tls/upload \
  -F 'cert_file=@cert.pem' -F 'key_file=@key.pem'

# Upload PKCS12 certificate
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/tls/upload \
  -F 'p12_file=@certificate.p12' -F 'password=mypassword'

# Remove certificate (revert to self-signed)
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/tls/remove

# Download certificate (requires password confirmation)
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/tls/download \
  -H 'Content-Type: application/json' \
  -d '{"password": "yourpassword"}'
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/system/tls` | Current certificate info (subject, issuer, expiry) |
| `POST` | `/api/system/tls/upload` | Upload PEM or PKCS12 certificate |
| `POST` | `/api/system/tls/remove` | Revert to self-signed certificate |
| `POST` | `/api/system/tls/download` | Export cert + key PEM (requires password) |

### ACME / Let's Encrypt

```bash
# Issue a wildcard certificate via Cloudflare DNS
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/tls/acme/issue \
  -H 'Content-Type: application/json' \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com",
    "provider": "cloudflare",
    "cloudflare_api_token": "your-cf-api-token",
    "use_staging": false
  }'

# Issue via manual DNS (you create the TXT record yourself)
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/tls/acme/issue \
  -H 'Content-Type: application/json' \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com",
    "provider": "manual",
    "use_staging": false
  }'

# Check issuance progress
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/system/tls/acme/status

# Confirm manual DNS challenge (after creating TXT record)
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/tls/acme/confirm

# Trigger manual renewal
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/tls/acme/renew

# Toggle auto-renewal
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/tls/acme/auto-renew \
  -H 'Content-Type: application/json' \
  -d '{"enabled": true}'
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/system/tls/acme/issue` | Start certificate issuance (issues `example.com` + `*.example.com`) |
| `GET` | `/api/system/tls/acme/status` | Issuance progress and ACME config |
| `POST` | `/api/system/tls/acme/confirm` | Confirm manual DNS challenge |
| `POST` | `/api/system/tls/acme/renew` | Trigger immediate renewal |
| `POST` | `/api/system/tls/acme/auto-renew` | Enable/disable auto-renewal |

### System

```bash
# Get version info
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/system/version

# Check for updates
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/version/check

# Perform update
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/update

# Restart service
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/restart

# Get/set auto-update
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/system/auto-update
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/auto-update \
  -H 'Content-Type: application/json' -d '{"enabled": true}'

# Get/set IPv6
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/system/ipv6
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/ipv6 \
  -H 'Content-Type: application/json' -d '{"enabled": true}'

# Get/set release channel
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/system/release-channel
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/system/release-channel \
  -H 'Content-Type: application/json' -d '{"channel": "stable"}'
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/system/version` | Version info |
| `POST` | `/api/system/version/check` | Check for updates |
| `POST` | `/api/system/update` | Start update |
| `GET` | `/api/system/update/status` | Update progress |
| `POST` | `/api/system/restart` | Restart the service |
| `GET/POST` | `/api/system/auto-update` | Get/set auto-update |
| `GET/POST` | `/api/system/ipv6` | Get/set IPv6 support |
| `GET/POST` | `/api/system/release-channel` | Get/set release channel |
| `GET/POST` | `/api/system/blocklist-interval` | Get/set blocklist refresh interval |

### User Management

```bash
# List users
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/users

# Create user
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/users \
  -H 'Content-Type: application/json' \
  -d '{"username": "viewer", "password": "pass123", "permissions": ["view_stats", "view_logs"]}'

# Update user permissions
curl -H "Authorization: Bearer $OXI_TOKEN" -X PUT http://localhost:9853/api/users/2 \
  -H 'Content-Type: application/json' \
  -d '{"permissions": ["view_stats", "view_logs", "manage_features"], "active": true}'

# Reset user password
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/users/2/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"new_password": "newpass123"}'

# Delete user
curl -H "Authorization: Bearer $OXI_TOKEN" -X DELETE http://localhost:9853/api/users/2
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/users` | List all users |
| `POST` | `/api/users` | Create user |
| `PUT` | `/api/users/{id}` | Update user permissions/status |
| `DELETE` | `/api/users/{id}` | Delete user |
| `POST` | `/api/users/{id}/reset-password` | Reset user password |

### API Tokens

```bash
# List tokens
curl -H "Authorization: Bearer $OXI_TOKEN" http://localhost:9853/api/tokens

# Create token
curl -H "Authorization: Bearer $OXI_TOKEN" -X POST http://localhost:9853/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"name": "monitoring", "permissions": ["view_stats"]}'

# Revoke token
curl -H "Authorization: Bearer $OXI_TOKEN" -X DELETE http://localhost:9853/api/tokens/1
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/tokens` | List API tokens |
| `POST` | `/api/tokens` | Create API token |
| `DELETE` | `/api/tokens/{id}` | Revoke API token |

### Permissions

Available permissions for users and API tokens:

| Permission | Description |
|------------|-------------|
| `view_stats` | View dashboard statistics |
| `view_logs` | View query log |
| `manage_features` | Toggle features (ad blocking, safe search, etc.) |
| `manage_blocklists` | Add/remove blocklist sources |
| `manage_allowlist` | Add/remove allowlisted domains |
| `manage_upstreams` | Add/remove upstream DNS servers |
| `manage_system` | Network config, TLS, updates, restart |
| `manage_users` | Create/edit/delete users |
| `manage_api_tokens` | Create/revoke API tokens |

## Contributing

Bug reports, feature requests, and pull requests are welcome. Open an issue on GitHub.

## TODO/PLANS

Please note that this list is not a promise, rather thoughts I might change my mind on in the future. Feel free to share your opinion and suggestions for the future of this project.

### Goals for Version 1:
- Make the UI more user friendly (feature)
- Verify DNS over TLS, HTTPS and QUIC work (feature)
- When enabling DoH, the user should be able to define the https request path (feature)
- if the user wants a different subdomain for DoH, DoT and DoQ, the user should be able to define it in the UI (feature)
  - this should include the ability that the server automatically creates the needed certificates for the subdomain (if not already present by wildcard certificate).
  - if the subdomain doesn't exist, the server should create a DNS A record for the subdomain pointing to the server's IP address.
- in addition, harden DoH, DoT and DoQ (feature) (pathing attacks, etc)
- Verify that changing Settings in the UI (Like Port or listen address) works with the generated terminal commands. (ipv4 yes, ipv6 has to be fixed)
- add a warning for cloudflare users, that the proxy should be disabled for oxi-dns to work properly. 

### Goals for Version 2:
- Add a "Test" button for the upstream DNS servers (feature)
- add oxi-dns cli commands. (adding certificate, rebooting the server) 
- Security enhancements
  - DNSsec
  - DNScrypt
  - Rate limits for clients
  - no DNAME, no EDNS0, sequential server tries within a single referral
   step, and glueless-NS resolution reuses the bootstrap walker which itself  
  only handles glued chains.
- logging system errors
- DHCP Server
- redundancy feature. Dns server cluster
- multiple subdomains using multiple filter configurations (feature)

### Goals for Version 3:
- More statistics, fancy graphs and more
- make the log entries clickable and show more information about the query
- dns rewrites

### Stuff that might be done
- Look into RFC Compliance
- Besides User Login and password, LDAP as well
- Not only single entries, but complete Allowlist section
- If my finances allow, a security audit of the code (option for Donations, maybe a donation button?)
