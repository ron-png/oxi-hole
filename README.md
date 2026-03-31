# Oxi-DNS — DNS Ad Blocker & Sinkhole Written in Rust

A fast, memory-safe DNS sinkhole that blocks ads, trackers, and malware at the network level. A modern alternative to Pi-hole and AdGuard Home, built from the ground up in Rust with encrypted DNS support.

Supports plain DNS (UDP), DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ). Ships as a single static binary with a built-in web dashboard — no dependencies, no containers required.

> **Early alpha** — under active development. Some features are not tested yet. Expect rough edges.

## Why Oxi-DNS?

- **Single binary, zero dependencies** — no Python, no PHP, no database server to maintain
- **Encrypted DNS out of the box** — DoT, DoH, and DoQ alongside plain DNS
- **Written in Rust** — memory-safe, no garbage collector, minimal resource usage
- **Zero-downtime updates** — automatic self-updates with health checks and seamless binary replacement
- **Runtime configuration** — change any setting from the web dashboard without restarting

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

```bash
curl -sSL "https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh" | sh
```

Installs the binary to `/opt/oxi-dns/`, config to `/etc/oxi-dns/config.toml`, and creates a systemd service.

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
curl -sSL "https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh" | sh

# Install latest development (pre-release)
curl -sSL "https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh" | sh -s -- -c development

# Install a specific version
curl -sSL "https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh" | sh -s -- -V v0.4.0.9-dev
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
curl -sSL "https://raw.githubusercontent.com/ron-png/oxi-dns/main/scripts/install.sh" | sh -s -- -u
```

## Contributing

Bug reports, feature requests, and pull requests are welcome. Open an issue on GitHub.

## License

MIT
