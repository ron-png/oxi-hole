# Oxi-DNS — DNS Ad Blocker & Sinkhole Written in Rust

A fast, memory-safe DNS sinkhole that blocks ads, trackers, and malware at the network level. A modern alternative to Pi-hole and AdGuard Home, built from the ground up in Rust with encrypted DNS support.

Supports plain DNS (UDP), DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and DNS-over-QUIC (DoQ). Ships as a single static binary with a built-in web dashboard — no dependencies, no containers required.

> [!NOTE]
> **This is a young project** - If you're looking for a more battle-tested solution, check out [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome).


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
  -p 53:53/udp -p 53:53/tcp \
  -p 853:853/tcp -p 853:853/udp \
  -p 443:443/tcp \
  -p 9853:9853 -p 9854:9854 \
  -v oxi-dns-data:/etc/oxi-dns \
  --restart unless-stopped \
  ghcr.io/ron-png/oxi-dns:latest
```

Then open the dashboard at **http://<host>:9853** (or **https://<host>:9854** with the auto-generated self-signed cert) and point a device's DNS at the server's IP. That's it — ads and trackers are blocked network-wide. The encrypted-DNS ports (DoT 853, DoH 443, DoQ 853/udp) are pre-published so you can just toggle them on in the dashboard later — drop `-p 443:443/tcp` if you already run a web server on the host. See [Installation](#installation) and [Configuration](#configuration) for details.

## Table of Contents

- [Why Oxi-DNS?](#why-oxi-dns)
- [Features](#features)
  - [DNS Protocol Support](#dns-protocol-support)
  - [Network-Wide Ad & Tracker Blocking](#network-wide-ad--tracker-blocking)
  - [DNS Blocking Modes](#dns-blocking-modes)
  - [IPv6 Support](#ipv6-support)
  - [Reliable Auto-Update](#reliable-auto-update)
  - [Web Dashboard](#web-dashboard)
  - [Query Logging & Statistics](#query-logging--statistics)
- [Installation](#installation)
  - [Install Script](#install-script)
  - [Docker / Podman](#docker--podman)
- [Configuration](#configuration)
  - [\[dns\]](#dns)
  - [\[web\]](#web)
  - [\[blocking\]](#blocking)
  - [\[tls\]](#tls)
  - [\[tls.acme\]](#tlsacme)
  - [\[system\]](#system)
  - [\[log\]](#log)
  - [\[limits\]](#limits)
- [Command-line options](#command-line-options)
- [Reconfigure](#reconfigure)
- [HTTPS & Reverse Proxy](#https--reverse-proxy)
- [Uninstall](#uninstall)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [TODO/PLANS](#todoplans)

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

Images are published to GHCR for `linux/amd64` and `linux/arm64`. The same commands work with `podman` — just substitute `podman` for `docker`.

```bash
docker run -d \
  --name oxi-dns \
  --restart unless-stopped \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 853:853/tcp \
  -p 853:853/udp \
  -p 443:443/tcp \
  -p 9853:9853 \
  -p 9854:9854 \
  -v oxi-dns-data:/etc/oxi-dns \
  ghcr.io/ron-png/oxi-dns:latest
```

The named volume `oxi-dns-data` persists `config.toml` along with the SQLite databases (`query_log.db`, `stats.db`, `auth.db`) that oxi-dns writes next to the config file. A single mount covers config, query logs, historical stats, and user accounts.

Open the dashboard at **http://<host>:9853** or **https://<host>:9854** (HTTPS uses a self-signed certificate by default).

**Why all the ports up front?** A container's published ports are fixed at `docker run` time — there's no way to add them later from inside the container. To save you a recreate later, the recommended command pre-publishes every listener oxi-dns can bind: plain DNS (53), DoT (853/tcp), DoQ (853/udp), DoH (443), HTTP dashboard (9853), HTTPS dashboard (9854). The DoT/DoH/DoQ listeners are still **off in the config by default** — flip them on from the Network tab of the dashboard whenever you want, and the published ports will already be there. You can drop any `-p` line you don't need.

**Conflict with port 443**: a lot of hosts already run a web server or reverse proxy on 443. If `docker run` fails with "address already in use" on 443, drop `-p 443:443/tcp`. You can keep DoT/DoQ on 853 even when DoH isn't published — and when you enable DoH later, it'll bind inside the container but won't be reachable from outside until you republish the port. Alternatively, bind the container's DoH to a different host port (e.g. `-p 8443:443/tcp`) and use your existing reverse proxy to forward `https://dns.example.com` to `localhost:8443` — see [HTTPS & Reverse Proxy](#https--reverse-proxy) for nginx and Caddy examples.

**Conflict with port 53**: if the host already runs a DNS resolver, the `-p 53:53` bindings will fail with `address already in use` (or `failed to bind host port 0.0.0.0:53/tcp`). On most modern Linux distros — Ubuntu, Debian 11+, Fedora, RHEL 9+, openSUSE — the culprit is **`systemd-resolved`**: it binds `127.0.0.53:53` as a stub resolver, and Docker's `0.0.0.0:53` bind overlaps with it because `0.0.0.0` covers every interface including the loopback alias. (`dnsmasq`, `unbound`, `BIND`, or another container can also be the cause; check with `sudo ss -lunp 'sport = :53'` to see which.)

The cleanest fix on a `systemd-resolved` host is to disable just the **stub listener** while keeping `systemd-resolved` running for the host's own outgoing DNS. This is the same sequence the bare-metal install script uses (`src/reconfigure.rs`):

```sh
# 1. Tell resolved to stop binding 127.0.0.53:53
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' \
  | sudo tee /etc/systemd/resolved.conf.d/oxi-dns.conf

# 2. Re-point /etc/resolv.conf away from the stub. Without this the host
#    can't resolve names because /etc/resolv.conf currently points at
#    127.0.0.53, which is about to disappear.
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

# 3. Restart resolved so the new setting takes effect
sudo systemctl restart systemd-resolved

# 4. Confirm port 53 is now free
sudo ss -lunp 'sport = :53'
sudo ss -ltnp 'sport = :53'   # both should be empty
```

To reverse it later (e.g. if you uninstall oxi-dns), undo all four steps:

```sh
sudo rm /etc/systemd/resolved.conf.d/oxi-dns.conf
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

**If you can't (or don't want to) disable the stub listener**, the alternatives are: bind oxi-dns's published port to a specific non-loopback host IP that doesn't overlap (`-p 192.168.1.10:53:53/udp`), publish DNS on a non-default host port like `-p 5300:53/udp -p 5300:53/tcp` (only useful for testing — most consumer devices can't query DNS on a non-standard port), or use `--network host` so the container shares the host's network namespace (Linux only — `--network host` is a no-op on Docker Desktop for Mac/Windows because the daemon runs inside a VM).

**Don't change `dns.listen` from inside the dashboard in a container** — see [What works differently in a container](#what-works-differently-in-a-container) below.

**Rootless Podman on Linux**: rootless Podman runs as your user, so its port-forwarding proxy can't bind to ports below 1024 by default. The recommended `podman run` command will fail with `permission denied` on ports 53, 443, and 853 — the kernel reserves them for root. There are two workable fixes:

- **Lower the unprivileged-port floor** (the upstream-recommended path):
  ```sh
  echo 'net.ipv4.ip_unprivileged_port_start=53' | sudo tee /etc/sysctl.d/99-oxi-dns.conf
  sudo sysctl --system
  ```
  This opens ports 53–1023 to every unprivileged user on the host, which covers 53, 443, and 853 in one shot. On a single-user / personal machine that's fine; on a shared multi-user server it's a small extra risk to weigh.
- **Run rootful Podman** with `sudo podman run …`. You lose rootless user-namespace isolation, and the container/volume/image cache live in the system store (`/var/lib/containers`) instead of `~/.local/share/containers` — `podman ps` and `sudo podman ps` show *different* containers, which surprises most people once.

If you only want to kick the tyres without changing any sysctls, publish DNS on a high port instead — but **do not pick `5353`**: that's the mDNS port, and `avahi-daemon` already binds it on virtually every Linux desktop install (it's how `.local` hostname resolution and printer/Chromecast discovery work). `5300` is the conventional "DNS but unprivileged" port and is almost always free:
```sh
podman run -d --name oxi-dns \
  -p 5300:53/udp -p 5300:53/tcp \
  -p 9853:9853 -p 9854:9854 \
  -v oxi-dns-data:/etc/oxi-dns \
  --restart unless-stopped \
  ghcr.io/ron-png/oxi-dns:latest
```
Test with `dig @127.0.0.1 -p 5300 example.com`. This is fine for verifying the dashboard but not useful for serving real LAN clients, since most consumer devices have no way to query DNS on a non-default port. Production use needs port 53, which means one of the two fixes above.

**Podman on macOS**: Podman runs inside a Linux VM on macOS, so port-forwarding goes through `gvproxy` and bind errors come from the macOS side, not from inside the container. `--network host` does *not* help on macOS — it shares the VM's network namespace, not your Mac's. If a port-bind fails, look at what's running on your Mac with `sudo lsof -iUDP:53 -iTCP:53 -P -n`. Common culprits are a stale `oxi-dns` container from a previous attempt (`podman rm -f oxi-dns`), a Homebrew DNS resolver (`brew services list`), or *System Settings → General → Sharing → Internet Sharing*.

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
      - "853:853/tcp"   # DoT — listener is off by default; toggle on in dashboard
      - "853:853/udp"   # DoQ — listener is off by default; toggle on in dashboard
      - "443:443/tcp"   # DoH — listener is off by default; comment out if 443 is taken
      - "9853:9853"     # Web dashboard (HTTP)
      - "9854:9854"     # Web dashboard (HTTPS, self-signed by default)
    volumes:
      - oxi-dns-data:/etc/oxi-dns

volumes:
  oxi-dns-data:
```

The image ships with the project's default `config.toml` (Quad9 over DoT as upstreams, plain DNS on `:53`, dashboard on `:9853` HTTP / `:9854` HTTPS). On first start with an empty named volume, Docker copies that file into the volume so it persists across recreations — edit it via the dashboard, the API, or directly on the volume.

The image is otherwise stateless — every piece of state oxi-dns writes (`config.toml`, `query_log.db`, `stats.db`, `auth.db`, `cert.pem`, `key.pem`) lives under `/etc/oxi-dns/`, so a single named volume covers config, history, auth, and certs. `docker pull` + `docker rm` + `docker run` is non-destructive as long as the same volume is reattached.

#### Updating the image

The in-process auto-updater (`system.auto_update` in `config.toml`, the **Update** button in *Advanced → System*) **does not work in containers and should stay off**. It rewrites `/usr/local/bin/oxi-dns`, which is image-layer storage and is discarded on every container recreation. The dashboard detects the container runtime (via `/.dockerenv` / `/run/.containerenv`) and replaces the in-place "Update" call-to-action with a "View release →" link to the new GitHub release.

For containerised installs, choose one of the following instead:

| Tool | What it does | Best for |
|---|---|---|
| **Manual** (`docker pull && docker rm && docker run …`, or `docker compose pull && docker compose up -d`) | You decide when to upgrade. | Single hosts, anyone who wants a human in the loop. |
| **[Watchtower](https://containrrr.dev/watchtower/)** | Polls the registry, pulls new images, recreates the container. Supports labels, schedules, and per-container opt-in. | Plain Docker hosts that want unattended updates. Pin a quiet hour with `--schedule` so an upgrade doesn't collide with an ACME renewal. |
| **[Diun](https://crazymax.dev/diun/)** | Notifies you (Discord, ntfy, email, Gotify, Slack, …) when a new image digest is available, but doesn't pull anything. | "Tell me, don't touch it" workflows. |
| **`podman auto-update`** | First-class Podman feature. Label the container `io.containers.autoupdate=registry`, generate a systemd unit with `podman generate systemd`, enable `podman-auto-update.timer`. | Podman + systemd hosts; the cleanest "update built into the runtime" option. |
| **Renovate / Dependabot** | Opens a PR against your Compose file when the `ghcr.io/ron-png/oxi-dns:latest` digest changes. CI handles the rollout. | GitOps / IaC setups where Compose is checked into git. |
| **Kubernetes image-update controllers** (Keel, Flux Image Automation, ArgoCD Image Updater) | Watch the registry and update the workload manifest. | Cluster deployments. |

Whichever tool you use, the persistent volume at `/etc/oxi-dns/` carries everything across the upgrade — config, query log, stats, auth, certs.

#### What works differently in a container

A handful of features in oxi-dns assume a bare-metal init system (systemd, launchd, OpenRC) and a writable on-disk binary. Inside an image, those features either no-op, fall back to a coarser code path, or simply aren't reachable. The table below covers the gaps that aren't already mentioned in the cert section above.

| Feature | Bare metal | In a container |
|---|---|---|
| **Listener port editing** (`dns.listen`, `web.listen`, `web.https_listen` ports + DoT/DoH/DoQ ports) | Editable from the dashboard's Network tab; the `--reconfigure` banner emits a `sudo … --reconfigure …` command that writes the new ports and restarts the service. | **Hidden in the dashboard.** A container's published ports are fixed at `docker run` time — changing the in-container listen port doesn't update the host's `-p HOST:CONTAINER` mapping, so it would silently break access. The dashboard detects the container runtime, hides every listener-port input, and shows an inline notice pointing here. To change a port, edit the `-p` lines in your `docker run` / Compose file on the host and recreate the container. |
| **DoT / DoH / DoQ enable/disable toggles** | Toggling on binds the matching port in-process via the graceful restart. | Toggles are still visible. The recommended `docker run` / Compose pre-publishes 853/tcp, 853/udp, and 443/tcp so the toggles "just work" once enabled. Toggling produces a Docker-aware reconfigure banner — `docker exec oxi-dns oxi-dns --reconfigure dns.dot_listen=0.0.0.0:853 && docker restart oxi-dns` — that you run on the host. Substitute `podman` for `docker` if you use Podman. Expect ~1–3 s of DNS downtime during the restart. |
| **`auto_redirect_https`, `trust_forwarded_proto`** | Live-applied via the API; non-port settings, no listener change. | Same — live-applied. Not affected by the container runtime. |
| **`/opt/oxi-dns/oxi-dns` binary path** | Where the install script puts the binary. | Doesn't exist in the image. The binary is at `/usr/local/bin/oxi-dns` and is on `$PATH`, so any documented command can be invoked as `docker exec oxi-dns oxi-dns …`. |
| **Install / uninstall scripts** (`scripts/install.sh`, `/opt/oxi-dns/uninstall.sh`) | Manage the systemd / launchd / OpenRC unit, drop the config in `/etc/oxi-dns/`, fetch the right binary, etc. | Not used. Install = `docker run`. Uninstall = `docker rm` (`docker volume rm oxi-dns-data` if you also want to wipe state). |
| **Service restart** (`systemctl restart oxi-dns`, `launchctl unload/load`, `rc-service oxi-dns restart`) | Used by `--reconfigure`, `--update`, ACME install, and the manual cert upload flow. | Replaced by `docker restart oxi-dns` (or `docker compose restart oxi-dns`). Inside the image neither `systemctl`, `launchctl`, nor `rc-service` exist, so anything that internally tries to call them just falls through to the "Could not detect init system. Please restart oxi-dns manually." path. |
| **`systemd-resolved` coordination** (port-53 conflict handling in `--reconfigure`) | The bare-metal flow disables/re-enables the systemd-resolved stub listener when you bind/unbind port 53. | Not applicable inside the container's network namespace. If `systemd-resolved` is running on the **host** and holding port 53, that's a *host* problem — disable it on the host, change `dns.listen` to a different port, or run with `--network host`. |
| **In-process zero-downtime restart** (SO_REUSEPORT takeover via `--takeover` + `--ready-file`) | New child binds the same port alongside the old process, becomes ready, parent exits — zero DNS downtime. | The takeover child is in the container's PID namespace under PID 1. When the parent exits, the kernel SIGKILLs the child too. Docker's restart policy then cold-starts the entrypoint, which loads the persisted config from the volume. Net result: ~1–3 s of DNS downtime instead of zero. |
| **Built-in auto-update** (`system.auto_update`) | Downloads a new binary, health-checks it, swaps the inode, performs the SO_REUSEPORT takeover. | Doesn't apply. The dashboard now **hides the auto-update toggle and the in-place "Update" button** in container mode, replacing them with a link back to [Updating the image](#updating-the-image). The "Check for Updates" button stays so you can see whether a newer image tag is available, and the update-available banner already links to the GitHub release. |
| **Health check** (`oxi-dns --health-check`) | Used by systemd `ExecStartPre`. | Still works as a binary command — wire it into Docker's `HEALTHCHECK` directive if you want orchestration to react: `HEALTHCHECK --interval=30s --timeout=35s CMD ["oxi-dns", "--health-check"]`. (The current image doesn't ship a `HEALTHCHECK` line; add one in your own override if you need it.) |

#### Certificates in containers

The HTTPS dashboard cert workflows all *function* in the image, but the in-process zero-downtime restart that normally swaps a new cert into the running server falls back to a full container restart. Here's what to expect:

| Cert source | Behaviour in container |
|---|---|
| **Self-signed (default)** | Generated in memory at startup, no disk, no restart. Works fully. The SANs cover `localhost`, `oxi-dns.local`, and the container's interface IPs — browsers will still warn on the host IP, same as bare metal. |
| **Manual upload** (Advanced → Certificates) | The uploaded `cert.pem` / `key.pem` are written into `/etc/oxi-dns/` on the persistent volume and `config.toml` is updated to point at them. The server then tries an in-process graceful restart, but since oxi-dns runs as PID 1 inside the container the spawned takeover child gets SIGKILL'd as soon as the parent exits. The container terminates and Docker has to restart it — about 1–3 s of DNS downtime instead of zero. |
| **ACME / Let's Encrypt** | Issuance works (DNS-01 only — no inbound port 80 needed; Cloudflare-API and manual confirmation modes are both supported). Install hits the same restart path as manual upload, and the auto-renewal loop will hard-restart the container roughly every 60 days when a 90-day Let's Encrypt cert enters its 30-day renewal window. |
| **Built-in auto-update** | Don't enable. The updater rewrites `/usr/local/bin/oxi-dns`, which is image-layer storage and is lost on container recreation. |

**Implications for your run command:**

- **Always pass `--restart unless-stopped`** (or a Compose `restart: unless-stopped`) if you plan to use manual upload or ACME — without it, the container stays stopped after the first cert install or renewal.
- **Keep the volume mounted at `/etc/oxi-dns`.** ACME writes to a hardcoded `/etc/oxi-dns/cert.pem` / `/etc/oxi-dns/key.pem` path; if you remap the config to a different directory, ACME will write the renewed cert into a location the running config no longer references.
- For ACME, prefer the **Cloudflare** provider over manual mode — manual mode requires you to be at the dashboard to confirm each renewal, which doesn't pair well with an unattended container.

## Configuration

Most settings are configurable at runtime through the web dashboard. The config file is located at `/etc/oxi-dns/config.toml` and only a minimal subset is needed to get started:

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

Everything else is optional and defaults to sensible values. All listen fields accept either a single string or a list of strings (e.g. `"0.0.0.0:53"` or `["0.0.0.0:53", "[::]:53"]`).

### `[dns]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | string \| list | `["0.0.0.0:53", "[::]:53"]` | Addresses for plain DNS (UDP + TCP). |
| `dot_listen` | string \| list | *not set* | Addresses for DNS-over-TLS. Typically `"0.0.0.0:853"`. Requires a TLS certificate (auto-generates self-signed if none configured). |
| `doh_listen` | string \| list | *not set* | Addresses for DNS-over-HTTPS. Typically `"0.0.0.0:443"`. Uses HTTP/2 (h2 ALPN). |
| `doq_listen` | string \| list | *not set* | Addresses for DNS-over-QUIC. Typically `"0.0.0.0:853"` (UDP). Shares port number with DoT but on a different transport. |
| `upstreams` | list | `["tls://9.9.9.9:853", "tls://1.1.1.1:853"]` | Upstream DNS servers. Prefix with `udp://`, `tls://`, `https://`, or `quic://`. No prefix defaults to UDP. |
| `timeout_ms` | integer | `5000` | Timeout for upstream queries in milliseconds. |
| `cache_enabled` | bool | `true` | Enable DNS response caching. |

### `[web]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | string \| list | `["0.0.0.0:9853", "[::]:9853"]` | Addresses for the HTTP web dashboard. |
| `https_listen` | string \| list | `["0.0.0.0:9854", "[::]:9854"]` | Addresses for the HTTPS web dashboard. Added automatically on first run if missing. |
| `auto_redirect_https` | bool | `false` | Redirect HTTP requests to HTTPS automatically. |
| `trust_forwarded_proto` | bool | `false` | Trust the `X-Forwarded-Proto` header from a reverse proxy. **Only enable if oxi-dns is behind a trusted TLS-terminating proxy** — otherwise attackers can spoof the header. See [HTTPS & Reverse Proxy](#https--reverse-proxy). |

### `[blocking]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Master switch for ad/tracker blocking. |
| `blocklists` | list | `[]` | URLs or file paths of blocklists to load (hosts-format or domain-list). |
| `custom_blocked` | list | `[]` | Manually blocked domains. |
| `allowlist` | list | `[]` | Domains that bypass blocking. |
| `update_interval_minutes` | integer | `60` | How often to refresh blocklists. `0` disables auto-refresh. |
| `enabled_features` | list | `[]` | Feature IDs to restore on restart (e.g. `"safe_search"`, `"root_servers"`). Managed by the dashboard. |
| `blocking_mode` | table | `{ mode = "Default" }` | How blocked domains are answered. See blocking modes below. |

**Blocking modes** (`blocking_mode.mode`):

| Mode | Response | Description |
|------|----------|-------------|
| `Default` | `0.0.0.0` / `::` | Adblock-style null response. Hosts-file entries use the IP from the rule. |
| `Refused` | REFUSED rcode | Tell the client the query was refused. |
| `NxDomain` | NXDOMAIN rcode | Tell the client the domain doesn't exist. |
| `NullIp` | `0.0.0.0` / `::` | Always respond with null IPs regardless of rule source. |
| `CustomIp` | user-defined | Respond with custom IPs. Requires `value = { ipv4 = "...", ipv6 = "..." }`. |

Example custom IP blocking mode:
```toml
[blocking.blocking_mode]
mode = "CustomIp"
value = { ipv4 = "192.168.1.100", ipv6 = "::1" }
```

### `[tls]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cert_path` | string | *not set* | Path to a PEM certificate file. If omitted, a self-signed certificate is generated at startup covering `localhost`, `oxi-dns.local`, and all interface IPs. |
| `key_path` | string | *not set* | Path to a PEM private key file. Must be set together with `cert_path`. |

### `[tls.acme]`

Automatic certificate management via Let's Encrypt (or compatible CA).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable ACME certificate issuance and auto-renewal. |
| `domain` | string | `""` | Domain to issue the certificate for (e.g. `"dns.example.com"` or `"*.example.com"`). |
| `email` | string | `""` | Contact email for the ACME account. |
| `provider` | string | `"cloudflare"` | DNS challenge provider. `"cloudflare"` for automatic DNS-01 via Cloudflare API, or `"manual"` to create TXT records yourself. |
| `cloudflare_api_token` | string | `""` | Cloudflare API token (required when `provider = "cloudflare"`). Must have DNS edit permissions for the zone. |
| `use_staging` | bool | `false` | Use the Let's Encrypt staging environment for testing (avoids rate limits). |

### `[system]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auto_update` | bool | `false` | Automatically check for and apply updates. Updates are health-checked before applying. |
| `ipv6_enabled` | bool | `true` | Include AAAA (IPv6) records in DNS responses. |
| `release_channel` | string | `"stable"` | Release channel for updates. `"stable"` or `"beta"`. |

### `[log]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `query_log_retention_days` | integer | `7` | Days to keep query log entries before automatic cleanup. |
| `stats_retention_days` | integer | `90` | Days to keep historical statistics. |
| `anonymize_client_ip` | bool | `false` | Anonymize client IPs in the query log (e.g. `192.168.1.100` becomes `192.168.1.0`). |

### `[limits]`

Oxi-DNS detects the available CPU cores and memory at startup (cgroup-aware
on Linux containers — host RAM is clamped to the cgroup limit when smaller)
and scales internal caps accordingly.  Caches grow with RAM, connection and
task counts grow with CPU, and per-request buffers stay small regardless.
The chosen values are logged at startup on the line beginning
`Resource limits:`.

Every key below is **optional**; unset keys use the hardware-scaled
default.  Set a key to override just that one cap — the others keep
auto-scaling.  All memory values are interpreted as mebibytes (1 MB = 1024×1024 bytes).

| Key | Type | Auto-scale formula | Floor | Ceiling | Description |
|-----|------|--------------------|-------|---------|-------------|
| `dns_cache_entries` | integer | `ram_mb × 250` | `10 000` | `500 000` | Max entries in the DNS response cache. Evicts entries closest to expiry first. |
| `ns_cache_entries` | integer | `ram_mb × 50` | `2 000` | `100 000` | Max entries in the per-zone NS+glue cache used by the iterative resolver. |
| `udp_max_inflight` | integer | `cpu × 512` | `1 024` | `16 384` | Concurrent in-flight UDP query tasks. Packets are dropped when exceeded. |
| `tcp_max_connections` | integer | `cpu × 128` | `512` | `8 192` | Concurrent plain-TCP DNS connections. New connections are dropped when exceeded. |
| `dot_max_connections` | integer | `cpu × 128` | `512` | `8 192` | Concurrent DNS-over-TLS connections. |
| `doh_max_connections` | integer | `cpu × 128` | `512` | `8 192` | Concurrent DNS-over-HTTPS connections. |
| `doq_max_streams_per_connection` | integer | `cpu × 16` | `64` | `512` | Max concurrent bidirectional streams per DoQ connection (enforced via QUIC transport parameters — RFC 9250 §7). |
| `blocklist_max_mb` | integer | `ram_mb ÷ 8` | `50` | `500` | Max size (MB) of a single downloaded or on-disk blocklist. Sources that exceed this are refused. |
| `web_upload_max_mb` | integer | `ram_mb ÷ 64` | `2` | `50` | Max size (MB) for web-admin uploads (TLS cert / key / PKCS#12 bundles). |

Example — a tiny VPS where you want a smaller cache and stricter upload cap:

```toml
[limits]
dns_cache_entries = 50000
web_upload_max_mb = 5
# Everything else auto-scales.
```

Example — a high-traffic server that wants to lift every cap:

```toml
[limits]
dns_cache_entries = 500000
udp_max_inflight = 16384
tcp_max_connections = 8192
dot_max_connections = 8192
doh_max_connections = 8192
doq_max_streams_per_connection = 512
blocklist_max_mb = 500
web_upload_max_mb = 50
```

### Full example

A fully-populated `config.toml` for reference (all values shown are defaults unless noted):

```toml
[dns]
listen = ["0.0.0.0:53", "[::]:53"]
# dot_listen = ["0.0.0.0:853", "[::]:853"]
# doh_listen = ["0.0.0.0:443", "[::]:443"]
# doq_listen = ["0.0.0.0:853", "[::]:853"]
upstreams = [
    "tls://9.9.9.9:853",
    "tls://1.1.1.1:853",
]
timeout_ms = 5000
cache_enabled = true

[web]
listen = ["0.0.0.0:9853", "[::]:9853"]
https_listen = ["0.0.0.0:9854", "[::]:9854"]
auto_redirect_https = false
trust_forwarded_proto = false

[blocking]
enabled = true
blocklists = []
custom_blocked = []
allowlist = []
update_interval_minutes = 60
enabled_features = []

[blocking.blocking_mode]
mode = "Default"

[tls]
# cert_path = "/etc/oxi-dns/cert.pem"
# key_path = "/etc/oxi-dns/key.pem"

# [tls.acme]
# enabled = true
# domain = "dns.example.com"
# email = "you@example.com"
# provider = "cloudflare"
# cloudflare_api_token = "your-token-here"

[system]
auto_update = false
ipv6_enabled = true
release_channel = "stable"

[log]
query_log_retention_days = 7
stats_retention_days = 90
anonymize_client_ip = false

# [limits]  — every key is optional; unset keys auto-scale from detected hardware.
# dns_cache_entries = 100000
# ns_cache_entries = 10000
# udp_max_inflight = 1024
# tcp_max_connections = 512
# dot_max_connections = 512
# doh_max_connections = 512
# doq_max_streams_per_connection = 128
# blocklist_max_mb = 100
# web_upload_max_mb = 10
```

## Command-line options

The `oxi-dns` binary is normally started by its systemd / launchd unit with
no arguments, but every option it accepts is documented here for
completeness. The packaged install path is `/opt/oxi-dns/oxi-dns`.

```
oxi-dns [CONFIG_PATH] [OPTIONS]
```

| Option | Description |
|---|---|
| `CONFIG_PATH` (positional) | Path to a `config.toml` to load. Defaults to `/etc/oxi-dns/config.toml` when omitted. The first bare argument (one that doesn't start with `-` and isn't consumed by another flag) is treated as the config path. |
| `--version`, `-V` | Print `oxi-dns <version>` and exit. |
| `--health-check` | Load the config, build the upstream client, issue a local DNS query end-to-end, and exit `0` on success. Intended for systemd `ExecStartPre` / graceful-restart health checks; a 30 s timeout aborts hung checks. |
| `--reconfigure KEY=VALUE …` | Apply one or more network-listener changes and restart the service (requires root). See [Reconfigure](#reconfigure) below for the accepted keys. Any number of `key=value` pairs may follow the flag. |
| `--takeover` | Marker used by the in-process graceful-restart flow to tell a freshly spawned child that it's taking over from a running parent. `SO_REUSEPORT` makes the hand-off seamless; the flag itself is a no-op beyond signalling intent. Not intended for manual use. |
| `--ready-file PATH` | Write-path used together with `--takeover`: when the child has successfully bound its listeners, it touches `PATH` to tell the parent process it's ready to replace it. Not intended for manual use. |

Examples:

```bash
# Print the version
oxi-dns --version

# Load a non-default config path
oxi-dns /etc/oxi-dns/custom.toml

# Run the health check (used by the graceful-restart flow)
oxi-dns --health-check
```

## Reconfigure

Change network listen addresses from the command line (requires root):

```bash
sudo oxi-dns --reconfigure dns.listen=0.0.0.0:5353
sudo oxi-dns --reconfigure web.listen=0.0.0.0:3000
sudo oxi-dns --reconfigure dns.listen=0.0.0.0:53 dns.dot_listen=0.0.0.0:853
sudo oxi-dns --reconfigure web.https_listen=0.0.0.0:9854 web.https_listen=[::]:9854
```

Accepted keys:

| Key | Required | Clears with empty value? |
|---|---|---|
| `dns.listen` | yes | no |
| `web.listen` | yes | no |
| `web.https_listen` | yes | no |
| `dns.dot_listen` | no | yes (`dns.dot_listen=`) |
| `dns.doh_listen` | no | yes (`dns.doh_listen=`) |
| `dns.doq_listen` | no | yes (`dns.doq_listen=`) |

Repeat the same key to bind multiple addresses (e.g. IPv4 + IPv6). `--reconfigure` handles systemd-resolved automatically when switching to/from port 53. The dashboard's Network tab also generates these commands for you when you edit any listen field.

`web.auto_redirect_https` and `web.trust_forwarded_proto` are **not** accepted by `--reconfigure` — they are web-editable via the Network tab and take effect through the in-process graceful restart (see below).

## HTTPS & Reverse Proxy

Oxi-DNS generates a self-signed certificate at startup if no cert is configured, so the dashboard is always reachable over HTTPS (default port `9854`). Uploading a real certificate or issuing one via ACME replaces the self-signed one.

Sensitive endpoints — TLS cert upload, ACME provider tokens, login, setup, and password change — are **always blocked over plain HTTP**, regardless of configuration. The dashboard shows a warning banner and inline-replaces the affected forms when loaded over HTTP, with a one-click "Switch to HTTPS" button.

### Configurable fields (Network tab)

| Field | Default | Effect |
|-------|---------|-------|
| `web.https_listen` | `["0.0.0.0:9854", "[::]:9854"]` | HTTPS listener for the dashboard. Always on — there is no enable/disable toggle. Ports are editable in the Network tab; saving emits a `sudo oxi-dns --reconfigure web.https_listen=…` command through the reconfig banner, same as DNS / HTTP / DoT / DoH / DoQ. |
| `web.auto_redirect_https` | `false` | When enabled, all HTTP requests get a 308 redirect to HTTPS. When disabled, HTTP still serves the dashboard for non-sensitive endpoints. |
| `web.trust_forwarded_proto` | `false` | Opt-in for reverse-proxied deployments (see below). ⚠ Security-critical. |

When `auto_redirect_https` transitions from off to on, the dashboard shows a one-time banner recommending a password rotation (since the password may have been transmitted in plaintext before HTTPS enforcement). The banner clears automatically after a successful password change.

### Running behind a reverse proxy

A common deployment pattern is TLS termination at a reverse proxy:

```
client ──HTTPS──▶ nginx/caddy/traefik ──HTTP──▶ oxi-dns
```

In this setup, oxi-dns sees only plain HTTP from the proxy, so by default its HTTP-gating middleware blocks sensitive endpoints — including login — and you'd be locked out of your own dashboard.

The fix is the opt-in `web.trust_forwarded_proto` flag. When enabled, oxi-dns trusts the `X-Forwarded-Proto` header that every standard reverse proxy injects, treating `X-Forwarded-Proto: https` as equivalent to a direct HTTPS connection:

```toml
[web]
listen = ["127.0.0.1:9853"]          # bound to loopback, only reachable via proxy
https_listen = ["127.0.0.1:9854"]    # optional — proxy can forward to HTTPS too
trust_forwarded_proto = true
```

**⚠ Only enable this flag if oxi-dns is *exclusively* reachable through a trusted reverse proxy.** If the HTTP listener is exposed to untrusted clients (e.g. bound to `0.0.0.0:9853` on an open network), an attacker can forge `X-Forwarded-Proto: https` and bypass every HTTPS-required check.

The middleware reads the **last** value of `X-Forwarded-Proto` if multiple are present, which is the authoritative value appended by the nearest trusted hop — a spoofed first value from an attacker before the proxy sees the request is ignored.

A warning is logged whenever `trust_forwarded_proto` transitions from disabled to enabled as an audit trail.

### Example: nginx

```nginx
server {
    listen 443 ssl http2;
    server_name oxi-dns.example.com;

    ssl_certificate     /etc/letsencrypt/live/oxi-dns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/oxi-dns.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:9853;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;   # nginx sets https
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Pair with `trust_forwarded_proto = true` in oxi-dns and bind `web.listen = ["127.0.0.1:9853"]` so the HTTP listener is not reachable from outside the host.

### Example: Caddy

```caddy
oxi-dns.example.com {
    reverse_proxy 127.0.0.1:9853
}
```

Caddy sets `X-Forwarded-Proto` automatically when using `reverse_proxy`.

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
| `POST` | `/api/system/network` | Update DoT/DoH/DoQ listen addresses and the `auto_redirect_https` / `trust_forwarded_proto` toggles. Changes to `dns.listen`, `web.listen`, and `web.https_listen` must go through `sudo oxi-dns --reconfigure` (the dashboard generates the exact command in its reconfig banner). |

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
- when query logs;
  - Add a toggle to enable/disable query logging
  - some users might want to keep query logging for a less than a day. (e.g. 12 hours)
  - when system resources are low, the query log should be rotated/oldest entries deleted.
- When enabling DoH, the user should be able to define the https request path (feature)
  - make sure that the path is not used by any other service on the same server.
- if the user wants a different subdomain for DoH, DoT and DoQ, the user should be able to define it in the UI (feature)
  - this should include the ability that the server automatically creates the needed certificates for the subdomain (if not already covered by wildcard certificate).
  - if the subdomain doesn't exist in the DNS zone, the server should create a DNS A (and if enabled AAAA) record for the subdomain pointing to the server's IP address.
    - this is only possible if the user has provided an API token for his authoritative DNS provider.
- in addition, harden DoH, DoT and DoQ (feature) (pathing attacks, etc)
- Verify that changing Settings in the UI (Like Port or listen address) works with the generated terminal commands. (ipv4 yes, ipv6 has to be fixed)
- add a warning for cloudflare users, that the proxy should be disabled for oxi-dns to work properly. 
- the oxi-dns command should be able to signal to the web UI that the config has changed and the UI should reload the config. (feature)
- test the container images
- purge all dead code


### Goals for Version 2:
- Add a "Test" button for the upstream DNS servers (feature)
- add oxi-dns cli commands. (adding certificate, rebooting the server) 
- Security enhancements
  - DNSsec
  - DNScrypt
  - Rate limits for clients
  - DDoS protection
  - no DNAME, no EDNS0, sequential server tries within a single referral
   step, and glueless-NS resolution reuses the bootstrap walker which itself  
  only handles glued chains.
- logging system errors
- DHCP Server
- redundancy feature. Dns server cluster
- multiple subdomains using multiple filter configurations (feature)
- purge all dead code

### Goals for Version 3:
- More statistics, fancy graphs and more
- Statistics need to be persistent
- make the log entries clickable and show more information about the query
- sort logs by ...
- dns rewrites
- ability to disable the Web UI (feature)
  - including all the feaures that are not essential for the DNS server to run. (like statistics, logs, etc.)
  - this should be done in a way that the server can still run without the Web UI.
  - the Web UI should be able to be started and stopped independently of the DNS server.
- ability to disable the API (feature)
  - including all the feaures that are not essential for the DNS server to run. (like statistics, logs, etc.)
  - this should be done in a way that the server can still run without the API.
  - the API should be able to be started and stopped independently of the DNS server.
- encrypted config download 
- purge all dead code

### Stuff that might be done
- Look into RFC Compliance
- Besides User Login and password, LDAP as well
- Not only single entries, but complete Allowlist section
- If my finances allow, a security audit of the code (option for Donations, maybe a donation button?)
