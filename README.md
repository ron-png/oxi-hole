# Oxi-Hole 🛡️ | Fast, Secure, Rust-Based DNS Sinkhole & Ad Blocker

> [!WARNING]
> This DNS server is currently in its early alpha stages. It is under active development and may be unstable. Do not use in production environments.

**Oxi-Hole** is a high-performance, lightweight, and secure **DNS sinkhole server** written entirely in **Rust**. ("Oxi" stands for *oxidized*, because it is a DNS sinkhole written in Rust.) Designed as a modern alternative to Pi-hole and AdGuard Home, Oxi-Hole protects your network privacy by blocking ads, trackers, and malicious domains at the DNS level.

With native support for standard and encrypted DNS protocols including **DNS-over-TLS (DoT)**, **DNS-over-HTTPS (DoH)**, and the cutting-edge **DNS-over-QUIC (DoQ)**, Oxi-Hole ensures your internet traffic remains private, secure, and remarkably fast.

## ✨ Key Features

- 🦀 **Powered by Rust**: Built for memory safety, concurrency, and minimal resource usage.
- 🔒 **Encrypted DNS**: Full support for standard (UDP/TCP) and modern encrypted DNS protocols (DoT, DoH, DoQ) out of the box.
- 🚫 **Network-Wide Ad Blocking**: Acts as a DNS sinkhole (similar to Pi-hole or AdGuard Home) to block ads and telemetry for all devices on your local network.
- 📊 **Web Dashboard**: Intuitive, easy-to-use graphical interface running on port `8080`.
- 🐳 **Container Ready**: Official Docker and Podman container images for `linux/amd64` and `linux/arm64`.
- ⚡ **High Performance**: Asynchronous architecture powered by Tokio for maximum throughput and low latency.

## 🚀 Getting Started

You can install Oxi-Hole directly on your host machine or run it via Docker/Podman.

### Host Installation

You can install Oxi-Hole easily using the provided automated installation script:

```bash
curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh
```

#### Installation Options

The installation script accepts the following flags. You must pass them to `sh` using `-s -- `:

- `-c <channel>`: Choose the release channel (`stable` [default], `beta`, or `edge`).
- `-r`: Reinstall (overwrites an existing installation).
- `-v`: Enable verbose output.
- `-h`: Show the installer's help message.
- `-U`: Update to the latest version (binary-only, preserves config).
- `-u`: Uninstall Oxi-Hole.

*Example (verbose install from the beta channel):*
```bash
curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh -s -- -v -c beta
```

### Docker / Podman (Recommended)

Container images are published to the GitHub Container Registry (GHCR) for both AMD64 and ARM64 architectures, making it perfect for Raspberry Pi or home lab server deployments.

#### Quick Start with Docker

```bash
docker run -d \
  --name oxi-hole \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8080:8080 \
  -v oxi-hole-config:/etc/oxi-hole \
  ghcr.io/ron-png/oxi-hole:latest
```

#### Docker Compose

For easier management, use `docker-compose.yml`:

```yaml
services:
  oxi-hole:
    image: ghcr.io/ron-png/oxi-hole:latest
    container_name: oxi-hole
    restart: unless-stopped
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "8080:8080"
      # Uncomment if using DNS-over-TLS / DNS-over-HTTPS / DNS-over-QUIC:
      # - "853:853/tcp"
      # - "443:443/tcp"
    volumes:
      - oxi-hole-config:/etc/oxi-hole

volumes:
  oxi-hole-config:
```

#### Build Locally

```bash
docker build -t oxi-hole .
docker run -d --name oxi-hole -p 53:53/udp -p 53:53/tcp -p 8080:8080 oxi-hole
```

## 🖥️ Web Dashboard

Once installed and running, the Oxi-Hole web dashboard is available at:
`http://<host>:8080`

Use the dashboard to monitor DNS queries, manage blocklists, and configure your upstream DNS servers in real-time.

## 🗑️ Uninstallation

To completely remove Oxi-Hole from your system, run the installation script with the `-u` (uninstall) flag:

```bash
curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh -s -- -u
```

## 🤝 Contributing & Support

As an early alpha project, bug reports, feature requests, and pull requests are highly appreciated. Feel free to open an issue or contribute to the development of this modern Rust DNS server!
