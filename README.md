# oxi-hole

> [!WARNING]
> This DNS server is currently in its early alpha stages. It is under active development and may be unstable. Do not use in production environments.

## Installation

You can install Oxi-Hole easily using the provided installation script:

```bash
curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh
```

### Installation Options

The installation script accepts the following flags. You must pass them to `sh` using `-s -- `:

- `-c <channel>`: Choose the release channel (`stable` [default], `beta`, or `edge`).
- `-r`: Reinstall (overwrites an existing installation).
- `-v`: Enable verbose output.
- `-h`: Show the installer's help message.
- `-U`: Update to the latest version (binary-only, preserves config).
- `-u`: Uninstall Oxi-Hole.

Example using flags (verbose install from the beta channel):
```bash
curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh -s -- -v -c beta
```

## Docker / Podman

Container images are published to GitHub Container Registry for `linux/amd64` and `linux/arm64`.

### Quick start

```bash
docker run -d \
  --name oxi-hole \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 8080:8080 \
  -v oxi-hole-config:/etc/oxi-hole \
  ghcr.io/ron-png/oxi-hole:latest
```

### Docker Compose

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

### Build locally

```bash
docker build -t oxi-hole .
docker run -d --name oxi-hole -p 53:53/udp -p 53:53/tcp -p 8080:8080 oxi-hole
```

The web dashboard is available at `http://<host>:8080`.

## Uninstallation

To completely remove Oxi-Hole from your system, run the script with the `-u` flag:

```bash
curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh -s -- -u
```
