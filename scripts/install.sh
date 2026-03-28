#!/bin/sh

# Oxi-Hole install script
# Usage:
#   curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh -s -- [options]
#
# Options:
#   -r  Reinstall (overwrite existing installation)
#   -u  Uninstall
#   -v  Verbose output
#   -c <channel>  Release channel (stable, beta, edge). Default: stable
#   -h  Show help

set -e

# ============================================================================
# Configuration
# ============================================================================

REPO_OWNER="ron-png"
REPO_NAME="oxi-hole"
BINARY_NAME="oxi-hole"
INSTALL_DIR="/opt/oxi-hole"
CONFIG_DIR="/etc/oxi-hole"
SERVICE_NAME="oxi-hole"
LOG_DIR="/var/log/oxi-hole"

CHANNEL="stable"
REINSTALL=0
UNINSTALL=0
VERBOSE=0

# Save original arguments before getopts consumes them
ORIG_ARGS="$*"

# ============================================================================
# Colors and output helpers
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

log_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

log_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        printf "${CYAN}[DEBUG]${NC} %s\n" "$1"
    fi
}

log_step() {
    printf "\n${BOLD}${BLUE}==>${NC} ${BOLD}%s${NC}\n" "$1"
}

# ============================================================================
# Parse arguments
# ============================================================================

usage() {
    cat <<EOF
Oxi-Hole Installer

Usage: $0 [options]

Options:
  -c <channel>  Release channel: stable (default), beta, edge
  -r            Reinstall (overwrite existing installation)
  -u            Uninstall Oxi-Hole
  -v            Verbose output
  -h            Show this help message

Note: -r and -u are mutually exclusive.

Examples:
  Install:     curl -s -S -L "https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/master/scripts/install.sh?v=\$(date +%s)" | sh
  Reinstall:   curl -s -S -L ... | sh -s -- -r
  Uninstall:   curl -s -S -L ... | sh -s -- -u
EOF
}

while getopts "c:ruvh" opt; do
    case "$opt" in
        c) CHANNEL="$OPTARG" ;;
        r) REINSTALL=1 ;;
        u) UNINSTALL=1 ;;
        v) VERBOSE=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

if [ "$REINSTALL" -eq 1 ] && [ "$UNINSTALL" -eq 1 ]; then
    log_error "Options -r (reinstall) and -u (uninstall) are mutually exclusive."
    exit 1
fi

# ============================================================================
# Check root
# ============================================================================

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        if [ "$ALREADY_ELEVATED" = "1" ]; then
            log_error "Failed to elevate privileges. Please run as root."
            exit 1
        fi
        export ALREADY_ELEVATED=1

        log_info "Elevating privileges using sudo..."
        if ! command -v sudo >/dev/null 2>&1; then
            log_error "This script requires root privileges. Please run as root or install 'sudo'."
            exit 1
        fi

        if [ -f "$0" ] && [ "$0" != "sh" ] && [ "$0" != "bash" ] && [ "$0" != "-sh" ] && [ "$0" != "dash" ]; then
            exec sudo sh "$0" $ORIG_ARGS
        else
            check_dependencies
            TMP_SCRIPT=$(mktemp)
            download "https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/master/scripts/install.sh?v=$(date +%s)" "$TMP_SCRIPT"
            trap 'rm -f "$TMP_SCRIPT"' EXIT
            sudo sh "$TMP_SCRIPT" $ORIG_ARGS
            exit $?
        fi
    fi
}

# ============================================================================
# Detect OS and architecture
# ============================================================================

detect_os() {
    OS="$(uname -s)"
    case "$OS" in
        Linux)   OS="linux" ;;
        Darwin)  OS="darwin" ;;
        FreeBSD) OS="freebsd" ;;
        OpenBSD) OS="openbsd" ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    log_verbose "Detected OS: $OS"
}

detect_arch() {
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64)       ARCH="amd64" ;;
        aarch64|arm64)      ARCH="arm64" ;;
        armv7l|armv7)       ARCH="armv7" ;;
        armv6l|armv6)       ARCH="armv6" ;;
        i386|i686)          ARCH="386" ;;
        riscv64)            ARCH="riscv64" ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    log_verbose "Detected architecture: $ARCH"
}

# ============================================================================
# Check for required tools
# ============================================================================

check_dependencies() {
    for cmd in tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done

    # Need at least one download tool
    if command -v curl >/dev/null 2>&1; then
        DOWNLOAD_CMD="curl"
    elif command -v wget >/dev/null 2>&1; then
        DOWNLOAD_CMD="wget"
    elif command -v fetch >/dev/null 2>&1; then
        DOWNLOAD_CMD="fetch"
    else
        log_error "No download tool found. Install curl, wget, or fetch."
        exit 1
    fi
    log_verbose "Download command: $DOWNLOAD_CMD"
}

# ============================================================================
# Download helper
# ============================================================================

download() {
    url="$1"
    dest="$2"

    log_verbose "Downloading: $url"

    case "$DOWNLOAD_CMD" in
        curl)
            curl -s -S -L -o "$dest" "$url"
            ;;
        wget)
            wget --no-verbose -O "$dest" "$url"
            ;;
        fetch)
            fetch -o "$dest" "$url"
            ;;
    esac
}

download_to_stdout() {
    url="$1"

    case "$DOWNLOAD_CMD" in
        curl)
            curl -s -S -L "$url"
            ;;
        wget)
            wget --no-verbose -O - "$url"
            ;;
        fetch)
            fetch -o - "$url"
            ;;
    esac
}

# ============================================================================
# Get latest release version
# ============================================================================

get_latest_version() {
    log_verbose "Fetching latest release version..."

    if [ "$CHANNEL" = "edge" ] || [ "$CHANNEL" = "beta" ]; then
        RELEASE_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases"
        VERSION=$(download_to_stdout "$RELEASE_URL" | grep '"tag_name"' | head -n 1 | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    else
        RELEASE_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
        VERSION=$(download_to_stdout "$RELEASE_URL" | grep '"tag_name"' | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    fi

    # Fallback to pre-releases if no stable release exists
    if [ -z "$VERSION" ]; then
        log_warn "No stable release found. Falling back to the newest available pre-release..."
        RELEASE_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases"
        VERSION=$(download_to_stdout "$RELEASE_URL" | grep '"tag_name"' | head -n 1 | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    fi

    if [ -z "$VERSION" ]; then
        log_error "Could not determine latest release version."
        log_error "Check https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
        exit 1
    fi

    log_verbose "Latest version: $VERSION"
}

# ============================================================================
# Install
# ============================================================================

do_install() {
    log_step "Installing Oxi-Hole"

    detect_os
    detect_arch
    check_dependencies
    get_latest_version

    # Check if already installed, compare versions and update if necessary
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ] && [ "$REINSTALL" -eq 0 ]; then
        CURRENT_VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")
        
        # Extract version numbers
        CV_NUM=$(echo "$CURRENT_VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "0.0.0")
        LV_NUM=$(echo "$VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "0.0.0")

        if [ "$CV_NUM" = "$LV_NUM" ]; then
            log_info "Oxi-Hole is already installed and up to date (version: ${CV_NUM})"
            exit 0
        fi

        # Compare versions backward/forward safely using sort -V if available
        if command -v sort >/dev/null 2>&1 && printf '%s\n' "1" | sort -V >/dev/null 2>&1; then
            HIGHEST=$(printf "%s\n%s" "$CV_NUM" "$LV_NUM" | sort -V | tail -n1)
            if [ "$HIGHEST" = "$CV_NUM" ] && [ "$CV_NUM" != "$LV_NUM" ]; then
                log_info "Oxi-Hole is already installed with a newer version (${CV_NUM}) than the latest release (${LV_NUM})."
                exit 0
            fi
        fi

        log_info "Updating Oxi-Hole from version ${CV_NUM} to ${LV_NUM}"
    fi

    # Build download URL
    ARCHIVE_NAME="${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}/${ARCHIVE_NAME}"

    log_info "Version:      ${VERSION}"
    log_info "OS:           ${OS}"
    log_info "Architecture: ${ARCH}"
    log_info "Download URL: ${DOWNLOAD_URL}"

    # Create temp directory
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    # Download
    log_step "Downloading Oxi-Hole ${VERSION}"
    ARCHIVE_PATH="${TMPDIR}/${ARCHIVE_NAME}"
    download "$DOWNLOAD_URL" "$ARCHIVE_PATH"

    if [ ! -f "$ARCHIVE_PATH" ] || [ ! -s "$ARCHIVE_PATH" ]; then
        log_error "Download failed. Check the URL: ${DOWNLOAD_URL}"
        exit 1
    fi

    log_info "Downloaded successfully"

    # Extract
    log_step "Extracting archive"
    tar -xzf "$ARCHIVE_PATH" -C "$TMPDIR"
    log_verbose "Extracted to $TMPDIR"

    # Find binary in extracted files
    EXTRACTED_BINARY=$(find "$TMPDIR" -name "$BINARY_NAME" -type f | head -1)
    if [ -z "$EXTRACTED_BINARY" ]; then
        log_error "Binary '$BINARY_NAME' not found in archive"
        exit 1
    fi

    # Stop existing service if reinstalling
    if [ "$REINSTALL" -eq 1 ]; then
        log_step "Stopping existing service"
        stop_service 2>/dev/null || true
    fi

    # Install binary
    log_step "Installing binary to ${INSTALL_DIR}"
    mkdir -p "$INSTALL_DIR"
    cp "$EXTRACTED_BINARY" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
    log_info "Binary installed: ${INSTALL_DIR}/${BINARY_NAME}"

    # Create symlink in /usr/local/bin
    ln -sf "${INSTALL_DIR}/${BINARY_NAME}" "/usr/local/bin/${BINARY_NAME}"
    log_info "Symlink created: /usr/local/bin/${BINARY_NAME}"

    # Create config directory and default config
    log_step "Setting up configuration"
    mkdir -p "$CONFIG_DIR"
    if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
        create_default_config
        log_info "Default config created: ${CONFIG_DIR}/config.toml"
    else
        log_info "Config already exists: ${CONFIG_DIR}/config.toml (preserved)"
    fi

    # Create log directory
    mkdir -p "$LOG_DIR"

    # Create system user
    create_user

    # Set ownership
    chown -R oxi-hole:oxi-hole "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" 2>/dev/null || true

    # Install service
    log_step "Installing system service"
    install_service

    # Check port 53 before starting
    check_port53

    # Enable and start
    log_step "Starting Oxi-Hole"
    enable_service
    start_service

    # Verify oxi-hole is actually listening on port 53
    verify_running

    log_step "Installation complete!"
    printf "\n"
    printf "  ${BOLD}Oxi-Hole has been installed successfully!${NC}\n"
    printf "\n"
    printf "  ${CYAN}Binary:${NC}    ${INSTALL_DIR}/${BINARY_NAME}\n"
    printf "  ${CYAN}Config:${NC}    ${CONFIG_DIR}/config.toml\n"
    printf "  ${CYAN}Logs:${NC}      ${LOG_DIR}/\n"
    printf "  ${CYAN}Service:${NC}   ${SERVICE_NAME}\n"
    printf "\n"
    printf "  ${BOLD}Web Dashboard:${NC}  ${GREEN}http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'localhost'):8080${NC}\n"
    printf "  ${BOLD}DNS Server:${NC}     UDP port 53\n"
    printf "\n"
    printf "  ${CYAN}Manage the service:${NC}\n"
    printf "    sudo systemctl status ${SERVICE_NAME}\n"
    printf "    sudo systemctl stop ${SERVICE_NAME}\n"
    printf "    sudo systemctl restart ${SERVICE_NAME}\n"
    printf "    sudo journalctl -u ${SERVICE_NAME} -f\n"
    printf "\n"
    printf "  ${CYAN}Edit config:${NC}  sudo nano ${CONFIG_DIR}/config.toml\n"
    printf "\n"
}

# ============================================================================
# Uninstall
# ============================================================================

do_uninstall() {
    log_step "Uninstalling Oxi-Hole"

    # Stop and disable service
    log_info "Stopping service..."
    stop_service 2>/dev/null || true
    disable_service 2>/dev/null || true

    # Remove service file
    remove_service

    # Remove binary and symlink
    log_info "Removing binary..."
    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    rm -f "/usr/local/bin/${BINARY_NAME}"
    rmdir "$INSTALL_DIR" 2>/dev/null || true

    # Ask about config
    if [ -d "$CONFIG_DIR" ]; then
        printf "${YELLOW}Remove configuration directory ${CONFIG_DIR}? [y/N]: ${NC}"
        read -r REPLY </dev/tty 2>/dev/null || REPLY="n"
        case "$REPLY" in
            [yY]|[yY][eE][sS])
                rm -rf "$CONFIG_DIR"
                log_info "Configuration removed"
                ;;
            *)
                log_info "Configuration preserved at ${CONFIG_DIR}"
                ;;
        esac
    fi

    # Ask about logs
    if [ -d "$LOG_DIR" ]; then
        printf "${YELLOW}Remove log directory ${LOG_DIR}? [y/N]: ${NC}"
        read -r REPLY </dev/tty 2>/dev/null || REPLY="n"
        case "$REPLY" in
            [yY]|[yY][eE][sS])
                rm -rf "$LOG_DIR"
                log_info "Logs removed"
                ;;
            *)
                log_info "Logs preserved at ${LOG_DIR}"
                ;;
        esac
    fi

    # Remove user
    if id oxi-hole >/dev/null 2>&1; then
        userdel oxi-hole 2>/dev/null || true
        log_info "System user 'oxi-hole' removed"
    fi

    log_step "Uninstallation complete!"
    log_info "Oxi-Hole has been removed from your system."
}

# ============================================================================
# System user
# ============================================================================

create_user() {
    if ! id oxi-hole >/dev/null 2>&1; then
        log_info "Creating system user 'oxi-hole'..."
        if command -v useradd >/dev/null 2>&1; then
            useradd --system --no-create-home --shell /usr/sbin/nologin oxi-hole 2>/dev/null || true
        elif command -v adduser >/dev/null 2>&1; then
            adduser --system --no-create-home --disabled-login oxi-hole 2>/dev/null || true
        fi
    else
        log_verbose "User 'oxi-hole' already exists"
    fi
}

# ============================================================================
# Default config
# ============================================================================

create_default_config() {
    cat > "${CONFIG_DIR}/config.toml" <<'CONFIGEOF'
# Oxi-Hole Configuration
# See: https://github.com/ron-png/oxi-hole

[dns]
# Plain DNS (UDP)
listen = "0.0.0.0:53"

# DNS-over-TLS (uncomment to enable)
# dot_listen = "0.0.0.0:853"

# DNS-over-HTTPS (uncomment to enable)
# doh_listen = "0.0.0.0:443"

# DNS-over-QUIC (uncomment to enable)
# doq_listen = "0.0.0.0:853"

# Upstream DNS servers
# Supported: plain UDP, tls://, https://, quic://
upstreams = [
    "8.8.8.8:53",
    "8.8.4.4:53",
    # "tls://1.1.1.1:853",
    # "https://cloudflare-dns.com/dns-query",
    # "quic://dns.adguard-dns.com:853",
]
timeout_ms = 5000

[web]
listen = "0.0.0.0:8080"

[tls]
# Auto-generates self-signed cert if not specified
# cert_path = "/etc/oxi-hole/cert.pem"
# key_path = "/etc/oxi-hole/key.pem"

[blocking]
enabled = true

# Blocklist URLs (uncomment to enable popular lists)
blocklists = [
    # "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    # "https://adaway.org/hosts.txt",
    # "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0",
]

custom_blocked = []
allowlist = []
CONFIGEOF
}

# ============================================================================
# Service management (systemd / launchd / rc.d)
# ============================================================================

detect_init_system() {
    if [ -d /run/systemd/system ] || command -v systemctl >/dev/null 2>&1; then
        INIT_SYSTEM="systemd"
    elif [ "$OS" = "darwin" ]; then
        INIT_SYSTEM="launchd"
    elif [ -d /etc/rc.d ] || [ -d /usr/local/etc/rc.d ]; then
        INIT_SYSTEM="rcd"
    elif command -v rc-service >/dev/null 2>&1; then
        INIT_SYSTEM="openrc"
    else
        INIT_SYSTEM="none"
    fi
    log_verbose "Init system: $INIT_SYSTEM"
}

install_service() {
    detect_init_system

    case "$INIT_SYSTEM" in
        systemd)
            install_systemd_service
            ;;
        launchd)
            install_launchd_service
            ;;
        openrc)
            install_openrc_service
            ;;
        *)
            log_warn "No supported init system detected. You'll need to start Oxi-Hole manually:"
            log_warn "  ${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/config.toml"
            ;;
    esac
}

install_systemd_service() {
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Oxi-Hole DNS Server
Documentation=https://github.com/${REPO_OWNER}/${REPO_NAME}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=oxi-hole
Group=oxi-hole
ExecStart=${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/config.toml
Restart=always
RestartSec=5
WorkingDirectory=${INSTALL_DIR}

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${CONFIG_DIR} ${LOG_DIR}
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Allow binding to privileged ports (53, 443, 853)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    log_info "Systemd service installed"
}

install_launchd_service() {
    PLIST="/Library/LaunchDaemons/com.oxi-hole.server.plist"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.oxi-hole.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/${BINARY_NAME}</string>
        <string>${CONFIG_DIR}/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/oxi-hole.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/oxi-hole.err</string>
</dict>
</plist>
EOF
    log_info "Launchd service installed: $PLIST"
}

install_openrc_service() {
    cat > "/etc/init.d/${SERVICE_NAME}" <<EOF
#!/sbin/openrc-run

name="Oxi-Hole DNS Server"
description="AdGuardHome-style DNS sinkhole"
command="${INSTALL_DIR}/${BINARY_NAME}"
command_args="${CONFIG_DIR}/config.toml"
command_user="oxi-hole"
command_background=true
pidfile="/run/${SERVICE_NAME}.pid"

depend() {
    need net
    after firewall
}
EOF
    chmod 755 "/etc/init.d/${SERVICE_NAME}"
    log_info "OpenRC service installed"
}

start_service() {
    detect_init_system
    case "$INIT_SYSTEM" in
        systemd)  systemctl start "$SERVICE_NAME" ;;
        launchd)  launchctl load "/Library/LaunchDaemons/com.oxi-hole.server.plist" ;;
        openrc)   rc-service "$SERVICE_NAME" start ;;
    esac
    log_info "Service started"
}

stop_service() {
    detect_init_system
    case "$INIT_SYSTEM" in
        systemd)  systemctl stop "$SERVICE_NAME" 2>/dev/null || true ;;
        launchd)  launchctl unload "/Library/LaunchDaemons/com.oxi-hole.server.plist" 2>/dev/null || true ;;
        openrc)   rc-service "$SERVICE_NAME" stop 2>/dev/null || true ;;
    esac
}

enable_service() {
    detect_init_system
    case "$INIT_SYSTEM" in
        systemd)  systemctl enable "$SERVICE_NAME" 2>/dev/null || true ;;
        openrc)   rc-update add "$SERVICE_NAME" default 2>/dev/null || true ;;
    esac
}

disable_service() {
    detect_init_system
    case "$INIT_SYSTEM" in
        systemd)  systemctl disable "$SERVICE_NAME" 2>/dev/null || true ;;
        openrc)   rc-update del "$SERVICE_NAME" default 2>/dev/null || true ;;
    esac
}

remove_service() {
    detect_init_system
    case "$INIT_SYSTEM" in
        systemd)
            rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
            systemctl daemon-reload 2>/dev/null || true
            log_info "Systemd service removed"
            ;;
        launchd)
            rm -f "/Library/LaunchDaemons/com.oxi-hole.server.plist"
            log_info "Launchd service removed"
            ;;
        openrc)
            rm -f "/etc/init.d/${SERVICE_NAME}"
            log_info "OpenRC service removed"
            ;;
    esac
}

# ============================================================================
# Preflight checks
# ============================================================================

check_port53() {
    log_step "Checking port 53 availability"

    # Detect what's using port 53
    PORT53_PID=""
    PORT53_PROC=""

    if command -v ss >/dev/null 2>&1; then
        PORT53_INFO=$(ss -tlnup 2>/dev/null | grep ':53 ' || true)
    elif command -v netstat >/dev/null 2>&1; then
        PORT53_INFO=$(netstat -tlnup 2>/dev/null | grep ':53 ' || true)
    elif command -v lsof >/dev/null 2>&1; then
        PORT53_INFO=$(lsof -i :53 2>/dev/null || true)
    else
        log_warn "Cannot check port 53 (no ss, netstat, or lsof found). Skipping check."
        return 0
    fi

    if [ -z "$PORT53_INFO" ]; then
        log_info "Port 53 is available"
        return 0
    fi

    log_warn "Port 53 is already in use:"
    printf "  %s\n" "$PORT53_INFO"
    printf "\n"

    # Check if systemd-resolved is the culprit
    if echo "$PORT53_INFO" | grep -q "systemd-resolve\|resolved"; then
        fix_systemd_resolved
    elif echo "$PORT53_INFO" | grep -q "dnsmasq"; then
        log_warn "dnsmasq is using port 53."
        printf "${YELLOW}Stop and disable dnsmasq so Oxi-Hole can use port 53? [Y/n]: ${NC}"
        read -r REPLY </dev/tty 2>/dev/null || REPLY="y"
        case "$REPLY" in
            [nN]|[nN][oO])
                log_error "Port 53 is required for Oxi-Hole. Please free it manually and re-run the installer."
                exit 1
                ;;
            *)
                systemctl stop dnsmasq 2>/dev/null || true
                systemctl disable dnsmasq 2>/dev/null || true
                log_info "dnsmasq stopped and disabled"
                ;;
        esac
    elif echo "$PORT53_INFO" | grep -q "named\|bind"; then
        log_error "BIND/named is using port 53."
        log_error "Please stop it manually and re-run the installer:"
        log_error "  sudo systemctl stop named && sudo systemctl disable named"
        exit 1
    else
        log_error "An unknown process is using port 53. Please free it and re-run the installer."
        exit 1
    fi
}

fix_systemd_resolved() {
    log_warn "systemd-resolved is using port 53 (stub listener)."
    printf "${YELLOW}Disable the systemd-resolved stub listener so Oxi-Hole can bind to port 53? [Y/n]: ${NC}"
    read -r REPLY </dev/tty 2>/dev/null || REPLY="y"
    case "$REPLY" in
        [nN]|[nN][oO])
            log_error "Port 53 is required for Oxi-Hole. Please free it manually and re-run the installer."
            exit 1
            ;;
    esac

    log_info "Disabling systemd-resolved stub listener..."

    # Create drop-in config to disable stub listener
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/oxi-hole.conf <<'RESOLVEDEOF'
# Created by Oxi-Hole installer
# Disables the stub listener on 127.0.0.53:53 so Oxi-Hole can use port 53
[Resolve]
DNSStubListener=no
RESOLVEDEOF

    # Point resolv.conf to oxi-hole once it's running
    # Back up the current symlink/file
    if [ -L /etc/resolv.conf ]; then
        RESOLV_TARGET=$(readlink -f /etc/resolv.conf 2>/dev/null || true)
        log_verbose "Current /etc/resolv.conf -> $RESOLV_TARGET"
    fi

    # Write a resolv.conf that points to localhost (oxi-hole)
    # Preserve existing search domains if present
    SEARCH_LINE=$(grep '^search ' /etc/resolv.conf 2>/dev/null || true)
    rm -f /etc/resolv.conf
    {
        echo "# Generated by Oxi-Hole installer"
        echo "# DNS queries are handled by Oxi-Hole on 127.0.0.1:53"
        [ -n "$SEARCH_LINE" ] && echo "$SEARCH_LINE"
        echo "nameserver 127.0.0.1"
    } > /etc/resolv.conf

    # Restart systemd-resolved to release port 53
    systemctl restart systemd-resolved 2>/dev/null || true

    # Verify port 53 is now free
    sleep 1
    if command -v ss >/dev/null 2>&1; then
        STILL_USED=$(ss -tlnup 2>/dev/null | grep ':53 ' || true)
    else
        STILL_USED=""
    fi

    if [ -n "$STILL_USED" ]; then
        log_error "Port 53 is still in use after disabling stub listener:"
        printf "  %s\n" "$STILL_USED"
        log_error "Please investigate and re-run the installer."
        exit 1
    fi

    log_info "systemd-resolved stub listener disabled"
    log_info "/etc/resolv.conf updated to use 127.0.0.1 (Oxi-Hole)"
}

verify_running() {
    log_step "Verifying Oxi-Hole is running"

    # Give the service a moment to start and bind
    sleep 2

    # Check if the process is running
    if ! pgrep -x "$BINARY_NAME" >/dev/null 2>&1; then
        log_error "Oxi-Hole process is not running."
        log_error "Check logs with: journalctl -u ${SERVICE_NAME} --no-pager -n 20"
        exit 1
    fi

    # Check if port 53 is bound by oxi-hole
    if command -v ss >/dev/null 2>&1; then
        if ! ss -tlnup 2>/dev/null | grep ':53 ' | grep -q "$BINARY_NAME"; then
            log_warn "Oxi-Hole is running but may not be listening on port 53."
            log_warn "Check logs with: journalctl -u ${SERVICE_NAME} --no-pager -n 20"
            return 0
        fi
    fi

    log_info "Oxi-Hole is running and listening on port 53"
}

# ============================================================================
# Banner
# ============================================================================

print_banner() {
    printf "${CYAN}"
    cat <<'BANNER'
   ____       _        _   _       _
  / __ \     (_)      | | | |     | |
 | |  | |_  ___       | |_| | ___ | | ___
 | |  | \ \/ / |______|  _  |/ _ \| |/ _ \
 | |__| |>  <| |______| | | | (_) | |  __/
  \____//_/\_\_|      |_| |_|\___/|_|\___|

BANNER
    printf "${NC}"
    printf "  ${BOLD}AdGuardHome-style DNS sinkhole, written in Rust${NC}\n"
    printf "  ${CYAN}https://github.com/${REPO_OWNER}/${REPO_NAME}${NC}\n\n"
}

# ============================================================================
# Main
# ============================================================================

main() {
    print_banner
    check_root

    if [ "$UNINSTALL" -eq 1 ]; then
        do_uninstall
    else
        do_install
    fi
}

main
