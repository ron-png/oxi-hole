#!/bin/sh

# Oxi-DNS install script
# Usage:
#   curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-dns/master/scripts/install.sh?v=$(date +%s)" | sh -s -- [options]
#
# Options:
#   -r  Reinstall (purge all files and install fresh)
#   -u  Uninstall
#   -U  Update (download latest binary and restart service)
#   -v  Verbose output
#   -c <channel>  Release channel (stable, beta, edge). Default: stable
#   -h  Show help

set -e

# ============================================================================
# Configuration
# ============================================================================

REPO_OWNER="ron-png"
REPO_NAME="oxi-dns"
BINARY_NAME="oxi-dns"
INSTALL_DIR="/opt/oxi-dns"
CONFIG_DIR="/etc/oxi-dns"
SERVICE_NAME="oxi-dns"
LOG_DIR="/var/log/oxi-dns"

CHANNEL="stable"
REINSTALL=0
UNINSTALL=0
UPDATE=0
VERBOSE=0

# Legacy package name for backwards compatibility
OLD_BINARY_NAME="oxi-hole"
OLD_INSTALL_DIR="/opt/oxi-hole"
OLD_CONFIG_DIR="/etc/oxi-hole"
OLD_SERVICE_NAME="oxi-hole"
OLD_LOG_DIR="/var/log/oxi-hole"

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
Oxi-DNS Installer

Usage: $0 [options]

Options:
  -c <channel>  Release channel: stable (default), beta, edge
  -r            Reinstall (purge all files and install fresh)
  -u            Uninstall Oxi-DNS
  -U            Update (download latest binary and restart service)
  -v            Verbose output
  -h            Show this help message

Note: -r, -u, and -U are mutually exclusive.

Examples:
  Install:     curl -s -S -L "https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/master/scripts/install.sh?v=\$(date +%s)" | sh
  Update:      curl -s -S -L ... | sh -s -- -U
  Reinstall:   curl -s -S -L ... | sh -s -- -r
  Uninstall:   curl -s -S -L ... | sh -s -- -u
EOF
}

while getopts "c:ruUvh" opt; do
    case "$opt" in
        c) CHANNEL="$OPTARG" ;;
        r) REINSTALL=1 ;;
        u) UNINSTALL=1 ;;
        U) UPDATE=1 ;;
        v) VERBOSE=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

EXCLUSIVE_COUNT=$(( REINSTALL + UNINSTALL + UPDATE ))
if [ "$EXCLUSIVE_COUNT" -gt 1 ]; then
    log_error "Options -r (reinstall), -u (uninstall), and -U (update) are mutually exclusive."
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
# Migrate from legacy oxi-hole package
# ============================================================================

detect_legacy_install() {
    # Returns 0 if a legacy oxi-hole installation is detected
    [ -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}" ] || \
    [ -d "$OLD_CONFIG_DIR" ] || \
    [ -f "/etc/systemd/system/${OLD_SERVICE_NAME}.service" ] || \
    [ -f "/Library/LaunchDaemons/com.oxi-hole.server.plist" ] || \
    [ -f "/etc/init.d/${OLD_SERVICE_NAME}" ] || \
    id oxi-hole >/dev/null 2>&1
}

migrate_from_legacy() {
    if ! detect_legacy_install; then
        return 0
    fi

    log_step "Migrating from legacy oxi-hole installation"

    # Stop old service
    detect_init_system
    case "$INIT_SYSTEM" in
        systemd)
            systemctl stop "$OLD_SERVICE_NAME" 2>/dev/null || true
            systemctl disable "$OLD_SERVICE_NAME" 2>/dev/null || true
            rm -f "/etc/systemd/system/${OLD_SERVICE_NAME}.service"
            systemctl daemon-reload 2>/dev/null || true
            log_info "Old systemd service removed"
            ;;
        launchd)
            launchctl unload "/Library/LaunchDaemons/com.oxi-hole.server.plist" 2>/dev/null || true
            rm -f "/Library/LaunchDaemons/com.oxi-hole.server.plist"
            log_info "Old launchd service removed"
            ;;
        openrc)
            rc-service "$OLD_SERVICE_NAME" stop 2>/dev/null || true
            rc-update del "$OLD_SERVICE_NAME" default 2>/dev/null || true
            rm -f "/etc/init.d/${OLD_SERVICE_NAME}"
            log_info "Old OpenRC service removed"
            ;;
    esac

    # Migrate config directory (preserve user config)
    if [ -d "$OLD_CONFIG_DIR" ] && [ ! -d "$CONFIG_DIR" ]; then
        mv "$OLD_CONFIG_DIR" "$CONFIG_DIR"
        log_info "Config migrated: ${OLD_CONFIG_DIR} -> ${CONFIG_DIR}"
    elif [ -d "$OLD_CONFIG_DIR" ]; then
        log_info "New config dir already exists; old config preserved at ${OLD_CONFIG_DIR}"
    fi

    # Migrate log directory
    if [ -d "$OLD_LOG_DIR" ] && [ ! -d "$LOG_DIR" ]; then
        mv "$OLD_LOG_DIR" "$LOG_DIR"
        log_info "Logs migrated: ${OLD_LOG_DIR} -> ${LOG_DIR}"
    elif [ -d "$OLD_LOG_DIR" ]; then
        rm -rf "$OLD_LOG_DIR"
        log_info "Old log directory removed"
    fi

    # Remove old binary and symlink
    rm -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}"
    rm -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}.bak"
    rmdir "$OLD_INSTALL_DIR" 2>/dev/null || true
    rm -f "/usr/local/bin/${OLD_BINARY_NAME}"
    log_info "Old binary removed"

    # Migrate system user from oxi-hole to oxi-dns
    if id oxi-hole >/dev/null 2>&1; then
        case "$OS" in
            darwin)
                dscl . -delete /Users/oxi-hole 2>/dev/null || true
                ;;
            freebsd|openbsd)
                if command -v pw >/dev/null 2>&1; then
                    pw userdel oxi-hole 2>/dev/null || true
                fi
                ;;
            *)
                userdel oxi-hole 2>/dev/null || true
                ;;
        esac
        log_info "Old system user 'oxi-hole' removed"
    fi

    # Clean up old resolved config if present
    if [ -f /etc/systemd/resolved.conf.d/oxi-hole.conf ]; then
        rm -f /etc/systemd/resolved.conf.d/oxi-hole.conf
        log_info "Old resolved drop-in removed"
    fi

    log_info "Migration from oxi-hole complete"
}

# ============================================================================
# Install
# ============================================================================

do_install() {
    log_step "Installing Oxi-DNS"

    detect_os
    detect_arch
    check_dependencies
    migrate_from_legacy
    get_latest_version

    # Check if already installed, compare versions and update if necessary
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ] && [ "$REINSTALL" -eq 0 ]; then
        CURRENT_VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")

        # Extract version numbers (take first match only to avoid matching IPs etc.)
        CV_NUM=$(echo "$CURRENT_VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
        CV_NUM="${CV_NUM:-0.0.0}"
        LV_NUM=$(echo "$VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
        LV_NUM="${LV_NUM:-0.0.0}"

        if [ "$CV_NUM" = "$LV_NUM" ]; then
            log_info "Oxi-DNS is already installed and up to date (version: ${CV_NUM})"
            exit 0
        fi

        # Compare versions backward/forward safely using sort -V if available
        if command -v sort >/dev/null 2>&1 && printf '%s\n' "1" | sort -V >/dev/null 2>&1; then
            HIGHEST=$(printf "%s\n%s" "$CV_NUM" "$LV_NUM" | sort -V | tail -n1)
            if [ "$HIGHEST" = "$CV_NUM" ] && [ "$CV_NUM" != "$LV_NUM" ]; then
                log_info "Oxi-DNS is already installed with a newer version (${CV_NUM}) than the latest release (${LV_NUM})."
                exit 0
            fi
        fi

        log_info "Updating Oxi-DNS from version ${CV_NUM} to ${LV_NUM}"
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
    log_step "Downloading Oxi-DNS ${VERSION}"
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

    # Pre-download config before purging so all files are ready
    if [ "$REINSTALL" -eq 1 ]; then
        log_step "Pre-downloading configuration"
        CONFIG_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/master/config.toml"
        download "$CONFIG_URL" "${TMPDIR}/config.toml"
        if [ ! -s "${TMPDIR}/config.toml" ]; then
            log_error "Failed to download default config from ${CONFIG_URL}"
            log_error "Aborting reinstall — existing installation was NOT removed."
            exit 1
        fi
        log_info "Configuration pre-downloaded"
    fi

    # Purge existing installation if reinstalling
    if [ "$REINSTALL" -eq 1 ]; then
        log_step "Purging existing installation"
        stop_service 2>/dev/null || true
        disable_service 2>/dev/null || true
        remove_service
        rm -f "${INSTALL_DIR}/${BINARY_NAME}"
        rm -f "/usr/local/bin/${BINARY_NAME}"
        rm -rf "$CONFIG_DIR"
        rm -rf "$LOG_DIR"
        # Also purge any remaining legacy oxi-hole paths
        rm -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}"
        rm -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}.bak"
        rmdir "$OLD_INSTALL_DIR" 2>/dev/null || true
        rm -f "/usr/local/bin/${OLD_BINARY_NAME}"
        rm -rf "$OLD_CONFIG_DIR"
        rm -rf "$OLD_LOG_DIR"
        if id oxi-dns >/dev/null 2>&1; then
            case "$OS" in
                darwin)
                    dscl . -delete /Users/oxi-dns 2>/dev/null || true
                    ;;
                freebsd|openbsd)
                    if command -v pw >/dev/null 2>&1; then
                        pw userdel oxi-dns 2>/dev/null || true
                    fi
                    ;;
                *)
                    userdel oxi-dns 2>/dev/null || true
                    ;;
            esac
        fi
        if id oxi-hole >/dev/null 2>&1; then
            case "$OS" in
                darwin)
                    dscl . -delete /Users/oxi-hole 2>/dev/null || true
                    ;;
                freebsd|openbsd)
                    if command -v pw >/dev/null 2>&1; then
                        pw userdel oxi-hole 2>/dev/null || true
                    fi
                    ;;
                *)
                    userdel oxi-hole 2>/dev/null || true
                    ;;
            esac
        fi
        log_info "Existing installation purged"
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
    chown -R oxi-dns:oxi-dns "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" 2>/dev/null || true

    # Install service
    log_step "Installing system service"
    install_service

    # Check port 53 before starting
    check_port53

    # Enable and start
    log_step "Starting Oxi-DNS"
    enable_service
    start_service

    # Verify oxi-dns is actually listening on port 53
    verify_running

    log_step "Installation complete!"
    printf "\n"
    printf "  ${BOLD}Oxi-DNS has been installed successfully!${NC}\n"
    printf "\n"
    printf "  ${CYAN}Binary:${NC}    ${INSTALL_DIR}/${BINARY_NAME}\n"
    printf "  ${CYAN}Config:${NC}    ${CONFIG_DIR}/config.toml\n"
    printf "  ${CYAN}Logs:${NC}      ${LOG_DIR}/\n"
    printf "  ${CYAN}Service:${NC}   ${SERVICE_NAME}\n"
    printf "\n"
    # Detect local IP address (platform-portable)
    LOCAL_IP=""
    if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
        LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    elif command -v ifconfig >/dev/null 2>&1; then
        LOCAL_IP=$(ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | sed 's/addr://')
    fi
    LOCAL_IP="${LOCAL_IP:-localhost}"

    printf "  ${BOLD}Web Dashboard:${NC}  ${GREEN}http://${LOCAL_IP}:8080${NC}\n"
    printf "  ${BOLD}DNS Server:${NC}     UDP port 53\n"
    printf "\n"
    printf "  ${CYAN}Manage the service:${NC}\n"
    case "$INIT_SYSTEM" in
        systemd)
            printf "    sudo systemctl status ${SERVICE_NAME}\n"
            printf "    sudo systemctl stop ${SERVICE_NAME}\n"
            printf "    sudo systemctl restart ${SERVICE_NAME}\n"
            printf "    sudo journalctl -u ${SERVICE_NAME} -f\n"
            ;;
        launchd)
            printf "    sudo launchctl list | grep ${SERVICE_NAME}\n"
            printf "    sudo launchctl unload /Library/LaunchDaemons/com.oxi-dns.server.plist\n"
            printf "    sudo launchctl load /Library/LaunchDaemons/com.oxi-dns.server.plist\n"
            printf "    tail -f ${LOG_DIR}/oxi-dns.log\n"
            ;;
        openrc)
            printf "    sudo rc-service ${SERVICE_NAME} status\n"
            printf "    sudo rc-service ${SERVICE_NAME} stop\n"
            printf "    sudo rc-service ${SERVICE_NAME} restart\n"
            ;;
        *)
            printf "    ${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/config.toml\n"
            ;;
    esac
    printf "\n"
    printf "  ${CYAN}Edit config:${NC}  sudo nano ${CONFIG_DIR}/config.toml\n"
    printf "\n"
}

# ============================================================================
# Update (binary-only, preserves config and service)
# ============================================================================

do_update() {
    log_step "Updating Oxi-DNS"

    detect_os
    detect_arch
    check_dependencies
    migrate_from_legacy

    if [ ! -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        log_info "No existing oxi-dns binary found. Performing fresh install instead."
        do_install
        return
    fi

    get_latest_version

    # Compare versions
    CURRENT_VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")
    CV_NUM=$(echo "$CURRENT_VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    CV_NUM="${CV_NUM:-0.0.0}"
    LV_NUM=$(echo "$VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    LV_NUM="${LV_NUM:-0.0.0}"

    if [ "$CV_NUM" = "$LV_NUM" ]; then
        log_info "Already up to date (version: ${CV_NUM})"
        exit 0
    fi

    if command -v sort >/dev/null 2>&1 && printf '%s\n' "1" | sort -V >/dev/null 2>&1; then
        HIGHEST=$(printf "%s\n%s" "$CV_NUM" "$LV_NUM" | sort -V | tail -n1)
        if [ "$HIGHEST" = "$CV_NUM" ] && [ "$CV_NUM" != "$LV_NUM" ]; then
            log_info "Installed version (${CV_NUM}) is newer than latest release (${LV_NUM}). Nothing to do."
            exit 0
        fi
    fi

    log_info "Updating from v${CV_NUM} to v${LV_NUM}"

    # Download
    ARCHIVE_NAME="${BINARY_NAME}-${OS}-${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${VERSION}/${ARCHIVE_NAME}"

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    log_step "Downloading Oxi-DNS ${VERSION}"
    ARCHIVE_PATH="${TMPDIR}/${ARCHIVE_NAME}"
    download "$DOWNLOAD_URL" "$ARCHIVE_PATH"

    if [ ! -f "$ARCHIVE_PATH" ] || [ ! -s "$ARCHIVE_PATH" ]; then
        log_error "Download failed. Check the URL: ${DOWNLOAD_URL}"
        exit 1
    fi

    # Extract
    tar -xzf "$ARCHIVE_PATH" -C "$TMPDIR"
    EXTRACTED_BINARY=$(find "$TMPDIR" -name "$BINARY_NAME" -type f | head -1)
    if [ -z "$EXTRACTED_BINARY" ]; then
        log_error "Binary '$BINARY_NAME' not found in archive"
        exit 1
    fi

    # Backup current binary
    cp "${INSTALL_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}.bak"
    log_verbose "Backed up current binary to ${INSTALL_DIR}/${BINARY_NAME}.bak"

    # Stop service
    log_step "Stopping service"
    stop_service 2>/dev/null || true

    # Replace binary
    cp "$EXTRACTED_BINARY" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
    chown oxi-dns:oxi-dns "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true
    log_info "Binary updated"

    # Restart service
    log_step "Restarting service"
    start_service

    verify_running

    log_step "Update complete!"
    printf "\n"
    printf "  ${BOLD}Oxi-DNS updated from v${CV_NUM} to v${LV_NUM}${NC}\n"
    printf "\n"
}

# ============================================================================
# Uninstall
# ============================================================================

do_uninstall() {
    log_step "Uninstalling Oxi-DNS"

    detect_os

    # Clean up any legacy oxi-hole installation too
    if detect_legacy_install; then
        log_info "Cleaning up legacy oxi-hole installation..."
        detect_init_system
        case "$INIT_SYSTEM" in
            systemd)
                systemctl stop "$OLD_SERVICE_NAME" 2>/dev/null || true
                systemctl disable "$OLD_SERVICE_NAME" 2>/dev/null || true
                rm -f "/etc/systemd/system/${OLD_SERVICE_NAME}.service"
                systemctl daemon-reload 2>/dev/null || true
                ;;
            launchd)
                launchctl unload "/Library/LaunchDaemons/com.oxi-hole.server.plist" 2>/dev/null || true
                rm -f "/Library/LaunchDaemons/com.oxi-hole.server.plist"
                ;;
            openrc)
                rc-service "$OLD_SERVICE_NAME" stop 2>/dev/null || true
                rc-update del "$OLD_SERVICE_NAME" default 2>/dev/null || true
                rm -f "/etc/init.d/${OLD_SERVICE_NAME}"
                ;;
        esac
        rm -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}"
        rm -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}.bak"
        rmdir "$OLD_INSTALL_DIR" 2>/dev/null || true
        rm -f "/usr/local/bin/${OLD_BINARY_NAME}"
        rm -rf "$OLD_CONFIG_DIR"
        rm -rf "$OLD_LOG_DIR"
        rm -f /etc/systemd/resolved.conf.d/oxi-hole.conf
        if id oxi-hole >/dev/null 2>&1; then
            case "$OS" in
                darwin)   dscl . -delete /Users/oxi-hole 2>/dev/null || true ;;
                freebsd|openbsd) command -v pw >/dev/null 2>&1 && pw userdel oxi-hole 2>/dev/null || true ;;
                *)        userdel oxi-hole 2>/dev/null || true ;;
            esac
        fi
        log_info "Legacy oxi-hole installation cleaned up"
    fi

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
    if id oxi-dns >/dev/null 2>&1; then
        case "$OS" in
            darwin)
                dscl . -delete /Users/oxi-dns 2>/dev/null || true
                ;;
            freebsd|openbsd)
                if command -v pw >/dev/null 2>&1; then
                    pw userdel oxi-dns 2>/dev/null || true
                fi
                ;;
            *)
                userdel oxi-dns 2>/dev/null || true
                ;;
        esac
        log_info "System user 'oxi-dns' removed"
    fi

    # Restore DNS resolution
    restore_dns

    log_step "Uninstallation complete!"
    log_info "Oxi-DNS has been removed from your system."
}

# ============================================================================
# System user
# ============================================================================

create_user() {
    if ! id oxi-dns >/dev/null 2>&1; then
        log_info "Creating system user 'oxi-dns'..."
        case "$OS" in
            darwin)
                # macOS: use dscl to create a system account
                LAST_ID=$(dscl . -list /Users UniqueID 2>/dev/null | awk '{print $2}' | sort -n | tail -1)
                NEXT_ID=$((LAST_ID + 1))
                dscl . -create /Users/oxi-dns 2>/dev/null || true
                dscl . -create /Users/oxi-dns UserShell /usr/bin/false 2>/dev/null || true
                dscl . -create /Users/oxi-dns UniqueID "$NEXT_ID" 2>/dev/null || true
                dscl . -create /Users/oxi-dns PrimaryGroupID 20 2>/dev/null || true
                dscl . -create /Users/oxi-dns NFSHomeDirectory /var/empty 2>/dev/null || true
                ;;
            freebsd|openbsd)
                if command -v pw >/dev/null 2>&1; then
                    pw useradd oxi-dns -s /usr/sbin/nologin -d /nonexistent -c "Oxi-DNS DNS" 2>/dev/null || true
                fi
                ;;
            *)
                if command -v useradd >/dev/null 2>&1; then
                    useradd --system --no-create-home --shell /usr/sbin/nologin oxi-dns 2>/dev/null || true
                elif command -v adduser >/dev/null 2>&1; then
                    adduser --system --no-create-home --disabled-login oxi-dns 2>/dev/null || true
                fi
                ;;
        esac
    else
        log_verbose "User 'oxi-dns' already exists"
    fi
}

# ============================================================================
# Default config
# ============================================================================

create_default_config() {
    # Use pre-downloaded config if available (from reinstall flow)
    if [ -n "$TMPDIR" ] && [ -s "${TMPDIR}/config.toml" ]; then
        cp "${TMPDIR}/config.toml" "${CONFIG_DIR}/config.toml"
        log_verbose "Using pre-downloaded config"
        return
    fi

    CONFIG_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/master/config.toml"
    log_verbose "Downloading default config from ${CONFIG_URL}"
    download "$CONFIG_URL" "${CONFIG_DIR}/config.toml"

    if [ ! -s "${CONFIG_DIR}/config.toml" ]; then
        log_error "Failed to download default config from ${CONFIG_URL}"
        exit 1
    fi
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
            log_warn "No supported init system detected. You'll need to start Oxi-DNS manually:"
            log_warn "  ${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/config.toml"
            ;;
    esac
}

install_systemd_service() {
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Oxi-DNS DNS Server
Documentation=https://github.com/${REPO_OWNER}/${REPO_NAME}
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=oxi-dns
Group=oxi-dns
ExecStart=${INSTALL_DIR}/${BINARY_NAME} ${CONFIG_DIR}/config.toml
Restart=always
RestartSec=5
WorkingDirectory=${INSTALL_DIR}

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${INSTALL_DIR} ${CONFIG_DIR} ${LOG_DIR}
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
    PLIST="/Library/LaunchDaemons/com.oxi-dns.server.plist"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.oxi-dns.server</string>
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
    <string>${LOG_DIR}/oxi-dns.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/oxi-dns.err</string>
</dict>
</plist>
EOF
    log_info "Launchd service installed: $PLIST"
}

install_openrc_service() {
    cat > "/etc/init.d/${SERVICE_NAME}" <<EOF
#!/sbin/openrc-run

name="Oxi-DNS DNS Server"
description="AdGuardHome-style DNS sinkhole"
command="${INSTALL_DIR}/${BINARY_NAME}"
command_args="${CONFIG_DIR}/config.toml"
command_user="oxi-dns"
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
        launchd)  launchctl load "/Library/LaunchDaemons/com.oxi-dns.server.plist" ;;
        openrc)   rc-service "$SERVICE_NAME" start ;;
    esac
    log_info "Service started"
}

stop_service() {
    detect_init_system
    case "$INIT_SYSTEM" in
        systemd)  systemctl stop "$SERVICE_NAME" 2>/dev/null || true ;;
        launchd)  launchctl unload "/Library/LaunchDaemons/com.oxi-dns.server.plist" 2>/dev/null || true ;;
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
            rm -f "/Library/LaunchDaemons/com.oxi-dns.server.plist"
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
        printf "${YELLOW}Stop and disable dnsmasq so Oxi-DNS can use port 53? [Y/n]: ${NC}"
        read -r REPLY </dev/tty 2>/dev/null || REPLY="y"
        case "$REPLY" in
            [nN]|[nN][oO])
                log_error "Port 53 is required for Oxi-DNS. Please free it manually and re-run the installer."
                exit 1
                ;;
            *)
                detect_init_system
                case "$INIT_SYSTEM" in
                    systemd)
                        systemctl stop dnsmasq 2>/dev/null || true
                        systemctl disable dnsmasq 2>/dev/null || true
                        ;;
                    launchd)
                        launchctl unload /Library/LaunchDaemons/*dnsmasq* 2>/dev/null || true
                        ;;
                    openrc)
                        rc-service dnsmasq stop 2>/dev/null || true
                        rc-update del dnsmasq default 2>/dev/null || true
                        ;;
                    *)
                        pkill dnsmasq 2>/dev/null || true
                        ;;
                esac
                log_info "dnsmasq stopped and disabled"
                ;;
        esac
    elif echo "$PORT53_INFO" | grep -q "named\|bind"; then
        log_error "BIND/named is using port 53."
        log_error "Please stop it manually and re-run the installer."
        detect_init_system
        case "$INIT_SYSTEM" in
            systemd)
                log_error "  sudo systemctl stop named && sudo systemctl disable named"
                ;;
            openrc)
                log_error "  sudo rc-service named stop && sudo rc-update del named default"
                ;;
            *)
                log_error "  sudo killall named"
                ;;
        esac
        exit 1
    else
        log_error "An unknown process is using port 53. Please free it and re-run the installer."
        exit 1
    fi
}

fix_systemd_resolved() {
    log_warn "systemd-resolved is using port 53 (stub listener)."
    printf "${YELLOW}Disable the systemd-resolved stub listener so Oxi-DNS can bind to port 53? [Y/n]: ${NC}"
    read -r REPLY </dev/tty 2>/dev/null || REPLY="y"
    case "$REPLY" in
        [nN]|[nN][oO])
            log_error "Port 53 is required for Oxi-DNS. Please free it manually and re-run the installer."
            exit 1
            ;;
    esac

    log_info "Disabling systemd-resolved stub listener..."

    # Create drop-in config to disable stub listener
    mkdir -p /etc/systemd/resolved.conf.d
    cat > /etc/systemd/resolved.conf.d/oxi-dns.conf <<'RESOLVEDEOF'
# Created by Oxi-DNS installer
# Disables the stub listener on 127.0.0.53:53 so Oxi-DNS can use port 53
[Resolve]
DNSStubListener=no
RESOLVEDEOF

    # Point resolv.conf to oxi-dns once it's running
    # Back up the current symlink/file
    if [ -L /etc/resolv.conf ]; then
        RESOLV_TARGET=$(readlink -f /etc/resolv.conf 2>/dev/null || true)
        log_verbose "Current /etc/resolv.conf -> $RESOLV_TARGET"
    fi

    # Write a resolv.conf that points to localhost (oxi-dns)
    # Preserve existing search domains if present
    SEARCH_LINE=$(grep '^search ' /etc/resolv.conf 2>/dev/null || true)
    rm -f /etc/resolv.conf
    {
        echo "# Generated by Oxi-DNS installer"
        echo "# DNS queries are handled by Oxi-DNS on 127.0.0.1:53"
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
    log_info "/etc/resolv.conf updated to use 127.0.0.1 (Oxi-DNS)"
}

restore_dns() {
    log_step "Restoring DNS resolution"

    # Check if DNS resolution is already working (e.g. another resolver is active)
    if command -v nslookup >/dev/null 2>&1; then
        if nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
            log_info "DNS resolution is still working (another resolver on 127.0.0.1)"
            return 0
        fi
    fi

    # Try to re-enable systemd-resolved if it exists
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
            log_info "Re-enabling systemd-resolved..."

            # Remove our drop-in that disabled the stub listener
            rm -f /etc/systemd/resolved.conf.d/oxi-dns.conf
            rmdir /etc/systemd/resolved.conf.d 2>/dev/null || true

            # Restore resolv.conf to use systemd-resolved stub
            rm -f /etc/resolv.conf
            if [ -f /run/systemd/resolve/stub-resolv.conf ]; then
                ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            else
                ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
            fi

            systemctl enable systemd-resolved 2>/dev/null || true
            systemctl restart systemd-resolved 2>/dev/null || true
            log_info "systemd-resolved re-enabled and resolv.conf restored"
            return 0
        fi
    fi

    # Fallback: write a resolv.conf with public DNS servers
    log_warn "No system DNS resolver found. Setting up fallback resolv.conf with public DNS servers."
    SEARCH_LINE=$(grep '^search ' /etc/resolv.conf 2>/dev/null || true)
    {
        echo "# Generated by Oxi-DNS uninstaller (fallback)"
        [ -n "$SEARCH_LINE" ] && echo "$SEARCH_LINE"
        echo "nameserver 1.1.1.1"
        echo "nameserver 9.9.9.9"
    } > /etc/resolv.conf
    log_info "Fallback DNS configured (1.1.1.1, 9.9.9.9)"
}

verify_running() {
    log_step "Verifying Oxi-DNS is running"

    # Give the service a moment to start and bind
    sleep 2

    # Check if the process is running
    if ! pgrep -x "$BINARY_NAME" >/dev/null 2>&1; then
        log_error "Oxi-DNS process is not running."
        detect_init_system
        case "$INIT_SYSTEM" in
            systemd)  log_error "Check logs with: journalctl -u ${SERVICE_NAME} --no-pager -n 20" ;;
            launchd)  log_error "Check logs with: tail -20 ${LOG_DIR}/oxi-dns.log" ;;
            *)        log_error "Check logs in: ${LOG_DIR}/" ;;
        esac
        exit 1
    fi

    # Check if port 53 is bound by oxi-dns
    if command -v ss >/dev/null 2>&1; then
        if ! ss -tlnup 2>/dev/null | grep ':53 ' | grep -q "$BINARY_NAME"; then
            log_warn "Oxi-DNS is running but may not be listening on port 53."
            detect_init_system
            case "$INIT_SYSTEM" in
                systemd)  log_warn "Check logs with: journalctl -u ${SERVICE_NAME} --no-pager -n 20" ;;
                launchd)  log_warn "Check logs with: tail -20 ${LOG_DIR}/oxi-dns.log" ;;
                *)        log_warn "Check logs in: ${LOG_DIR}/" ;;
            esac
            return 0
        fi
    fi

    log_info "Oxi-DNS is running and listening on port 53"
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
    elif [ "$UPDATE" -eq 1 ]; then
        do_update
    else
        do_install
    fi
}

main
