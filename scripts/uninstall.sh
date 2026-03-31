#!/bin/sh

# Oxi-DNS standalone uninstall script
# This script is placed at /opt/oxi-dns/uninstall.sh during installation.
# It requires no network access and removes oxi-dns completely,
# restoring original DNS resolution.

set -e

# ============================================================================
# Configuration
# ============================================================================

BINARY_NAME="oxi-dns"
INSTALL_DIR="/opt/oxi-dns"
CONFIG_DIR="/etc/oxi-dns"
SERVICE_NAME="oxi-dns"
LOG_DIR="/var/log/oxi-dns"

OLD_BINARY_NAME="oxi-hole"
OLD_INSTALL_DIR="/opt/oxi-hole"
OLD_CONFIG_DIR="/etc/oxi-hole"
OLD_SERVICE_NAME="oxi-hole"
OLD_LOG_DIR="/var/log/oxi-hole"

# ============================================================================
# Colors and output helpers
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log_info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

log_warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1" >&2
}

log_step() {
    printf "\n${BOLD}${BLUE}==>${NC} ${BOLD}%s${NC}\n" "$1"
}

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

        if ! command -v sudo >/dev/null 2>&1; then
            log_error "This script requires root privileges. Please run as root or install 'sudo'."
            exit 1
        fi
        log_info "Elevating privileges using sudo..."
        exec sudo sh "$0" "$@"
    fi
}

# ============================================================================
# Detect OS and init system
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
}

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
}

# ============================================================================
# Service management helpers
# ============================================================================

stop_and_remove_service() {
    svc_name="$1"
    log_info "Stopping ${svc_name} service..."

    case "$INIT_SYSTEM" in
        systemd)
            systemctl stop "$svc_name" 2>/dev/null || true
            systemctl disable "$svc_name" 2>/dev/null || true
            rm -f "/etc/systemd/system/${svc_name}.service"
            systemctl daemon-reload 2>/dev/null || true
            ;;
        launchd)
            if [ "$svc_name" = "$SERVICE_NAME" ]; then
                launchctl unload "/Library/LaunchDaemons/com.oxi-dns.server.plist" 2>/dev/null || true
                rm -f "/Library/LaunchDaemons/com.oxi-dns.server.plist"
            elif [ "$svc_name" = "$OLD_SERVICE_NAME" ]; then
                launchctl unload "/Library/LaunchDaemons/com.oxi-hole.server.plist" 2>/dev/null || true
                rm -f "/Library/LaunchDaemons/com.oxi-hole.server.plist"
            fi
            ;;
        openrc)
            rc-service "$svc_name" stop 2>/dev/null || true
            rc-update del "$svc_name" default 2>/dev/null || true
            rm -f "/etc/init.d/${svc_name}"
            ;;
        rcd)
            if [ -f "/usr/local/etc/rc.d/${svc_name}" ]; then
                "/usr/local/etc/rc.d/${svc_name}" stop 2>/dev/null || true
                rm -f "/usr/local/etc/rc.d/${svc_name}"
            elif [ -f "/etc/rc.d/${svc_name}" ]; then
                "/etc/rc.d/${svc_name}" stop 2>/dev/null || true
                rm -f "/etc/rc.d/${svc_name}"
            fi
            ;;
        none|*)
            if command -v pkill >/dev/null 2>&1; then
                pkill -x "$svc_name" 2>/dev/null || true
            elif command -v killall >/dev/null 2>&1; then
                killall "$svc_name" 2>/dev/null || true
            fi
            ;;
    esac
}

remove_user() {
    username="$1"
    if id "$username" >/dev/null 2>&1; then
        log_info "Removing system user '${username}'..."
        case "$OS" in
            darwin)
                dscl . -delete "/Users/${username}" 2>/dev/null || true
                ;;
            freebsd|openbsd)
                if command -v pw >/dev/null 2>&1; then
                    pw userdel "$username" 2>/dev/null || true
                fi
                ;;
            *)
                userdel "$username" 2>/dev/null || true
                ;;
        esac
    fi
}

# ============================================================================
# DNS restoration
# ============================================================================

restore_dns() {
    log_step "Restoring DNS resolution"

    # Always clean up oxi-dns resolved drop-ins first, regardless of DNS state
    RESOLVED_CHANGED=0

    # Remove oxi-dns resolved drop-in
    if [ -f /etc/systemd/resolved.conf.d/oxi-dns.conf ]; then
        rm -f /etc/systemd/resolved.conf.d/oxi-dns.conf
        RESOLVED_CHANGED=1
    fi

    # Remove legacy oxi-hole resolved drop-in
    if [ -f /etc/systemd/resolved.conf.d/oxi-hole.conf ]; then
        rm -f /etc/systemd/resolved.conf.d/oxi-hole.conf
        RESOLVED_CHANGED=1
    fi

    # Clean up empty drop-in directory
    rmdir /etc/systemd/resolved.conf.d 2>/dev/null || true

    # If we removed a resolved drop-in, restart resolved and restore resolv.conf
    if [ "$RESOLVED_CHANGED" -eq 1 ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
            log_info "Re-enabling systemd-resolved..."
            systemctl enable systemd-resolved 2>/dev/null || true
            systemctl restart systemd-resolved 2>/dev/null || true

            # Restore resolv.conf symlink
            rm -f /etc/resolv.conf
            if [ -f /run/systemd/resolve/stub-resolv.conf ]; then
                ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
            elif [ -f /run/systemd/resolve/resolv.conf ]; then
                ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
            fi

            log_info "systemd-resolved re-enabled and resolv.conf restored"
            return 0
        fi
    fi

    # Check if DNS resolution is already working (e.g. another resolver is active)
    if command -v nslookup >/dev/null 2>&1; then
        if nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
            log_info "DNS resolution is still working (another resolver on 127.0.0.1)"
            return 0
        fi
    fi

    # Fallback: write resolv.conf with public DNS servers
    # Preserve existing search domains
    SEARCH_LINE=""
    if [ -f /etc/resolv.conf ]; then
        SEARCH_LINE=$(grep '^search ' /etc/resolv.conf 2>/dev/null || true)
    fi

    log_warn "No system DNS resolver found. Setting up fallback resolv.conf with public DNS servers."
    {
        echo "# Generated by Oxi-DNS uninstaller (fallback)"
        [ -n "$SEARCH_LINE" ] && echo "$SEARCH_LINE"
        echo "nameserver 1.1.1.1"
        echo "nameserver 9.9.9.9"
    } > /etc/resolv.conf
    log_info "Fallback DNS configured (1.1.1.1, 9.9.9.9)"
}

# ============================================================================
# Interactive directory removal prompt
# ============================================================================

ask_remove_dir() {
    dir_path="$1"
    dir_label="$2"

    if [ -d "$dir_path" ]; then
        printf "${YELLOW}Remove ${dir_label} directory ${dir_path}? [y/N]: ${NC}"
        read -r REPLY </dev/tty 2>/dev/null || REPLY="n"
        case "$REPLY" in
            [yY]|[yY][eE][sS])
                rm -rf "$dir_path"
                log_info "${dir_label} removed: ${dir_path}"
                ;;
            *)
                log_info "${dir_label} preserved at ${dir_path}"
                ;;
        esac
    fi
}

# ============================================================================
# Legacy oxi-hole detection and cleanup
# ============================================================================

detect_legacy_install() {
    [ -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}" ] && return 0
    [ -d "$OLD_CONFIG_DIR" ] && return 0
    [ -f "/etc/systemd/system/${OLD_SERVICE_NAME}.service" ] && return 0
    [ -f "/Library/LaunchDaemons/com.oxi-hole.server.plist" ] && return 0
    [ -f "/etc/init.d/${OLD_SERVICE_NAME}" ] && return 0
    [ -f "/usr/local/etc/rc.d/${OLD_SERVICE_NAME}" ] && return 0
    [ -f "/etc/rc.d/${OLD_SERVICE_NAME}" ] && return 0
    id oxi-hole >/dev/null 2>&1 && return 0
    return 1
}

cleanup_legacy() {
    if ! detect_legacy_install; then
        return 0
    fi

    log_step "Cleaning up legacy oxi-hole installation"

    # Stop and remove legacy service
    stop_and_remove_service "$OLD_SERVICE_NAME"

    # Remove binary and symlink
    rm -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}"
    rm -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}.bak"
    rmdir "$OLD_INSTALL_DIR" 2>/dev/null || true
    rm -f "/usr/local/bin/${OLD_BINARY_NAME}"

    # Prompt for config and logs
    ask_remove_dir "$OLD_CONFIG_DIR" "Legacy configuration"
    ask_remove_dir "$OLD_LOG_DIR" "Legacy log"

    # Remove legacy user
    remove_user "oxi-hole"

    log_info "Legacy oxi-hole installation cleaned up"
}

# ============================================================================
# Main uninstall
# ============================================================================

do_uninstall() {
    log_step "Uninstalling Oxi-DNS"

    detect_os
    detect_init_system

    # 1. Stop and remove oxi-dns service
    stop_and_remove_service "$SERVICE_NAME"
    log_info "Service removed"

    # 2. Restore DNS resolution
    restore_dns || log_warn "DNS restoration encountered errors. You may need to manually configure /etc/resolv.conf."

    # 3. Remove binary and symlink
    log_info "Removing binary..."
    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    rm -f "${INSTALL_DIR}/${BINARY_NAME}.bak"
    rm -f "/usr/local/bin/${BINARY_NAME}"

    # 4. Interactive config/logs prompt
    ask_remove_dir "$CONFIG_DIR" "Configuration"
    ask_remove_dir "$LOG_DIR" "Log"

    # 5. Remove system user
    remove_user "oxi-dns"

    # 6. Legacy oxi-hole cleanup
    cleanup_legacy

    # 7. Self-cleanup — remove this script, then install dir if empty
    SELF_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    rm -f "$SELF_PATH"
    rmdir "$INSTALL_DIR" 2>/dev/null || true

    log_step "Uninstallation complete!"
    log_info "Oxi-DNS has been removed from your system."
}

# ============================================================================
# Banner and entry point
# ============================================================================

printf "${BLUE}${BOLD}"
cat <<'BANNER'
   ____       _        ____  _   _ ____
  / __ \     (_)      |  _ \| \ | / ___|
 | |  | |_  ___       | | | |  \| \___ \
 | |  | \ \/ / |_____ | |_| | |\  |___) |
 | |__| |>  <| |      |____/|_| \_|____/
  \____//_/\_\_|       Uninstaller

BANNER
printf "${NC}"

check_root "$@"
do_uninstall
