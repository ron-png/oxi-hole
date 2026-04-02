# Standalone Uninstall Script Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a self-contained uninstall script at `/opt/oxi-dns/uninstall.sh` that removes oxi-dns, restores DNS, and works without network access.

**Architecture:** A standalone shell script (`scripts/uninstall.sh`) committed to the repo and deployed to `/opt/oxi-dns/uninstall.sh` during installation. The install script (`scripts/install.sh`) gets a new function that copies this file into place. The uninstall script duplicates relevant logic from install.sh intentionally — it must work with zero external dependencies.

**Tech Stack:** POSIX shell (`#!/bin/sh`), same platform support as install.sh (Linux/macOS/FreeBSD/OpenBSD)

---

### Task 1: Create the standalone uninstall script

**Files:**
- Create: `scripts/uninstall.sh`

This is the core deliverable. The script follows the exact execution order from the design spec, modeled on the existing `do_uninstall()` and `restore_dns()` functions in `scripts/install.sh` (lines 732-842 and 1235-1280).

- [ ] **Step 1: Create `scripts/uninstall.sh` with the complete script**

```sh
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
    [ -f "${OLD_INSTALL_DIR}/${OLD_BINARY_NAME}" ] || \
    [ -d "$OLD_CONFIG_DIR" ] || \
    [ -f "/etc/systemd/system/${OLD_SERVICE_NAME}.service" ] || \
    [ -f "/Library/LaunchDaemons/com.oxi-hole.server.plist" ] || \
    [ -f "/etc/init.d/${OLD_SERVICE_NAME}" ] || \
    id oxi-hole >/dev/null 2>&1
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
    restore_dns

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
```

- [ ] **Step 2: Make the script executable**

Run: `chmod 755 scripts/uninstall.sh`

- [ ] **Step 3: Commit the new script**

```bash
git add scripts/uninstall.sh
git commit -m "feat: add standalone uninstall script for offline use"
```

---

### Task 2: Deploy the uninstall script during installation

**Files:**
- Modify: `scripts/install.sh:539-548` (inside `do_install()`, after binary install)
- Modify: `scripts/install.sh:710-714` (inside `do_update()`, after binary update)

The install script needs to copy `uninstall.sh` into the install directory. Since the install script is fetched from GitHub (not run from the repo checkout), we embed the uninstall script inline using a heredoc — the same pattern used for service files (lines 942-979, 986-1008, 1013-1031).

However, the uninstall script is large. A cleaner approach: during the build/release process the uninstall script is included in the release tarball alongside the binary. But since the current release archives only contain the binary, we'll use the simpler approach of writing it from within install.sh via a heredoc function.

- [ ] **Step 1: Add `deploy_uninstall_script()` function to `scripts/install.sh`**

Insert after the `create_default_config()` function (after line 900), before the service management section. This function writes the content of `scripts/uninstall.sh` as a heredoc into `/opt/oxi-dns/uninstall.sh`.

Add the following function at `scripts/install.sh` line 901 (between the `create_default_config` closing brace and the service management section header):

```sh
# ============================================================================
# Deploy standalone uninstall script
# ============================================================================

deploy_uninstall_script() {
    log_info "Installing standalone uninstall script..."
    cat > "${INSTALL_DIR}/uninstall.sh" <<'UNINSTALLEOF'
<full content of scripts/uninstall.sh goes here>
UNINSTALLEOF
    chmod 755 "${INSTALL_DIR}/uninstall.sh"
    chown root:root "${INSTALL_DIR}/uninstall.sh" 2>/dev/null || true
    log_info "Uninstall script installed: ${INSTALL_DIR}/uninstall.sh"
}
```

The heredoc content is the exact content of `scripts/uninstall.sh` (from Task 1), minus the shebang line (since the heredoc includes everything verbatim, keep the shebang).

- [ ] **Step 2: Call `deploy_uninstall_script()` in `do_install()`**

In `scripts/install.sh`, inside `do_install()`, insert the call after the symlink creation (after line 548) and before the config setup (line 550):

Find this block around line 547-550:
```sh
    ln -sf "${INSTALL_DIR}/${BINARY_NAME}" "/usr/local/bin/${BINARY_NAME}"
    log_info "Symlink created: /usr/local/bin/${BINARY_NAME}"

    # Create config directory and default config
```

Insert after the symlink log line:
```sh
    # Deploy standalone uninstall script
    deploy_uninstall_script

```

- [ ] **Step 3: Call `deploy_uninstall_script()` in `do_update()`**

In `scripts/install.sh`, inside `do_update()`, insert the call after the binary is updated (after line 714, the "Binary updated" log line):

Find this block around line 712-716:
```sh
    chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
    chown oxi-dns:oxi-dns "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true
    log_info "Binary updated"

    # Restart service
```

Insert after the "Binary updated" log line:
```sh
    # Update standalone uninstall script
    deploy_uninstall_script

```

- [ ] **Step 4: Update the install completion message to mention the uninstall script**

In `scripts/install.sh`, inside `do_install()`, find the completion output block around line 586-591:

```sh
    printf "  ${CYAN}Binary:${NC}    ${INSTALL_DIR}/${BINARY_NAME}\n"
    printf "  ${CYAN}Config:${NC}    ${CONFIG_DIR}/config.toml\n"
    printf "  ${CYAN}Logs:${NC}      ${LOG_DIR}/\n"
    printf "  ${CYAN}Service:${NC}   ${SERVICE_NAME}\n"
```

Add after the Service line:
```sh
    printf "  ${CYAN}Uninstall:${NC} ${INSTALL_DIR}/uninstall.sh\n"
```

- [ ] **Step 5: Commit the install script changes**

```bash
git add scripts/install.sh
git commit -m "feat: deploy standalone uninstall script during install and update"
```

---

### Task 3: Verify both scripts are syntactically valid

**Files:**
- Verify: `scripts/uninstall.sh`
- Verify: `scripts/install.sh`

- [ ] **Step 1: Syntax-check the uninstall script**

Run: `sh -n scripts/uninstall.sh`
Expected: No output (success, no syntax errors)

- [ ] **Step 2: Syntax-check the install script**

Run: `sh -n scripts/install.sh`
Expected: No output (success, no syntax errors)

- [ ] **Step 3: Verify the uninstall script is executable**

Run: `ls -la scripts/uninstall.sh`
Expected: `-rwxr-xr-x` permissions

- [ ] **Step 4: Verify the heredoc in install.sh matches the standalone script**

Run: Extract the heredoc content from install.sh (between `UNINSTALLEOF` markers) and diff it against `scripts/uninstall.sh`:

```bash
sed -n '/^cat > "\${INSTALL_DIR}\/uninstall.sh" <<'\''UNINSTALLEOF'\''$/,/^UNINSTALLEOF$/{ /UNINSTALLEOF/d; p; }' scripts/install.sh > /tmp/embedded-uninstall.sh && diff scripts/uninstall.sh /tmp/embedded-uninstall.sh && echo "MATCH" || echo "MISMATCH"
```

Expected: `MATCH`
