# Standalone Uninstall Script

**Date:** 2026-03-31
**Status:** Approved

## Problem

The existing uninstall functionality lives inside `scripts/install.sh` (invoked via `-u` flag), which must be fetched from GitHub. If the network is down or the repository is unreachable, users have no way to cleanly uninstall oxi-dns and restore their system's original DNS resolution.

## Solution

A self-contained `uninstall.sh` script placed at `/opt/oxi-dns/uninstall.sh` during installation. It requires no network access, no external dependencies, and no other files to function.

## Scope

- New file: `/opt/oxi-dns/uninstall.sh` (standalone script)
- Modified file: `scripts/install.sh` (deploy the uninstall script during install)

## Uninstall Script Behavior

### Execution Order

1. **Root check** — elevate via `sudo` if not already root
2. **Detect init system** — systemd, launchd, OpenRC, or SysV
3. **Stop and remove oxi-dns service** — stop service, disable autostart, delete unit file
4. **Restore DNS resolution:**
   - Remove `/etc/systemd/resolved.conf.d/oxi-dns.conf` if present
   - Remove `/etc/systemd/resolved.conf.d/oxi-hole.conf` if present (legacy)
   - Restart `systemd-resolved` if available
   - Restore `/etc/resolv.conf` symlink to `/run/systemd/resolve/stub-resolv.conf`
   - If systemd-resolved is not available: write `/etc/resolv.conf` with fallback nameservers `1.1.1.1` and `9.9.9.9`
   - Preserve existing `search` domains from current `/etc/resolv.conf`
5. **Remove binary and symlink** — `/opt/oxi-dns/oxi-dns`, `/opt/oxi-dns/oxi-dns.bak`, `/usr/local/bin/oxi-dns`
6. **Interactive config/logs prompt:**
   - Ask whether to remove `/etc/oxi-dns/` (default: preserve)
   - Ask whether to remove `/var/log/oxi-dns/` (default: preserve)
7. **Remove system user** — delete `oxi-dns` user via platform-appropriate command
8. **Legacy oxi-hole cleanup:**
   - Detect oxi-hole artifacts (binary, service, config, user, resolved drop-in)
   - Stop and remove oxi-hole service if running
   - Remove `/opt/oxi-hole/`, `/usr/local/bin/oxi-hole`
   - Prompt for `/etc/oxi-hole/` and `/var/log/oxi-hole/` removal
   - Remove `oxi-hole` system user
9. **Self-cleanup** — remove the uninstall script itself, then remove `/opt/oxi-dns/` if empty

### Platform Support

| Platform | Init System | Service File Location |
|----------|-------------|----------------------|
| Linux | systemd | `/etc/systemd/system/oxi-dns.service` |
| Linux | OpenRC | `/etc/init.d/oxi-dns` |
| Linux | SysV | `/etc/init.d/oxi-dns` |
| macOS | launchd | `/Library/LaunchDaemons/com.oxi-dns.server.plist` |
| FreeBSD | rc.d | `/usr/local/etc/rc.d/oxi-dns` |
| OpenBSD | rc.d | `/etc/rc.d/oxi-dns` |

### DNS Restoration Logic

```
if /etc/systemd/resolved.conf.d/oxi-dns.conf exists:
    remove it
    also remove oxi-hole.conf if present
    restart systemd-resolved
    if /run/systemd/resolve/stub-resolv.conf exists:
        symlink /etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf
    else:
        write fallback resolv.conf
else:
    preserve existing search domains from /etc/resolv.conf
    write /etc/resolv.conf with 1.1.1.1 and 9.9.9.9 + preserved search domains
```

## Install Script Changes

Add a function in `scripts/install.sh` that writes the uninstall script to `/opt/oxi-dns/uninstall.sh` with:
- Permissions: `755`
- Ownership: `root:root`

This function is called after the binary is installed and the service is configured, as a final installation step.

## Design Decisions

- **Self-contained over DRY:** The uninstall script duplicates some logic from `install.sh`. This is intentional — an emergency recovery tool must not depend on external files.
- **Interactive by default:** Matches existing `-u` flag behavior. Config and logs are preserved unless the user explicitly opts to remove them.
- **Fallback DNS:** Uses `1.1.1.1` (Cloudflare) and `9.9.9.9` (Quad9) as fallback nameservers when systemd-resolved cannot be restored. This ensures the system has working DNS after uninstall regardless of prior state.
- **Legacy cleanup included:** Users who migrated from oxi-hole may still have leftover artifacts. The uninstall script handles both old and new installations.
