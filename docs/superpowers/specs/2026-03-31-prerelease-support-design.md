# Pre-Release Support

**Date:** 2026-03-31
**Status:** Approved

## Problem

There is no mechanism to publish pre-release builds of oxi-dns. All releases are treated as stable. The install script's beta/edge channels don't meaningfully differ. The auto-updater only checks stable releases. Users have no way to opt into development builds.

## Solution

1. `version.txt` gains a second line controlling pre-release status
2. The release workflow reads this flag and tags GitHub releases accordingly (with the yellow "Pre-release" badge)
3. Release channels are simplified to `stable` and `development`
4. The install script, auto-updater, and dashboard all respect the chosen channel

## version.txt Format

```
0.3.5
--prerelease
```

- Line 1: version number
- Line 2: `--prerelease` → GitHub release is marked as pre-release; `#--prerelease` → normal stable release

Pre-release versions get a `-dev` suffix on the git tag (e.g., `v0.3.5-dev`) so GitHub's `/releases/latest` API continues to return only stable releases.

## Release Workflow Changes

**File:** `.github/workflows/release.yml`

After extracting the version from version.txt or git tag:
1. Read line 2 of `version.txt`
2. If line 2 is exactly `--prerelease` (not commented):
   - Set `prerelease: true` on the GitHub release creation step
   - Append `-dev` to the release tag (e.g., `v0.3.5-dev`)
3. If line 2 is `#--prerelease` or absent:
   - Create a normal (stable) release
   - Tag as `v0.3.5` (no suffix)

This ensures GitHub shows the yellow "Pre-release" badge on pre-release versions and `/releases/latest` only returns stable releases.

## Install Script Changes

**File:** `scripts/install.sh`

### Channel simplification

The `-c <channel>` flag accepts two channels:
- `stable` (default) — fetches `/releases/latest` (excludes pre-releases)
- `development` — fetches `/releases` (all releases, including pre-releases) and picks the newest

For backwards compatibility, `beta` and `edge` are treated as aliases for `development` with a printed note: `"Note: 'beta'/'edge' channels are now 'development'."`

### Channel persistence

The selected channel is written to `config.toml` as `system.release_channel = "stable"` or `system.release_channel = "development"`. This is done in `create_default_config()`.

### get_latest_version() update

```
if CHANNEL = "development":
    fetch /releases (all)
    pick first tag_name (newest, may be pre-release)
else:
    fetch /releases/latest (stable only)
```

Same logic as today but with clear two-channel semantics instead of the ambiguous three-channel system.

### All operations respect channel

Install (default), reinstall (`-r`), and update (`-U`) all use the selected channel when calling `get_latest_version()`.

## Auto-Updater Changes

**File:** `src/update.rs`

### Config field

New field in `SystemConfig` (`src/config.rs`):
```rust
pub release_channel: String,  // "stable" or "development", default "stable"
```

### fetch_latest_release() update

The function gains a `channel: &str` parameter:
- `"stable"`: fetch `https://api.github.com/repos/{owner}/{repo}/releases/latest` (current behavior)
- `"development"`: fetch `https://api.github.com/repos/{owner}/{repo}/releases` and pick the first (newest)

### Immediate check on channel switch

A new `tokio::sync::watch::Sender<bool>` channel (`update_check_signal`) is added to `AppState`. The auto-update background loop watches both its 8-hour timer and this signal. When the signal fires, it runs an immediate check.

When the dashboard API changes the release channel, it:
1. Updates the shared `release_channel` state
2. Saves config
3. Sends `true` on `update_check_signal`

### Shared state

`AppState` gets:
- `release_channel: Arc<RwLock<String>>` — current channel, read by update loop
- `update_check_signal: tokio::sync::watch::Sender<bool>` — triggers immediate check

## Dashboard UI

**File:** `src/web/dashboard.html`

### Location

New "Release Channel" setting row in System Settings, between the auto-update toggle and the IPv6 toggle.

### Layout

A dropdown select with two options:
- `Stable` — "Recommended. Only receives tested, stable releases."
- `Development` — triggers warning when selected

### Warning

When Development is selected, an amber warning box appears inline (same style as the `--reconfigure` banner):

```
⚠ Development channel is not recommended for production use.
You will receive untested pre-release builds that may contain bugs or breaking changes.
Only use this for development or testing purposes.
```

Warning stays visible while Development is selected. Switching back to Stable dismisses it.

### API endpoints

`GET /api/system/release-channel` — authenticated, requires `ManageSystem`. Returns:
```json
{"channel": "stable"}
```

`POST /api/system/release-channel` — authenticated, requires `ManageSystem`. Request:
```json
{"channel": "development"}
```

Updates shared state, saves config, triggers immediate update check. Returns updated channel.

## Scope

### Modified files
- `.github/workflows/release.yml` — pre-release flag reading + conditional release tagging
- `version.txt` — add second line (`#--prerelease` for current stable state)
- `scripts/install.sh` — simplify channels, store in config, update get_latest_version
- `src/config.rs` — add `release_channel` to `SystemConfig`
- `src/update.rs` — channel-aware fetch, immediate check signal
- `src/web/mod.rs` — add release channel GET/POST endpoints, add `update_check_signal` and `release_channel` to `AppState`
- `src/web/dashboard.html` — release channel dropdown with warning
- `src/main.rs` — create update-check signal, add to AppState, update background loop

### Not changed
- `scripts/uninstall.sh` — uninstall is channel-agnostic
- `src/auth/*` — endpoints behind existing auth
- `config.toml` — defaults to stable (no explicit entry needed)
