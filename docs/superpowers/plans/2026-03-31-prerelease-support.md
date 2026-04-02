# Pre-Release Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add pre-release build support with version.txt flag, GitHub release tagging, channel-aware install/update, and dashboard channel selection.

**Architecture:** version.txt gains a second line controlling pre-release status. The release workflow reads it to tag releases. Channels simplify to `stable`/`development`. The auto-updater becomes channel-aware with an immediate-check signal. The dashboard adds a channel selector with a warning.

**Tech Stack:** GitHub Actions YAML, POSIX shell (install.sh), Rust (config, update, web), vanilla HTML/CSS/JS (dashboard)

---

### Task 1: Update version.txt and release workflow

**Files:**
- Modify: `version.txt`
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1: Add second line to version.txt**

Update `version.txt` to:
```
0.3.4.1
#--prerelease
```

The `#` means this is currently a stable version. Remove the `#` to mark a release as pre-release.

- [ ] **Step 2: Update the release workflow's version determination step**

In `.github/workflows/release.yml`, find the "Determine version" step (around line 36-55). Replace the `run:` block with:

```yaml
        run: |
          if [ "$REF_TYPE" = "tag" ]; then
            VERSION=$(echo "$REF_NAME" | sed 's/^v//' | sed 's/---.*//')
          else
            VERSION=$(head -n1 version.txt | tr -d '[:space:]')
          fi

          # Check pre-release flag (line 2 of version.txt)
          PRERELEASE_LINE=$(sed -n '2p' version.txt 2>/dev/null || echo "")
          if [ "$PRERELEASE_LINE" = "--prerelease" ]; then
            IS_PRERELEASE=true
            TAG="v${VERSION}-dev"
          else
            IS_PRERELEASE=false
            TAG="v${VERSION}"
          fi

          NUMS=$(echo "$VERSION" | grep -oE '^[0-9]+(\.[0-9]+)*')
          IFS='.' read -r MAJOR MINOR PATCH _REST <<< "$NUMS"
          CARGO_VERSION="${MAJOR:-0}.${MINOR:-0}.${PATCH:-0}"

          echo "version=$VERSION" >> "$GITHUB_OUTPUT"
          echo "cargo_version=$CARGO_VERSION" >> "$GITHUB_OUTPUT"
          echo "tag=$TAG" >> "$GITHUB_OUTPUT"
          echo "is_prerelease=$IS_PRERELEASE" >> "$GITHUB_OUTPUT"
          echo "Version: $VERSION (Cargo: $CARGO_VERSION, Tag: $TAG, Pre-release: $IS_PRERELEASE)"
```

Also add the new output to the job's `outputs:` section:
```yaml
      is_prerelease: ${{ steps.version.outputs.is_prerelease }}
```

- [ ] **Step 3: Update the GitHub Release creation step**

In the `release` job, find the "Create GitHub Release" step. Update it to use the pre-release flag:

```yaml
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ needs.prepare.outputs.tag }}
          name: ${{ needs.prepare.outputs.tag }}
          generate_release_notes: true
          prerelease: ${{ needs.prepare.outputs.is_prerelease == 'true' }}
          files: |
            artifacts/*.tar.gz
            artifacts/checksums.txt
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 4: Update container image tags for pre-releases**

In the `container` job, find the "Extract metadata" step. Update the tags to avoid overwriting `latest` for pre-releases:

```yaml
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=raw,value=${{ needs.prepare.outputs.version }}
            type=raw,value=latest,enable=${{ needs.prepare.outputs.is_prerelease != 'true' }}
```

- [ ] **Step 5: Commit**

```bash
git add version.txt .github/workflows/release.yml
git commit -m "feat: add pre-release support to version.txt and release workflow"
```

---

### Task 2: Add release_channel to config

**Files:**
- Modify: `src/config.rs`

- [ ] **Step 1: Add release_channel field to SystemConfig**

In `src/config.rs`, find the `SystemConfig` struct (around line 118). Add a new field:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    #[serde(default)]
    pub auto_update: bool,
    #[serde(default = "default_true")]
    pub ipv6_enabled: bool,
    #[serde(default = "default_release_channel")]
    pub release_channel: String,
}
```

Add the default function:

```rust
fn default_release_channel() -> String {
    "stable".to_string()
}
```

Update the `Default` impl:

```rust
impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            auto_update: false,
            ipv6_enabled: true,
            release_channel: default_release_channel(),
        }
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add src/config.rs
git commit -m "feat: add release_channel field to SystemConfig"
```

---

### Task 3: Make auto-updater channel-aware

**Files:**
- Modify: `src/update.rs`

- [ ] **Step 1: Update fetch_latest_release to accept a channel parameter**

In `src/update.rs`, find `async fn fetch_latest_release()` (around line 442). Change its signature and body:

```rust
async fn fetch_latest_release(channel: &str) -> anyhow::Result<GitHubRelease> {
    if channel == "development" {
        // Fetch all releases (including pre-releases), pick newest
        let url = format!(
            "https://api.github.com/repos/{}/{}/releases",
            REPO_OWNER, REPO_NAME
        );
        let client = reqwest::Client::new();
        let releases: Vec<GitHubRelease> = client
            .get(&url)
            .header("User-Agent", format!("oxi-dns/{}", VERSION))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        releases.into_iter().next().ok_or_else(|| anyhow::anyhow!("No releases found"))
    } else {
        // Stable: fetch latest (excludes pre-releases)
        let url = format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            REPO_OWNER, REPO_NAME
        );
        let client = reqwest::Client::new();
        let release: GitHubRelease = client
            .get(&url)
            .header("User-Agent", format!("oxi-dns/{}", VERSION))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(release)
    }
}
```

- [ ] **Step 2: Update the check() method to pass channel**

In the `UpdateChecker` impl, find the `check` method (around line 90). Update the call to `fetch_latest_release`:

Change:
```rust
        let info = match fetch_latest_release().await {
```
To:
```rust
        let info = match fetch_latest_release(channel).await {
```

Also update the method signature to accept a channel parameter:

```rust
    pub async fn check(&self, force: bool, channel: &str) -> VersionInfo {
```

- [ ] **Step 3: Update all call sites of check()**

Search for all calls to `update_checker.check(` in the codebase. There are calls in:
- `src/update.rs` in `download_update()` — change `self.check(true).await` to `self.check(true, "stable").await` (downloads always use current channel, but since download_update is called from the update loop which already checked, "stable" is safe as fallback)
- `src/main.rs` in the auto-update loop — change `update_checker.check(true).await` to `update_checker.check(true, "stable").await` (will be updated in Task 5 to use shared channel state)
- `src/web/mod.rs` wherever update checking is called — update to pass `"stable"` for now

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass (update tests use the check method)

- [ ] **Step 5: Commit**

```bash
git add src/update.rs src/main.rs src/web/mod.rs
git commit -m "feat: make auto-updater channel-aware with stable/development support"
```

---

### Task 4: Add release channel and update-check signal to AppState

**Files:**
- Modify: `src/web/mod.rs` (AppState)
- Modify: `src/main.rs` (channel creation, AppState construction, update loop)

- [ ] **Step 1: Add fields to AppState**

In `src/web/mod.rs`, add to the `AppState` struct (after `restart_signal`):

```rust
    pub release_channel: std::sync::Arc<tokio::sync::RwLock<String>>,
    pub update_check_signal: tokio::sync::watch::Sender<bool>,
```

- [ ] **Step 2: Create channels and add to AppState in main.rs**

In `src/main.rs`, find the `web_state` construction. Add before it:

```rust
    let release_channel = std::sync::Arc::new(tokio::sync::RwLock::new(
        config.system.release_channel.clone(),
    ));
    let (update_check_tx, mut update_check_rx) = tokio::sync::watch::channel(false);
```

Add to the `web::AppState` construction:

```rust
        release_channel: release_channel.clone(),
        update_check_signal: update_check_tx,
```

- [ ] **Step 3: Update the auto-update loop to use channel and check signal**

In `src/main.rs`, find the auto-update background task spawn block. Replace the loop body to watch both the timer and the signal:

```rust
    // Spawn background auto-update task
    {
        let auto_update_flag = web_state.auto_update.clone();
        let update_checker = web_state.update_checker.clone();
        let update_status = web_state.update_status.clone();
        let current_exe = std::env::current_exe().ok();
        let config_path_for_update = config_path.clone();
        let channel_lock = release_channel.clone();

        tokio::spawn(async move {
            loop {
                let channel = channel_lock.read().await.clone();
                let version_info = update_checker.check(true, &channel).await;

                if version_info.update_available {
                    if let Some(ref latest) = version_info.latest_version {
                        if *auto_update_flag.read().await {
                            let current_exe_path = match &current_exe {
                                Some(p) => p.clone(),
                                None => {
                                    tracing::warn!(
                                        "Auto-update: cannot determine current binary path"
                                    );
                                    tokio::time::sleep(crate::update::CHECK_INTERVAL).await;
                                    continue;
                                }
                            };

                            crate::update::perform_robust_update(
                                &update_checker,
                                &update_status,
                                &config_path_for_update,
                                &current_exe_path,
                            )
                            .await;
                        } else {
                            info!(
                                "Update available: v{} (current: v{}). Enable auto-update or visit {} to update manually.",
                                latest,
                                version_info.current_version,
                                version_info.release_url.as_deref().unwrap_or("GitHub"),
                            );
                        }
                    }
                }

                // Wait for either the check interval OR an immediate check signal
                tokio::select! {
                    _ = tokio::time::sleep(crate::update::CHECK_INTERVAL) => {}
                    _ = update_check_rx.changed() => {
                        info!("Immediate update check triggered by channel change");
                    }
                }
            }
        });
    }
```

- [ ] **Step 4: Update save_config to persist release_channel**

In `src/web/mod.rs`, find the `save_config` method in `AppState`. Add after the `config.log.anonymize_client_ip` line:

```rust
        config.system.release_channel = self.release_channel.read().await.clone();
```

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/web/mod.rs src/main.rs
git commit -m "feat: add release channel state and update-check signal to AppState"
```

---

### Task 5: Add release channel API endpoints

**Files:**
- Modify: `src/web/mod.rs` (add routes + handlers)

- [ ] **Step 1: Add routes**

In `src/web/mod.rs`, find the system settings routes. Add:

```rust
        // Release channel
        .route("/api/system/release-channel", get(api_get_release_channel).post(api_set_release_channel))
```

- [ ] **Step 2: Add the GET handler**

```rust
async fn api_get_release_channel(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let channel = state.release_channel.read().await.clone();
    Json(serde_json::json!({"channel": channel})).into_response()
}
```

- [ ] **Step 3: Add the POST handler**

```rust
#[derive(Deserialize)]
struct SetReleaseChannelRequest {
    channel: String,
}

async fn api_set_release_channel(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    Json(req): Json<SetReleaseChannelRequest>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let channel = match req.channel.as_str() {
        "stable" | "development" => req.channel.clone(),
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid channel. Must be 'stable' or 'development'."}))).into_response();
        }
    };

    *state.release_channel.write().await = channel.clone();
    state.save_config().await;

    // Trigger immediate update check
    let _ = state.update_check_signal.send(true);

    Json(serde_json::json!({"channel": channel})).into_response()
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: add release channel GET/POST API endpoints"
```

---

### Task 6: Update install script channels

**Files:**
- Modify: `scripts/install.sh`

- [ ] **Step 1: Update channel validation after getopts**

Find the channel validation section (after the getopts loop, around line 120). The current code just validates mutual exclusivity. Add channel aliasing after it:

```sh
# Normalize channel names
case "$CHANNEL" in
    stable) ;;
    development) ;;
    beta|edge)
        log_info "Note: '$CHANNEL' channel is now 'development'."
        CHANNEL="development"
        ;;
    *)
        log_error "Unknown channel: $CHANNEL. Valid channels: stable, development"
        exit 1
        ;;
esac
```

- [ ] **Step 2: Update get_latest_version()**

Replace the `get_latest_version()` function (around line 262-287) with:

```sh
get_latest_version() {
    log_verbose "Fetching latest release version (channel: ${CHANNEL})..."

    if [ "$CHANNEL" = "development" ]; then
        RELEASE_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases"
        VERSION=$(download_to_stdout "$RELEASE_URL" | grep '"tag_name"' | head -n 1 | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    else
        RELEASE_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"
        VERSION=$(download_to_stdout "$RELEASE_URL" | grep '"tag_name"' | sed -E 's/.*"tag_name":\s*"([^"]+)".*/\1/')
    fi

    # Fallback to pre-releases if no stable release exists
    if [ -z "$VERSION" ]; then
        log_warn "No release found for channel '${CHANNEL}'. Falling back to newest available..."
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
```

- [ ] **Step 3: Add release_channel to create_default_config()**

In `create_default_config()`, add a `[system]` section to the generated config. Update the heredoc:

```sh
create_default_config() {
    if [ -n "$TMPDIR" ] && [ -s "${TMPDIR}/config.toml" ]; then
        cp "${TMPDIR}/config.toml" "${CONFIG_DIR}/config.toml"
        log_verbose "Using pre-downloaded config"
    else
        cat > "${CONFIG_DIR}/config.toml" <<CONFIGEOF
# Oxi-DNS Configuration
# Configure additional settings via the web dashboard.

[dns]
listen = "${DNS_LISTEN:-0.0.0.0:53}"
upstreams = [
    "tls://9.9.9.10:853",
    "tls://149.112.112.10:853",
]

[web]
listen = "0.0.0.0:${WEB_PORT:-9853}"

[system]
release_channel = "${CHANNEL:-stable}"
CONFIGEOF
    fi
}
```

- [ ] **Step 4: Syntax-check**

Run: `sh -n scripts/install.sh`
Expected: No output (success)

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat: simplify install script channels to stable/development with persistence"
```

---

### Task 7: Add release channel dropdown to dashboard

**Files:**
- Modify: `src/web/dashboard.html`

- [ ] **Step 1: Add CSS for the channel warning**

Find the existing amber warning/banner CSS. Add:

```css
        .channel-warning {
            margin-top: 10px; padding: 10px 14px;
            background: rgba(234, 179, 8, 0.06); border: 1px solid rgba(234, 179, 8, 0.2);
            border-radius: 8px; font-size: 12px; color: #eab308; line-height: 1.5; display: none;
        }
        .channel-warning.visible { display: block; }
        .channel-select {
            background: var(--bg-page); border: 1px solid var(--border); border-radius: 6px;
            padding: 7px 10px; font-size: 13px; color: var(--text-primary); outline: none;
            font-family: var(--font-sans);
        }
        .channel-select:focus { border-color: var(--accent); }
```

- [ ] **Step 2: Add HTML between auto-update and IPv6 setting rows**

Find the auto-update setting row's closing `</div>` and the IPv6 setting row. Insert between them:

```html
                <div class="setting-row manage-system-only">
                    <div class="setting-info">
                        <h3>Release Channel</h3>
                        <p>Choose which release channel to receive updates from.</p>
                        <div class="channel-warning" id="channelWarning">
                            &#9888; Development channel is not recommended for production use.
                            You will receive untested pre-release builds that may contain bugs or breaking changes.
                            Only use this for development or testing purposes.
                        </div>
                    </div>
                    <select class="channel-select" id="releaseChannelSelect" onchange="setReleaseChannel(this.value)">
                        <option value="stable">Stable</option>
                        <option value="development">Development</option>
                    </select>
                </div>
```

- [ ] **Step 3: Add JavaScript**

Find the `// ---- System Settings ----` section. Add BEFORE the `refreshSystemSettings` function:

```javascript
        // ---- Release Channel ----
        async function refreshReleaseChannel() {
            try {
                const res = await fetch('/api/system/release-channel');
                if (!res.ok) return;
                const data = await res.json();
                document.getElementById('releaseChannelSelect').value = data.channel;
                document.getElementById('channelWarning').classList.toggle('visible', data.channel === 'development');
            } catch (_) {}
        }

        async function setReleaseChannel(channel) {
            document.getElementById('channelWarning').classList.toggle('visible', channel === 'development');
            try {
                await fetch('/api/system/release-channel', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ channel }),
                });
            } catch (_) {}
        }
```

- [ ] **Step 4: Add init call**

Find where `refreshSystemSettings()` is called on page load. Add after it:

```javascript
                refreshReleaseChannel();
```

- [ ] **Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat: add release channel dropdown with development warning to dashboard"
```

---

### Task 8: Final verification

- [ ] **Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 2: Verify build**

Run: `cargo build`
Expected: Successful

- [ ] **Step 3: Syntax-check install script**

Run: `sh -n scripts/install.sh`
Expected: No errors

- [ ] **Step 4: Verify version.txt has two lines**

Run: `cat -A version.txt`
Expected: Shows two lines, second line is `#--prerelease$`

- [ ] **Step 5: Verify release workflow has prerelease flag**

Run: `grep 'prerelease' .github/workflows/release.yml`
Expected: Shows `is_prerelease` output and `prerelease:` in the release step

- [ ] **Step 6: Verify API routes**

Run: `grep 'release-channel' src/web/mod.rs`
Expected: Shows the route registration

- [ ] **Step 7: Verify config field**

Run: `grep 'release_channel' src/config.rs`
Expected: Shows the field in SystemConfig
