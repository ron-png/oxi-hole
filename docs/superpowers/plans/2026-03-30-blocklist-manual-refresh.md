# Manual Blocklist Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Refresh Now" button with SSE-streamed per-source progress and a live "last refreshed" timer to the blocklist sources section of the dashboard.

**Architecture:** Add `last_refreshed_at` and `refreshing` fields to `BlocklistManager`, a new `refresh_sources_streaming()` method that yields per-source progress, two new API endpoints (SSE refresh + last-refresh timestamp), and frontend UI with EventSource consumption and a live-ticking timer.

**Tech Stack:** Rust (Axum SSE via `axum::response::sse`), `tokio::sync::mpsc` for streaming progress, `chrono` for timestamps, vanilla JavaScript `EventSource` API.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/blocklist.rs` | Modify | Add `last_refreshed_at`, `refreshing` fields, `refresh_sources_streaming()` method, getters |
| `src/web/mod.rs` | Modify | Add two new endpoints + route registrations, SSE handler |
| `src/web/dashboard.html` | Modify | Add refresh button, last-refreshed timer, per-source status indicators, CSS, JS |
| `src/main.rs` | Modify | Update background refresh task to set `last_refreshed_at` and respect concurrency guard |

---

### Task 1: Add `last_refreshed_at` and `refreshing` fields to BlocklistManager

**Files:**
- Modify: `src/blocklist.rs:19-44` (struct definition + `new()`)

- [ ] **Step 1: Add new fields to `BlocklistManager` struct**

In `src/blocklist.rs`, add two new fields to the struct (after `sources`):

```rust
pub struct BlocklistManager {
    // ... existing fields ...
    /// Blocklist source URLs/paths
    sources: Arc<RwLock<Vec<String>>>,
    /// Timestamp of the last completed refresh (manual or auto)
    last_refreshed_at: Arc<RwLock<Option<chrono::DateTime<chrono::Utc>>>>,
    /// Whether a refresh is currently in progress (concurrency guard)
    refreshing: Arc<std::sync::atomic::AtomicBool>,
}
```

Add `use chrono` import at top of file:

```rust
use chrono::Utc;
```

- [ ] **Step 2: Initialize new fields in `new()`**

Update the `new()` method to initialize the new fields:

```rust
pub fn new(enabled: bool) -> Self {
    Self {
        blocked: Arc::new(RwLock::new(HashSet::new())),
        source_domains: Arc::new(RwLock::new(HashMap::new())),
        custom_blocked: Arc::new(RwLock::new(HashSet::new())),
        allowlist: Arc::new(RwLock::new(HashSet::new())),
        enabled: Arc::new(RwLock::new(enabled)),
        sources: Arc::new(RwLock::new(Vec::new())),
        last_refreshed_at: Arc::new(RwLock::new(None)),
        refreshing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}
```

- [ ] **Step 3: Add getter methods**

Add these public methods to the `impl BlocklistManager` block (after `get_allowlist()`):

```rust
/// Get the timestamp of the last completed refresh.
pub async fn get_last_refreshed_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
    *self.last_refreshed_at.read().await
}

/// Check if a refresh is currently running.
pub fn is_refreshing(&self) -> bool {
    self.refreshing.load(std::sync::atomic::Ordering::SeqCst)
}

/// Try to acquire the refresh lock. Returns false if already refreshing.
pub fn try_start_refresh(&self) -> bool {
    self.refreshing.compare_exchange(
        false,
        true,
        std::sync::atomic::Ordering::SeqCst,
        std::sync::atomic::Ordering::SeqCst,
    ).is_ok()
}

/// Release the refresh lock and set the last_refreshed_at timestamp.
pub async fn finish_refresh(&self) {
    *self.last_refreshed_at.write().await = Some(Utc::now());
    self.refreshing.store(false, std::sync::atomic::Ordering::SeqCst);
}
```

- [ ] **Step 4: Update existing `refresh_sources()` to set timestamp and use concurrency guard**

Modify the existing `refresh_sources()` method to acquire/release the refresh lock and set the timestamp:

```rust
pub async fn refresh_sources(&self) {
    let sources = self.sources.read().await.clone();
    if sources.is_empty() {
        return;
    }

    // Skip if another refresh is already running
    if !self.try_start_refresh() {
        info!("Blocklist refresh skipped — another refresh is in progress");
        return;
    }

    info!("Refreshing {} blocklist sources...", sources.len());

    let mut new_src_map = HashMap::new();
    let mut all_domains = HashSet::new();

    for source in &sources {
        match self.fetch_blocklist(source).await {
            Ok(entries) => {
                info!("Refreshed {} entries from {}", entries.len(), source);
                let set: HashSet<String> = entries.into_iter().collect();
                all_domains.extend(set.clone());
                new_src_map.insert(source.clone(), set);
            }
            Err(e) => {
                warn!("Failed to refresh blocklist {}: {}", source, e);
                let existing = self.source_domains.read().await;
                if let Some(existing_set) = existing.get(source) {
                    all_domains.extend(existing_set.clone());
                    new_src_map.insert(source.clone(), existing_set.clone());
                }
            }
        }
    }

    let custom = self.custom_blocked.read().await;
    all_domains.extend(custom.clone());

    let total = all_domains.len();
    *self.source_domains.write().await = new_src_map;
    *self.blocked.write().await = all_domains;

    self.finish_refresh().await;

    info!(
        "Blocklist refresh complete: {} total blocked domains",
        total
    );
}
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check 2>&1 | tail -5`
Expected: no errors (warnings OK)

- [ ] **Step 6: Run existing tests**

Run: `cargo test --lib blocklist 2>&1 | tail -10`
Expected: All existing tests pass

- [ ] **Step 7: Commit**

```bash
git add src/blocklist.rs
git commit -m "feat(blocklist): add last_refreshed_at timestamp and refresh concurrency guard"
```

---

### Task 2: Add `refresh_sources_streaming()` method to BlocklistManager

**Files:**
- Modify: `src/blocklist.rs` (add new method after `refresh_sources()`)

- [ ] **Step 1: Define the progress event struct**

Add this struct above the `impl BlocklistManager` block (after the `BlocklistManager` struct definition, around line 33):

```rust
/// Progress event emitted during a streaming blocklist refresh.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum RefreshEvent {
    #[serde(rename = "progress")]
    Progress {
        source: String,
        index: usize,
        total: usize,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        domains: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    #[serde(rename = "done")]
    Done {
        total_domains: usize,
        sources_ok: usize,
        sources_failed: usize,
        refreshed_at: String,
    },
}
```

Add `use serde::Serialize;` to the imports at the top of the file (serde is already a dependency).

- [ ] **Step 2: Implement `refresh_sources_streaming()`**

Add this method to the `impl BlocklistManager` block, after `refresh_sources()`:

```rust
/// Re-fetch all blocklist sources, sending progress events through the channel.
/// Returns false if a refresh is already in progress.
pub async fn refresh_sources_streaming(
    &self,
    tx: tokio::sync::mpsc::Sender<RefreshEvent>,
) -> bool {
    let sources = self.sources.read().await.clone();

    if !self.try_start_refresh() {
        return false;
    }

    let total = sources.len();
    let mut new_src_map = HashMap::new();
    let mut all_domains = HashSet::new();
    let mut sources_ok: usize = 0;
    let mut sources_failed: usize = 0;

    for (i, source) in sources.iter().enumerate() {
        match self.fetch_blocklist(source).await {
            Ok(entries) => {
                let count = entries.len();
                info!("Refreshed {} entries from {}", count, source);
                let set: HashSet<String> = entries.into_iter().collect();
                all_domains.extend(set.clone());
                new_src_map.insert(source.clone(), set);
                sources_ok += 1;
                let _ = tx.send(RefreshEvent::Progress {
                    source: source.clone(),
                    index: i + 1,
                    total,
                    status: "ok".to_string(),
                    domains: Some(count),
                    error: None,
                }).await;
            }
            Err(e) => {
                warn!("Failed to refresh blocklist {}: {}", source, e);
                let existing = self.source_domains.read().await;
                if let Some(existing_set) = existing.get(source) {
                    all_domains.extend(existing_set.clone());
                    new_src_map.insert(source.clone(), existing_set.clone());
                }
                sources_failed += 1;
                let _ = tx.send(RefreshEvent::Progress {
                    source: source.clone(),
                    index: i + 1,
                    total,
                    status: "error".to_string(),
                    domains: None,
                    error: Some(e.to_string()),
                }).await;
            }
        }
    }

    let custom = self.custom_blocked.read().await;
    all_domains.extend(custom.clone());

    let total_domains = all_domains.len();
    *self.source_domains.write().await = new_src_map;
    *self.blocked.write().await = all_domains;

    self.finish_refresh().await;

    let refreshed_at = Utc::now().to_rfc3339();
    let _ = tx.send(RefreshEvent::Done {
        total_domains,
        sources_ok,
        sources_failed,
        refreshed_at,
    }).await;

    info!("Blocklist refresh complete: {} total blocked domains", total_domains);
    true
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 4: Run tests**

Run: `cargo test --lib blocklist 2>&1 | tail -10`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/blocklist.rs
git commit -m "feat(blocklist): add streaming refresh method with per-source progress events"
```

---

### Task 3: Add SSE refresh endpoint and last-refresh endpoint

**Files:**
- Modify: `src/web/mod.rs` (add two handlers + register routes)

- [ ] **Step 1: Add imports for SSE**

Add these imports at the top of `src/web/mod.rs`:

```rust
use axum::response::sse::{Event, Sse};
use futures::stream::Stream;
use std::convert::Infallible;
```

- [ ] **Step 2: Add the last-refresh endpoint handler**

Add this after the `api_remove_blocklist_source` handler (around line 461):

```rust
// ==================== Blocklist Refresh ====================

#[derive(Serialize)]
struct LastRefreshResponse {
    refreshed_at: Option<String>,
}

async fn api_blocklist_last_refresh(
    State(state): State<AppState>,
) -> Json<LastRefreshResponse> {
    let ts = state.blocklist.get_last_refreshed_at().await;
    Json(LastRefreshResponse {
        refreshed_at: ts.map(|t| t.to_rfc3339()),
    })
}
```

- [ ] **Step 3: Add the SSE refresh endpoint handler**

Add this right after the `api_blocklist_last_refresh` handler:

```rust
async fn api_blocklist_refresh_sse(
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    if state.blocklist.is_refreshing() {
        return Err(StatusCode::CONFLICT);
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<crate::blocklist::RefreshEvent>(32);
    let blocklist = state.blocklist.clone();

    tokio::spawn(async move {
        blocklist.refresh_sources_streaming(tx).await;
    });

    let stream = async_stream::stream! {
        while let Some(event) = rx.recv().await {
            let event_type = match &event {
                crate::blocklist::RefreshEvent::Progress { .. } => "progress",
                crate::blocklist::RefreshEvent::Done { .. } => "done",
            };
            let data = serde_json::to_string(&event).unwrap_or_default();
            yield Ok(Event::default().event(event_type).data(data));
        }
    };

    Ok(Sse::new(stream))
}
```

- [ ] **Step 4: Add `async-stream` dependency**

The `async_stream::stream!` macro is the simplest way to create the SSE stream. Add it to `Cargo.toml`:

Run:
```bash
cargo add async-stream
```

- [ ] **Step 5: Register the new routes**

In `src/web/mod.rs`, in the `run_web_server` function, add these routes after the existing blocklist source routes (after the `.route("/api/blocklist-source/remove", ...)` line around line 103):

```rust
        // Blocklist refresh
        .route(
            "/api/blocklist-sources/refresh",
            get(api_blocklist_refresh_sse),
        )
        .route(
            "/api/blocklist-sources/last-refresh",
            get(api_blocklist_last_refresh),
        )
```

- [ ] **Step 6: Verify it compiles**

Run: `cargo check 2>&1 | tail -10`
Expected: no errors

- [ ] **Step 7: Commit**

```bash
git add src/web/mod.rs Cargo.toml Cargo.lock
git commit -m "feat(web): add SSE blocklist refresh and last-refresh API endpoints"
```

---

### Task 4: Update background refresh task in main.rs

**Files:**
- Modify: `src/main.rs:285-301` (background refresh task)

- [ ] **Step 1: Update the background refresh task**

The existing `refresh_sources()` method now handles the concurrency guard and timestamp internally (from Task 1 changes). No changes needed to `main.rs` — the background task calls `bm.refresh_sources().await` which already uses `try_start_refresh()` / `finish_refresh()`.

Verify by re-reading the background task code — it just calls `bm.refresh_sources().await` on line 298, which now includes the guard and timestamp update.

- [ ] **Step 2: Verify full build**

Run: `cargo build 2>&1 | tail -10`
Expected: Build succeeds

- [ ] **Step 3: Commit (if any changes were needed)**

If no changes to main.rs were needed, skip this commit.

---

### Task 5: Add frontend UI — CSS, HTML, and JavaScript

**Files:**
- Modify: `src/web/dashboard.html` (CSS + HTML structure + JavaScript)

- [ ] **Step 1: Add CSS for the refresh row and status indicators**

In `src/web/dashboard.html`, add these styles after the `.interval-hint` rule (after line 689, before the `/* ---- Blocking Mode ---- */` comment):

```css
        /* ---- Refresh row ---- */
        .refresh-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border-light);
        }

        .refresh-row .last-refreshed {
            font-size: 13px;
            color: var(--text-muted);
            font-family: var(--font-mono);
        }

        .btn-refresh {
            padding: 5px 14px;
            font-size: 12px;
            font-family: var(--font-mono);
            background: transparent;
            border: 1px solid var(--color-accent);
            color: var(--color-accent);
            border-radius: 999px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-refresh:hover {
            background: rgba(138, 100, 229, 0.1);
        }

        .btn-refresh:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .source-status {
            font-size: 11px;
            font-family: var(--font-mono);
            margin-left: auto;
            margin-right: 8px;
            white-space: nowrap;
        }

        .source-status.ok {
            color: var(--color-green);
        }

        .source-status.error {
            color: var(--color-red);
        }

        .source-status.loading {
            color: var(--text-muted);
        }
```

- [ ] **Step 2: Add the refresh row HTML**

In the Blocklist Sources section of the HTML, add a refresh row between the `<ul id="activeBlocklists">` and the `<div class="interval-row">`. Find lines 1147-1150 and insert after the `</ul>` (line 1149):

```html
                <div class="refresh-row">
                    <span class="last-refreshed" id="lastRefreshedText">Last refreshed: never</span>
                    <button class="btn-refresh" id="refreshNowBtn" onclick="triggerRefresh()">&#8635; Refresh Now</button>
                </div>
```

The HTML should look like:

```html
                <ul class="upstream-list" id="activeBlocklists">
                    <li>Loading...</li>
                </ul>
                <div class="refresh-row">
                    <span class="last-refreshed" id="lastRefreshedText">Last refreshed: never</span>
                    <button class="btn-refresh" id="refreshNowBtn" onclick="triggerRefresh()">&#8635; Refresh Now</button>
                </div>
                <div class="interval-row">
```

- [ ] **Step 3: Add JavaScript for the live timer**

In the `<script>` section, add these functions after the `setBlocklistInterval()` function (after line 1546):

```javascript
        // ---- Blocklist Refresh ----
        let lastRefreshedTime = null;
        let refreshTimerInterval = null;

        function formatElapsed(ms) {
            const totalSec = Math.floor(ms / 1000);
            const h = String(Math.floor(totalSec / 3600)).padStart(2, '0');
            const m = String(Math.floor((totalSec % 3600) / 60)).padStart(2, '0');
            const s = String(totalSec % 60).padStart(2, '0');
            return h + ':' + m + ':' + s;
        }

        function updateRefreshTimer() {
            const el = document.getElementById('lastRefreshedText');
            if (!lastRefreshedTime) {
                el.textContent = 'Last refreshed: never';
                return;
            }
            const elapsed = Date.now() - lastRefreshedTime.getTime();
            el.textContent = 'Last refreshed: ' + formatElapsed(elapsed) + ' ago';
        }

        function startRefreshTimer() {
            if (refreshTimerInterval) clearInterval(refreshTimerInterval);
            updateRefreshTimer();
            refreshTimerInterval = setInterval(updateRefreshTimer, 1000);
        }

        async function loadLastRefreshed() {
            try {
                const res = await fetch('/api/blocklist-sources/last-refresh');
                const data = await res.json();
                if (data.refreshed_at) {
                    lastRefreshedTime = new Date(data.refreshed_at);
                }
            } catch (e) { console.error(e); }
            startRefreshTimer();
        }
```

- [ ] **Step 4: Add JavaScript for the SSE refresh trigger**

Add this function right after `loadLastRefreshed()`:

```javascript
        function triggerRefresh() {
            const btn = document.getElementById('refreshNowBtn');
            btn.disabled = true;
            btn.textContent = 'Refreshing...';

            // Clear previous status indicators
            document.querySelectorAll('.source-status').forEach(el => el.remove());

            const evtSource = new EventSource('/api/blocklist-sources/refresh');

            evtSource.addEventListener('progress', function(e) {
                const data = JSON.parse(e.data);
                // Find the matching source row in the list
                const listItems = document.querySelectorAll('#activeBlocklists li');
                listItems.forEach(li => {
                    const label = li.querySelector('.upstream-label');
                    if (label && label.textContent === data.source) {
                        // Remove any existing status
                        const existing = li.querySelector('.source-status');
                        if (existing) existing.remove();

                        const status = document.createElement('span');
                        status.className = 'source-status';
                        if (data.status === 'ok') {
                            status.classList.add('ok');
                            status.textContent = '\u2713 ' + data.domains.toLocaleString();
                        } else {
                            status.classList.add('error');
                            status.textContent = '\u2717 failed';
                        }
                        // Insert before the remove button
                        const removeBtn = li.querySelector('.btn-remove');
                        li.insertBefore(status, removeBtn);
                    }
                });
            });

            evtSource.addEventListener('done', function(e) {
                const data = JSON.parse(e.data);
                evtSource.close();
                btn.disabled = false;
                btn.textContent = '\u21BB Refresh Now';
                lastRefreshedTime = new Date(data.refreshed_at);
                updateRefreshTimer();
                refreshStats();
            });

            evtSource.onerror = function() {
                evtSource.close();
                btn.disabled = false;
                btn.textContent = '\u21BB Refresh Now';
            };
        }
```

- [ ] **Step 5: Call `loadLastRefreshed()` on page load**

Find the initialization section where other refresh functions are called on page load. Search for `refreshBlocklistSources()` in the init/DOMContentLoaded section. Add `loadLastRefreshed()` right after it.

Look for the block that calls multiple `refresh*()` functions (likely near the end of the script). Add:

```javascript
        loadLastRefreshed();
```

- [ ] **Step 6: Verify it compiles (HTML is embedded at compile time)**

Run: `cargo build 2>&1 | tail -5`
Expected: Build succeeds

- [ ] **Step 7: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat(dashboard): add refresh button, per-source progress, and live last-refreshed timer"
```

---

### Task 6: Manual testing and final verification

**Files:**
- No file changes — testing only

- [ ] **Step 1: Build the release binary**

Run: `cargo build 2>&1 | tail -5`
Expected: Build succeeds with no errors

- [ ] **Step 2: Run all tests**

Run: `cargo test 2>&1 | tail -15`
Expected: All tests pass

- [ ] **Step 3: Verify endpoints exist by checking route registration**

Search `src/web/mod.rs` for both new routes:

```bash
grep -n "blocklist-sources/refresh\|blocklist-sources/last-refresh" src/web/mod.rs
```

Expected: Both routes appear in the router

- [ ] **Step 4: Verify frontend references correct endpoints**

```bash
grep -n "blocklist-sources/refresh\|blocklist-sources/last-refresh" src/web/dashboard.html
```

Expected: Both endpoints referenced in JavaScript

- [ ] **Step 5: Commit (if any fixes needed)**

If fixes were required, commit them:

```bash
git add -A
git commit -m "fix: address issues found during manual verification"
```
