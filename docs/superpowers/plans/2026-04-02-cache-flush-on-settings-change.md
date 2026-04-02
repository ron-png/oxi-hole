# Cache Flush on Settings Change — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Flush the DNS cache whenever a filtering-related setting is changed, so stale cached responses don't bypass new rules.

**Architecture:** Add `state.upstream.cache_flush()` calls to each API endpoint in `src/web/mod.rs` that mutates filtering behavior. The method already exists and clears the DashMap + resets counters.

**Tech Stack:** Rust, Axum

---

### Task 1: Add cache flush to feature toggle endpoint

**Files:**
- Modify: `src/web/mod.rs:1412-1422`

- [ ] **Step 1: Add cache flush after feature toggle**

In `api_toggle_feature`, add the cache flush call between `set_feature` and `save_config`:

```rust
async fn api_toggle_feature(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<FeatureToggleRequest>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageFeatures)?;
    state.features.set_feature(&id, req.enabled).await;
    state.upstream.cache_flush();
    state.save_config().await;
    Ok(StatusCode::OK)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: flush DNS cache on feature toggle"
```

---

### Task 2: Add cache flush to blocking enable/disable endpoints

**Files:**
- Modify: `src/web/mod.rs:1269-1289`

- [ ] **Step 1: Add cache flush to api_enable_blocking**

Add `state.upstream.cache_flush();` between `set_enabled(true)` and `save_config`:

```rust
async fn api_enable_blocking(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageFeatures)?;
    state.blocklist.set_enabled(true).await;
    state.upstream.cache_flush();
    info!("Blocking enabled via web API");
    state.save_config().await;
    Ok(StatusCode::OK)
}
```

- [ ] **Step 2: Add cache flush to api_disable_blocking**

Add `state.upstream.cache_flush();` between `set_enabled(false)` and `save_config`:

```rust
async fn api_disable_blocking(
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
    State(state): State<AppState>,
) -> Result<StatusCode, Response> {
    require_permission(&user, Permission::ManageFeatures)?;
    state.blocklist.set_enabled(false).await;
    state.upstream.cache_flush();
    info!("Blocking disabled via web API");
    state.save_config().await;
    Ok(StatusCode::OK)
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 4: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: flush DNS cache on blocking enable/disable"
```

---

### Task 3: Add cache flush to blocking mode endpoint

**Files:**
- Modify: `src/web/mod.rs:1329-1361`

- [ ] **Step 1: Add cache flush after mode change**

Add `state.upstream.cache_flush();` between the blocking mode write and `save_config`:

```rust
    info!("Blocking mode set to {}", new_mode);
    *state.blocking_mode.write().await = new_mode;
    state.upstream.cache_flush();
    state.save_config().await;
    Ok(StatusCode::OK)
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 3: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: flush DNS cache on blocking mode change"
```

---

### Task 4: Add cache flush to custom blocked/allowlist endpoints

**Files:**
- Modify: `src/web/mod.rs:1443-1507`

- [ ] **Step 1: Add cache flush to api_add_blocked (line ~1460)**

Add `state.upstream.cache_flush();` between `add_custom_blocked` and `save_config`:

```rust
    state.blocklist.add_custom_blocked(&req.domain).await;
    state.upstream.cache_flush();
    info!("Added {} to blocklist via web API", req.domain);
    state.save_config().await;
    Ok(StatusCode::OK)
```

- [ ] **Step 2: Add cache flush to api_remove_blocked (line ~1472)**

Add `state.upstream.cache_flush();` between `remove_custom_blocked` and `save_config`:

```rust
    state.blocklist.remove_custom_blocked(&req.domain).await;
    state.upstream.cache_flush();
    info!("Removed {} from blocklist via web API", req.domain);
    state.save_config().await;
    Ok(StatusCode::OK)
```

- [ ] **Step 3: Add cache flush to api_add_allowlisted (line ~1493)**

Add `state.upstream.cache_flush();` between `add_allowlisted` and `save_config`:

```rust
    state.blocklist.add_allowlisted(&req.domain).await;
    state.upstream.cache_flush();
    info!("Added {} to allowlist via web API", req.domain);
    state.save_config().await;
    Ok(StatusCode::OK)
```

- [ ] **Step 4: Add cache flush to api_remove_allowlisted (line ~1505)**

Add `state.upstream.cache_flush();` between `remove_allowlisted` and `save_config`:

```rust
    state.blocklist.remove_allowlisted(&req.domain).await;
    state.upstream.cache_flush();
    info!("Removed {} from allowlist via web API", req.domain);
    state.save_config().await;
    Ok(StatusCode::OK)
```

- [ ] **Step 5: Verify it compiles**

Run: `cargo check 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 6: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: flush DNS cache on custom blocked/allowlist changes"
```

---

### Task 5: Add cache flush to blocklist source and IPv6 endpoints

**Files:**
- Modify: `src/web/mod.rs:1526-1576` (blocklist sources)
- Modify: `src/web/mod.rs:1715-1727` (IPv6)

- [ ] **Step 1: Add cache flush to api_add_blocklist_source (line ~1553)**

Add `state.upstream.cache_flush();` before `save_config` in the success branch:

```rust
        Ok(count) => {
            info!("Added blocklist source: {} ({} entries)", req.url, count);
            state.upstream.cache_flush();
            state.save_config().await;
            Ok(Json(BlocklistAddResponse {
                success: true,
                message: format!("Loaded {} domains", count),
            }))
        }
```

- [ ] **Step 2: Add cache flush to api_remove_blocklist_source (line ~1574)**

Add `state.upstream.cache_flush();` between `remove_blocklist_source` and `save_config`:

```rust
    state.blocklist.remove_blocklist_source(&req.url).await;
    state.upstream.cache_flush();
    info!("Removed blocklist source: {}", req.url);
    state.save_config().await;
    Ok(StatusCode::OK)
```

- [ ] **Step 3: Add cache flush to api_set_ipv6 (line ~1725)**

Add `state.upstream.cache_flush();` between the IPv6 store and `save_config`:

```rust
    state
        .ipv6_enabled
        .store(req.enabled, std::sync::atomic::Ordering::Relaxed);
    state.upstream.cache_flush();
    tracing::info!("IPv6 (AAAA) set to {}", req.enabled);
    state.save_config().await;
    Ok(StatusCode::OK)
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check 2>&1 | tail -5`
Expected: no errors

- [ ] **Step 5: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: flush DNS cache on blocklist source and IPv6 changes"
```

---

### Task 6: Final build verification

- [ ] **Step 1: Full build**

Run: `cargo build 2>&1 | tail -10`
Expected: compiles successfully

- [ ] **Step 2: Run existing tests**

Run: `cargo test 2>&1 | tail -20`
Expected: all existing tests pass

- [ ] **Step 3: Squash into single commit (optional)**

If preferred, squash the per-task commits into one:

```bash
git rebase -i HEAD~5
# squash all into: "feat: flush DNS cache when filtering settings change"
```
