# Cross-Platform Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure oxi-hole compiles and runs correctly on Linux, macOS, and FreeBSD, with compile-time guards and CI coverage to prevent regressions.

**Architecture:** Three independent changes — fix two hardcoded temp paths, add a compile-time guard for non-Unix platforms, and add a macOS CI job.

**Tech Stack:** Rust std library (`std::env::temp_dir`), GitHub Actions

---

### Task 1: Replace hardcoded `/tmp/` paths with `std::env::temp_dir()`

**Files:**
- Modify: `src/update.rs:154`
- Modify: `src/update.rs:332`

- [ ] **Step 1: Fix the download temp path**

In `src/update.rs`, replace line 154:

```rust
// Before:
let tmp_path = std::path::PathBuf::from("/tmp/oxi-hole-update");

// After:
let tmp_path = std::env::temp_dir().join("oxi-hole-update");
```

- [ ] **Step 2: Fix the readiness signal path**

In `src/update.rs`, replace line 332:

```rust
// Before:
let ready_path = std::path::PathBuf::from("/tmp/oxi-hole.ready");

// After:
let ready_path = std::env::temp_dir().join("oxi-hole.ready");
```

- [ ] **Step 3: Build and verify**

Run: `cargo check --all-targets`
Expected: Compiles with no errors.

- [ ] **Step 4: Commit**

```bash
git add src/update.rs
git commit -m "fix: use std::env::temp_dir() instead of hardcoded /tmp/ paths"
```

---

### Task 2: Add compile-time guard for non-Unix platforms

**Files:**
- Modify: `src/main.rs:1` (add before existing code)

- [ ] **Step 1: Add compile_error! at the top of main.rs**

Add these lines at the very top of `src/main.rs`, before the existing `mod blocklist;`:

```rust
#[cfg(not(unix))]
compile_error!(
    "oxi-hole only supports Unix platforms (Linux, macOS, FreeBSD). Use Docker for other platforms."
);
```

- [ ] **Step 2: Build and verify**

Run: `cargo check --all-targets`
Expected: Compiles with no errors (we're on Unix).

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "build: add compile-time guard for non-Unix platforms"
```

---

### Task 3: Add macOS CI runner

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add macOS check job to ci.yml**

Replace the current `check` job with a matrix strategy that runs on both `ubuntu-latest` and `macos-latest`. The full updated `ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [master, main]
    tags: ['*']
  pull_request:
  workflow_dispatch:

env:
  CARGO_TERM_COLOR: always

jobs:
  check:
    name: Check & Test
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo check --all-targets
      - run: cargo test
      - run: cargo clippy -- -D warnings

  fmt:
    name: Format
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --check
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add macOS to CI matrix for cross-platform regression detection"
```
