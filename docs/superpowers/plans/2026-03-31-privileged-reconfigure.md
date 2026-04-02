# Privileged Reconfigure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--reconfigure` CLI flag for privileged config changes and a dashboard Network section that generates copy-paste commands for those changes.

**Architecture:** New `src/reconfigure.rs` module handles CLI reconfiguration (config update, systemd-resolved, service restart). Main.rs routes `--reconfigure` to this module before server startup. Dashboard gets a Network settings section with editable fields and a command-generation banner. New `GET /api/system/network` endpoint serves current listen config.

**Tech Stack:** Rust (CLI + Axum API), vanilla HTML/CSS/JS (dashboard), std::process::Command for system operations

---

### Task 1: Create reconfigure module

**Files:**
- Create: `src/reconfigure.rs`

This module contains all the reconfigure logic: argument parsing, config modification, systemd-resolved handling, and service restart.

- [ ] **Step 1: Write tests for argument parsing**

Add tests at the bottom of the new file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_change() {
        let changes = parse_changes(&["dns.listen=0.0.0.0:5353".to_string()]).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0], ("dns.listen".to_string(), "0.0.0.0:5353".to_string()));
    }

    #[test]
    fn parse_multiple_changes() {
        let changes = parse_changes(&[
            "dns.listen=0.0.0.0:5353".to_string(),
            "web.listen=0.0.0.0:3000".to_string(),
        ]).unwrap();
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn parse_invalid_format() {
        let result = parse_changes(&["badformat".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_key() {
        let result = parse_changes(&["unknown.key=value".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn apply_dns_listen() {
        let mut config = Config::default();
        let changes = vec![("dns.listen".to_string(), "0.0.0.0:5353".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.listen, vec!["0.0.0.0:5353".to_string()]);
    }

    #[test]
    fn apply_web_listen() {
        let mut config = Config::default();
        let changes = vec![("web.listen".to_string(), "0.0.0.0:3000".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.web.listen, vec!["0.0.0.0:3000".to_string()]);
    }

    #[test]
    fn apply_dot_listen() {
        let mut config = Config::default();
        let changes = vec![("dns.dot_listen".to_string(), "0.0.0.0:853".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.dot_listen, Some(vec!["0.0.0.0:853".to_string()]));
    }

    #[test]
    fn apply_clear_optional_listen() {
        let mut config = Config::default();
        config.dns.dot_listen = Some(vec!["0.0.0.0:853".to_string()]);
        let changes = vec![("dns.dot_listen".to_string(), "".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.dot_listen, None);
    }

    #[test]
    fn needs_resolved_disable_port53_all_interfaces() {
        assert!(needs_resolved_change("0.0.0.0:5353", "0.0.0.0:53") == ResolvedAction::Disable);
    }

    #[test]
    fn needs_resolved_enable_leaving_port53() {
        assert!(needs_resolved_change("0.0.0.0:53", "0.0.0.0:5353") == ResolvedAction::Enable);
    }

    #[test]
    fn no_resolved_change_non53() {
        assert!(needs_resolved_change("0.0.0.0:5353", "0.0.0.0:8053") == ResolvedAction::None);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test reconfigure`
Expected: FAIL — module doesn't exist yet

- [ ] **Step 3: Write the reconfigure module implementation**

Create `src/reconfigure.rs`:

```rust
use crate::config::Config;
use std::path::Path;
use std::process::Command;

const VALID_KEYS: &[&str] = &[
    "dns.listen",
    "dns.dot_listen",
    "dns.doh_listen",
    "dns.doq_listen",
    "web.listen",
];

#[derive(Debug, PartialEq)]
pub enum ResolvedAction {
    None,
    Disable, // switching TO port 53 — disable stub listener
    Enable,  // switching FROM port 53 — re-enable stub listener
}

pub fn run(config_path: &Path, args: &[String]) -> anyhow::Result<()> {
    // Check root
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("--reconfigure requires root privileges. Run with sudo.");
    }

    let changes = parse_changes(args)?;

    // Load config
    let mut config = Config::load(config_path)?;

    // Check if dns.listen is changing (for systemd-resolved handling)
    let old_dns_listen = config.dns.listen.first().cloned().unwrap_or_default();
    let new_dns_listen = changes.iter()
        .find(|(k, _)| k == "dns.listen")
        .map(|(_, v)| v.clone());

    // Apply changes
    apply_changes(&mut config, &changes);

    // Handle systemd-resolved if dns.listen changed
    if let Some(ref new_listen) = new_dns_listen {
        let action = needs_resolved_change(&old_dns_listen, new_listen);
        match action {
            ResolvedAction::Disable => {
                println!("Disabling systemd-resolved stub listener...");
                disable_resolved_stub();
            }
            ResolvedAction::Enable => {
                println!("Re-enabling systemd-resolved stub listener...");
                enable_resolved_stub();
            }
            ResolvedAction::None => {}
        }
    }

    // Save config
    config.save(config_path)?;
    println!("Configuration saved to {}", config_path.display());

    // Restart service
    restart_service();

    println!("Reconfiguration complete.");
    Ok(())
}

pub fn parse_changes(args: &[String]) -> anyhow::Result<Vec<(String, String)>> {
    let mut changes = Vec::new();
    for arg in args {
        let (key, value) = arg.split_once('=')
            .ok_or_else(|| anyhow::anyhow!("expected key=value format, got '{}'", arg))?;

        if !VALID_KEYS.contains(&key) {
            anyhow::bail!(
                "unknown config key '{}'. Valid keys: {}",
                key,
                VALID_KEYS.join(", ")
            );
        }
        changes.push((key.to_string(), value.to_string()));
    }
    if changes.is_empty() {
        anyhow::bail!("--reconfigure requires at least one key=value argument");
    }
    Ok(changes)
}

pub fn apply_changes(config: &mut Config, changes: &[(String, String)]) {
    for (key, value) in changes {
        match key.as_str() {
            "dns.listen" => {
                config.dns.listen = vec![value.clone()];
            }
            "dns.dot_listen" => {
                config.dns.dot_listen = if value.is_empty() { None } else { Some(vec![value.clone()]) };
            }
            "dns.doh_listen" => {
                config.dns.doh_listen = if value.is_empty() { None } else { Some(vec![value.clone()]) };
            }
            "dns.doq_listen" => {
                config.dns.doq_listen = if value.is_empty() { None } else { Some(vec![value.clone()]) };
            }
            "web.listen" => {
                config.web.listen = vec![value.clone()];
            }
            _ => {} // validated in parse_changes
        }
    }
}

pub fn needs_resolved_change(old_listen: &str, new_listen: &str) -> ResolvedAction {
    let old_is_53 = is_port53_local(old_listen);
    let new_is_53 = is_port53_local(new_listen);

    match (old_is_53, new_is_53) {
        (false, true) => ResolvedAction::Disable,
        (true, false) => ResolvedAction::Enable,
        _ => ResolvedAction::None,
    }
}

fn is_port53_local(addr: &str) -> bool {
    let port = addr.rsplit(':').next().unwrap_or("");
    if port != "53" {
        return false;
    }
    let host = addr.rsplitn(2, ':').nth(1).unwrap_or("");
    matches!(host, "0.0.0.0" | "127.0.0.1" | "" | "[::]" | "[::1]")
}

fn has_systemd_resolved() -> bool {
    Path::new("/run/systemd/system").exists()
        && Command::new("systemctl")
            .args(["list-unit-files", "systemd-resolved.service"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

fn disable_resolved_stub() {
    if !has_systemd_resolved() {
        return;
    }

    // Create drop-in config
    let _ = std::fs::create_dir_all("/etc/systemd/resolved.conf.d");
    let _ = std::fs::write(
        "/etc/systemd/resolved.conf.d/oxi-dns.conf",
        "# Created by oxi-dns --reconfigure\n[Resolve]\nDNSStubListener=no\n",
    );

    // Preserve search domains from current resolv.conf
    let search_line = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("search "))
        .map(|l| l.to_string());

    // Write resolv.conf pointing to localhost
    let mut content = String::from("# Generated by oxi-dns --reconfigure\nnameserver 127.0.0.1\n");
    if let Some(search) = search_line {
        content = format!("# Generated by oxi-dns --reconfigure\n{}\nnameserver 127.0.0.1\n", search);
    }
    let _ = std::fs::remove_file("/etc/resolv.conf");
    let _ = std::fs::write("/etc/resolv.conf", content);

    // Restart systemd-resolved
    let _ = Command::new("systemctl").args(["restart", "systemd-resolved"]).output();
    println!("systemd-resolved stub listener disabled");
}

fn enable_resolved_stub() {
    if !has_systemd_resolved() {
        return;
    }

    // Remove drop-in config
    let _ = std::fs::remove_file("/etc/systemd/resolved.conf.d/oxi-dns.conf");
    let _ = std::fs::remove_dir("/etc/systemd/resolved.conf.d");

    // Restore resolv.conf symlink
    let _ = std::fs::remove_file("/etc/resolv.conf");
    if Path::new("/run/systemd/resolve/stub-resolv.conf").exists() {
        let _ = std::os::unix::fs::symlink("/run/systemd/resolve/stub-resolv.conf", "/etc/resolv.conf");
    } else if Path::new("/run/systemd/resolve/resolv.conf").exists() {
        let _ = std::os::unix::fs::symlink("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf");
    }

    // Restart systemd-resolved
    let _ = Command::new("systemctl").args(["enable", "systemd-resolved"]).output();
    let _ = Command::new("systemctl").args(["restart", "systemd-resolved"]).output();
    println!("systemd-resolved stub listener re-enabled");
}

fn restart_service() {
    if Path::new("/run/systemd/system").exists() {
        println!("Restarting oxi-dns service...");
        let _ = Command::new("systemctl").args(["restart", "oxi-dns"]).output();
    } else if cfg!(target_os = "macos") {
        println!("Restarting oxi-dns service...");
        let _ = Command::new("launchctl").args(["unload", "/Library/LaunchDaemons/com.oxi-dns.server.plist"]).output();
        let _ = Command::new("launchctl").args(["load", "/Library/LaunchDaemons/com.oxi-dns.server.plist"]).output();
    } else if Path::new("/etc/init.d/oxi-dns").exists() {
        println!("Restarting oxi-dns service...");
        let _ = Command::new("rc-service").args(["oxi-dns", "restart"]).output();
    } else {
        println!("Could not detect init system. Please restart oxi-dns manually.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_change() {
        let changes = parse_changes(&["dns.listen=0.0.0.0:5353".to_string()]).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0], ("dns.listen".to_string(), "0.0.0.0:5353".to_string()));
    }

    #[test]
    fn parse_multiple_changes() {
        let changes = parse_changes(&[
            "dns.listen=0.0.0.0:5353".to_string(),
            "web.listen=0.0.0.0:3000".to_string(),
        ]).unwrap();
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn parse_invalid_format() {
        let result = parse_changes(&["badformat".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_key() {
        let result = parse_changes(&["unknown.key=value".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_args() {
        let result = parse_changes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn apply_dns_listen() {
        let mut config = Config::default();
        let changes = vec![("dns.listen".to_string(), "0.0.0.0:5353".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.listen, vec!["0.0.0.0:5353".to_string()]);
    }

    #[test]
    fn apply_web_listen() {
        let mut config = Config::default();
        let changes = vec![("web.listen".to_string(), "0.0.0.0:3000".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.web.listen, vec!["0.0.0.0:3000".to_string()]);
    }

    #[test]
    fn apply_dot_listen() {
        let mut config = Config::default();
        let changes = vec![("dns.dot_listen".to_string(), "0.0.0.0:853".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.dot_listen, Some(vec!["0.0.0.0:853".to_string()]));
    }

    #[test]
    fn apply_clear_optional_listen() {
        let mut config = Config::default();
        config.dns.dot_listen = Some(vec!["0.0.0.0:853".to_string()]);
        let changes = vec![("dns.dot_listen".to_string(), "".to_string())];
        apply_changes(&mut config, &changes);
        assert_eq!(config.dns.dot_listen, None);
    }

    #[test]
    fn resolved_disable_for_port53() {
        assert_eq!(needs_resolved_change("0.0.0.0:5353", "0.0.0.0:53"), ResolvedAction::Disable);
    }

    #[test]
    fn resolved_enable_leaving_port53() {
        assert_eq!(needs_resolved_change("0.0.0.0:53", "0.0.0.0:5353"), ResolvedAction::Enable);
    }

    #[test]
    fn resolved_none_for_non53() {
        assert_eq!(needs_resolved_change("0.0.0.0:5353", "0.0.0.0:8053"), ResolvedAction::None);
    }

    #[test]
    fn resolved_none_same_port53() {
        assert_eq!(needs_resolved_change("0.0.0.0:53", "127.0.0.1:53"), ResolvedAction::None);
    }

    #[test]
    fn is_port53_various() {
        assert!(is_port53_local("0.0.0.0:53"));
        assert!(is_port53_local("127.0.0.1:53"));
        assert!(!is_port53_local("192.168.1.10:53"));
        assert!(!is_port53_local("0.0.0.0:5353"));
    }
}
```

- [ ] **Step 4: Register the module in main.rs**

In `src/main.rs`, add after line 14 (`mod web;`):

```rust
mod reconfigure;
```

- [ ] **Step 5: Run tests**

Run: `cargo test reconfigure`
Expected: All 14 reconfigure tests pass

- [ ] **Step 6: Commit**

```bash
git add src/reconfigure.rs src/main.rs
git commit -m "feat: add reconfigure module with config change and resolved handling logic"
```

---

### Task 2: Wire `--reconfigure` flag into main.rs

**Files:**
- Modify: `src/main.rs:26-54` (CLI arg parsing section)

- [ ] **Step 1: Add --reconfigure handling to the CLI parser**

In `src/main.rs`, modify the CLI parsing section. Find the argument parsing block (around line 26-54) and replace it with:

```rust
    let args: Vec<String> = std::env::args().collect();
    let mut health_check = false;
    let mut ready_file: Option<PathBuf> = None;
    let mut config_arg: Option<String> = None;
    let mut reconfigure_args: Vec<String> = Vec::new();
    let mut is_reconfigure = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--version" | "-V" => {
                println!("oxi-dns {}", VERSION);
                return Ok(());
            }
            "--health-check" => health_check = true,
            "--takeover" => {}
            "--ready-file" => {
                i += 1;
                ready_file =
                    Some(PathBuf::from(args.get(i).ok_or_else(|| {
                        anyhow::anyhow!("--ready-file requires a path")
                    })?));
            }
            "--reconfigure" => {
                is_reconfigure = true;
            }
            other => {
                if is_reconfigure && other.contains('=') {
                    reconfigure_args.push(other.to_string());
                } else if config_arg.is_none() && !other.starts_with('-') {
                    config_arg = Some(other.to_string());
                }
            }
        }
        i += 1;
    }

    let config_path = config_arg
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/oxi-dns/config.toml"));

    // Handle --reconfigure before any server initialization
    if is_reconfigure {
        if let Err(e) = reconfigure::run(&config_path, &reconfigure_args) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        return Ok(());
    }
```

Note: the default config path changes from `config.toml` (relative) to `/etc/oxi-dns/config.toml` (absolute) so that `sudo oxi-dns --reconfigure` works without specifying the path. The server startup path (when running as a service) still gets the path from the systemd service file's ExecStart argument.

- [ ] **Step 2: Run all tests**

Run: `cargo test`
Expected: All tests pass (including the 14 new reconfigure tests)

- [ ] **Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire --reconfigure CLI flag into main.rs arg parsing"
```

---

### Task 3: Add `GET /api/system/network` endpoint

**Files:**
- Modify: `src/web/mod.rs` (add route + handler)

- [ ] **Step 1: Add the route**

In `src/web/mod.rs`, find the system settings routes (around line 318-322):

```rust
        // System settings
        .route("/api/system/auto-update", get(api_get_auto_update))
```

Add before it:

```rust
        // Network configuration
        .route("/api/system/network", get(api_system_network))
```

- [ ] **Step 2: Add the handler**

In `src/web/mod.rs`, find the `api_setup_info` function (added in the previous feature). Add the new handler after it:

```rust
async fn api_system_network(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthenticatedUser>,
) -> Response {
    if !user.permissions.contains(&Permission::ManageSystem) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let config = Config::load(&state.config_path).unwrap_or_default();

    Json(serde_json::json!({
        "dns_listen": config.dns.listen,
        "web_listen": config.web.listen,
        "dot_listen": config.dns.dot_listen,
        "doh_listen": config.dns.doh_listen,
        "doq_listen": config.dns.doq_listen,
    }))
    .into_response()
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: add GET /api/system/network endpoint for dashboard network config"
```

---

### Task 4: Add Network settings section to dashboard

**Files:**
- Modify: `src/web/dashboard.html`

This adds the Network subsection with editable fields and the command generation banner.

- [ ] **Step 1: Add CSS for the network settings**

In `src/web/dashboard.html`, find the existing CSS section. Search for `.logs-settings {` (around line 913). Add before it:

```css
        .network-settings { margin-bottom: 24px; }
        .network-settings h3 { font-size: 15px; margin-bottom: 12px; color: var(--text-primary); }
        .network-field { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
        .network-field label { width: 140px; font-size: 13px; color: var(--text-secondary); flex-shrink: 0; }
        .network-field input {
            flex: 1; background: var(--bg-page); border: 1px solid var(--border); border-radius: 6px;
            padding: 7px 10px; font-size: 13px; font-family: var(--font-mono, monospace);
            color: var(--text-primary); outline: none; transition: border-color 0.15s;
        }
        .network-field input:focus { border-color: var(--accent); }
        .network-field input::placeholder { color: var(--text-muted); font-family: var(--font-sans); font-style: italic; }

        .reconfig-banner {
            margin-top: 16px; padding: 14px 16px;
            background: rgba(234, 179, 8, 0.06); border: 1px solid rgba(234, 179, 8, 0.2);
            border-radius: 8px; display: none;
        }
        .reconfig-banner.visible { display: block; }
        .reconfig-banner .banner-title { font-size: 13px; font-weight: 600; color: #eab308; margin-bottom: 8px; }
        .reconfig-banner .banner-desc { font-size: 12px; color: var(--text-secondary); margin-bottom: 10px; }
        .reconfig-banner .banner-cmd {
            background: var(--bg-page); border: 1px solid var(--border); border-radius: 6px;
            padding: 10px 12px; font-family: var(--font-mono, monospace); font-size: 13px;
            color: var(--text-primary); word-break: break-all; margin-bottom: 10px;
        }
        .reconfig-banner .banner-actions { display: flex; gap: 8px; justify-content: flex-end; }
        .reconfig-banner .banner-actions button {
            padding: 5px 12px; border-radius: 6px; font-size: 12px; cursor: pointer; border: none;
        }
        .reconfig-btn-copy { background: #eab308; color: #000; font-weight: 500; }
        .reconfig-btn-copy:hover { background: #facc15; }
        .reconfig-btn-dismiss { background: transparent; color: var(--text-muted); border: 1px solid var(--border) !important; }
        .reconfig-btn-dismiss:hover { color: var(--text-secondary); }
```

- [ ] **Step 2: Add the Network HTML section**

In `src/web/dashboard.html`, find the System Settings section start (around line 1374):

```html
                <h2>System Settings</h2>
                <div class="setting-row">
                    <div class="setting-info">
                        <h3>Auto-Update Server</h3>
```

Insert BEFORE the auto-update setting-row (between `<h2>System Settings</h2>` and the first `<div class="setting-row">`):

```html
                <div class="network-settings manage-system-only">
                    <h3>Network</h3>
                    <div class="network-field">
                        <label>DNS Server</label>
                        <input type="text" id="net-dns" placeholder="0.0.0.0:53" oninput="checkNetworkChanges()">
                    </div>
                    <div class="network-field">
                        <label>Web Dashboard</label>
                        <input type="text" id="net-web" placeholder="0.0.0.0:9853" oninput="checkNetworkChanges()">
                    </div>
                    <div class="network-field">
                        <label>DNS-over-TLS</label>
                        <input type="text" id="net-dot" placeholder="Enable (e.g. 0.0.0.0:853)" oninput="checkNetworkChanges()">
                    </div>
                    <div class="network-field">
                        <label>DNS-over-HTTPS</label>
                        <input type="text" id="net-doh" placeholder="Enable (e.g. 0.0.0.0:443)" oninput="checkNetworkChanges()">
                    </div>
                    <div class="network-field">
                        <label>DNS-over-QUIC</label>
                        <input type="text" id="net-doq" placeholder="Enable (e.g. 0.0.0.0:853)" oninput="checkNetworkChanges()">
                    </div>
                    <div class="reconfig-banner" id="reconfigBanner">
                        <div class="banner-title">&#9888; System command required</div>
                        <div class="banner-desc">This change requires root privileges. Run this command in your terminal:</div>
                        <div class="banner-cmd" id="reconfigCmd"></div>
                        <div class="banner-desc">The service will restart automatically.</div>
                        <div class="banner-actions">
                            <button class="reconfig-btn-dismiss" onclick="dismissBanner()">Dismiss</button>
                            <button class="reconfig-btn-copy" onclick="copyReconfigCmd()">Copy</button>
                        </div>
                    </div>
                </div>
```

- [ ] **Step 3: Add the JavaScript logic**

In `src/web/dashboard.html`, find the `// ---- System Settings ----` comment (around line 2584). Add BEFORE it:

```javascript
        // ---- Network Settings ----
        let serverNetworkState = {};
        let networkPollTimer = null;
        let bannerDismissed = false;

        async function refreshNetworkSettings() {
            try {
                const res = await fetch('/api/system/network');
                if (!res.ok) return;
                serverNetworkState = await res.json();
                const dns = (serverNetworkState.dns_listen || [])[0] || '';
                const web = (serverNetworkState.web_listen || [])[0] || '';
                const dot = (serverNetworkState.dot_listen || [])?.[0] || '';
                const doh = (serverNetworkState.doh_listen || [])?.[0] || '';
                const doq = (serverNetworkState.doq_listen || [])?.[0] || '';
                document.getElementById('net-dns').value = dns;
                document.getElementById('net-web').value = web;
                document.getElementById('net-dot').value = dot;
                document.getElementById('net-doh').value = doh;
                document.getElementById('net-doq').value = doq;
            } catch (_) {}
        }

        function checkNetworkChanges() {
            const fields = [
                { id: 'net-dns', key: 'dns.listen', server: (serverNetworkState.dns_listen || [])[0] || '' },
                { id: 'net-web', key: 'web.listen', server: (serverNetworkState.web_listen || [])[0] || '' },
                { id: 'net-dot', key: 'dns.dot_listen', server: (serverNetworkState.dot_listen || [])?.[0] || '' },
                { id: 'net-doh', key: 'dns.doh_listen', server: (serverNetworkState.doh_listen || [])?.[0] || '' },
                { id: 'net-doq', key: 'dns.doq_listen', server: (serverNetworkState.doq_listen || [])?.[0] || '' },
            ];

            const changes = [];
            for (const f of fields) {
                const val = document.getElementById(f.id).value.trim();
                if (val !== f.server) {
                    changes.push(f.key + '=' + val);
                }
            }

            const banner = document.getElementById('reconfigBanner');
            if (changes.length > 0) {
                const cmd = 'sudo oxi-dns --reconfigure ' + changes.join(' ');
                document.getElementById('reconfigCmd').textContent = cmd;
                if (!bannerDismissed) {
                    banner.classList.add('visible');
                    startNetworkPolling();
                }
            } else {
                banner.classList.remove('visible');
                bannerDismissed = false;
                stopNetworkPolling();
            }
        }

        function dismissBanner() {
            document.getElementById('reconfigBanner').classList.remove('visible');
            bannerDismissed = true;
        }

        async function copyReconfigCmd() {
            const cmd = document.getElementById('reconfigCmd').textContent;
            try {
                await navigator.clipboard.writeText(cmd);
                const btn = document.querySelector('.reconfig-btn-copy');
                btn.textContent = 'Copied!';
                setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
            } catch (_) {
                // Fallback: select text
                const range = document.createRange();
                range.selectNodeContents(document.getElementById('reconfigCmd'));
                window.getSelection().removeAllRanges();
                window.getSelection().addRange(range);
            }
        }

        function startNetworkPolling() {
            if (networkPollTimer) return;
            networkPollTimer = setInterval(async () => {
                await refreshNetworkSettings();
                checkNetworkChanges();
            }, 5000);
        }

        function stopNetworkPolling() {
            if (networkPollTimer) {
                clearInterval(networkPollTimer);
                networkPollTimer = null;
            }
        }
```

- [ ] **Step 4: Call refreshNetworkSettings on page load**

In `src/web/dashboard.html`, find the initialization section where other settings are loaded. Search for `refreshSystemSettings()` (around line 2100). Add before it:

```javascript
                refreshNetworkSettings();
```

- [ ] **Step 5: Run tests to verify compilation**

Run: `cargo test`
Expected: All tests pass (HTML is embedded at compile time)

- [ ] **Step 6: Commit**

```bash
git add src/web/dashboard.html
git commit -m "feat: add Network settings section with command generation banner to dashboard"
```

---

### Task 5: Add libc dependency for euid check

**Files:**
- Modify: `Cargo.toml`

The reconfigure module uses `libc::geteuid()` to check for root privileges.

- [ ] **Step 1: Check if libc is already a dependency**

Run: `grep libc Cargo.toml`

- [ ] **Step 2: Add libc if not present**

If not present, add to `[dependencies]` in `Cargo.toml`:

```toml
libc = "0.2"
```

- [ ] **Step 3: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 4: Commit (if changed)**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add libc dependency for privilege check in reconfigure"
```

---

### Task 6: Final verification

**Files:**
- Verify: all modified files

- [ ] **Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass (54 existing + 14 new reconfigure tests = 68 total)

- [ ] **Step 2: Verify the reconfigure module tests specifically**

Run: `cargo test reconfigure -- --nocapture`
Expected: 14 tests pass with output visible

- [ ] **Step 3: Verify compilation**

Run: `cargo build`
Expected: Successful build

- [ ] **Step 4: Verify --reconfigure flag is recognized**

Run: `cargo run -- --reconfigure 2>&1 || true`
Expected: Error message about requiring root or requiring arguments (NOT "unknown flag")

- [ ] **Step 5: Verify the network endpoint is in the router**

Run: `grep 'api/system/network' src/web/mod.rs`
Expected: Shows the route registration
