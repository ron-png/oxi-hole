# Setup Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a setup wizard with install-time DNS mode selection and a multi-step web-based first-run wizard for account creation and configuration summary.

**Architecture:** Two-part setup: (1) install.sh gets interactive prompts for web port and DNS mode (replace vs. coexist with systemd-resolved) since these need root, (2) the web `/setup` page becomes a 3-step wizard (account creation → DNS config summary → done). A new `GET /api/system/setup-info` endpoint provides config data to the wizard.

**Tech Stack:** POSIX shell (install.sh), Rust/Axum (backend API), vanilla HTML/CSS/JS (wizard UI)

---

### Task 1: Change default web port from 8080 to 9853

**Files:**
- Modify: `src/config.rs:255-257`
- Modify: `config.toml:11`

- [ ] **Step 1: Update the default web listen function in config.rs**

In `src/config.rs`, change the `default_web_listen` function:

```rust
fn default_web_listen() -> Vec<String> {
    vec!["0.0.0.0:9853".to_string(), "[::]:9853".to_string()]
}
```

- [ ] **Step 2: Update the repo root config.toml**

In `config.toml`, change line 11:

```toml
[web]
listen = "0.0.0.0:9853"
```

- [ ] **Step 3: Run tests**

Run: `cargo test`
Expected: All 54 tests pass (no tests depend on the port number)

- [ ] **Step 4: Commit**

```bash
git add src/config.rs config.toml
git commit -m "chore: change default web dashboard port from 8080 to 9853"
```

---

### Task 2: Add `GET /api/system/setup-info` endpoint

**Files:**
- Modify: `src/web/mod.rs` (add route + handler)
- Modify: `src/auth/middleware.rs:10` (whitelist the new route during setup)

- [ ] **Step 1: Add the setup-info route to the router**

In `src/web/mod.rs`, find the router definition (around line 258). Add the new route after the existing auth setup route on line 264:

```rust
        .route("/api/auth/setup", post(api_auth_setup))
        .route("/api/system/setup-info", get(api_setup_info))
```

- [ ] **Step 2: Add the handler function**

In `src/web/mod.rs`, add the handler after the `setup_page` function (after line 424):

```rust
async fn api_setup_info(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let config = Config::load(&state.config_path).unwrap_or_default();

    let dns_listen = config.dns.listen.first()
        .cloned()
        .unwrap_or_else(|| "0.0.0.0:53".to_string());

    let web_listen = config.web.listen.first()
        .cloned()
        .unwrap_or_else(|| "0.0.0.0:9853".to_string());

    // Detect server's LAN IP
    let server_ip = get_local_ip().unwrap_or_else(|| "127.0.0.1".to_string());

    Json(serde_json::json!({
        "dns_listen": dns_listen,
        "web_listen": web_listen,
        "server_ip": server_ip,
    }))
}

fn get_local_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    let addr = socket.local_addr().ok()?;
    Some(addr.ip().to_string())
}
```

Note: `get_local_ip()` uses a UDP socket trick — it doesn't actually send traffic, just asks the OS which interface would be used to reach 8.8.8.8, giving us the LAN IP.

- [ ] **Step 3: Whitelist the endpoint in auth middleware**

In `src/auth/middleware.rs`, update the setup-mode whitelist on line 21 to also allow the setup-info endpoint:

```rust
        if path == "/setup" || path == "/api/auth/setup" || path == "/api/system/setup-info" {
            return next.run(request).await;
        }
```

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/web/mod.rs src/auth/middleware.rs
git commit -m "feat: add GET /api/system/setup-info endpoint for setup wizard"
```

---

### Task 3: Replace setup.html with multi-step wizard

**Files:**
- Modify: `src/web/setup.html` (complete rewrite)

This replaces the single-form setup page with a 3-step wizard. The HTML is self-contained (inline CSS + JS), matching the existing pattern of the other HTML files.

- [ ] **Step 1: Replace setup.html with the wizard**

Overwrite `src/web/setup.html` with the complete wizard HTML. The wizard has:

- **Step 1 (Account Creation):** Username, password, confirm password form. POSTs to `/api/auth/setup`. On success, auto-logs in and advances to step 2. Same validation as current page (min 8 chars, passwords match).
- **Step 2 (DNS Config Summary):** Fetches `/api/system/setup-info` and displays DNS listen address, web listen address, server IP, and a tip about pointing devices to the server. Read-only, informational.
- **Step 3 (Done):** Summary card with admin username, DNS address, dashboard URL. "Open Dashboard" button navigates to `/`.
- **Navigation:** Step dots at top. Back/Next between steps. "Skip to dashboard" link on steps 2-3.
- **Design:** Dark theme (#000 background, #111 cards, #8a64e5 purple accent, matching existing setup.html/login.html CSS variables).

Write the following to `src/web/setup.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Setup — Oxi-DNS</title>
    <style>
        :root {
            --color-accent: #8a64e5;
            --color-accent-hover: #9d7cf2;
            --color-red: #f87171;
            --text-primary: #e6e6e6;
            --text-secondary: #999;
            --text-muted: #666;
            --bg-page: #000;
            --bg-subtle: #111;
            --border: #222;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --font-mono: "SF Mono", "Fira Code", "Cascadia Code", monospace;
        }

        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { -webkit-font-smoothing: antialiased; }
        body {
            font-family: var(--font-sans);
            font-size: 15px;
            line-height: 1.6;
            color: var(--text-secondary);
            background: var(--bg-page);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        ::selection { background: var(--color-accent); color: #fff; }

        .wizard { width: 100%; max-width: 440px; padding: 24px; }

        .header { text-align: center; margin-bottom: 24px; }
        .header h1 { font-size: 24px; font-weight: 600; color: var(--text-primary); letter-spacing: -0.5px; }
        .header h1 span { color: var(--color-accent); }
        .header .subtitle { font-size: 13px; color: var(--text-muted); margin-top: 4px; }

        /* Step dots */
        .steps { display: flex; justify-content: center; gap: 8px; margin-bottom: 24px; }
        .dot {
            width: 10px; height: 10px; border-radius: 50%; background: #222;
            transition: background 0.3s, box-shadow 0.3s;
        }
        .dot.active { background: var(--color-accent); box-shadow: 0 0 8px rgba(138,100,229,0.5); }
        .dot.done { background: #6c4fbf; }

        /* Card */
        .card {
            background: var(--bg-subtle);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 32px 28px;
        }
        .step { display: none; }
        .step.active { display: block; }

        .card h2 { font-size: 18px; font-weight: 600; color: var(--text-primary); margin-bottom: 2px; }
        .card .desc { font-size: 13px; color: var(--text-muted); margin-bottom: 24px; }

        /* Form */
        .form-group { margin-bottom: 16px; }
        .form-group label {
            display: block; font-size: 12px; text-transform: uppercase;
            letter-spacing: 0.5px; color: var(--text-secondary); margin-bottom: 6px;
        }
        .form-group input {
            width: 100%; background: #000; border: 1px solid var(--border); border-radius: 8px;
            padding: 10px 14px; font-size: 15px; font-family: var(--font-sans);
            color: var(--text-primary); outline: none; transition: border-color 0.15s;
        }
        .form-group input:focus { border-color: var(--color-accent); }
        .form-group input::placeholder { color: var(--text-muted); }

        /* Info rows */
        .info-row {
            display: flex; justify-content: space-between; align-items: center;
            padding: 10px 14px; background: #000; border-radius: 8px; margin-bottom: 6px;
        }
        .info-row .label { font-size: 13px; color: var(--text-muted); }
        .info-row .value { font-size: 14px; font-weight: 500; color: var(--text-primary); font-family: var(--font-mono); }

        /* Tip box */
        .tip {
            background: rgba(138,100,229,0.06); border: 1px solid rgba(138,100,229,0.15);
            border-radius: 8px; padding: 12px 14px; margin-top: 16px;
            font-size: 13px; color: #b8a0e8; line-height: 1.5;
        }
        .tip strong { color: #c9b3f5; }

        /* Done */
        .done-icon {
            width: 56px; height: 56px; border-radius: 50%;
            background: rgba(138,100,229,0.12); display: flex;
            align-items: center; justify-content: center;
            margin: 0 auto 16px; font-size: 24px; color: var(--color-accent);
        }
        .done-text { text-align: center; margin-bottom: 20px; }
        .done-text p { color: var(--text-muted); font-size: 14px; margin-top: 4px; }

        /* Buttons */
        .btn-row { display: flex; justify-content: space-between; align-items: center; margin-top: 24px; gap: 10px; }
        .btn {
            padding: 10px 20px; border-radius: 8px; font-size: 14px; font-weight: 500;
            font-family: var(--font-sans); cursor: pointer; border: none; transition: all 0.15s;
        }
        .btn-primary { background: var(--color-accent); color: #fff; flex: 1; }
        .btn-primary:hover:not(:disabled) { background: var(--color-accent-hover); }
        .btn-primary:disabled { opacity: 0.55; cursor: not-allowed; }
        .btn-back { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }
        .btn-back:hover { border-color: var(--color-accent); color: var(--text-secondary); }
        .btn-skip { background: transparent; color: var(--text-muted); font-size: 13px; padding: 10px 12px; }
        .btn-skip:hover { color: var(--text-secondary); }

        /* Error */
        .error {
            margin-top: 14px; padding: 10px 14px;
            background: rgba(248,113,113,0.08); border: 1px solid rgba(248,113,113,0.25);
            border-radius: 8px; font-size: 13px; color: var(--color-red); display: none;
        }
        .error.visible { display: block; }

        .note { margin-top: 14px; font-size: 12px; color: #444; text-align: center; }
    </style>
</head>
<body>
    <div class="wizard">
        <div class="header">
            <h1><span>oxi</span>-dns</h1>
            <div class="subtitle">Initial Setup</div>
        </div>

        <div class="steps">
            <div class="dot" id="dot-1"></div>
            <div class="dot" id="dot-2"></div>
            <div class="dot" id="dot-3"></div>
        </div>

        <div class="card">
            <!-- Step 1: Account -->
            <div class="step" id="step-1">
                <h2>Create Admin Account</h2>
                <p class="desc">This account has full access to all settings.</p>
                <form id="setup-form" novalidate>
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" id="username" autocomplete="username" required placeholder="admin">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" id="password" autocomplete="new-password" required minlength="8" placeholder="Minimum 8 characters">
                    </div>
                    <div class="form-group">
                        <label for="confirm-password">Confirm Password</label>
                        <input type="password" id="confirm-password" autocomplete="new-password" required minlength="8" placeholder="Re-enter password">
                    </div>
                    <div class="btn-row">
                        <div></div>
                        <button type="submit" class="btn btn-primary" id="submit-btn">Create Account &amp; Continue</button>
                    </div>
                    <div class="error" id="error-msg"></div>
                </form>
                <p class="note">This account will have full admin permissions.</p>
            </div>

            <!-- Step 2: DNS Summary -->
            <div class="step" id="step-2">
                <h2>Your Configuration</h2>
                <p class="desc">Configured during installation. Change these from the dashboard later.</p>
                <div id="config-info">
                    <div class="info-row"><span class="label">DNS Server</span><span class="value" id="info-dns">—</span></div>
                    <div class="info-row"><span class="label">Web Dashboard</span><span class="value" id="info-web">—</span></div>
                    <div class="info-row"><span class="label">Server IP</span><span class="value" id="info-ip">—</span></div>
                </div>
                <div class="tip" id="tip-box">
                    <strong>Next step:</strong> Point your devices' DNS to <strong id="tip-ip">—</strong> to start blocking ads.
                </div>
                <div class="btn-row">
                    <button class="btn btn-back" onclick="goStep(1)">Back</button>
                    <button class="btn btn-skip" onclick="window.location.href='/'">Skip to dashboard</button>
                    <button class="btn btn-primary" onclick="goStep(3)">Next</button>
                </div>
            </div>

            <!-- Step 3: Done -->
            <div class="step" id="step-3">
                <div class="done-icon">&#10003;</div>
                <div class="done-text">
                    <h2>You're All Set!</h2>
                    <p>Oxi-DNS is running and ready to protect your network.</p>
                </div>
                <div id="summary-info">
                    <div class="info-row"><span class="label">Admin</span><span class="value" id="sum-user">—</span></div>
                    <div class="info-row"><span class="label">DNS</span><span class="value" id="sum-dns">—</span></div>
                    <div class="info-row"><span class="label">Dashboard</span><span class="value" id="sum-dash">—</span></div>
                </div>
                <div class="btn-row">
                    <button class="btn btn-back" onclick="goStep(2)">Back</button>
                    <button class="btn btn-primary" onclick="window.location.href='/'">Open Dashboard</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentStep = 1;
        let setupInfo = {};
        let adminUsername = '';

        function goStep(n) {
            currentStep = n;
            document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
            document.getElementById('step-' + n).classList.add('active');
            document.querySelectorAll('.dot').forEach((d, i) => {
                d.className = 'dot';
                if (i + 1 < n) d.classList.add('done');
                if (i + 1 === n) d.classList.add('active');
            });

            if (n === 2) loadSetupInfo();
            if (n === 3) populateSummary();
        }

        async function loadSetupInfo() {
            try {
                const res = await fetch('/api/system/setup-info');
                if (res.ok) {
                    setupInfo = await res.json();
                    document.getElementById('info-dns').textContent = setupInfo.dns_listen || '—';
                    document.getElementById('info-web').textContent = setupInfo.web_listen || '—';
                    document.getElementById('info-ip').textContent = setupInfo.server_ip || '—';
                    document.getElementById('tip-ip').textContent = setupInfo.server_ip || '—';
                }
            } catch (_) {}
        }

        function populateSummary() {
            document.getElementById('sum-user').textContent = adminUsername || '—';
            document.getElementById('sum-dns').textContent = setupInfo.dns_listen || '—';
            const ip = setupInfo.server_ip || window.location.hostname;
            const port = (setupInfo.web_listen || '').split(':').pop() || '9853';
            document.getElementById('sum-dash').textContent = 'http://' + ip + ':' + port;
        }

        // Error handling
        const errorEl = document.getElementById('error-msg');
        function showError(msg) { errorEl.textContent = msg; errorEl.classList.add('visible'); }
        function clearError() { errorEl.textContent = ''; errorEl.classList.remove('visible'); }

        // Form submit
        const form = document.getElementById('setup-form');
        const submitBtn = document.getElementById('submit-btn');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearError();

            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            const confirm = document.getElementById('confirm-password').value;

            if (!username) { showError('Please enter a username.'); return; }
            if (password.length < 8) { showError('Password must be at least 8 characters.'); return; }
            if (password !== confirm) { showError('Passwords do not match.'); return; }

            submitBtn.disabled = true;
            submitBtn.textContent = 'Creating account\u2026';

            try {
                const res = await fetch('/api/auth/setup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password }),
                });
                if (res.ok) {
                    adminUsername = username;
                    goStep(2);
                } else {
                    let msg = 'Failed to create account. Please try again.';
                    try { const d = await res.json(); if (d && d.error) msg = d.error; } catch (_) {}
                    showError(msg);
                }
            } catch (_) {
                showError('Unable to reach the server. Please try again.');
            }
            submitBtn.disabled = false;
            submitBtn.textContent = 'Create Account & Continue';
        });

        goStep(1);
    </script>
</body>
</html>
```

- [ ] **Step 2: Run tests**

Run: `cargo test`
Expected: All tests pass (the HTML is embedded at compile time, so a cargo test verifies compilation)

- [ ] **Step 3: Commit**

```bash
git add src/web/setup.html
git commit -m "feat: replace setup page with multi-step wizard"
```

---

### Task 4: Add web port prompt to install script

**Files:**
- Modify: `scripts/install.sh`

This adds an interactive web port prompt and updates `create_default_config()` to use the chosen port.

- [ ] **Step 1: Add a `prompt_web_port()` function**

In `scripts/install.sh`, add a new function after the `create_default_config()` function (after the closing brace around line 900) and before the `deploy_uninstall_script` section:

```sh
# ============================================================================
# Interactive setup prompts
# ============================================================================

prompt_web_port() {
    log_step "Web Dashboard Configuration"
    printf "${BOLD}Web dashboard port${NC} [${CYAN}9853${NC}]: "
    read -r WEB_PORT </dev/tty 2>/dev/null || WEB_PORT=""
    WEB_PORT="${WEB_PORT:-9853}"

    # Validate port number
    case "$WEB_PORT" in
        ''|*[!0-9]*)
            log_warn "Invalid port number. Using default: 9853"
            WEB_PORT="9853"
            ;;
    esac
    if [ "$WEB_PORT" -lt 1 ] || [ "$WEB_PORT" -gt 65535 ]; then
        log_warn "Port out of range (1-65535). Using default: 9853"
        WEB_PORT="9853"
    fi

    log_info "Web dashboard will listen on port ${WEB_PORT}"
}
```

- [ ] **Step 2: Update `create_default_config()` to accept web port and DNS listen parameters**

Replace the existing `create_default_config()` function (around line 884-900) with:

```sh
create_default_config() {
    # Use pre-downloaded config if available (from reinstall flow)
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
CONFIGEOF
    fi

    # Patch config with user choices if set
    if [ -n "$WEB_PORT" ] && [ "$WEB_PORT" != "9853" ]; then
        sed -i.bak "s|^listen = \"0.0.0.0:[0-9]*\"$|listen = \"0.0.0.0:${WEB_PORT}\"|" "${CONFIG_DIR}/config.toml" 2>/dev/null || true
        rm -f "${CONFIG_DIR}/config.toml.bak"
    fi
    if [ -n "$DNS_LISTEN" ] && [ "$DNS_LISTEN" != "0.0.0.0:53" ]; then
        # Only patch the [dns] section listen line (first occurrence)
        sed -i.bak "0,/^listen = /{s|^listen = \"[^\"]*\"|listen = \"${DNS_LISTEN}\"|}" "${CONFIG_DIR}/config.toml" 2>/dev/null || true
        rm -f "${CONFIG_DIR}/config.toml.bak"
    fi
}
```

- [ ] **Step 3: Call `prompt_web_port()` in `do_install()` before config creation**

In `do_install()`, find the config setup section (around line 550):

```sh
    # Create config directory and default config
    log_step "Setting up configuration"
    mkdir -p "$CONFIG_DIR"
    if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
        create_default_config
```

Insert the prompt call before it:

```sh
    # Prompt for web port (only for fresh installs)
    if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
        prompt_web_port
    fi

    # Create config directory and default config
    log_step "Setting up configuration"
    mkdir -p "$CONFIG_DIR"
    if [ ! -f "${CONFIG_DIR}/config.toml" ]; then
        create_default_config
```

- [ ] **Step 4: Update the install completion message**

In `do_install()`, find the completion output (around line 590). Change the web dashboard URL to use the chosen port:

Find:
```sh
    printf "  ${BOLD}Web Dashboard:${NC}  ${GREEN}http://${LOCAL_IP}:8080${NC}\n"
```

Replace with:
```sh
    printf "  ${BOLD}Web Dashboard:${NC}  ${GREEN}http://${LOCAL_IP}:${WEB_PORT:-9853}${NC}\n"
```

- [ ] **Step 5: Syntax-check**

Run: `sh -n scripts/install.sh`
Expected: No output (success)

- [ ] **Step 6: Commit**

```bash
git add scripts/install.sh
git commit -m "feat: add interactive web port prompt to install script"
```

---

### Task 5: Replace `fix_systemd_resolved()` with DNS mode choice

**Files:**
- Modify: `scripts/install.sh`

This replaces the simple yes/no resolved prompt with a two-choice DNS mode selection.

- [ ] **Step 1: Add LAN IP detection helper**

In `scripts/install.sh`, add after the `prompt_web_port()` function:

```sh
detect_lan_ip() {
    LOCAL_IP=""
    if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
        LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    elif command -v ifconfig >/dev/null 2>&1; then
        LOCAL_IP=$(ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | sed 's/addr://')
    fi
    LOCAL_IP="${LOCAL_IP:-127.0.0.1}"
}
```

- [ ] **Step 2: Add `prompt_dns_mode()` function**

Add after `detect_lan_ip()`:

```sh
prompt_dns_mode() {
    log_step "DNS Configuration"
    printf "\n"
    printf "  ${BOLD}systemd-resolved is using port 53.${NC}\n"
    printf "  How should Oxi-DNS handle this?\n"
    printf "\n"
    printf "  ${CYAN}1)${NC} Replace systemd-resolved ${GREEN}(recommended)${NC}\n"
    printf "     Disables the stub listener, Oxi-DNS becomes your system DNS on port 53\n"
    printf "\n"
    printf "  ${CYAN}2)${NC} Run alongside systemd-resolved\n"
    printf "     Oxi-DNS listens on a different address/port, point clients to it directly\n"
    printf "\n"
    printf "${BOLD}Choice${NC} [${CYAN}1${NC}]: "
    read -r DNS_MODE </dev/tty 2>/dev/null || DNS_MODE=""
    DNS_MODE="${DNS_MODE:-1}"

    case "$DNS_MODE" in
        2)
            prompt_coexist_config
            ;;
        *)
            # Replace mode — run existing resolved fix
            DNS_LISTEN="0.0.0.0:53"
            fix_systemd_resolved
            ;;
    esac
}

prompt_coexist_config() {
    detect_lan_ip
    printf "\n"
    printf "  ${BOLD}Choose a listen configuration:${NC}\n"
    printf "\n"
    printf "  ${CYAN}1)${NC} All interfaces, alternate port (0.0.0.0:5353)\n"
    printf "  ${CYAN}2)${NC} LAN IP only, standard port (${LOCAL_IP}:53)\n"
    printf "  ${CYAN}3)${NC} Custom (enter address:port)\n"
    printf "\n"
    printf "${BOLD}Choice${NC} [${CYAN}1${NC}]: "
    read -r COEXIST_MODE </dev/tty 2>/dev/null || COEXIST_MODE=""
    COEXIST_MODE="${COEXIST_MODE:-1}"

    case "$COEXIST_MODE" in
        2)
            DNS_LISTEN="${LOCAL_IP}:53"
            ;;
        3)
            printf "Enter listen address (ip:port): "
            read -r DNS_LISTEN </dev/tty 2>/dev/null || DNS_LISTEN="0.0.0.0:5353"
            DNS_LISTEN="${DNS_LISTEN:-0.0.0.0:5353}"
            ;;
        *)
            DNS_LISTEN="0.0.0.0:5353"
            ;;
    esac

    log_info "Oxi-DNS will listen on ${DNS_LISTEN} (systemd-resolved untouched)"
}
```

- [ ] **Step 3: Update `check_port53()` to call `prompt_dns_mode()` instead of `fix_systemd_resolved()` directly**

In `check_port53()`, find the systemd-resolved detection block (around line 1175 in the current file):

```sh
    if echo "$PORT53_INFO" | grep -q "systemd-resolve\|resolved"; then
        fix_systemd_resolved
```

Replace with:

```sh
    if echo "$PORT53_INFO" | grep -q "systemd-resolve\|resolved"; then
        prompt_dns_mode
```

- [ ] **Step 4: Syntax-check**

Run: `sh -n scripts/install.sh`
Expected: No output (success)

- [ ] **Step 5: Commit**

```bash
git add scripts/install.sh
git commit -m "feat: add DNS mode choice (replace vs coexist) to install script"
```

---

### Task 6: Update embedded uninstall script in install.sh

**Files:**
- Modify: `scripts/install.sh` (the heredoc between UNINSTALLEOF markers)

The uninstall script itself doesn't need functional changes (the `RESOLVED_CHANGED` flag already handles both modes correctly). But the embedded copy in install.sh must stay in sync with `scripts/uninstall.sh`.

- [ ] **Step 1: Verify the standalone uninstall.sh is unchanged**

Run: `git diff scripts/uninstall.sh`
Expected: No changes (the uninstall script needs no modifications for this feature)

- [ ] **Step 2: Verify the embedded copy still matches**

Run:
```bash
grep -n 'UNINSTALLEOF' scripts/install.sh
```
Note the line numbers. Then extract and diff:
```bash
START=$(grep -n "cat > \"\${INSTALL_DIR}/uninstall.sh\" <<'UNINSTALLEOF'" scripts/install.sh | cut -d: -f1)
END=$(grep -n '^UNINSTALLEOF$' scripts/install.sh | cut -d: -f1)
sed -n "$((START+1)),$((END-1))p" scripts/install.sh > /tmp/embedded.sh
diff scripts/uninstall.sh /tmp/embedded.sh && echo "MATCH" || echo "MISMATCH - resync needed"
```

Expected: MATCH

If MISMATCH, resync by replacing the heredoc body with the content of `scripts/uninstall.sh`.

- [ ] **Step 3: Syntax-check both scripts**

Run: `sh -n scripts/install.sh && sh -n scripts/uninstall.sh && echo "BOTH OK"`
Expected: `BOTH OK`

- [ ] **Step 4: Commit (if any resync was needed)**

```bash
git add scripts/install.sh
git commit -m "chore: resync embedded uninstall script"
```

---

### Task 7: Final verification

**Files:**
- Verify: all modified files

- [ ] **Step 1: Run Rust tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 2: Syntax-check shell scripts**

Run: `sh -n scripts/install.sh && sh -n scripts/uninstall.sh && echo "OK"`
Expected: `OK`

- [ ] **Step 3: Verify the build compiles**

Run: `cargo build`
Expected: Successful build (this also verifies `include_str!("setup.html")` can find the file)

- [ ] **Step 4: Verify default port in config.rs**

Run: `grep '9853' src/config.rs`
Expected: Shows the default_web_listen function with 9853

- [ ] **Step 5: Verify config.toml has new port**

Run: `grep '9853' config.toml`
Expected: Shows `listen = "0.0.0.0:9853"`

- [ ] **Step 6: Verify the setup-info endpoint is whitelisted**

Run: `grep 'setup-info' src/auth/middleware.rs`
Expected: Shows the endpoint in the setup whitelist
