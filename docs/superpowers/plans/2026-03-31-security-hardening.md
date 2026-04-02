# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden frontend-backend communication with optional HTTPS, HSTS, tiered rate limiting, and CSP nonce for inline scripts.

**Architecture:** Four independent security improvements applied to the web layer: (1) optional HTTPS listener with HTTP→HTTPS redirect when a real cert is available, (2) HSTS header on HTTPS responses, (3) generalized rate limiter with auth and admin tiers, (4) per-request CSP nonce replacing `unsafe-inline` for scripts.

**Tech Stack:** Rust/Axum, rustls (TLS), tokio-rustls (HTTPS binding), DashMap (rate limiter)

---

### Task 1: Generalize rate limiter with tiered support

**Files:**
- Modify: `src/web/mod.rs` (rename LoginRateLimiter → RateLimiter, parameterize, update AppState)
- Modify: `src/main.rs` (update AppState construction, cleanup task)

This is the most self-contained change and doesn't depend on the others.

- [ ] **Step 1: Rename and parameterize the rate limiter**

In `src/web/mod.rs`, find the `LoginRateLimiter` struct and impl (around lines 126-173). Replace the entire block with:

```rust
// ==================== Rate Limiter ====================

/// In-memory per-IP rate limiter with configurable limits.
#[derive(Clone)]
pub struct RateLimiter {
    max_attempts: u32,
    window_secs: u64,
    attempts: Arc<DashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new(max_attempts: u32, window_secs: u64) -> Self {
        Self {
            max_attempts,
            window_secs,
            attempts: Arc::new(DashMap::new()),
        }
    }

    /// Returns true if the request should be allowed, false if rate limited.
    pub fn check_rate_limit(&self, ip: &str) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs);

        let mut entry = self.attempts.entry(ip.to_string()).or_insert((0, now));
        let (count, window_start) = entry.value_mut();

        if now.duration_since(*window_start) > window {
            *count = 0;
            *window_start = now;
        }

        *count += 1;
        *count <= self.max_attempts
    }

    /// Periodically clean up stale entries.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.window_secs * 2);
        self.attempts
            .retain(|_, (_, window_start)| now.duration_since(*window_start) < window);
    }
}
```

- [ ] **Step 2: Update AppState fields**

In `src/web/mod.rs`, find the `AppState` struct. Replace the `login_rate_limiter` field:

Change:
```rust
    #[doc(hidden)]
    pub login_rate_limiter: LoginRateLimiter,
```
To:
```rust
    pub auth_rate_limiter: RateLimiter,
    pub admin_rate_limiter: RateLimiter,
```

- [ ] **Step 3: Update the cleanup task in run_web_server**

In `src/web/mod.rs`, find the cleanup task spawn (around line 252-260):

```rust
    let cleanup_limiter = state.login_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_limiter.cleanup();
        }
    });
```

Replace with:

```rust
    let auth_cleanup = state.auth_rate_limiter.clone();
    let admin_cleanup = state.admin_rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            auth_cleanup.cleanup();
            admin_cleanup.cleanup();
        }
    });
```

- [ ] **Step 4: Update all rate limiter references in handlers**

Find all occurrences of `login_rate_limiter` in `src/web/mod.rs`. The login handler (around line 568) uses:
```rust
    if !state.login_rate_limiter.check_rate_limit(&ip) {
```
Change to:
```rust
    if !state.auth_rate_limiter.check_rate_limit(&ip) {
```

- [ ] **Step 5: Add rate limiting to auth endpoints**

Find `api_auth_setup` handler. Add at the top of the function body (after extracting the IP):

```rust
    let ip = addr.ip().to_string();
    if !state.auth_rate_limiter.check_rate_limit(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many attempts. Please try again later."})),
        ).into_response();
    }
```

Find `api_change_password` handler. Add the same rate limit check using `auth_rate_limiter` (it should already have `ConnectInfo(addr)` — if not, add it to the handler signature).

- [ ] **Step 6: Add rate limiting to admin endpoints**

Add `admin_rate_limiter` checks to these handlers:
- `api_create_token` — add `ConnectInfo(addr)` to signature if needed, check `state.admin_rate_limiter.check_rate_limit(&ip)`
- `api_tls_upload` — same pattern
- `api_create_user` — same pattern  
- `api_reset_password` — same pattern

Each gets the same pattern:
```rust
    let ip = addr.ip().to_string();
    if !state.admin_rate_limiter.check_rate_limit(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error": "Too many requests. Please try again later."})),
        ).into_response();
    }
```

- [ ] **Step 7: Update AppState construction in main.rs**

In `src/main.rs`, find the `web::AppState {` construction. Replace:
```rust
        login_rate_limiter: web::LoginRateLimiter::new(),
```
With:
```rust
        auth_rate_limiter: web::RateLimiter::new(5, 60),
        admin_rate_limiter: web::RateLimiter::new(20, 60),
```

- [ ] **Step 8: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 9: Commit**

```bash
git add src/web/mod.rs src/main.rs
git commit -m "feat: generalize rate limiter with auth (5/60s) and admin (20/60s) tiers"
```

---

### Task 2: Add CSP nonce for inline scripts

**Files:**
- Modify: `src/web/mod.rs` (nonce type, middleware update, HTML handler updates)

- [ ] **Step 1: Add the CspNonce type**

In `src/web/mod.rs`, add before the `security_headers_middleware` function:

```rust
#[derive(Clone)]
struct CspNonce(String);
```

- [ ] **Step 2: Update security_headers_middleware to generate nonce**

Replace the entire `security_headers_middleware` function with:

```rust
async fn security_headers_middleware(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Generate per-request nonce for CSP
    let nonce_bytes: [u8; 16] = rand::random();
    let nonce = hex::encode(nonce_bytes);

    // Store nonce in request extensions for HTML handlers
    request.extensions_mut().insert(CspNonce(nonce.clone()));

    // Check if this is an HTTPS request (set by HTTPS middleware layer)
    let is_https = request.extensions().get::<IsHttps>().is_some();

    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(axum::http::header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().unwrap(),
    );
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        format!(
            "default-src 'self'; script-src 'self' 'nonce-{}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
            nonce
        ).parse().unwrap(),
    );
    headers.insert(
        axum::http::header::REFERRER_POLICY,
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        axum::http::header::HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=()".parse().unwrap(),
    );

    // HSTS only on HTTPS responses
    if is_https {
        headers.insert(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }

    response
}
```

Also add the `IsHttps` marker type before the middleware:

```rust
#[derive(Clone)]
struct IsHttps;
```

- [ ] **Step 3: Update HTML-serving handlers to inject nonce**

Find `login_page`, `setup_page`, and `dashboard` handlers. Update each to extract and inject the nonce:

```rust
async fn login_page(
    nonce: Option<axum::Extension<CspNonce>>,
) -> Html<String> {
    let html = include_str!("login.html");
    let nonce_val = nonce.map(|n| n.0 .0.clone()).unwrap_or_default();
    Html(html.replace("<script>", &format!("<script nonce=\"{}\">", nonce_val)))
}

async fn setup_page(
    nonce: Option<axum::Extension<CspNonce>>,
) -> Html<String> {
    let html = include_str!("setup.html");
    let nonce_val = nonce.map(|n| n.0 .0.clone()).unwrap_or_default();
    Html(html.replace("<script>", &format!("<script nonce=\"{}\">", nonce_val)))
}
```

Find the `dashboard` handler (which serves the main dashboard). Update it similarly:

```rust
async fn dashboard(
    nonce: Option<axum::Extension<CspNonce>>,
    // ... existing parameters ...
) -> impl IntoResponse {
    // ... existing auth check logic ...
    let html = include_str!("dashboard.html");
    let nonce_val = nonce.map(|n| n.0 .0.clone()).unwrap_or_default();
    Html(html.replace("<script>", &format!("<script nonce=\"{}\">", nonce_val)))
}
```

NOTE: The dashboard handler may have additional logic (auth check, redirect). Read the actual handler and preserve all existing logic — only change the return type and add nonce injection at the end.

- [ ] **Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add src/web/mod.rs
git commit -m "feat: add per-request CSP nonce for scripts, remove unsafe-inline"
```

---

### Task 3: Add https_listen to WebConfig

**Files:**
- Modify: `src/config.rs`

- [ ] **Step 1: Add https_listen field to WebConfig**

In `src/config.rs`, find the `WebConfig` struct (around line 76):

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_web_listen", deserialize_with = "string_or_vec")]
    pub listen: Vec<String>,
}
```

Change to:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    #[serde(default = "default_web_listen", deserialize_with = "string_or_vec")]
    pub listen: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec_opt")]
    pub https_listen: Option<Vec<String>>,
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add src/config.rs
git commit -m "feat: add https_listen field to WebConfig"
```

---

### Task 4: Add HTTPS web server support

**Files:**
- Modify: `src/web/mod.rs` (run_web_server gains TLS support, HTTP redirect)
- Modify: `src/main.rs` (pass TLS config to web server)

- [ ] **Step 1: Update run_web_server signature**

In `src/web/mod.rs`, change `run_web_server` to accept optional TLS config:

```rust
pub async fn run_web_server(
    listen: &[String],
    https_listen: Option<&[String]>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    state: AppState,
) -> anyhow::Result<()> {
```

- [ ] **Step 2: Add the HTTP redirect handler**

Add before `run_web_server`:

```rust
async fn https_redirect(
    axum::extract::Host(host): axum::extract::Host,
    uri: axum::http::Uri,
) -> Response {
    // Extract hostname without port
    let hostname = host.split(':').next().unwrap_or(&host);
    // Build HTTPS URL (uses default HTTPS port from config)
    let https_url = format!("https://{}{}", hostname, uri.path());
    axum::response::Redirect::permanent(&https_url).into_response()
}
```

Note: This simple redirect drops the port — for non-standard HTTPS ports this won't work perfectly. A more robust approach stores the HTTPS port in a shared context. For now, the redirect points to the hostname which the user can configure in their DNS/reverse proxy.

Actually, let's make it configurable by storing the HTTPS address:

```rust
async fn https_redirect(
    axum::extract::State(https_addr): axum::extract::State<String>,
    uri: axum::http::Uri,
) -> Response {
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let url = format!("https://{}{}", https_addr, path);
    axum::response::Redirect::permanent(&url).into_response()
}
```

- [ ] **Step 3: Add HTTPS middleware layer**

Add a middleware that inserts `IsHttps` extension for HTTPS connections:

```rust
async fn mark_https_middleware(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    request.extensions_mut().insert(IsHttps);
    next.run(request).await
}
```

- [ ] **Step 4: Update run_web_server body to handle both HTTP and HTTPS**

Replace the listener binding logic in `run_web_server` with:

```rust
    let mut handles = Vec::new();

    // If HTTPS is configured, HTTP becomes redirect-only
    let is_https_active = https_listen.is_some() && tls_config.is_some();

    if is_https_active {
        let tls_cfg = tls_config.unwrap();
        let https_addrs = https_listen.unwrap();

        // Build HTTPS app: full router + HTTPS marker middleware
        let https_app = app.clone()
            .layer(axum::middleware::from_fn(mark_https_middleware));

        // Spawn HTTPS listeners
        for addr in https_addrs {
            let https_app = https_app.clone();
            let tls_cfg = tls_cfg.clone();
            let sock_addr: std::net::SocketAddr = addr.parse()?;
            let domain = if sock_addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
            socket.set_reuse_port(true)?;
            socket.set_nonblocking(true)?;
            socket.bind(&sock_addr.into())?;
            socket.listen(1024)?;
            let tcp_listener = tokio::net::TcpListener::from_std(socket.into())?;
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
            let addr_str = addr.clone();
            info!("Web admin HTTPS listening on {}", addr_str);

            handles.push(tokio::spawn(async move {
                loop {
                    let (stream, peer_addr) = match tcp_listener.accept().await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("HTTPS accept error: {}", e);
                            continue;
                        }
                    };
                    let tls_acceptor = tls_acceptor.clone();
                    let app = https_app.clone();
                    tokio::spawn(async move {
                        match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                let io = hyper_util::rt::TokioIo::new(tls_stream);
                                let svc = app.into_make_service_with_connect_info::<SocketAddr>();
                                // Use tower_service to serve
                                let tower_svc = tower::ServiceExt::ready(svc)
                                    .await
                                    .ok()
                                    .and_then(|mut s| {
                                        tower::Service::call(&mut s, peer_addr).ok()
                                    });
                                if let Some(service) = tower_svc {
                                    let _ = hyper::server::conn::http1::Builder::new()
                                        .serve_connection(io, service)
                                        .await;
                                }
                            }
                            Err(e) => {
                                tracing::debug!("TLS handshake error: {}", e);
                            }
                        }
                    });
                }
            }));
        }

        // HTTP listeners become redirect-only
        let redirect_target = https_addrs.first().cloned().unwrap_or_default();
        // Extract host:port for redirect target
        let redirect_host = redirect_target.split(':').next().unwrap_or("localhost");
        let redirect_port = redirect_target.split(':').last().unwrap_or("9443");
        let redirect_addr = if redirect_host == "0.0.0.0" || redirect_host == "[::]" {
            format!("localhost:{}", redirect_port)
        } else {
            redirect_target.clone()
        };

        let redirect_app = Router::new()
            .fallback(https_redirect)
            .with_state(redirect_addr);

        for addr in listen {
            let redirect_app = redirect_app.clone();
            let sock_addr: std::net::SocketAddr = addr.parse()?;
            let domain = if sock_addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
            let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
            socket.set_reuse_port(true)?;
            socket.set_nonblocking(true)?;
            socket.bind(&sock_addr.into())?;
            socket.listen(1024)?;
            let listener = tokio::net::TcpListener::from_std(socket.into())?;
            let addr_str = addr.clone();
            info!("Web admin HTTP (redirect) listening on {}", addr_str);
            handles.push(tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, redirect_app.into_make_service()).await {
                    tracing::error!("HTTP redirect server error on {}: {}", addr_str, e);
                }
            }));
        }
    } else {
        // Normal HTTP mode
        for addr in listen {
            let app = app.clone();
            let sock_addr: std::net::SocketAddr = addr.parse()?;
            let domain = if sock_addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
            let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
            socket.set_reuse_port(true)?;
            socket.set_nonblocking(true)?;
            socket.bind(&sock_addr.into())?;
            socket.listen(1024)?;
            let listener = tokio::net::TcpListener::from_std(socket.into())?;
            let addr_str = addr.clone();
            info!("Web admin listening on {}", addr_str);
            handles.push(tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
                    tracing::error!("Web server error on {}: {}", addr_str, e);
                }
            }));
        }
    }

    futures::future::join_all(handles).await;
    Ok(())
```

NOTE: The HTTPS listener implementation above is complex. The implementer should check if `axum-server` or `axum_server` crate with rustls support would simplify this. If a simpler approach exists, use it. The key requirements are: (1) bind TLS on https_listen addresses, (2) serve the same app router, (3) insert IsHttps extension, (4) support SO_REUSEPORT.

If the hyper/tower approach is too complex, an alternative is to add `axum-server = { version = "0.7", features = ["tls-rustls"] }` as a dependency and use its TLS listener.

- [ ] **Step 5: Update the call site in main.rs**

In `src/main.rs`, find where `run_web_server` is called:

```rust
    let web_listen = config.web.listen.clone();
    let web_handle = tokio::spawn(async move {
        if let Err(e) = web::run_web_server(&web_listen, web_state).await {
```

Replace with:

```rust
    let web_listen = config.web.listen.clone();
    let web_https_listen = config.web.https_listen.clone();

    // Build TLS config for web HTTPS (only if user-uploaded cert is configured)
    let web_tls_config = if config.tls.cert_path.is_some() && config.tls.key_path.is_some() && web_https_listen.is_some() {
        match tls::build_server_config(&config.tls, vec![b"h2".to_vec(), b"http/1.1".to_vec()]) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                tracing::warn!("Failed to build web TLS config: {}. HTTPS disabled.", e);
                None
            }
        }
    } else {
        None
    };

    let web_handle = tokio::spawn(async move {
        if let Err(e) = web::run_web_server(
            &web_listen,
            web_https_listen.as_deref(),
            web_tls_config,
            web_state,
        ).await {
            tracing::error!("Web server error: {}", e);
        }
    });
```

- [ ] **Step 6: Add tokio-rustls and hyper-util dependencies if needed**

Check `Cargo.toml` — `tokio-rustls` is already present. `hyper-util` may be needed for the TLS serving approach. If the implementer uses `axum-server`, add that instead. The goal is whatever compiles cleanly.

- [ ] **Step 7: Run tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 8: Commit**

```bash
git add src/web/mod.rs src/main.rs Cargo.toml Cargo.lock
git commit -m "feat: add optional HTTPS listener with HTTP redirect and HSTS"
```

---

### Task 5: Final verification

- [ ] **Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass

- [ ] **Step 2: Verify build**

Run: `cargo build`
Expected: Success

- [ ] **Step 3: Verify CSP nonce is in middleware**

Run: `grep "nonce" src/web/mod.rs | head -5`
Expected: Shows nonce generation and CSP header with nonce

- [ ] **Step 4: Verify rate limiter tiers**

Run: `grep "rate_limiter" src/web/mod.rs | head -10`
Expected: Shows auth_rate_limiter and admin_rate_limiter usage

- [ ] **Step 5: Verify HSTS in middleware**

Run: `grep "STRICT_TRANSPORT_SECURITY\|HSTS\|hsts" src/web/mod.rs`
Expected: Shows HSTS header insertion

- [ ] **Step 6: Verify https_listen config field**

Run: `grep "https_listen" src/config.rs`
Expected: Shows the field in WebConfig
