use crate::auth::{AuthService, AuthenticatedUser};
use axum::{
    body::Body,
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

const PUBLIC_ROUTES: &[&str] = &[
    "/login",
    "/setup",
    "/api/auth/login",
    "/api/auth/setup",
];

pub async fn auth_middleware(
    axum::extract::State(auth): axum::extract::State<AuthService>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();

    // Check if setup is needed — redirect everything to /setup except setup routes
    if auth.needs_setup().await {
        if path == "/setup" || path == "/api/auth/setup" {
            return next.run(request).await;
        }
        if path.starts_with("/api/") {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        return Redirect::to("/setup").into_response();
    }

    // Public routes don't need auth
    if PUBLIC_ROUTES.contains(&path.as_str()) {
        return next.run(request).await;
    }

    // Try session cookie first
    let session_token = extract_cookie(&request, "oxi_session");
    if let Some(ref token) = session_token {
        if let Some(user) = auth.validate_session(token).await {
            let mut request = request;
            request.extensions_mut().insert(user);
            return next.run(request).await;
        }
    }

    // Try Bearer token
    let bearer_token = extract_bearer(&request);
    if let Some(ref token) = bearer_token {
        if let Some(user) = auth.validate_api_token(token).await {
            let mut request = request;
            request.extensions_mut().insert(user);
            return next.run(request).await;
        }
    }

    // Not authenticated
    if path.starts_with("/api/") {
        StatusCode::UNAUTHORIZED.into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

fn extract_cookie(request: &Request<Body>, name: &str) -> Option<String> {
    let header = request.headers().get(header::COOKIE)?;
    let header_str = header.to_str().ok()?;
    for pair in header_str.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{}=", name)) {
            return Some(value.to_string());
        }
    }
    None
}

fn extract_bearer(request: &Request<Body>) -> Option<String> {
    let header = request.headers().get(header::AUTHORIZATION)?;
    let header_str = header.to_str().ok()?;
    header_str
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}
