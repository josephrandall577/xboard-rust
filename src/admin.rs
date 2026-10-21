//! Read-only local health, statistics and panel user queries.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tracing::info;

use crate::accounting::{Counters, Registry};
use crate::config::{UserSpec, unix_now};
use crate::store::{Store, StoreError};

#[derive(Clone)]
pub struct AdminState {
    pub store: Store,
    pub registry: Arc<Registry>,
    pub counters: Arc<Counters>,
    pub token: Arc<String>,
}

pub fn router(state: AdminState) -> Router {
    let protected = Router::new()
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/users", get(list_users))
        .route("/api/v1/users/{id}", get(get_user))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth))
        .with_state(state.clone());
    // Health stays public so process supervisors can probe it without the
    // admin token.
    Router::new().route("/health", get(health)).merge(protected)
}

pub async fn serve(listen: &str, state: AdminState) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    serve_listener(listener, state).await
}

pub async fn serve_listener(listener: tokio::net::TcpListener, state: AdminState) -> std::io::Result<()> {
    let router = router(state);
    let local = listener.local_addr()?;
    info!(%local, "admin api listening");
    axum::serve(listener, router).await
}

async fn auth(
    State(state): State<AdminState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if state.token.is_empty() {
        return next.run(request).await;
    }
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .or_else(|| headers.get("x-api-token").and_then(|value| value.to_str().ok()));
    match provided {
        Some(token) if constant_time_eq(token.as_bytes(), state.token.as_bytes()) => next.run(request).await,
        _ => (StatusCode::UNAUTHORIZED, Json(ErrorBody { error: "invalid token".to_string() })).into_response(),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(ErrorBody { error: message.into() })).into_response()
}

fn store_error(err: StoreError) -> Response {
    match err {
        StoreError::DuplicateUuid(_) => error_response(StatusCode::CONFLICT, err.to_string()),
        StoreError::Invalid(_) => error_response(StatusCode::BAD_REQUEST, err.to_string()),
        StoreError::Sqlite(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok", "time": unix_now()}))
}

#[derive(Serialize)]
struct UserView {
    #[serde(flatten)]
    spec: UserSpec,
    upload: u64,
    download: u64,
    used: u64,
    remaining: Option<u64>,
    active: bool,
    online_connections: usize,
    devices: usize,
    blocked: bool,
}

fn user_view(state: &AdminState, user: crate::config::User) -> UserView {
    let now = std::time::Instant::now();
    let ttl = state.registry.device_ttl();
    let (online_connections, devices) =
        state.registry.state(user.id).map(|s| (s.online_connections(), s.device_count(ttl, now))).unwrap_or((0, 0));
    UserView {
        upload: user.upload,
        download: user.download,
        used: user.used(),
        remaining: user.remaining(),
        active: user.is_active(unix_now()),
        online_connections,
        devices,
        blocked: state.registry.is_blocked(user.id),
        spec: UserSpec::from(&user),
    }
}

#[derive(Serialize)]
struct Stats {
    uptime_seconds: u64,
    users: usize,
    active_users: usize,
    active_connections: u64,
    total_connections: u64,
    device_limit_hits: u64,
    quota_rejects: u64,
    upload: u64,
    download: u64,
    online: HashMap<i64, usize>,
}

async fn stats(State(state): State<AdminState>) -> Response {
    let users = match state.store.list_users() {
        Ok(users) => users,
        Err(err) => return store_error(err),
    };
    let now = std::time::Instant::now();
    let ttl = state.registry.device_ttl();
    let mut upload = 0u64;
    let mut download = 0u64;
    let mut online = HashMap::new();
    let mut active_users = 0usize;
    for user in &users {
        let pending = state.registry.state(user.id).map(|s| s.totals()).unwrap_or_default();
        upload = upload.saturating_add(user.upload).saturating_add(pending.upload);
        download = download.saturating_add(user.download).saturating_add(pending.download);
        if let Some(state) = state.registry.state(user.id) {
            let devices = state.device_count(ttl, now);
            if devices > 0 {
                online.insert(user.id, devices);
            }
            if user.is_active(unix_now()) {
                active_users += 1;
            }
        }
    }
    let body = Stats {
        uptime_seconds: crate::uptime_seconds(),
        users: users.len(),
        active_users,
        active_connections: state.counters.active.load(std::sync::atomic::Ordering::Relaxed),
        total_connections: state.counters.total.load(std::sync::atomic::Ordering::Relaxed),
        device_limit_hits: state.counters.device_limit_hits.load(std::sync::atomic::Ordering::Relaxed),
        quota_rejects: state.counters.quota_rejects.load(std::sync::atomic::Ordering::Relaxed),
        upload,
        download,
        online,
    };
    Json(body).into_response()
}

async fn list_users(State(state): State<AdminState>) -> Response {
    match state.store.list_users() {
        Ok(users) => {
            let views: Vec<UserView> = users.into_iter().map(|user| user_view(&state, user)).collect();
            Json(views).into_response()
        }
        Err(err) => store_error(err),
    }
}

async fn get_user(State(state): State<AdminState>, Path(id): Path<i64>) -> Response {
    match state.store.get_user(id) {
        Ok(Some(user)) => Json(user_view(&state, user)).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "user not found"),
        Err(err) => store_error(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_behaviour() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
