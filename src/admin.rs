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
    let local = listener.local_addr()?;
    if !local.ip().to_canonical().is_loopback() && state.token.trim().is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "external admin listener requires a token"));
    }
    let router = router(state);
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
    let users = match state.registry.snapshot_usage(|| state.store.list_users()) {
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
        upload = upload.saturating_add(user.upload);
        download = download.saturating_add(user.download);
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
    match state.registry.snapshot_usage(|| state.store.list_users()) {
        Ok(users) => {
            let views: Vec<UserView> = users.into_iter().map(|user| user_view(&state, user)).collect();
            Json(views).into_response()
        }
        Err(err) => store_error(err),
    }
}

async fn get_user(State(state): State<AdminState>, Path(id): Path<i64>) -> Response {
    match state.registry.snapshot_usage(|| state.store.get_user(id).map(|user| user.into_iter().collect())) {
        Ok(mut users) if !users.is_empty() => Json(user_view(&state, users.remove(0))).into_response(),
        Ok(_) => error_response(StatusCode::NOT_FOUND, "user not found"),
        Err(err) => store_error(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn queries_count_persisted_and_pending_bytes_once() {
        let store = Store::open_memory().unwrap();
        let spec = UserSpec {
            id: 1,
            uuid: "query-test-user".into(),
            speed_limit: 0,
            device_limit: 0,
            transfer_enable: 130,
            expired_at: 0,
            enabled: true,
        };
        store.replace_users(&[spec]).unwrap();
        let registry = Arc::new(Registry::new(std::time::Duration::from_secs(60)));
        registry.apply_users(&store.list_users().unwrap());
        let relay = registry.state(1).unwrap();
        relay.record_upload(100);
        registry.persist_pending(|d| store.stage_traffic(d)).unwrap();
        relay.record_download(40);
        let state =
            AdminState { store, registry, counters: Arc::new(Counters::default()), token: Arc::new(String::new()) };
        let response = stats(State(state.clone())).await;
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let stats: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(100, stats["upload"]);
        assert_eq!(40, stats["download"]);
        assert_eq!(0, stats["active_users"]);
        let response = get_user(State(state), Path(1)).await;
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let user: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(140, user["used"]);
        assert_eq!(0, user["remaining"]);
        assert_eq!(false, user["active"]);
    }

    #[test]
    fn constant_time_eq_behaviour() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
