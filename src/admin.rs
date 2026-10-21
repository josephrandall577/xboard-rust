//! Local admin API.
//!
//! This is the node's management surface when no panel is configured (and a
//! convenience surface when one is): user CRUD, traffic reset, live stats and
//! health. All writes go through the store and are then pushed to the live
//! Snell service, so the data plane and the database never diverge.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::accounting::{Counters, Registry};
use crate::config::{UserSpec, unix_now};
use crate::server::SnellServer;
use crate::store::{Store, StoreError};

#[derive(Clone)]
pub struct AdminState {
    pub store: Store,
    pub registry: Arc<Registry>,
    pub counters: Arc<Counters>,
    pub server: Arc<tokio::sync::RwLock<Option<Arc<SnellServer>>>>,
    pub token: Arc<String>,
}

impl AdminState {
    pub async fn reload_users(&self) -> Result<(), StoreError> {
        let users = self.store.list_users()?;
        self.registry.apply_users(&users);
        let guard = self.server.read().await;
        if let Some(server) = guard.as_ref()
            && let Err(err) = server.update_users(&users)
        {
            return Err(StoreError::Invalid(format!("apply users to snell service: {err}")));
        }
        Ok(())
    }
}

pub fn router(state: AdminState) -> Router {
    let protected = Router::new()
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/{id}", get(get_user).put(update_user).delete(delete_user))
        .route("/api/v1/users/{id}/traffic", post(reset_user_traffic))
        .route("/api/v1/traffic/reset", post(reset_all_traffic))
        .route("/api/v1/users/{id}/block", put(block_user))
        .route("/api/v1/users/{id}/unblock", put(unblock_user))
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

#[derive(Deserialize)]
struct CreateUser {
    id: i64,
    uuid: String,
    #[serde(default)]
    speed_limit: u64,
    #[serde(default)]
    device_limit: u32,
    #[serde(default)]
    transfer_enable: u64,
    #[serde(default)]
    expired_at: i64,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

async fn create_user(State(state): State<AdminState>, Json(body): Json<CreateUser>) -> Response {
    let spec = UserSpec {
        id: body.id,
        uuid: body.uuid,
        speed_limit: body.speed_limit,
        device_limit: body.device_limit,
        transfer_enable: body.transfer_enable,
        expired_at: body.expired_at,
        enabled: body.enabled,
    };
    if state.store.get_user(spec.id).ok().flatten().is_some() {
        return error_response(StatusCode::CONFLICT, "user id already exists");
    }
    match state.store.upsert_user(&spec) {
        Ok(user) => match state.reload_users().await {
            Ok(()) => Json(user_view(&state, user)).into_response(),
            Err(err) => store_error(err),
        },
        Err(err) => store_error(err),
    }
}

async fn update_user(State(state): State<AdminState>, Path(id): Path<i64>, Json(body): Json<CreateUser>) -> Response {
    if body.id != id {
        return error_response(StatusCode::BAD_REQUEST, "user id in body does not match path");
    }
    match state.store.upsert_user(&UserSpec {
        id,
        uuid: body.uuid,
        speed_limit: body.speed_limit,
        device_limit: body.device_limit,
        transfer_enable: body.transfer_enable,
        expired_at: body.expired_at,
        enabled: body.enabled,
    }) {
        Ok(user) => match state.reload_users().await {
            Ok(()) => Json(user_view(&state, user)).into_response(),
            Err(err) => store_error(err),
        },
        Err(err) => store_error(err),
    }
}

async fn delete_user(State(state): State<AdminState>, Path(id): Path<i64>) -> Response {
    match state.store.delete_user(id) {
        Ok(true) => match state.reload_users().await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(err) => store_error(err),
        },
        Ok(false) => error_response(StatusCode::NOT_FOUND, "user not found"),
        Err(err) => store_error(err),
    }
}

async fn reset_user_traffic(State(state): State<AdminState>, Path(id): Path<i64>) -> Response {
    match state.store.reset_traffic(Some(id)) {
        Ok(0) => error_response(StatusCode::NOT_FOUND, "user not found"),
        Ok(_) => match state.reload_users().await {
            Ok(()) => Json(serde_json::json!({"data": true})).into_response(),
            Err(err) => store_error(err),
        },
        Err(err) => store_error(err),
    }
}

async fn reset_all_traffic(State(state): State<AdminState>) -> Response {
    match state.store.reset_traffic(None) {
        Ok(count) => match state.reload_users().await {
            Ok(()) => Json(serde_json::json!({"data": true, "users": count})).into_response(),
            Err(err) => store_error(err),
        },
        Err(err) => store_error(err),
    }
}

async fn block_user(State(state): State<AdminState>, Path(id): Path<i64>) -> Response {
    set_blocked(state, id, true).await
}

async fn unblock_user(State(state): State<AdminState>, Path(id): Path<i64>) -> Response {
    set_blocked(state, id, false).await
}

async fn set_blocked(state: AdminState, id: i64, blocked: bool) -> Response {
    if state.store.get_user(id).ok().flatten().is_none() {
        return error_response(StatusCode::NOT_FOUND, "user not found");
    }
    state.registry.set_blocked(id, blocked);
    Json(serde_json::json!({"data": true, "blocked": blocked})).into_response()
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
