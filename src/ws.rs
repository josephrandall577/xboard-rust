//! Panel WebSocket push client.
//!
//! Xboard's node WebSocket authenticates through query parameters and pushes
//! `sync.users` / `sync.user.delta` events. The node applies full user syncs
//! by rewriting the local user set; everything else is handled by the regular
//! poll loop, which remains the baseline so a missing WebSocket is only a
//! latency change, never a correctness one.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::config::UserSpec;
use crate::panel::PanelClient;
use crate::store::Store;

#[derive(Deserialize)]
struct Envelope {
    event: String,
    #[serde(default)]
    data: serde_json::Value,
}

#[derive(Deserialize)]
struct UsersPayload {
    #[serde(default)]
    users: Vec<PanelUser>,
}

#[derive(Deserialize)]
struct PanelUser {
    id: i64,
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    speed_limit: u64,
    #[serde(default)]
    device_limit: u32,
}

impl From<PanelUser> for UserSpec {
    fn from(user: PanelUser) -> Self {
        UserSpec {
            id: user.id,
            uuid: user.uuid,
            speed_limit: user.speed_limit,
            device_limit: user.device_limit,
            transfer_enable: 0,
            expired_at: 0,
            enabled: true,
        }
    }
}

/// Runs the WebSocket client until cancelled, reconnecting with backoff.
///
/// Full user syncs are written to the store and then forwarded to the node,
/// which applies them to the live listener as well.
pub async fn run(
    url: String,
    token: String,
    node_id: i64,
    machine_id: Option<i64>,
    store: Store,
    events: tokio::sync::mpsc::UnboundedSender<Vec<UserSpec>>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect(&url, &token, node_id, machine_id, &store, &events, &cancel).await {
            Ok(()) => return,
            Err(err) => {
                if cancel.is_cancelled() {
                    return;
                }
                warn!(error = %err, "panel websocket disconnected");
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

async fn connect(
    url: &str,
    token: &str,
    node_id: i64,
    machine_id: Option<i64>,
    store: &Store,
    events: &tokio::sync::mpsc::UnboundedSender<Vec<UserSpec>>,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut request = tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)?;
    {
        let mut query = request.uri().query().unwrap_or("").to_string();
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(&format!("token={}", urlencode(token)));
        match machine_id {
            Some(machine_id) => query.push_str(&format!("&machine_id={machine_id}")),
            None => query.push_str(&format!("&node_id={node_id}")),
        }
        // Preserve scheme and authority: only the query is extended.
        let path = request.uri().path().to_string();
        let uri = format!(
            "{}://{}{}?{}",
            request.uri().scheme_str().unwrap_or("ws"),
            request.uri().authority().ok_or("websocket url has no host")?,
            path,
            query
        );
        *request.uri_mut() = uri.parse()?;
    }

    let (mut socket, _) = tokio_tungstenite::connect_async(request).await?;
    info!(url, "panel websocket connected");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = socket.close(None).await;
                return Ok(());
            }
            message = socket.next() => {
                let Some(message) = message else {
                    return Err("websocket closed".into());
                };
                let message = message?;
                match message {
                    Message::Text(text) => {
                        if let Err(err) = handle_message(&text, store, events) {
                            warn!(error = %err, "invalid websocket event");
                        }
                    }
                    Message::Ping(payload) => {
                        socket.send(Message::Pong(payload)).await?;
                    }
                    Message::Close(_) => return Err("websocket closed by panel".into()),
                    _ => {}
                }
            }
        }
    }
}

fn handle_message(
    text: &str,
    store: &Store,
    events: &tokio::sync::mpsc::UnboundedSender<Vec<UserSpec>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let envelope: Envelope = serde_json::from_str(text)?;
    match envelope.event.as_str() {
        "ping" => Ok(()),
        "auth.success" => {
            debug!("websocket authenticated");
            Ok(())
        }
        "sync.users" => {
            let payload: UsersPayload = serde_json::from_value(envelope.data)?;
            if payload.users.is_empty() {
                return Ok(());
            }
            let users: Vec<UserSpec> = payload.users.into_iter().map(Into::into).collect();
            let specs = users.clone();
            store.replace_users(&users)?;
            info!(users = users.len(), "websocket user sync applied");
            let _ = events.send(specs);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[allow(dead_code)]
fn _panel(_: &PanelClient) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::open_memory().unwrap()
    }

    #[test]
    fn sync_users_replaces_user_set() {
        let store = store();
        store
            .replace_users(&[UserSpec {
                id: 1,
                uuid: "a".into(),
                speed_limit: 0,
                device_limit: 0,
                transfer_enable: 0,
                expired_at: 0,
                enabled: true,
            }])
            .unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let event =
            r#"{"event":"sync.users","data":{"users":[{"id":2,"uuid":"b","speed_limit":10,"device_limit":2}]}}"#;
        handle_message(event, &store, &tx).unwrap();
        let users = store.list_users().unwrap();
        assert_eq!(1, users.len());
        assert_eq!(2, users[0].id);
        assert_eq!(10, users[0].speed_limit);
        assert_eq!(2, users[0].device_limit);
    }

    #[test]
    fn user_delta_is_left_to_polling() {
        let store = store();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let event = r#"{"event":"sync.user.delta","data":{"action":"add","users":[{"id":3,"uuid":"c"}]}}"#;
        handle_message(event, &store, &tx).unwrap();
        assert!(store.list_users().unwrap().is_empty());
    }

    #[test]
    fn urlencode_escapes_specials() {
        assert_eq!("a%20b%26c", urlencode("a b&c"));
    }
}
