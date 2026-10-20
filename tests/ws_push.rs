//! WebSocket push tests: panel events update the local user set.

use std::time::Duration;

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use serde_json::json;
use xboard_snell::store::Store;
use xboard_snell::ws;

#[derive(Clone, Default)]
struct Params {
    seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

async fn upgrade(
    ws: WebSocketUpgrade,
    Query(query): Query<Vec<(String, String)>>,
    State(params): State<Params>,
) -> Response {
    params.seen.lock().unwrap().extend(query);
    ws.on_upgrade(handle)
}

async fn handle(mut socket: WebSocket) {
    let event = json!({
        "event": "sync.users",
        "data": {"users": [
            {"id": 1, "uuid": "alice-key", "speed_limit": 128, "device_limit": 2},
            {"id": 2, "uuid": "bob-key", "speed_limit": 0, "device_limit": 0}
        ]}
    });
    let _ = socket.send(Message::Text(event.to_string().into())).await;
    // Keep the socket open so the client stays connected during the test.
    tokio::time::sleep(Duration::from_secs(2)).await;
}

async fn start_panel() -> (Params, String) {
    let params = Params::default();
    let router = Router::new().route("/ws", get(upgrade)).with_state(params.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (params, format!("ws://{address}/ws"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_users_event_updates_store() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).with_test_writer().try_init();
    let (params, url) = start_panel().await;
    let store = Store::open_memory().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(ws::run(url, "panel-token".into(), 7, None, store.clone(), tx, cancel.clone()));

    // Wait for the sync event to be forwarded to the node.
    let delivered = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("ws event not delivered")
        .expect("channel closed");
    assert_eq!(2, delivered.len());

    let users = store.list_users().unwrap();
    assert_eq!(2, users.len());
    assert_eq!("alice-key", users[0].uuid);
    assert_eq!(128, users[0].speed_limit);
    assert_eq!(2, users[0].device_limit);

    let query = params.seen.lock().unwrap().clone();
    assert!(query.iter().any(|(key, value)| key == "token" && value == "panel-token"), "{query:?}");
    assert!(query.iter().any(|(key, value)| key == "node_id" && value == "7"), "{query:?}");

    cancel.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
}
