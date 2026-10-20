//! Panel client tests against a mock Xboard server.
//!
//! The mock records every request and replies with the response bodies the
//! panel produces, so these tests pin the protocol shape (paths, auth
//! placement and payload keys) that the node depends on.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use xboard_snell::config::{PanelConfig, Traffic};
use xboard_snell::panel::{PanelClient, SystemStatus, build_metrics};

#[derive(Clone, Default)]
struct Recorded {
    requests: Arc<Mutex<Vec<(String, String, Value)>>>,
}

impl Recorded {
    fn push(&self, method: &str, uri: &Uri, body: &Value) {
        let query = uri.query().unwrap_or("").to_string();
        self.requests.lock().unwrap().push((method.into(), query, body.clone()));
    }

    fn take(&self) -> Vec<(String, String, Value)> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

async fn mock_panel(recorded: Recorded) -> Router {
    Router::new()
        .route(
            "/api/v2/server/handshake",
            post(|State(r): State<Recorded>, uri: Uri, Json(body): Json<Value>| async move {
                r.push("POST", &uri, &body);
                Json(json!({"websocket": {"enabled": false}}))
            }),
        )
        .route(
            "/api/v2/server/config",
            get(|State(r): State<Recorded>, uri: Uri| async move {
                r.push("GET", &uri, &Value::Null);
                Json(json!({
                    "protocol": "snell",
                    "listen_ip": "0.0.0.0",
                    "server_port": 6160,
                    "base_config": {"push_interval": 60, "pull_interval": 60}
                }))
            }),
        )
        .route(
            "/api/v2/server/user",
            get(|State(r): State<Recorded>, uri: Uri| async move {
                r.push("GET", &uri, &Value::Null);
                Json(json!({"users": [
                    {"id": 1, "uuid": "alice", "speed_limit": 100, "device_limit": 3},
                    {"id": 2, "uuid": "bob", "speed_limit": 0, "device_limit": 0}
                ]}))
            }),
        )
        .route(
            "/api/v2/server/report",
            post(|State(r): State<Recorded>, uri: Uri, Json(body): Json<Value>| async move {
                r.push("POST", &uri, &body);
                Json(json!({"data": true}))
            }),
        )
        .route(
            "/api/v1/server/UniProxy/push",
            post(|State(r): State<Recorded>, uri: Uri, Json(body): Json<Value>| async move {
                r.push("POST", &uri, &body);
                Json(json!({"data": true}))
            }),
        )
        .route(
            "/api/v1/server/UniProxy/status",
            post(|State(r): State<Recorded>, uri: Uri, Json(body): Json<Value>| async move {
                r.push("POST", &uri, &body);
                Json(json!({"data": true, "code": 0, "message": "success"}))
            }),
        )
        .with_state(recorded)
}

async fn start_mock() -> (Recorded, String) {
    let recorded = Recorded::default();
    let router: Router = mock_panel(recorded.clone()).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (recorded, format!("http://{address}"))
}

fn client(url: String, api_version: u8) -> PanelClient {
    PanelClient::new(PanelConfig {
        url,
        token: "panel-token".into(),
        node_id: 7,
        pull_interval: 60,
        push_interval: 60,
        api_version,
        ws_url: None,
        machine_id: None,
    })
    .unwrap()
}

#[tokio::test]
async fn v2_handshake_and_user_sync_match_panel_contract() {
    let (recorded, url) = start_mock().await;
    let client = client(url, 2);
    let handshake = client.handshake().await.unwrap();
    assert!(!handshake.websocket.enabled);

    let users = client.fetch_users().await.unwrap();
    assert_eq!(2, users.len());
    assert_eq!(1, users[0].id);
    assert_eq!("alice", users[0].uuid);
    assert_eq!(100, users[0].speed_limit);
    assert_eq!(3, users[0].device_limit);

    let config = client.fetch_config().await.unwrap();
    assert_eq!("snell", config.protocol);
    assert_eq!(6160, config.server_port);

    let requests = recorded.take();
    // Handshake: auth fields in the JSON body.
    assert_eq!("POST", requests[0].0);
    assert_eq!("panel-token", requests[0].2["token"]);
    assert_eq!(7, requests[0].2["node_id"]);
    // GET endpoints: auth as query parameters.
    assert_eq!("GET", requests[1].0);
    assert!(requests[1].1.contains("token=panel-token"), "query {}", requests[1].1);
    assert!(requests[1].1.contains("node_id=7"), "query {}", requests[1].1);
    assert!(requests[2].1.contains("token=panel-token"));
}

#[tokio::test]
async fn v2_report_uses_panel_payload_shape() {
    let (recorded, url) = start_mock().await;
    let client = client(url, 2);
    let traffic = vec![(1, Traffic { upload: 10, download: 20 }), (2, Traffic { upload: 1, download: 2 })];
    let alive = vec![(1, vec!["1.2.3.4".to_string()])];
    let online = vec![(1, 2)];
    let status = SystemStatus {
        cpu: 5.0,
        mem_total: 100,
        mem_used: 50,
        swap_total: 0,
        swap_used: 0,
        disk_total: 200,
        disk_used: 100,
    };
    let metrics = build_metrics(1, 2, 3, 4, 1, 0, 0);
    client.report(&traffic, &alive, &online, status, metrics).await.unwrap();

    let requests = recorded.take();
    let (method, _, body) = &requests[0];
    assert_eq!("POST", method);
    // Traffic is keyed by user id with [upload, download] pairs.
    assert_eq!(json!([10, 20]), body["traffic"]["1"]);
    assert_eq!(json!([1, 2]), body["traffic"]["2"]);
    assert_eq!(json!(["1.2.3.4"]), body["alive"]["1"]);
    assert_eq!(json!(2), body["online"]["1"]);
    assert_eq!(json!(5.0), body["status"]["cpu"]);
    assert_eq!(json!(100), body["status"]["mem"]["total"]);
    assert_eq!(json!(50), body["status"]["mem"]["used"]);
    assert_eq!(json!(200), body["status"]["disk"]["total"]);
    assert!(body["metrics"]["uptime"].is_number());
    assert_eq!("panel-token", body["token"]);
    assert_eq!(7, body["node_id"]);
}

#[tokio::test]
async fn v1_traffic_and_status_match_panel_contract() {
    let (recorded, url) = start_mock().await;
    let client = client(url, 1);
    client.push_traffic(&[(1, Traffic { upload: 3, download: 4 })]).await.unwrap();
    client.push_status(SystemStatus { cpu: 1.0, mem_total: 2, mem_used: 1, ..Default::default() }).await.unwrap();

    let requests = recorded.take();
    assert_eq!("POST", requests[0].0);
    // V1 pushes the traffic map at the top level, not under "traffic".
    assert_eq!(json!([3, 4]), requests[0].2["1"]);
    assert_eq!("panel-token", requests[0].2["token"]);
    assert_eq!(json!(1.0), requests[1].2["cpu"]);
    assert_eq!(json!(2), requests[1].2["mem"]["total"]);
}

#[tokio::test]
async fn machine_mode_uses_machine_auth() {
    let (recorded, url) = start_mock().await;
    let mut config = PanelConfig {
        url,
        token: "machine-token".into(),
        node_id: 0,
        pull_interval: 60,
        push_interval: 60,
        api_version: 2,
        ws_url: None,
        machine_id: Some(9),
    };
    config.node_id = 0;
    let client = PanelClient::new(config).unwrap();
    // Only the request shape matters here; the mock returns users for /user.
    let _ = client.fetch_users().await;
    let requests = recorded.take();
    assert!(requests[0].1.contains("machine_id=9"), "query {}", requests[0].1);
    assert!(!requests[0].1.contains("node_id"), "machine mode must not send node_id");
}

#[allow(dead_code)]
fn _headers(_: HeaderMap) {}

#[allow(dead_code)]
fn _json(_: impl IntoResponse) {}
