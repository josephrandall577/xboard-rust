//! Node startup, shutdown and panel delivery through real local sockets.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use xboard_snell::config::{Config, UserSpec};
use xboard_snell::node::Node;

fn managed_config(path: &std::path::Path) -> Config {
    let mut config = Config::load(concat!(env!("CARGO_MANIFEST_DIR"), "/config.multi-node.example.toml")).unwrap();
    config.nodes.truncate(1);
    config.nodes[0].listen = "127.0.0.1:0".into();
    config.nodes[0].admin.disabled = true;
    config.nodes[0].panel.url = "http://127.0.0.1:9".into();
    config.nodes[0].panel.push_interval = 3600;
    config.nodes[0].panel.pull_interval = 3600;
    config.storage.path = path.to_string_lossy().into_owned();
    config
}

fn user() -> UserSpec {
    UserSpec {
        id: 7,
        uuid: "lifecycle-user".into(),
        speed_limit: 0,
        device_limit: 0,
        transfer_enable: 0,
        expired_at: 0,
        enabled: true,
    }
}

#[test]
fn managed_nodes_reject_mapped_listen_ips() {
    for ip in ["::ffff:0.0.0.0", "::ffff:127.0.0.1", "::ffff:192.0.2.10"] {
        let mut config = managed_config(std::path::Path::new("unused.db"));
        config.nodes[0].listen = format!("[{ip}]:6160");
        assert!(config.validate().is_err(), "mapped listen IP must be rejected: {ip}");
    }
}

#[test]
fn admin_conflicts_are_rejected_in_both_node_orders() {
    for reverse in [false, true] {
        let mut config = Config::load(concat!(env!("CARGO_MANIFEST_DIR"), "/config.multi-node.example.toml")).unwrap();
        config.nodes[0].admin.listen = config.nodes[1].listen.clone();
        config.nodes[1].admin.disabled = true;
        if reverse {
            config.nodes.reverse();
        }
        assert!(config.validate().is_err(), "admin/listener overlap; reversed={reverse}");
    }
}

#[test]
fn wildcard_admins_cannot_cover_another_node_endpoint() {
    for wildcard in ["0.0.0.0:6162", "[::]:6162", "[::ffff:0.0.0.0]:6162"] {
        let mut config = Config::load(concat!(env!("CARGO_MANIFEST_DIR"), "/config.multi-node.example.toml")).unwrap();
        config.nodes[0].admin.listen = wildcard.into();
        assert!(config.validate().is_err(), "wildcard overlaps another admin: {wildcard}");
    }
}

#[tokio::test]
async fn occupied_admin_fails_start_without_leaking_snell_listener() {
    let temp = tempfile::tempdir().unwrap();
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let snell_address = reserved.local_addr().unwrap();
    drop(reserved);
    let mut config = managed_config(&temp.path().join("admin.db"));
    config.nodes[0].listen = snell_address.to_string();
    config.nodes[0].admin.disabled = false;
    config.nodes[0].admin.listen = blocker.local_addr().unwrap().to_string();
    let result = Node::start_many(config).await;
    if let Ok(nodes) = &result {
        for node in nodes {
            node.shutdown().await;
        }
    }
    assert!(result.is_err(), "startup must report admin bind failure");
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Ok(listener) = TcpListener::bind(snell_address).await {
                break listener;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed startup must release Snell listener");
}

#[derive(Clone, Default)]
struct PanelState {
    fail: Arc<AtomicBool>,
    accepted: Arc<Mutex<Vec<Value>>>,
    hold_first: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

async fn panel_report(State(state): State<PanelState>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    state.entered.notify_one();
    if state.hold_first.swap(false, Ordering::SeqCst) {
        state.release.notified().await;
    }
    if state.fail.load(Ordering::SeqCst) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"offline"})));
    }
    state.accepted.lock().unwrap().push(body);
    (StatusCode::OK, Json(json!({"data":true})))
}

async fn mock_panel(state: PanelState) -> (String, tokio::task::JoinHandle<()>) {
    let router = Router::new()
        .route("/api/v2/server/handshake", post(|| async { Json(json!({})) }))
        .route("/api/v2/server/report", post(panel_report))
        .route("/api/v1/server/UniProxy/push", post(panel_report))
        .route("/api/v1/server/UniProxy/alive", post(|| async { Json(json!({})) }))
        .route("/api/v1/server/UniProxy/status", post(|| async { Json(json!({})) }))
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (url, task)
}

async fn seed(node: &Node) {
    node.store.upsert_user(&user()).unwrap();
    node.registry.apply_users(&node.store.list_users().unwrap());
}

#[tokio::test]
async fn shutdown_reports_and_persists_the_same_traffic_once() {
    for version in [1, 2] {
        let temp = tempfile::tempdir().unwrap();
        let state = PanelState::default();
        let (url, task) = mock_panel(state.clone()).await;
        let mut config = managed_config(&temp.path().join("shutdown.db"));
        config.nodes[0].panel.url = url;
        config.nodes[0].panel.api_version = version;
        let nodes = Node::start_many(config).await.unwrap();
        let node = &nodes[0];
        seed(node).await;
        node.registry.state(7).unwrap().record_upload(123);
        node.registry.state(7).unwrap().record_download(45);
        node.shutdown().await;
        node.shutdown().await;
        assert_eq!(168, node.store.get_user(7).unwrap().unwrap().used());
        let reports = state.accepted.lock().unwrap();
        assert_eq!(1, reports.len(), "final traffic must be sent once; API v{version}");
        let traffic = if version == 1 { &reports[0]["7"] } else { &reports[0]["traffic"]["7"] };
        assert_eq!(&json!([123, 45]), traffic);
        task.abort();
    }
}

#[tokio::test]
async fn failed_shutdown_report_survives_restart_without_double_local_accounting() {
    let temp = tempfile::tempdir().unwrap();
    let state = PanelState::default();
    state.fail.store(true, Ordering::SeqCst);
    let (url, task) = mock_panel(state.clone()).await;
    let mut config = managed_config(&temp.path().join("retry.db"));
    config.nodes[0].panel.url = url;
    let nodes = Node::start_many(config.clone()).await.unwrap();
    seed(&nodes[0]).await;
    nodes[0].registry.state(7).unwrap().record_upload(123);
    nodes[0].shutdown().await;
    assert_eq!(123, nodes[0].store.get_user(7).unwrap().unwrap().upload);
    assert!(state.accepted.lock().unwrap().is_empty());
    drop(nodes);
    state.fail.store(false, Ordering::SeqCst);
    let nodes = Node::start_many(config).await.unwrap();
    nodes[0].registry.state(7).unwrap().record_download(45);
    nodes[0].shutdown().await;
    assert_eq!(168, nodes[0].store.get_user(7).unwrap().unwrap().used());
    let reports = state.accepted.lock().unwrap();
    assert_eq!(1, reports.len(), "persisted failed report must be retried");
    assert_eq!(json!([123, 45]), reports[0]["traffic"]["7"]);
    task.abort();
}

#[tokio::test]
async fn shutdown_waits_for_periodic_report_without_losing_or_duplicating_traffic() {
    let temp = tempfile::tempdir().unwrap();
    let state = PanelState::default();
    state.hold_first.store(true, Ordering::SeqCst);
    let (url, task) = mock_panel(state.clone()).await;
    let mut config = managed_config(&temp.path().join("concurrent.db"));
    config.nodes[0].panel.url = url;
    config.nodes[0].panel.push_interval = 0;
    let nodes = Node::start_many(config).await.unwrap();
    let node = &nodes[0];
    seed(node).await;
    node.registry.state(7).unwrap().record_upload(111);
    tokio::time::timeout(Duration::from_secs(2), state.entered.notified()).await.unwrap();
    node.registry.state(7).unwrap().record_download(22);
    let stopping = {
        let node = node.clone();
        tokio::spawn(async move { node.shutdown().await })
    };
    state.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), stopping).await.unwrap().unwrap();
    assert_eq!(133, node.store.get_user(7).unwrap().unwrap().used());
    let reports = state.accepted.lock().unwrap();
    assert_eq!(2, reports.len());
    assert_eq!(json!([111, 0]), reports[0]["traffic"]["7"]);
    assert_eq!(json!([0, 22]), reports[1]["traffic"]["7"]);
    task.abort();
}

#[tokio::test]
async fn failed_periodic_report_keeps_usage_visible_to_quota_checks() {
    let temp = tempfile::tempdir().unwrap();
    let state = PanelState::default();
    state.fail.store(true, Ordering::SeqCst);
    let (url, task) = mock_panel(state.clone()).await;
    let mut config = managed_config(&temp.path().join("quota.db"));
    config.nodes[0].panel.url = url;
    config.nodes[0].panel.push_interval = 0;
    let nodes = Node::start_many(config).await.unwrap();
    let node = &nodes[0];
    seed(node).await;
    node.registry.state(7).unwrap().record_upload(123);
    tokio::time::timeout(Duration::from_secs(2), state.entered.notified()).await.unwrap();
    let used = node.registry.used_bytes(7);
    node.shutdown().await;
    task.abort();
    assert_eq!(Some(123), used, "persisting pending traffic must not reset live quota usage");
}

#[tokio::test]
async fn shutdown_closes_active_relays_before_final_accounting() {
    use snell::{Conn, Socksaddr, TcpConn, v6};
    use tokio::io::AsyncReadExt;
    let temp = tempfile::tempdir().unwrap();
    let state = PanelState::default();
    let (url, task) = mock_panel(state.clone()).await;
    let mut config = managed_config(&temp.path().join("active.db"));
    config.nodes[0].panel.url = url;
    let nodes = Node::start_many(config).await.unwrap();
    let node = &nodes[0];
    seed(node).await;
    let server = node.server.read().await.clone().unwrap();
    server.update_users(&node.store.list_users().unwrap()).unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = v6::Client::new(v6::ClientOptions {
        psk: node.config.node.psk.as_bytes().to_vec(),
        user_key: user().uuid.into_bytes(),
        mode: v6::parse_mode(&node.config.node.mode).unwrap(),
        server: Socksaddr::from(server.local_addr()),
        ..Default::default()
    })
    .unwrap();
    let transport = tokio::net::TcpStream::connect(server.local_addr()).await.unwrap();
    let proxy = client
        .dial_conn(Arc::new(TcpConn::new(transport).unwrap()), target.local_addr().unwrap().into())
        .await
        .unwrap();
    proxy.write(b"ping").await.unwrap();
    let (mut upstream, _) = target.accept().await.unwrap();
    let mut bytes = [0; 4];
    upstream.read_exact(&mut bytes).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), node.shutdown()).await.unwrap();
    assert_eq!(0, node.counters.active.load(Ordering::SeqCst), "relay tasks must stop before the final report");
    assert_eq!(4, node.store.get_user(7).unwrap().unwrap().upload);
    assert_eq!(json!([4, 0]), state.accepted.lock().unwrap()[0]["traffic"]["7"]);
    let _ = proxy.close().await;
    task.abort();
}

#[tokio::test]
async fn admin_is_ready_at_start_and_released_when_shutdown_returns() {
    let temp = tempfile::tempdir().unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut config = managed_config(&temp.path().join("ready.db"));
    config.nodes[0].admin.disabled = false;
    config.nodes[0].admin.listen = address.to_string();
    let nodes = Node::start_many(config).await.unwrap();
    let response = reqwest::Client::new()
        .get(format!("http://{address}/health"))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .unwrap();
    assert_eq!(StatusCode::OK, response.status());
    nodes[0].shutdown().await;
    assert!(TcpListener::bind(address).await.is_ok(), "shutdown must release the admin endpoint before returning");
}

#[tokio::test]
async fn shutdown_closes_udp_association_before_final_accounting() {
    use snell::{Buffer, PacketConn, TcpConn, v6};
    let temp = tempfile::tempdir().unwrap();
    let state = PanelState::default();
    let (url, task) = mock_panel(state.clone()).await;
    let mut config = managed_config(&temp.path().join("udp.db"));
    config.nodes[0].panel.url = url;
    let nodes = Node::start_many(config).await.unwrap();
    let node = &nodes[0];
    seed(node).await;
    let server = node.server.read().await.clone().unwrap();
    server.update_users(&node.store.list_users().unwrap()).unwrap();
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = v6::Client::new(v6::ClientOptions {
        psk: node.config.node.psk.as_bytes().to_vec(),
        user_key: user().uuid.into_bytes(),
        mode: v6::parse_mode(&node.config.node.mode).unwrap(),
        server: server.local_addr().into(),
        ..Default::default()
    })
    .unwrap();
    let transport = tokio::net::TcpStream::connect(server.local_addr()).await.unwrap();
    let proxy = client.dial_packet_conn(Arc::new(TcpConn::new(transport).unwrap())).unwrap();
    let buffer = Buffer::from_slice_with_headroom(b"ping", proxy.front_headroom(), proxy.rear_headroom());
    proxy.write_packet(buffer, target.local_addr().unwrap().into()).await.unwrap();
    let mut bytes = [0; 4];
    tokio::time::timeout(Duration::from_secs(2), target.recv_from(&mut bytes)).await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(2), node.shutdown()).await.unwrap();
    assert_eq!(0, node.counters.active.load(Ordering::SeqCst));
    assert_eq!(4, node.store.get_user(7).unwrap().unwrap().upload);
    assert_eq!(json!([4, 0]), state.accepted.lock().unwrap()[0]["traffic"]["7"]);
    let _ = proxy.close().await;
    task.abort();
}
