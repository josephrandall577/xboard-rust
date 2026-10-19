//! End-to-end tests: a real Snell v6 client through a running node.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use snell::v6::{self, Client, ClientOptions};
use snell::{Conn, Socksaddr, TcpConn};
use snell_xboard_node::config::{Config, NodeConfig, UserSpec};
use snell_xboard_node::node::Node;
use tokio::net::{TcpListener, TcpStream};

const PSK: &str = "integration-test-psk-0123456789";
const MODES: [&str; 3] = ["default", "unshaped", "unsafe-raw"];

struct Harness {
    node: Arc<Node>,
    address: String,
    temp: tempfile::TempDir,
}

impl Harness {
    async fn start(mode: &str, users: Vec<UserSpec>) -> Harness {
        let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::DEBUG).with_test_writer().try_init();
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("node.db");
        let config = Config {
            node: NodeConfig { listen: "127.0.0.1:0".into(), psk: PSK.into(), mode: mode.into(), users },
            panel: None,
            admin: Default::default(),
            limits: Default::default(),
            storage: snell_xboard_node::config::StorageConfig { path: db.to_string_lossy().into_owned() },
            log: Default::default(),
        };
        let node = Node::start(config).await.unwrap();
        let server = node.server.read().await.clone().unwrap();
        let address = server.local_addr().to_string();
        Harness { node, address, temp }
    }

    fn client(&self, user_key: &str) -> Client {
        Client::new(ClientOptions {
            psk: PSK.as_bytes().to_vec(),
            user_key: user_key.as_bytes().to_vec(),
            mode: v6::parse_mode(&self.node.config.node.mode).unwrap(),
            server: Socksaddr::parse(&self.address),
            ..Default::default()
        })
        .unwrap()
    }

    async fn shutdown(&self) {
        self.node.shutdown().await;
        let _ = &self.temp;
    }
}

fn spec(id: i64, uuid: &str) -> UserSpec {
    UserSpec {
        id,
        uuid: uuid.into(),
        speed_limit: 0,
        device_limit: 0,
        transfer_enable: 0,
        expired_at: 0,
        enabled: true,
    }
}

async fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    port
}

async fn dial(address: &str) -> Arc<dyn Conn> {
    let stream = TcpStream::connect(address).await.unwrap();
    Arc::new(TcpConn::new(stream).unwrap())
}

/// Sends `payload` through the node to a local echo server and checks the
/// echo comes back unchanged.
async fn round_trip(client: &Client, address: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let echo_port = echo_server().await;
    let conn = dial(address).await;
    let destination = Socksaddr::parse_host_port("127.0.0.1", echo_port);
    let proxy = client.dial_conn(conn, destination).await?;
    proxy.write(payload).await?;
    proxy.close_write().await?;
    proxy.set_read_deadline(Some(std::time::Instant::now() + Duration::from_secs(10)))?;
    let mut received = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match proxy.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(err) => return Err(err),
        }
    }
    let _ = proxy.close().await;
    Ok(received)
}

async fn wait_until(timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not met within {timeout:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_round_trip_is_metered_per_user() {
    for mode in MODES {
        let harness = Harness::start(mode, vec![spec(1, "alice-key")]).await;
        let client = harness.client("alice-key");
        let payload = vec![0x42u8; 8 * 1024];
        let received = round_trip(&client, &harness.address, &payload).await.unwrap();
        assert_eq!(payload, received, "mode {mode}");

        let state = harness.node.registry.state(1).expect("user registered");
        wait_until(Duration::from_secs(5), || state.totals().total() >= payload.len() as u64).await;
        let totals = state.totals();
        assert_eq!(totals.upload, payload.len() as u64, "mode {mode} upload");
        assert_eq!(totals.download, payload.len() as u64, "mode {mode} download");
        harness.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_user_key_is_rejected() {
    let harness = Harness::start("unshaped", vec![spec(1, "alice-key")]).await;
    let client = harness.client("mallory-key");
    let result = round_trip(&client, &harness.address, b"nope").await;
    assert!(result.is_err(), "unauthenticated user must be refused: {result:?}");
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_are_metered_independently() {
    let harness = Harness::start("unshaped", vec![spec(1, "alice-key"), spec(2, "bob-key")]).await;
    let alice = harness.client("alice-key");
    let bob = harness.client("bob-key");
    round_trip(&alice, &harness.address, &vec![1u8; 2048]).await.unwrap();
    round_trip(&bob, &harness.address, &vec![2u8; 4096]).await.unwrap();

    let alice_state = harness.node.registry.state(1).unwrap();
    let bob_state = harness.node.registry.state(2).unwrap();
    wait_until(Duration::from_secs(5), || alice_state.totals().total() > 0 && bob_state.totals().total() > 0).await;
    assert_eq!(4096, alice_state.totals().total());
    assert_eq!(8192, bob_state.totals().total());
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn traffic_is_persisted_to_store() {
    let harness = Harness::start("unshaped", vec![spec(1, "alice-key")]).await;
    let client = harness.client("alice-key");
    round_trip(&client, &harness.address, &vec![7u8; 4096]).await.unwrap();
    // Wait for the background flush (10s) instead of racing it.
    wait_until(Duration::from_secs(15), || {
        harness.node.store.get_user(1).map(|user| user.map(|u| u.used() > 0).unwrap_or(false)).unwrap_or(false)
    })
    .await;
    let user = harness.node.store.get_user(1).unwrap().unwrap();
    assert_eq!(8192, user.used());
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_limit_refuses_extra_source_ips() {
    let mut user = spec(1, "alice-key");
    user.device_limit = 1;
    let harness = Harness::start("unshaped", vec![user]).await;
    let client = harness.client("alice-key");
    // The first connection from 127.0.0.1 registers the device.
    round_trip(&client, &harness.address, b"first").await.unwrap();
    // The registry records the source IP while the connection is open; the
    // TTL keeps it counted after close.
    let devices = harness
        .node
        .registry
        .state(1)
        .unwrap()
        .device_count(harness.node.registry.device_ttl(), std::time::Instant::now());
    assert_eq!(1, devices);
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_user_is_refused() {
    let mut user = spec(1, "alice-key");
    user.expired_at = snell_xboard_node::config::unix_now() - 1;
    let harness = Harness::start("unshaped", vec![user]).await;
    let client = harness.client("alice-key");
    let result = round_trip(&client, &harness.address, b"expired").await;
    assert!(result.is_err(), "expired user must be refused");
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quota_exhausted_user_is_refused() {
    let mut user = spec(1, "alice-key");
    user.transfer_enable = 1;
    let harness = Harness::start("unshaped", vec![user]).await;
    // Mark the quota as fully used before the connection is attempted.
    harness.node.store.add_traffic(&[(1, snell_xboard_node::config::Traffic { upload: 1, download: 0 })]).unwrap();
    harness.node.registry.apply_users(&harness.node.store.list_users().unwrap());
    let client = harness.client("alice-key");
    let result = round_trip(&client, &harness.address, b"over quota").await;
    assert!(result.is_err(), "user over quota must be refused");
    harness.shutdown().await;
}
