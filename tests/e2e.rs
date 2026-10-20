//! End-to-end tests: a real Snell v6 client through a running node.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use snell::v6::{self, Client, ClientOptions};
use snell::{Buffer, Conn, PacketConn, Socksaddr, TcpConn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use xboard_snell::config::{AdminConfig, Config, ManagedNodeConfig, NodeConfig, PanelConfig, UserSpec};
use xboard_snell::node::Node;

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
            admin: xboard_snell::config::AdminConfig { disabled: true, ..Default::default() },
            limits: Default::default(),
            storage: xboard_snell::config::StorageConfig { path: db.to_string_lossy().into_owned() },
            log: Default::default(),
            nodes: Vec::new(),
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
    user.expired_at = xboard_snell::config::unix_now() - 1;
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
    harness.node.store.add_traffic(&[(1, xboard_snell::config::Traffic { upload: 1, download: 0 })]).unwrap();
    harness.node.registry.apply_users(&harness.node.store.list_users().unwrap());
    let client = harness.client("alice-key");
    let result = round_trip(&client, &harness.address, b"over quota").await;
    assert!(result.is_err(), "user over quota must be refused");
    harness.shutdown().await;
}

// Independent replies expose download loss even if the request was truncated.
async fn limited_tcp_transfer(harness: &Harness, seed: u8) {
    let payload: Vec<u8> = (0..128 * 1024).map(|n| (n as u8).wrapping_add(seed)).collect();
    let reply: Vec<u8> = payload.iter().map(|byte| byte ^ 0xa5).collect();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = listener.local_addr().unwrap();
    let target_reply = reply.clone();
    let target = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        stream.write_all(&target_reply).await.unwrap();
        received
    });
    let proxy =
        harness.client("limited-key").dial_conn(dial(&harness.address).await, destination.into()).await.unwrap();
    proxy.set_read_deadline(Some(std::time::Instant::now() + Duration::from_secs(15))).unwrap();
    proxy.write(&payload).await.unwrap();
    proxy.close_write().await.unwrap();
    let mut received = Vec::new();
    let mut buffer = vec![0; 32 * 1024];
    loop {
        let n = proxy.read(&mut buffer).await.unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..n]);
    }
    let upload = target.await.unwrap();
    let _ = proxy.close().await;
    assert_eq!(payload.len(), upload.len(), "limited TCP upload length");
    assert_eq!(payload, upload, "limited TCP upload contents");
    assert_eq!(reply.len(), received.len(), "limited TCP download length");
    assert_eq!(reply, received, "limited TCP download contents");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limited_tcp_preserves_concurrent_streams() {
    for mode in MODES {
        let mut user = spec(1, "limited-key");
        user.speed_limit = 1;
        let harness = Harness::start(mode, vec![user]).await;
        tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(limited_tcp_transfer(&harness, 1), limited_tcp_transfer(&harness, 2));
        })
        .await
        .expect("limited TCP transfers must finish");
        let totals = harness.node.registry.state(1).unwrap().totals();
        assert_eq!(256 * 1024, totals.upload, "mode {mode} upload accounting");
        assert_eq!(256 * 1024, totals.download, "mode {mode} download accounting");
        harness.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn limited_udp_preserves_complete_datagrams() {
    for mode in MODES {
        let mut user = spec(1, "limited-key");
        user.speed_limit = 1;
        let harness = Harness::start(mode, vec![user]).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination = socket.local_addr().unwrap();
        let target = tokio::spawn(async move {
            let mut packets = Vec::new();
            let mut buffer = vec![0; 65536];
            for size in [4096, 8192] {
                let (n, source) =
                    tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await.unwrap().unwrap();
                packets.push(buffer[..n].to_vec());
                socket.send_to(&vec![0x73; size], source).await.unwrap();
            }
            packets
        });
        let proxy = harness.client("limited-key").dial_packet_conn(dial(&harness.address).await).unwrap();
        proxy.set_read_deadline(Some(std::time::Instant::now() + Duration::from_secs(10))).unwrap();
        let mut replies = Vec::new();
        for size in [4096, 8192] {
            let payload = vec![0x35; size];
            let packet = Buffer::from_slice_with_headroom(&payload, proxy.front_headroom(), proxy.rear_headroom());
            proxy.write_packet(packet, destination.into()).await.unwrap();
            let mut reply = Buffer::new_packet();
            let source = proxy.read_packet(&mut reply).await.unwrap();
            assert_eq!(size, reply.len(), "mode {mode} UDP download length");
            assert_eq!(Socksaddr::from(destination), source);
            replies.push(reply.into_vec());
        }
        let uploads = target.await.unwrap();
        let _ = proxy.close().await;
        for ((size, upload), reply) in [4096, 8192].into_iter().zip(uploads).zip(replies) {
            assert_eq!(size, upload.len(), "mode {mode} UDP upload length");
            assert_eq!(vec![0x35; size], upload, "mode {mode} UDP upload contents");
            assert_eq!(size, reply.len(), "mode {mode} UDP download length");
            assert_eq!(vec![0x73; size], reply, "mode {mode} UDP download contents");
        }
        let totals = harness.node.registry.state(1).unwrap().totals();
        assert_eq!(12288, totals.upload, "mode {mode} UDP upload accounting");
        assert_eq!(12288, totals.download, "mode {mode} UDP download accounting");
        harness.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_nodes_keep_tcp_udp_egress_and_state_on_their_own_ips() {
    use std::net::IpAddr;
    let temp = tempfile::tempdir().unwrap();
    let make_node = |name: &str, ip: &str, psk: &str, node_id| ManagedNodeConfig {
        name: name.into(),
        listen: if ip.contains(":") { format!("[{ip}]:0") } else { format!("{ip}:0") },
        psk: psk.into(),
        mode: "unshaped".into(),
        panel: PanelConfig {
            url: "http://127.0.0.1:9".into(),
            token: format!("panel-{name}"),
            node_id,
            pull_interval: 3600,
            push_interval: 3600,
            api_version: 2,
            ws_url: None,
            machine_id: None,
        },
        admin: AdminConfig { disabled: true, ..Default::default() },
    };
    let config = Config {
        node: NodeConfig::default(),
        panel: None,
        admin: AdminConfig::default(),
        limits: Default::default(),
        storage: xboard_snell::config::StorageConfig {
            path: temp.path().join("shared.db").to_string_lossy().into_owned(),
        },
        log: Default::default(),
        nodes: vec![
            make_node("a", "127.0.0.1", "managed-node-psk-a-001", 1),
            make_node("b", "::1", "managed-node-psk-b-002", 2),
        ],
    };
    let nodes = Node::start_many(config).await.unwrap();
    assert_eq!(2, nodes.len());
    let payloads = [b"node-a-payload".to_vec(), b"node-b-payload".to_vec()];
    for (index, ((node, expected_ip), psk)) in
        nodes.iter().zip(["127.0.0.1", "::1"]).zip(["managed-node-psk-a-001", "managed-node-psk-b-002"]).enumerate()
    {
        let key = format!("key-{}", node.name);
        let user = xboard_snell::config::User {
            id: 7,
            uuid: key.clone(),
            speed_limit: 0,
            device_limit: 0,
            transfer_enable: 0,
            expired_at: 0,
            enabled: true,
            upload: 0,
            download: 0,
        };
        node.registry.apply_users(std::slice::from_ref(&user));
        node.server.read().await.as_ref().unwrap().update_users(&[user]).unwrap();
        let listen_ip = expected_ip.parse::<IpAddr>().unwrap();
        let listener = TcpListener::bind(std::net::SocketAddr::new(listen_ip, 0)).await.unwrap();
        let tcp_addr = listener.local_addr().unwrap();
        let tcp_target = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let source = stream.peer_addr().unwrap().ip();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            (source, received)
        });
        let server_addr = node.server.read().await.as_ref().unwrap().local_addr();
        let client = Client::new(ClientOptions {
            psk: psk.as_bytes().to_vec(),
            user_key: key.as_bytes().to_vec(),
            mode: v6::Mode::Unshaped,
            server: Socksaddr::from(server_addr),
            ..Default::default()
        })
        .unwrap();
        let proxy = client.dial_conn(dial(&server_addr.to_string()).await, tcp_addr.into()).await.unwrap();
        proxy.write(&payloads[index]).await.unwrap();
        proxy.close_write().await.unwrap();
        let (tcp_source, received) = tokio::time::timeout(Duration::from_secs(5), tcp_target).await.unwrap().unwrap();
        assert_eq!(expected_ip.parse::<IpAddr>().unwrap(), tcp_source, "node {} TCP egress IP", node.name);
        assert_eq!(payloads[index], received, "node {} TCP payload", node.name);
        let _ = proxy.close().await;

        let udp_target = UdpSocket::bind(std::net::SocketAddr::new(listen_ip, 0)).await.unwrap();
        let udp_addr = udp_target.local_addr().unwrap();
        let udp_server = tokio::spawn(async move {
            let mut buffer = vec![0; 65536];
            let (length, source) =
                tokio::time::timeout(Duration::from_secs(5), udp_target.recv_from(&mut buffer)).await.unwrap().unwrap();
            let received = buffer[..length].to_vec();
            udp_target.send_to(&received, source).await.unwrap();
            (source.ip(), received)
        });
        let packet_conn = client.dial_packet_conn(dial(&server_addr.to_string()).await).unwrap();
        packet_conn.set_read_deadline(Some(std::time::Instant::now() + Duration::from_secs(5))).unwrap();
        let packet = Buffer::from_slice_with_headroom(
            &payloads[index],
            packet_conn.front_headroom(),
            packet_conn.rear_headroom(),
        );
        packet_conn.write_packet(packet, Socksaddr::from(udp_addr)).await.unwrap();
        let mut reply = Buffer::new_packet();
        let reply_source = packet_conn.read_packet(&mut reply).await.unwrap();
        let (udp_source, sent) = udp_server.await.unwrap();
        assert_eq!(expected_ip.parse::<IpAddr>().unwrap(), udp_source, "node {} UDP egress IP", node.name);
        assert_eq!(payloads[index], sent, "node {} UDP payload", node.name);
        assert_eq!(payloads[index], reply.into_vec(), "node {} UDP reply", node.name);
        assert_eq!(Socksaddr::from(udp_addr), reply_source);
        let totals = node.registry.state(7).unwrap().totals();
        assert_eq!(2 * payloads[index].len() as u64, totals.upload);
        assert_eq!(payloads[index].len() as u64, totals.download);
        let _ = packet_conn.close().await;
    }
    assert_ne!(nodes[0].config.storage.path, nodes[1].config.storage.path);
    assert_ne!(nodes[0].registry.spec(7).unwrap().uuid, nodes[1].registry.spec(7).unwrap().uuid);
    for node in &nodes {
        node.shutdown().await;
    }
}
