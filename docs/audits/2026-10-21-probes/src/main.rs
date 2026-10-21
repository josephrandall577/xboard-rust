use snell::{Conn, Socksaddr, TcpConn, v6};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use xboard_snell::{
    config::{Config, User},
    node::Node,
};

fn config() -> Config {
    Config::load(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../config.multi-node.example.toml")).unwrap()
}

fn validation_probes() {
    let mut c = config();
    c.nodes[0].listen = "127.0.0.1:40001".into();
    c.nodes[0].admin.listen = "[::1]:40002".into();
    c.nodes[1].listen = "[::1]:40002".into();
    c.nodes[1].admin.disabled = true;
    println!("admin_conflicts_future_listener: {:?}", c.validate());
    c.nodes.reverse();
    println!("same_config_reversed: {:?}", c.validate());

    let mut c = config();
    c.nodes[0].admin.listen = "0.0.0.0:40003".into();
    c.nodes[1].admin.listen = "127.0.0.1:40003".into();
    println!("wildcard_admin_overlap: {:?}", c.validate());

    let mut c = config();
    c.nodes[1].panel.node_id = c.nodes[0].panel.node_id;
    println!("duplicate_panel_id_different_tokens: {:?}", c.validate());

    let mut c = config();
    c.nodes[0].listen = "127.0.0.1:40001".into();
    c.nodes[1].listen = "[::ffff:127.0.0.1]:40002".into();
    println!("mapped_duplicate_ip: {:?}", c.validate());

    let mut c = config();
    c.nodes.truncate(1);
    c.nodes[0].listen = "[::ffff:0.0.0.0]:0".into();
    c.nodes[0].admin.disabled = true;
    println!("mapped_wildcard_ip: {:?}", c.validate());
}

async fn mapped_wildcard_relay() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config();
    c.nodes.truncate(1);
    c.nodes[0].listen = "[::ffff:0.0.0.0]:0".into();
    c.nodes[0].admin.disabled = true;
    c.storage.path = temp.path().join("audit.db").to_string_lossy().into();
    let result = Node::start_many(c).await;
    if let Ok(nodes) = &result {
        for node in nodes {
            node.shutdown().await;
        }
    }
    println!("mapped_wildcard_start_rejected: {}", result.is_err());
    assert!(result.is_err(), "mapped wildcard must be rejected before binding");
}

async fn admin_start_probe() {
    let temp = tempfile::tempdir().unwrap();
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blocked_addr = blocker.local_addr().unwrap();
    let mut c = config();
    c.nodes.truncate(1);
    c.nodes[0].listen = "127.0.0.1:0".into();
    c.nodes[0].admin.listen = blocked_addr.to_string();
    c.nodes[0].panel.url = "http://127.0.0.1:9".into();
    c.storage.path = temp.path().join("admin.db").to_string_lossy().into();
    let result = Node::start_many(c).await;
    if let Ok(nodes) = &result {
        for node in nodes {
            node.shutdown().await;
        }
    }
    println!("occupied_admin_start_rejected: {}", result.is_err());
    assert!(result.is_err(), "admin bind failure must fail startup");
}

async fn dns_probe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let addresses: Vec<_> = tokio::net::lookup_host(("audit-two.invalid", port)).await.unwrap().collect();
    println!("controlled_dns: {addresses:?}");
    let plain = TcpStream::connect(("audit-two.invalid", port)).await;
    println!("legacy_tcpstream_connect: {}", if plain.is_ok() { "success" } else { "error" });
    assert!(plain.is_ok());
    let _ = listener.accept().await.unwrap();
    drop(plain);
    let temp = tempfile::tempdir().unwrap();
    let mut c = config();
    c.nodes.truncate(1);
    c.nodes[0].listen = "127.0.0.1:0".into();
    c.nodes[0].psk = "audit-fixture-psk-1234".into();
    c.nodes[0].mode = "unshaped".into();
    c.nodes[0].admin.disabled = true;
    c.nodes[0].panel.url = "http://127.0.0.1:9".into();
    c.storage.path = temp.path().join("dns.db").to_string_lossy().into();
    let nodes = Node::start_many(c).await.unwrap();
    let node = &nodes[0];
    let user = User {
        id: 7,
        uuid: "audit-user".into(),
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
    let server_addr = node.server.read().await.as_ref().unwrap().local_addr();
    let client = v6::Client::new(v6::ClientOptions {
        psk: b"audit-fixture-psk-1234".to_vec(),
        user_key: b"audit-user".to_vec(),
        mode: v6::Mode::Unshaped,
        server: server_addr.into(),
        ..Default::default()
    })
    .unwrap();
    let transport: Arc<dyn Conn> = Arc::new(TcpConn::new(TcpStream::connect(server_addr).await.unwrap()).unwrap());
    let conn = client.dial_conn(transport, Socksaddr::parse_host_port("audit-two.invalid", port)).await.unwrap();
    let write = conn.write(b"ping").await;
    println!("managed_dns_request_write: {write:?}");
    let reached = match tokio::time::timeout(Duration::from_secs(2), listener.accept()).await {
        Ok(Ok((mut peer, _))) => {
            let mut bytes = [0; 4];
            peer.read_exact(&mut bytes).await.unwrap();
            assert_eq!(*b"ping", bytes);
            peer.write_all(&bytes).await.unwrap();
            true
        }
        _ => false,
    };
    let mut reply = [0; 4];
    let read = tokio::time::timeout(Duration::from_millis(400), conn.read(&mut reply)).await;
    println!("managed_dns_target_reached: {reached}; client_read: {read:?}");
    assert!(reached, "bound TCP must try the second DNS address");
    assert!(matches!(read, Ok(Ok(4))));
    assert_eq!(*b"ping", reply);
    let _ = conn.close().await;
    node.shutdown().await;
}

async fn panel_once(body: &str) -> Result<Vec<xboard_snell::config::UserSpec>, xboard_snell::panel::PanelError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body = body.to_owned();
    let worker = tokio::spawn(async move {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        let _ = conn.read(&mut request).await.unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        conn.write_all(response.as_bytes()).await.unwrap();
    });
    let mut panel = config().nodes[0].panel.clone();
    panel.url = format!("http://{addr}");
    let result = xboard_snell::panel::PanelClient::new(panel).unwrap().fetch_users().await;
    worker.await.unwrap();
    result
}

async fn panel_null_probes() {
    for (case, body) in [
        ("missing", r#"{"users":[{"id":1,"uuid":"audit-user"}]}"#),
        ("null", r#"{"users":[{"id":1,"uuid":"audit-user","speed_limit":null,"device_limit":null}]}"#),
        ("numeric", r#"{"users":[{"id":1,"uuid":"audit-user","speed_limit":12,"device_limit":3}]}"#),
        ("invalid_type", r#"{"users":[{"id":1,"uuid":"audit-user","speed_limit":"fast","device_limit":3}]}"#),
    ] {
        let result = panel_once(body).await;
        match result {
            Ok(users) => {
                println!("panel_limits_{case}: speed={} devices={}", users[0].speed_limit, users[0].device_limit)
            }
            Err(_) => println!("panel_limits_{case}: rejected"),
        }
    }
}

async fn startup_rollback_probe() {
    let temp = tempfile::tempdir().unwrap();
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first.local_addr().unwrap();
    drop(first);
    let second = TcpListener::bind("[::1]:0").await.unwrap();
    let second_addr = second.local_addr().unwrap();
    let mut c = config();
    c.storage.path = temp.path().join("rollback.db").to_string_lossy().into();
    c.nodes[0].listen = first_addr.to_string();
    c.nodes[1].listen = second_addr.to_string();
    for node in &mut c.nodes {
        node.admin.disabled = true;
        node.panel.url = "http://127.0.0.1:9".into();
    }
    let result = Node::start_many(c).await;
    println!("second_node_listener_occupied: returned_error={}", result.is_err());
    tokio::time::sleep(Duration::from_millis(50)).await;
    println!("first_node_listener_released: {}", TcpListener::bind(first_addr).await.is_ok());
}

async fn shutdown_accounting_probe() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let panel_addr = listener.local_addr().unwrap();
    let reports = Arc::new(AtomicUsize::new(0));
    let observed = reports.clone();
    let worker = tokio::spawn(async move {
        loop {
            let (mut conn, _) = listener.accept().await.unwrap();
            let observed = observed.clone();
            tokio::spawn(async move {
                let mut buffer = vec![0; 8192];
                let n = conn.read(&mut buffer).await.unwrap();
                if buffer[..n].windows(b"/api/v2/server/report".len()).any(|w| w == b"/api/v2/server/report") {
                    observed.fetch_add(1, Ordering::SeqCst);
                }
                let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await;
            });
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let mut c = config();
    c.nodes.truncate(1);
    c.nodes[0].listen = "127.0.0.1:0".into();
    c.nodes[0].admin.disabled = true;
    c.nodes[0].panel.url = format!("http://{panel_addr}");
    c.nodes[0].panel.push_interval = 3600;
    c.nodes[0].panel.pull_interval = 3600;
    c.storage.path = temp.path().join("shutdown.db").to_string_lossy().into();
    let nodes = Node::start_many(c).await.unwrap();
    let node = &nodes[0];
    let user = User {
        id: 7,
        uuid: "audit-user".into(),
        speed_limit: 0,
        device_limit: 0,
        transfer_enable: 0,
        expired_at: 0,
        enabled: true,
        upload: 0,
        download: 0,
    };
    node.store.upsert_user(&(&user).into()).unwrap();
    node.registry.apply_users(&[user]);
    node.registry.state(7).unwrap().record_upload(123);
    node.shutdown().await;
    println!(
        "shutdown_pending_upload: local={} panel_reports={} remaining_pending={}",
        node.store.get_user(7).unwrap().unwrap().upload,
        reports.load(Ordering::SeqCst),
        node.registry.take_pending().len()
    );
    assert_eq!(123, node.store.get_user(7).unwrap().unwrap().upload);
    assert_eq!(1, reports.load(Ordering::SeqCst));
    worker.abort();
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("error").init();
    if std::env::args().any(|a| a == "--dns") {
        dns_probe().await;
    } else {
        validation_probes();
        mapped_wildcard_relay().await;
        admin_start_probe().await;
        panel_null_probes().await;
        startup_rollback_probe().await;
        shutdown_accounting_probe().await;
    }
}
