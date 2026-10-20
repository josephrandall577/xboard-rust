use snell::{Buffer, Conn, PacketConn, TcpConn, v6};
use snell_xboard_node::{
    config::{Config, NodeConfig, StorageConfig, UserSpec},
    node::Node,
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
const PSK: &[u8] = b"audit-test-psk-0123456789";

async fn start(speed: u64, mode: &str) -> (Arc<Node>, tempfile::TempDir, String) {
    let temp = tempfile::tempdir().unwrap();
    let config = Config {
        node: NodeConfig {
            listen: "127.0.0.1:0".into(),
            psk: String::from_utf8(PSK.to_vec()).unwrap(),
            mode: mode.into(),
            users: vec![UserSpec {
                id: 1,
                uuid: "audit-user".into(),
                speed_limit: speed,
                device_limit: 0,
                transfer_enable: 0,
                expired_at: 0,
                enabled: true,
            }],
        },
        panel: None,
        admin: snell_xboard_node::config::AdminConfig {
            disabled: true,
            ..Default::default()
        },
        limits: Default::default(),
        storage: StorageConfig {
            path: temp.path().join("db.sqlite").to_str().unwrap().into(),
        },
        log: Default::default(),
    };
    let node = Node::start(config).await.unwrap();
    let addr = node
        .server
        .read()
        .await
        .as_ref()
        .unwrap()
        .local_addr()
        .to_string();
    (node, temp, addr)
}
fn client(mode: &str) -> v6::Client {
    v6::Client::new(v6::ClientOptions {
        psk: PSK.to_vec(),
        user_key: b"audit-user".to_vec(),
        mode: v6::parse_mode(mode).unwrap(),
        ..Default::default()
    })
    .unwrap()
}
async fn dial(addr: &str) -> Arc<dyn Conn> {
    Arc::new(TcpConn::new(TcpStream::connect(addr).await.unwrap()).unwrap())
}

async fn tcp(speed: u64, mode: &str) {
    let (node, _temp, addr) = start(speed, mode).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut data = Vec::new();
        stream.read_to_end(&mut data).await.unwrap();
        let n = data.len();
        // Send a full independent response to distinguish download loss from upload loss.
        stream.write_all(&vec![0x42; 32768]).await.unwrap();
        n
    });
    let proxy = client(mode)
        .dial_conn(dial(&addr).await, target.into())
        .await
        .unwrap();
    let payload = vec![0x42; 32768];
    proxy.write(&payload).await.unwrap();
    proxy.close_write().await.unwrap();
    proxy
        .set_read_deadline(Some(Instant::now() + Duration::from_secs(3)))
        .unwrap();
    let mut got = Vec::new();
    let mut buf = vec![0; 32768];
    loop {
        match proxy.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => {
                println!("tcp read error: {e}");
                break;
            }
        }
    }
    let upstream = echo.await.unwrap();
    println!(
        "tcp mode={mode} speed={speed}Mbps sent={} upstream={} target_reply=32768 received={}",
        payload.len(),
        upstream,
        got.len()
    );
    let _ = proxy.close().await;
    node.shutdown().await;
}

async fn udp(speed: u64, target_host: &str, mode: &str) {
    let (node, _temp, addr) = start(speed, mode).await;
    let socket = UdpSocket::bind((target_host, 0)).await.unwrap();
    let target = socket.local_addr().unwrap();
    let receiver = tokio::spawn(async move {
        let mut buf = vec![0; 65536];
        match tokio::time::timeout(Duration::from_millis(600), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, src))) => {
                // A full response independently exercises the download limiter.
                socket.send_to(&vec![0x43; 4096], src).await.unwrap();
                n
            }
            _ => 0,
        }
    });
    let proxy = client(mode).dial_packet_conn(dial(&addr).await).unwrap();
    let payload = vec![0x43; 4096];
    let buffer =
        Buffer::from_slice_with_headroom(&payload, proxy.front_headroom(), proxy.rear_headroom());
    proxy.write_packet(buffer, target.into()).await.unwrap();
    proxy
        .set_read_deadline(Some(Instant::now() + Duration::from_secs(1)))
        .unwrap();
    let mut buf = Buffer::new_packet();
    let result = proxy.read_packet(&mut buf).await;
    let upstream = receiver.await.unwrap();
    println!(
        "udp mode={mode} target={target_host} speed={speed}Mbps sent={} upstream={} received={} result={:?} (target replies with 4096 bytes if reached)",
        payload.len(),
        upstream,
        buf.len(),
        result.map(|_| ())
    );
    let _ = proxy.close().await;
    node.shutdown().await;
}

fn addresses() {
    for host in [
        &[0xffu8][..],
        b"fe80::1%lo0".as_slice(),
        b"[::1]".as_slice(),
    ] {
        let mut data = vec![host.len() as u8];
        data.extend_from_slice(host);
        data.extend_from_slice(&443u16.to_be_bytes());
        let mut buffer = Buffer::from_vec(data);
        let dest = snell::address::read_connect_address(&mut buffer).unwrap();
        println!(
            "rust address input={:02x?} host={:02x?} is_ip={}",
            host,
            dest.host_bytes(),
            dest.is_ip()
        );
    }
}

async fn tls_empty_record() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let sender = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut data = vec![0; 142 + 75];
        data.extend_from_slice(&[0x17, 3, 3, 0, 1, b'A']);
        s.write_all(&data).await.unwrap();
    });
    let c = snell::ObfsConfig {
        mode: snell::ObfsMode::Tls,
        ..Default::default()
    }
    .server_conn(dial(&addr.to_string()).await);
    c.set_read_deadline(Some(Instant::now() + Duration::from_secs(1)))
        .unwrap();
    let mut b = [0; 16];
    let n = c.read(&mut b).await.unwrap();
    println!("rust tls empty first record: n={n} data={:02x?}", &b[..n]);
    sender.await.unwrap();
}

#[tokio::main]
async fn main() {
    addresses();
    tls_empty_record().await;
    for mode in ["default", "unshaped", "unsafe-raw"] {
        tcp(0, mode).await;
        tcp(1, mode).await;
        udp(0, "127.0.0.1", mode).await;
        udp(1, "127.0.0.1", mode).await;
    }
    udp(0, "::1", "unshaped").await;
}
