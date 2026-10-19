//! Interop tests against a snell server, ported from the Go suite's
//! `v4_test.go`, `v5_test.go` and `v6_test.go`. See `common/server.rs` for how
//! the server is started.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::server::{free_port, start_snell_server};
use common::*;
use snell::crypto::{Aead, derive_key, increase_nonce};
use snell::{Buffer, Conn, ObfsMode, PacketConn, Socksaddr, v4, v6};
use tokio::sync::Notify;

macro_rules! start_server {
    ($version:expr, $config:expr, $port:expr) => {
        match start_snell_server($version, &$config, $port) {
            Some(server) => server,
            None => return,
        }
    };
}

fn v4_config(port: u16) -> String {
    format!("[snell-server]\nlisten = 0.0.0.0:{port}\npsk = {TEST_PSK}\nipv6 = false\n")
}

fn v5_config(psk: &str, port: u16) -> String {
    format!("[snell-server]\nlisten = 0.0.0.0:{port}\npsk = {psk}\nipv6 = false\n")
}

fn v6_config(psk: &str, port: u16, mode: &str) -> String {
    format!("[snell-server]\nlisten = 0.0.0.0:{port}\npsk = {psk}\nmode = {mode}\n")
}

const V6_MODES: [(&str, v6::Mode); 3] =
    [("unshaped", v6::Mode::Unshaped), ("unsafe-raw", v6::Mode::UnsafeRaw), ("default", v6::Mode::Default)];

const V6_UDP_TEST_PSK: &str = "snell-rc-udp-0371991";
const V6_UDP_TEST_PAYLOAD_SIZE: usize = 1400;

fn v4_client(options: v4::ClientOptions) -> v4::Client {
    v4::Client::new(v4::ClientOptions { psk: TEST_PSK.as_bytes().to_vec(), ..options }).unwrap()
}

fn v6_client(psk: &str, options: v6::ClientOptions) -> v6::Client {
    v6::Client::new(v6::ClientOptions { psk: psk.as_bytes().to_vec(), ..options }).unwrap()
}

fn address(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

async fn bulk_echo(proxy_conn: Arc<dyn snell::Conn>, len: usize) {
    let payload = Arc::new(random_bytes(len));
    let writer = {
        let (proxy_conn, payload) = (proxy_conn.clone(), payload.clone());
        tokio::spawn(async move { proxy_conn.write(&payload).await })
    };
    proxy_conn.set_read_deadline(deadline(20)).unwrap();
    let mut received = vec![0u8; len];
    read_full(proxy_conn.as_ref(), &mut received).await.unwrap();
    writer.await.unwrap().unwrap();
    assert!(received == *payload, "payload mismatch");
}

async fn vectorised_echo(proxy_conn: Arc<dyn snell::Conn>) {
    assert!(proxy_conn.supports_vectorised());
    let part_a = random_bytes(700);
    let part_b = random_bytes(900);
    proxy_conn.write_vectorised(vectorised_buffers(proxy_conn.as_ref(), &[&part_a, &part_b])).await.unwrap();
    let mut expected = part_a.clone();
    expected.extend_from_slice(&part_b);
    let mut received = vec![0u8; expected.len()];
    proxy_conn.set_read_deadline(deadline(10)).unwrap();
    read_full(proxy_conn.as_ref(), &mut received).await.unwrap();
    assert_eq!(expected, received);
}

async fn udp_rounds(packet_conn: &dyn PacketConn, target: Socksaddr, size: usize, rounds: usize) {
    for round in 0..rounds {
        let message = random_bytes(size);
        packet_conn.write_to(&message, target.clone()).await.unwrap();
        packet_conn.set_read_deadline(deadline(10)).unwrap();
        let mut received = vec![0u8; 2048];
        let (n, _) = packet_conn.read_from(&mut received).await.unwrap();
        assert!(message[..] == received[..n], "round {round}");
    }
}

async fn udp_batch(packet_conn: &dyn PacketConn, target: Socksaddr, size: usize) {
    assert!(packet_conn.supports_packet_batch());
    let payloads: Vec<Vec<u8>> = (0..3)
        .map(|index| {
            let mut payload = random_bytes(size);
            payload[0] = index as u8;
            payload
        })
        .collect();
    let buffers = payloads
        .iter()
        .map(|payload| {
            Buffer::from_slice_with_headroom(payload, packet_conn.front_headroom(), packet_conn.rear_headroom())
        })
        .collect();
    packet_conn.write_packet_batch(buffers, vec![target; 3]).await.unwrap();
    let mut received = std::collections::HashMap::new();
    for _ in 0..payloads.len() {
        let mut reply = vec![0u8; 2048];
        packet_conn.set_read_deadline(deadline(10)).unwrap();
        let (n, _) = packet_conn.read_from(&mut reply).await.unwrap();
        *received.entry(reply[..n].to_vec()).or_insert(0) += 1;
    }
    for payload in &payloads {
        assert_eq!(Some(&1), received.get(payload));
    }
}

/// The scenario sequence of `TestV4TCPReuse`, `TestV5TCPReuse` and `TestV6TCPReuse`.
async fn tcp_reuse_scenarios(client: &dyn ReuseClient, proxy: &CountingTcpProxy, label: &str) {
    let echo_port = start_tcp_half_close_echo(Duration::ZERO).await;
    let delayed_echo_port = start_tcp_half_close_echo(Duration::from_millis(750)).await;
    let tail_echo_port = start_tcp_half_close_tail_echo(32 * 1024, Duration::from_millis(250)).await;
    let oversized_tail_echo_port = start_tcp_half_close_tail_echo(0x80001, Duration::from_millis(250)).await;
    let destination = |port| Socksaddr::parse_host_port("127.0.0.1", port);

    let scenario = ReuseScenario { client, destination: destination(echo_port) };
    scenario.round_trip(&format!("{label}-1")).await;
    scenario.round_trip(&format!("{label}-2")).await;
    ReuseScenario { client, destination: destination(delayed_echo_port) }
        .close_before_server_eof(&format!("{label}-drain"), Duration::from_secs(1))
        .await;
    scenario.round_trip(&format!("{label}-after-drain")).await;
    ReuseScenario { client, destination: destination(tail_echo_port) }
        .close_before_server_eof(&format!("{label}-tail"), Duration::from_millis(500))
        .await;
    scenario.round_trip(&format!("{label}-after-tail")).await;
    assert_eq!(1, proxy.count());
    ReuseScenario { client, destination: destination(oversized_tail_echo_port) }
        .close_before_server_eof(&format!("{label}-oversized-tail"), Duration::from_millis(500))
        .await;
    scenario.round_trip(&format!("{label}-after-oversized-tail")).await;
    assert_eq!(2, proxy.count());
}

async fn close_cancels_drain(client: &dyn ReuseClient, label: &str) {
    let delayed_echo_port = start_tcp_half_close_echo(Duration::from_millis(750)).await;
    ReuseScenario { client, destination: Socksaddr::parse_host_port("127.0.0.1", delayed_echo_port) }
        .close_before_server_eof(label, Duration::ZERO)
        .await;
    let close_start = std::time::Instant::now();
    client.close().await.unwrap();
    assert!(
        close_start.elapsed() <= Duration::from_millis(250),
        "client close waited for draining EOF instead of canceling the session"
    );
}

async fn close_lets_active_read_finish(client: &dyn ReuseClient, proxy: &CountingTcpProxy, label: &str) {
    let delayed_echo_port = start_tcp_half_close_echo(Duration::from_millis(750)).await;
    let echo_port = start_tcp_half_close_echo(Duration::ZERO).await;
    ReuseScenario { client, destination: Socksaddr::parse_host_port("127.0.0.1", delayed_echo_port) }
        .close_while_read_blocked(&format!("{label}-active-read-close"))
        .await;
    ReuseScenario { client, destination: Socksaddr::parse_host_port("127.0.0.1", echo_port) }
        .round_trip(&format!("{label}-after-active-read-close"))
        .await;
    assert_eq!(1, proxy.count());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_tcp() {
    let port = free_port();
    let _server = start_server!("v4", v4_config(port), port);
    let echo_port = start_tcp_echo().await;
    let client = v4_client(Default::default());
    let proxy_conn =
        client.dial_conn(dial(&address(port)).await, Socksaddr::parse_host_port("127.0.0.1", echo_port)).await.unwrap();
    bulk_echo(proxy_conn, 1024 * 1024).await;
    NormalScenario { address: &address(port), client: &client }.half_close_echo("v4-official").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_tcp_reuse() {
    let port = free_port();
    let _server = start_server!("v4", v4_config(port), port);
    let proxy = CountingTcpProxy::start(address(port)).await;
    let client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    tcp_reuse_scenarios(&client, &proxy, "v4-reuse").await;
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_tcp_reuse_client_close_cancels_drain() {
    let port = free_port();
    let _server = start_server!("v4", v4_config(port), port);
    let proxy = CountingTcpProxy::start(address(port)).await;
    let client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    close_cancels_drain(&client, "v4-reuse-close-cancel").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_tcp_reuse_client_close_lets_active_read_finish() {
    let port = free_port();
    let _server = start_server!("v4", v4_config(port), port);
    let proxy = CountingTcpProxy::start(address(port)).await;
    let client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    close_lets_active_read_finish(&client, &proxy, "v4-reuse").await;
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_udp() {
    let port = free_port();
    let _server = start_server!("v4", v4_config(port), port);
    let echo_port = start_udp_echo().await;
    let client = v4_client(Default::default());
    let packet_conn = client.dial_packet_conn(dial(&address(port)).await).unwrap();
    udp_rounds(packet_conn.as_ref(), Socksaddr::parse_host_port("127.0.0.1", echo_port), 1200, 10).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_tcp_vectorised_writer() {
    let port = free_port();
    let _server = start_server!("v4", v4_config(port), port);
    let echo_port = start_tcp_echo().await;
    let client = v4_client(Default::default());
    vectorised_echo(
        client.dial_early_conn(dial(&address(port)).await, Socksaddr::parse_host_port("127.0.0.1", echo_port)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_udp_packet_batch_writer() {
    for version in ["v4", "v5"] {
        let port = free_port();
        let config = if version == "v4" { v4_config(port) } else { v5_config(TEST_PSK, port) };
        let _server = start_server!(version, config, port);
        let echo_port = start_udp_echo().await;
        let client = v4_client(Default::default());
        let packet_conn = client.dial_packet_conn(dial(&address(port)).await).unwrap();
        udp_batch(packet_conn.as_ref(), Socksaddr::parse_host_port("127.0.0.1", echo_port), 1200).await;
    }
}

async fn obfs_suite(version: &str, obfs_mode: ObfsMode, with_udp: bool) {
    let label = format!("{version}-obfs-{obfs_mode}");
    {
        let port = free_port();
        let _server = start_server!(version, v5_config(TEST_PSK, port) + &format!("obfs = {obfs_mode}\n"), port);
        let echo_port = start_tcp_echo().await;
        let client = v4_client(v4::ClientOptions { obfs_mode, obfs_host: "obfs.example".into(), ..Default::default() });
        let proxy_conn = client
            .dial_conn(dial(&address(port)).await, Socksaddr::parse_host_port("127.0.0.1", echo_port))
            .await
            .unwrap();
        bulk_echo(proxy_conn, 256 * 1024).await;
        NormalScenario { address: &address(port), client: &client }.half_close_echo(&label).await;
    }
    {
        let port = free_port();
        let _server = start_server!(version, v5_config(TEST_PSK, port) + &format!("obfs = {obfs_mode}\n"), port);
        let proxy = CountingTcpProxy::start(address(port)).await;
        let echo_port = start_tcp_half_close_echo(Duration::ZERO).await;
        let client = v4_client(v4::ClientOptions {
            reuse: true,
            obfs_mode,
            obfs_host: "obfs.example".into(),
            dialer: system_dialer(),
            server: proxy.socksaddr(),
            ..Default::default()
        });
        let scenario =
            ReuseScenario { client: &client, destination: Socksaddr::parse_host_port("127.0.0.1", echo_port) };
        scenario.round_trip(&format!("{label}-reuse-1")).await;
        scenario.round_trip(&format!("{label}-reuse-2")).await;
        assert_eq!(1, proxy.count());
        client.close().await.unwrap();
    }
    if with_udp {
        let port = free_port();
        let _server = start_server!(version, v5_config(TEST_PSK, port) + &format!("obfs = {obfs_mode}\n"), port);
        let echo_port = start_udp_echo().await;
        let client = v4_client(v4::ClientOptions { obfs_mode, obfs_host: "obfs.example".into(), ..Default::default() });
        let packet_conn = client.dial_packet_conn(dial(&address(port)).await).unwrap();
        udp_rounds(packet_conn.as_ref(), Socksaddr::parse_host_port("127.0.0.1", echo_port), 1200, 5).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_obfs_http() {
    obfs_suite("v4", ObfsMode::Http, true).await;
}

/// Not part of the Go suite: the TLS obfuscation against a server.
///
/// Runs only with `SNELL_SERVER_BIN` (the Go reference or Rust server). The official
/// snell-server v4.1.1 and v5.0.1 reject the TLS obfuscation of the Go reference client
/// ("Decryption failed") exactly as they reject this port's, while HTTP obfuscation works,
/// so the official binaries are skipped here rather than diverging from the reference.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_obfs_tls() {
    if std::env::var_os("SNELL_SERVER_BIN").is_none() {
        eprintln!("skipping: official servers do not accept the reference TLS obfuscation");
        return;
    }
    obfs_suite("v4", ObfsMode::Tls, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_first_response_record_shape() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let target_port = start_tcp_echo().await;
    let server_conn = dial(&address(port)).await;
    let early_payload = b"v5 first response record shape";
    let mut raw = V5RawConn::new(server_conn.clone());
    raw.write_first_record(&random_bytes(16), &connect_request(snell::COMMAND_CONNECT_V2, target_port, early_payload))
        .await;
    raw.write_record(&[]).await;
    server_conn.set_read_deadline(deadline(10)).unwrap();

    let mut response_salt = [0u8; 16];
    read_full(server_conn.as_ref(), &mut response_salt).await.unwrap();
    let aead = Aead::new(&derive_key(TEST_PSK.as_bytes(), &response_salt)).unwrap();
    let mut nonce = [0u8; 12];
    let mut header = [0u8; snell::HEADER_CIPHER_LEN];
    read_full(server_conn.as_ref(), &mut header).await.unwrap();
    aead.open_in_place(&nonce, &[], &mut header).unwrap();
    increase_nonce(&mut nonce);
    assert_eq!([snell::HEADER_VERSION, 0, 0], header[..3]);
    let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    assert!((0x100..=0x1ff).contains(&padding_len));
    let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
    assert_eq!(1 + early_payload.len(), payload_len);
    let mut padding = vec![0u8; padding_len];
    read_full(server_conn.as_ref(), &mut padding).await.unwrap();
    let mut payload = vec![0u8; payload_len + 16];
    read_full(server_conn.as_ref(), &mut payload).await.unwrap();
    for index in (0..padding.len().min(payload.len())).step_by(2) {
        std::mem::swap(&mut padding[index], &mut payload[index]);
    }
    let n = aead.open_in_place(&nonce, &[], &mut payload).unwrap();
    let mut expected = vec![snell::REPLY_TUNNEL];
    expected.extend_from_slice(early_payload);
    assert_eq!(expected, payload[..n]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_server_payload_growth_under_continuous_download() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let payload = Arc::new(vec![0x5a; 4 * 1024 * 1024]);
    let release = Arc::new(Notify::new());
    let target_port = start_continuous_download_target(payload.clone(), release.clone()).await;
    let recording = Arc::new(RecordingConn { conn: dial(&address(port)).await, read_bytes: Default::default() });
    let client = v4_client(Default::default());
    let proxy_conn =
        client.dial_conn(recording.clone(), Socksaddr::parse_host_port("127.0.0.1", target_port)).await.unwrap();
    proxy_conn.write(&[1]).await.unwrap();
    proxy_conn.close_write().await.unwrap();
    proxy_conn.set_read_deadline(deadline(20)).unwrap();
    let mut response = vec![0u8; payload.len()];
    read_full(proxy_conn.as_ref(), &mut response).await.unwrap();
    assert!(response == *payload, "response payload mismatch");
    proxy_conn.close().await.unwrap();
    release.notify_waiters();

    let metrics = payload_growth_metrics(&recording.read_bytes.lock().unwrap());
    eprintln!("{metrics:?}");
    assert_eq!(payload.len() + 1, metrics.payload_bytes);
    assert!(metrics.found_max_payload, "payload limit never reached the protocol ceiling");
    assert!(metrics.first_max_payload_offset > 1024 * 1024);
    assert!(metrics.first_max_payload_offset < 3 * 1024 * 1024);
    assert!(metrics.max_payload_before_1mib < 15 * 1024);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_tcp() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let echo_port = start_tcp_echo().await;
    let client = v4_client(Default::default());
    let proxy_conn =
        client.dial_conn(dial(&address(port)).await, Socksaddr::parse_host_port("127.0.0.1", echo_port)).await.unwrap();
    bulk_echo(proxy_conn, 1024 * 1024).await;
    NormalScenario { address: &address(port), client: &client }.half_close_echo("v5-official").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_tcp_vectorised_writer() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let echo_port = start_tcp_echo().await;
    let client = v4_client(Default::default());
    vectorised_echo(
        client.dial_early_conn(dial(&address(port)).await, Socksaddr::parse_host_port("127.0.0.1", echo_port)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_tcp_reuse() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let proxy = CountingTcpProxy::start(address(port)).await;
    let client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    tcp_reuse_scenarios(&client, &proxy, "v5-reuse").await;
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_tcp_reuse_client_close_lets_active_read_finish() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let proxy = CountingTcpProxy::start(address(port)).await;
    let client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    close_lets_active_read_finish(&client, &proxy, "v5-reuse").await;
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_obfs_http() {
    obfs_suite("v5", ObfsMode::Http, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_udp() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let echo_port = start_udp_echo().await;
    let client = v4_client(Default::default());
    let packet_conn = client.dial_packet_conn(dial(&address(port)).await).unwrap();
    udp_rounds(packet_conn.as_ref(), Socksaddr::parse_host_port("127.0.0.1", echo_port), 1200, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_ping_reply_closes_connection() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let server_conn = dial(&address(port)).await;
    let mut raw = V5RawConn::new(server_conn.clone());
    raw.write_first_record(&random_bytes(16), &[snell::REQUEST_VERSION, snell::COMMAND_PING, 1, b'x']).await;
    server_conn.set_read_deadline(deadline(10)).unwrap();
    match raw.read_first_record().await.unwrap() {
        RawRead::Payload(reply) => assert_eq!(vec![snell::REPLY_PONG], reply),
        RawRead::ZeroChunk => panic!("unexpected zero chunk"),
    }
    if let Ok(read) = raw.read_record().await {
        panic!("ping closes the connection instead of writing {read:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_legacy_command_connect_closes_without_zero_chunk_after_reply() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let target_port = start_tcp_half_close_echo(Duration::ZERO).await;
    let server_conn = dial(&address(port)).await;
    let payload = b"v5 legacy command connect";
    let mut raw = V5RawConn::new(server_conn.clone());
    raw.write_first_record(&random_bytes(16), &connect_request(snell::COMMAND_CONNECT, target_port, payload)).await;
    raw.write_record(&[]).await;
    server_conn.set_read_deadline(deadline(10)).unwrap();
    let mut expected = vec![snell::REPLY_TUNNEL];
    expected.extend_from_slice(payload);
    match raw.read_first_record().await.unwrap() {
        RawRead::Payload(reply) => assert_eq!(expected, reply),
        RawRead::ZeroChunk => panic!("unexpected zero chunk"),
    }
    if let Ok(read) = raw.read_record().await {
        panic!("legacy command-1 closes the TCP connection instead of writing {read:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_salt_replay_rejects_duplicate() {
    let port = free_port();
    let _server = start_server!("v5", v5_config(TEST_PSK, port), port);
    let target_port = start_tcp_half_close_echo(Duration::ZERO).await;
    let payload = b"v5 duplicated salt";
    let request = connect_request(snell::COMMAND_CONNECT_V2, target_port, payload);
    let salt = random_bytes(16);

    let first_conn = dial(&address(port)).await;
    let mut first_raw = V5RawConn::new(first_conn.clone());
    first_raw.write_first_record(&salt, &request).await;
    first_raw.write_record(&[]).await;
    first_conn.set_read_deadline(deadline(10)).unwrap();
    let mut expected = vec![snell::REPLY_TUNNEL];
    expected.extend_from_slice(payload);
    match first_raw.read_first_record().await.unwrap() {
        RawRead::Payload(reply) => assert_eq!(expected, reply),
        RawRead::ZeroChunk => panic!("unexpected zero chunk"),
    }
    first_conn.close().await.unwrap();

    let second_conn = dial(&address(port)).await;
    let mut second_raw = V5RawConn::new(second_conn.clone());
    second_raw.write_first_record(&salt, &request).await;
    second_raw.write_record(&[]).await;
    second_conn.set_read_deadline(deadline(10)).unwrap();
    assert!(second_raw.read_first_record().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_tcp() {
    for (name, mode) in V6_MODES {
        let port = free_port();
        let _server = start_server!("v6", v6_config(TEST_PSK, port, name), port);
        let echo_port = start_tcp_echo().await;
        let client = v6_client(TEST_PSK, v6::ClientOptions { mode, ..Default::default() });
        let proxy_conn = client
            .dial_conn(dial(&address(port)).await, Socksaddr::parse_host_port("127.0.0.1", echo_port))
            .await
            .unwrap();
        bulk_echo(proxy_conn, 512 * 1024).await;
        NormalScenario { address: &address(port), client: &client }
            .half_close_echo(&format!("v6-official-{name}"))
            .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_tcp_vectorised_writer() {
    for (name, mode) in V6_MODES {
        let port = free_port();
        let _server = start_server!("v6", v6_config(TEST_PSK, port, name), port);
        let echo_port = start_tcp_echo().await;
        let client = v6_client(TEST_PSK, v6::ClientOptions { mode, ..Default::default() });
        vectorised_echo(
            client.dial_early_conn(dial(&address(port)).await, Socksaddr::parse_host_port("127.0.0.1", echo_port)),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_tcp_unshaped_large_write_buffer_first_record() {
    let port = free_port();
    let _server = start_server!("v6", v6_config(TEST_PSK, port, "unshaped"), port);
    let echo_port = start_tcp_echo().await;
    let client = v6_client(TEST_PSK, v6::ClientOptions { mode: v6::Mode::Unshaped, ..Default::default() });
    let destination = Socksaddr::parse_host_port("127.0.0.1", echo_port);
    let proxy_conn = client.dial_early_conn(dial(&address(port)).await, destination.clone());
    let payload = random_bytes(80 * 1024);
    let request = snell::Request { command: snell::COMMAND_CONNECT, destination, ..Default::default() };
    proxy_conn.write_buffer(Buffer::from_slice_with_headroom(&payload, request.len(), 0)).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    proxy_conn.set_read_deadline(deadline(20)).unwrap();
    read_full(proxy_conn.as_ref(), &mut received).await.unwrap();
    assert!(payload == received, "payload mismatch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_tcp_reuse() {
    for (name, mode) in V6_MODES {
        let port = free_port();
        let _server = start_server!("v6", v6_config(TEST_PSK, port, name), port);
        let proxy = CountingTcpProxy::start(address(port)).await;
        let client = v6_client(
            TEST_PSK,
            v6::ClientOptions {
                mode,
                reuse: true,
                dialer: system_dialer(),
                server: proxy.socksaddr(),
                ..Default::default()
            },
        );
        tcp_reuse_scenarios(&client, &proxy, &format!("v6-reuse-{name}")).await;
        client.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_tcp_reuse_client_close_cancels_drain() {
    for (name, mode) in V6_MODES {
        let port = free_port();
        let _server = start_server!("v6", v6_config(TEST_PSK, port, name), port);
        let proxy = CountingTcpProxy::start(address(port)).await;
        let client = v6_client(
            TEST_PSK,
            v6::ClientOptions {
                mode,
                reuse: true,
                dialer: system_dialer(),
                server: proxy.socksaddr(),
                ..Default::default()
            },
        );
        close_cancels_drain(&client, &format!("v6-reuse-close-cancel-{name}")).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_tcp_reuse_client_close_lets_active_read_finish() {
    for (name, mode) in V6_MODES {
        let port = free_port();
        let _server = start_server!("v6", v6_config(TEST_PSK, port, name), port);
        let proxy = CountingTcpProxy::start(address(port)).await;
        let client = v6_client(
            TEST_PSK,
            v6::ClientOptions {
                mode,
                reuse: true,
                dialer: system_dialer(),
                server: proxy.socksaddr(),
                ..Default::default()
            },
        );
        close_lets_active_read_finish(&client, &proxy, &format!("v6-reuse-{name}")).await;
        client.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_udp() {
    for (name, mode) in V6_MODES {
        let port = free_port();
        let _server = start_server!("v6", v6_config(V6_UDP_TEST_PSK, port, name), port);
        let echo_port = start_udp_echo().await;
        let client = v6_client(V6_UDP_TEST_PSK, v6::ClientOptions { mode, ..Default::default() });
        let packet_conn = client.dial_packet_conn(dial(&address(port)).await).unwrap();
        assert!(packet_conn.writer_mtu() >= V6_UDP_TEST_PAYLOAD_SIZE);
        // Including its Snell UDP header, this exceeds the default-shaped
        // first dynamic chunk limit for V6_UDP_TEST_PSK (1400 bytes).
        udp_rounds(
            packet_conn.as_ref(),
            Socksaddr::parse_host_port("127.0.0.1", echo_port),
            V6_UDP_TEST_PAYLOAD_SIZE,
            10,
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_udp_packet_batch_writer() {
    for (name, mode) in V6_MODES {
        let port = free_port();
        let _server = start_server!("v6", v6_config(V6_UDP_TEST_PSK, port, name), port);
        let echo_port = start_udp_echo().await;
        let client = v6_client(V6_UDP_TEST_PSK, v6::ClientOptions { mode, ..Default::default() });
        let packet_conn = client.dial_packet_conn(dial(&address(port)).await).unwrap();
        udp_batch(packet_conn.as_ref(), Socksaddr::parse_host_port("127.0.0.1", echo_port), V6_UDP_TEST_PAYLOAD_SIZE)
            .await;
    }
}
