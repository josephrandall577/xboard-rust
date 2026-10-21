//! Loopback tests ported from the Go `test` module, plus extra coverage that
//! does not need the official binaries.

mod common;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use common::*;
use snell::crypto::{Aead, derive_key, increase_nonce};
use snell::{Buffer, CloseHandler, Conn, Context, Handler, ObfsMode, PacketConn, Service, Socksaddr, v4, v5, v6};
use tokio::sync::{Notify, mpsc};

fn v4_client(options: v4::ClientOptions) -> v4::Client {
    v4::Client::new(v4::ClientOptions { psk: TEST_PSK.as_bytes().to_vec(), ..options }).unwrap()
}

fn v5_service(handler: Arc<dyn Handler>, obfs_mode: ObfsMode) -> Arc<dyn Service> {
    Arc::new(v5::Service::new(v5::ServiceOptions { psk: TEST_PSK.as_bytes().to_vec(), obfs_mode, handler }).unwrap())
}

fn v6_service(handler: Arc<dyn Handler>, mode: v6::Mode) -> Arc<dyn Service> {
    Arc::new(v6::Service::new(v6::ServerOptions { psk: TEST_PSK.as_bytes().to_vec(), mode, handler }).unwrap())
}

const V6_MODES: [(&str, v6::Mode); 3] =
    [("unshaped", v6::Mode::Unshaped), ("unsafe-raw", v6::Mode::UnsafeRaw), ("default", v6::Mode::Default)];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_obfs_tls_loopback() {
    let service_address = start_local_snell_service(v5_service(Arc::new(LocalEchoHandler), ObfsMode::Tls)).await;
    let client = v4_client(v4::ClientOptions {
        obfs_mode: ObfsMode::Tls,
        obfs_host: "obfs.example".into(),
        ..Default::default()
    });
    NormalScenario { address: &service_address, client: &client }.half_close_echo("v5-tls-tcp").await;

    let proxy = CountingTcpProxy::start(service_address.clone()).await;
    let reuse_client = v4_client(v4::ClientOptions {
        reuse: true,
        obfs_mode: ObfsMode::Tls,
        obfs_host: "obfs.example".into(),
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    let destination = Socksaddr::parse_host_port("127.0.0.1", 443);
    ReuseScenario { client: &reuse_client, destination: destination.clone() }.round_trip("v5-tls-reuse-1").await;
    ReuseScenario { client: &reuse_client, destination }.round_trip("v5-tls-reuse-2").await;
    assert_eq!(1, proxy.count());
    reuse_client.close().await.unwrap();

    let packet_conn = client.dial_packet_conn(dial(&service_address).await).unwrap();
    round_trip_packet(packet_conn.as_ref(), "v5-tls-udp-v4-wire").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_obfs_http_loopback() {
    let service_address = start_local_snell_service(v5_service(Arc::new(LocalEchoHandler), ObfsMode::Http)).await;
    let client = v4_client(v4::ClientOptions {
        obfs_mode: ObfsMode::Http,
        obfs_host: "obfs.example".into(),
        ..Default::default()
    });
    NormalScenario { address: &service_address, client: &client }.half_close_echo("v5-http-tcp").await;

    let proxy = CountingTcpProxy::start(service_address.clone()).await;
    let reuse_client = v4_client(v4::ClientOptions {
        reuse: true,
        obfs_mode: ObfsMode::Http,
        obfs_host: "obfs.example".into(),
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    let destination = Socksaddr::parse_host_port("127.0.0.1", 443);
    ReuseScenario { client: &reuse_client, destination: destination.clone() }.round_trip("v5-http-reuse-1").await;
    ReuseScenario { client: &reuse_client, destination }.round_trip("v5-http-reuse-2").await;
    assert_eq!(1, proxy.count());
    reuse_client.close().await.unwrap();

    let packet_conn = client.dial_packet_conn(dial(&service_address).await).unwrap();
    round_trip_packet(packet_conn.as_ref(), "v5-http-udp").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_server_accepts_v4_client_loopback() {
    let service_address = start_local_snell_service(v5_service(Arc::new(LocalEchoHandler), ObfsMode::None)).await;
    let client = v4_client(Default::default());
    NormalScenario { address: &service_address, client: &client }.half_close_echo("v5-service-v4-client-tcp").await;

    let proxy = CountingTcpProxy::start(service_address.clone()).await;
    let reuse_client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    let destination = Socksaddr::parse_host_port("127.0.0.1", 443);
    ReuseScenario { client: &reuse_client, destination: destination.clone() }
        .round_trip("v5-service-v4-client-reuse-1")
        .await;
    ReuseScenario { client: &reuse_client, destination }.round_trip("v5-service-v4-client-reuse-2").await;
    assert_eq!(1, proxy.count());
    reuse_client.close().await.unwrap();

    let packet_conn = client.dial_packet_conn(dial(&service_address).await).unwrap();
    round_trip_packet(packet_conn.as_ref(), "v5-service-v4-client-udp").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_server_reuse_handler_close_before_client_eof() {
    let service_address =
        start_local_snell_service(v5_service(Arc::new(PartialEchoHandler { echo_len: 4 * 1024 }), ObfsMode::None))
            .await;
    let proxy = CountingTcpProxy::start(service_address).await;
    let reuse_client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    let scenario = ReuseScenario { client: &reuse_client, destination: Socksaddr::parse_host_port("127.0.0.1", 443) };
    scenario.partial_echo_round_trip("v5-server-drain-1", 8 * 1024, 4 * 1024).await;
    scenario.partial_echo_round_trip("v5-server-drain-2", 8 * 1024, 4 * 1024).await;
    assert_eq!(1, proxy.count());
    reuse_client.close().await.unwrap();
}

struct CloseWhileReadActiveHandler {
    connection_count: AtomicI32,
    read_started: Arc<Notify>,
    close_done: Arc<Notify>,
}

impl Handler for CloseWhileReadActiveHandler {
    fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        if self.connection_count.fetch_add(1, Ordering::SeqCst) + 1 > 1 {
            LocalEchoHandler.new_connection(ctx, conn, source, destination, on_close);
            return;
        }
        let read_started = self.read_started.clone();
        let close_done = self.close_done.clone();
        tokio::spawn(async move {
            let mut payload = vec![0u8; 4 * 1024];
            let mut result = read_full(conn.as_ref(), &mut payload).await;
            if result.is_ok() {
                result = conn.write(&payload).await.map(|_| ());
            }
            if let Err(err) = result {
                if let Some(on_close) = on_close {
                    on_close(Some(err));
                }
                return;
            }
            let read_conn = conn.clone();
            let read_task = tokio::spawn(async move {
                read_started.notify_one();
                let mut one = [0u8; 1];
                read_conn.read(&mut one).await
            });
            tokio::time::sleep(Duration::from_millis(100)).await;
            let close_result = conn.close().await;
            close_done.notify_one();
            let read_result = read_task.await.unwrap();
            let err = close_result.err().or(read_result.err());
            if let Some(on_close) = on_close {
                on_close(err);
            }
        });
    }

    fn new_packet_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn PacketConn>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        LocalEchoHandler.new_packet_connection(ctx, conn, source, destination, on_close);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_server_reuse_close_while_read_active() {
    let read_started = Arc::new(Notify::new());
    let close_done = Arc::new(Notify::new());
    let handler = Arc::new(CloseWhileReadActiveHandler {
        connection_count: AtomicI32::new(0),
        read_started: read_started.clone(),
        close_done: close_done.clone(),
    });
    let service_address = start_local_snell_service(v5_service(handler, ObfsMode::None)).await;
    let proxy = CountingTcpProxy::start(service_address).await;
    let client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });

    let conn = client.dial_context(&Context::new(), Socksaddr::parse_host_port("127.0.0.1", 443)).await.unwrap();
    let payload = random_bytes(4 * 1024);
    conn.write(&payload).await.unwrap();
    conn.set_read_deadline(deadline(10)).unwrap();
    let mut received = vec![0u8; payload.len()];
    read_full(conn.as_ref(), &mut received).await.unwrap();
    assert_eq!(payload, received);
    read_started.notified().await;
    close_done.notified().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let received = read_all(conn.as_ref()).await.unwrap();
    assert!(received.is_empty());
    conn.close_write().await.unwrap();
    conn.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    ReuseScenario { client: &client, destination: Socksaddr::parse_host_port("127.0.0.1", 443) }
        .round_trip("v5-reuse-after-active-server-read")
        .await;
    assert_eq!(1, proxy.count());
    client.close().await.unwrap();
}

#[derive(Debug)]
struct CloseThenWriteResult {
    response: io::Result<usize>,
    close_write: io::Result<()>,
    write: io::Result<usize>,
    vectorised_created: bool,
    vectorised: io::Result<()>,
}

struct CloseThenWriteHandler {
    connection_count: AtomicI32,
    results: mpsc::UnboundedSender<CloseThenWriteResult>,
}

impl Handler for CloseThenWriteHandler {
    fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        if self.connection_count.fetch_add(1, Ordering::SeqCst) + 1 > 1 {
            LocalEchoHandler.new_connection(ctx, conn, source, destination, on_close);
            return;
        }
        let results = self.results.clone();
        tokio::spawn(async move {
            let response = conn.write(b"response").await;
            let close_write = conn.close_write().await;
            let write = conn.write(b"late-write").await;
            let vectorised_created = conn.supports_vectorised();
            let mut vectorised = Ok(());
            if vectorised_created {
                let late = Buffer::from_slice_with_headroom(
                    b"late-vectorised-write",
                    conn.front_headroom(),
                    conn.rear_headroom(),
                );
                vectorised = conn.write_vectorised(vec![late]).await;
            }
            let _ = results.send(CloseThenWriteResult { response, close_write, write, vectorised_created, vectorised });
            if let Some(on_close) = on_close {
                on_close(None);
            }
        });
    }

    fn new_packet_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn PacketConn>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        LocalEchoHandler.new_packet_connection(ctx, conn, source, destination, on_close);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_server_reuse_rejects_writes_after_close_write() {
    let (results_tx, mut results_rx) = mpsc::unbounded_channel();
    let handler = Arc::new(CloseThenWriteHandler { connection_count: AtomicI32::new(0), results: results_tx });
    let service_address = start_local_snell_service(v5_service(handler, ObfsMode::None)).await;
    let proxy = CountingTcpProxy::start(service_address).await;
    let client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });

    let conn = client.dial_context(&Context::new(), Socksaddr::parse_host_port("127.0.0.1", 443)).await.unwrap();
    conn.write(b"request").await.unwrap();
    let result = results_rx.recv().await.unwrap();
    result.response.unwrap();
    result.close_write.unwrap();
    assert!(snell::is_closed(&result.write.unwrap_err()));
    assert!(result.vectorised_created);
    assert!(snell::is_closed(&result.vectorised.unwrap_err()));
    conn.set_read_deadline(deadline(10)).unwrap();
    let response = read_all(conn.as_ref()).await.unwrap();
    assert_eq!(b"response".to_vec(), response);
    conn.close_write().await.unwrap();
    conn.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    ReuseScenario { client: &client, destination: Socksaddr::parse_host_port("127.0.0.1", 443) }
        .round_trip("v5-reuse-after-rejected-late-write")
        .await;
    assert_eq!(1, proxy.count());
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_first_response_record_shape_local() {
    let service_address = start_local_snell_service(v5_service(Arc::new(LocalEchoHandler), ObfsMode::None)).await;
    let server_conn = dial(&service_address).await;
    let early_payload = b"v5 first response record shape";
    let mut raw = V5RawConn::new(server_conn.clone());
    let salt = random_bytes(16);
    raw.write_first_record(&salt, &connect_request(snell::COMMAND_CONNECT_V2, 443, early_payload)).await;
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
    assert_eq!(snell::HEADER_VERSION, header[0]);
    assert_eq!(0, header[1]);
    assert_eq!(0, header[2]);
    // snell-server v5.0.1: FUN_00139670 subtracts first-record padding
    // from the first payload limit, and FUN_00138af0 serializes and mixes it.
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
async fn v5_server_payload_growth_under_continuous_download_local() {
    let payload = Arc::new(vec![0x5a; 4 * 1024 * 1024]);
    let release = Arc::new(Notify::new());
    let target_port = start_continuous_download_target(payload.clone(), release.clone()).await;
    let service_address = start_local_snell_service(v5_service(Arc::new(LocalRouteHandler), ObfsMode::None)).await;

    let recording = Arc::new(RecordingConn { conn: dial(&service_address).await, read_bytes: Default::default() });
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

async fn assert_ping_closes(address: &str) {
    let server_conn = dial(address).await;
    let mut raw = V5RawConn::new(server_conn.clone());
    raw.write_first_record(&random_bytes(16), &[snell::REQUEST_VERSION, snell::COMMAND_PING, 1, b'x']).await;
    server_conn.set_read_deadline(deadline(10)).unwrap();
    match raw.read_first_record().await.unwrap() {
        RawRead::Payload(reply) => assert_eq!(vec![snell::REPLY_PONG], reply),
        RawRead::ZeroChunk => panic!("unexpected zero chunk"),
    }
    match raw.read_record().await {
        Err(_) => {}
        Ok(read) => panic!("ping closes the connection instead of writing {read:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_ping_reply_closes_connection() {
    let address = start_local_snell_service(v5_service(Arc::new(LocalEchoHandler), ObfsMode::None)).await;
    assert_ping_closes(&address).await;
    let multi: Arc<dyn Service> = Arc::new(
        v5::MultiService::<i32>::new(v5::ServiceOptions {
            psk: TEST_PSK.as_bytes().to_vec(),
            obfs_mode: ObfsMode::None,
            handler: Arc::new(LocalEchoHandler),
        })
        .unwrap(),
    );
    let address = start_local_snell_service(multi).await;
    assert_ping_closes(&address).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_legacy_command_connect_closes_without_zero_chunk_after_reply() {
    let address = start_local_snell_service(v5_service(Arc::new(LocalEchoHandler), ObfsMode::None)).await;
    let server_conn = dial(&address).await;
    let payload = b"v5 legacy command connect";
    let mut raw = V5RawConn::new(server_conn.clone());
    raw.write_first_record(&random_bytes(16), &connect_request(snell::COMMAND_CONNECT, 443, payload)).await;
    raw.write_record(&[]).await;
    server_conn.set_read_deadline(deadline(10)).unwrap();
    let mut expected = vec![snell::REPLY_TUNNEL];
    expected.extend_from_slice(payload);
    match raw.read_first_record().await.unwrap() {
        RawRead::Payload(reply) => assert_eq!(expected, reply),
        RawRead::ZeroChunk => panic!("unexpected zero chunk"),
    }
    match raw.read_record().await {
        Err(_) => {}
        Ok(read) => panic!("legacy command-1 closes the TCP connection instead of writing {read:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v5_salt_replay_rejects_duplicate() {
    let address = start_local_snell_service(v5_service(Arc::new(LocalEchoHandler), ObfsMode::None)).await;
    let payload = b"v5 duplicated salt";
    let request = connect_request(snell::COMMAND_CONNECT_V2, 443, payload);
    let salt = random_bytes(16);

    let first_conn = dial(&address).await;
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

    let second_conn = dial(&address).await;
    let mut second_raw = V5RawConn::new(second_conn.clone());
    second_raw.write_first_record(&salt, &request).await;
    second_raw.write_record(&[]).await;
    second_conn.set_read_deadline(deadline(10)).unwrap();
    assert!(second_raw.read_first_record().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_server_accepts_v6_client_loopback() {
    for (name, mode) in V6_MODES {
        let service_address = start_local_snell_service(v6_service(Arc::new(LocalEchoHandler), mode)).await;
        let proxy = CountingTcpProxy::start(service_address).await;
        let client = v6::Client::new(v6::ClientOptions {
            psk: TEST_PSK.as_bytes().to_vec(),
            mode,
            reuse: true,
            dialer: system_dialer(),
            server: proxy.socksaddr(),
            ..Default::default()
        })
        .unwrap();
        let scenario = ReuseScenario { client: &client, destination: Socksaddr::parse_host_port("127.0.0.1", 443) };
        scenario.round_trip(&format!("v6-service-v6-client-reuse-1-{name}")).await;
        scenario.round_trip(&format!("v6-service-v6-client-reuse-2-{name}")).await;
        assert_eq!(1, proxy.count());
        client.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_server_reuse_handler_close_before_client_eof() {
    for (name, mode) in V6_MODES {
        let service_address =
            start_local_snell_service(v6_service(Arc::new(PartialEchoHandler { echo_len: 4 * 1024 }), mode)).await;
        let proxy = CountingTcpProxy::start(service_address).await;
        let client = v6::Client::new(v6::ClientOptions {
            psk: TEST_PSK.as_bytes().to_vec(),
            mode,
            reuse: true,
            dialer: system_dialer(),
            server: proxy.socksaddr(),
            ..Default::default()
        })
        .unwrap();
        let scenario = ReuseScenario { client: &client, destination: Socksaddr::parse_host_port("127.0.0.1", 443) };
        scenario.partial_echo_round_trip(&format!("v6-server-drain-1-{name}"), 8 * 1024, 4 * 1024).await;
        scenario.partial_echo_round_trip(&format!("v6-server-drain-2-{name}"), 8 * 1024, 4 * 1024).await;
        assert_eq!(1, proxy.count());
        client.close().await.unwrap();
    }
}

/// The reuse scenarios of `TestV4TCPReuse` / `TestV6TCPReuse`, against a local server.
async fn reuse_suite(client: &dyn ReuseClient, proxy: &CountingTcpProxy, label: &str) {
    let echo_port = start_tcp_half_close_echo(Duration::ZERO).await;
    let delayed_echo_port = start_tcp_half_close_echo(Duration::from_millis(750)).await;
    let tail_echo_port = start_tcp_half_close_tail_echo(32 * 1024, Duration::from_millis(250)).await;
    let oversized_tail_echo_port = start_tcp_half_close_tail_echo(0x80001, Duration::from_millis(250)).await;
    let destination = |port| Socksaddr::parse_host_port("127.0.0.1", port);

    let scenario = ReuseScenario { client, destination: destination(echo_port) };
    scenario.round_trip(&format!("{label}-reuse-1")).await;
    scenario.round_trip(&format!("{label}-reuse-2")).await;
    ReuseScenario { client, destination: destination(delayed_echo_port) }
        .close_before_server_eof(&format!("{label}-reuse-drain"), Duration::from_secs(1))
        .await;
    scenario.round_trip(&format!("{label}-reuse-after-drain")).await;
    ReuseScenario { client, destination: destination(tail_echo_port) }
        .close_before_server_eof(&format!("{label}-reuse-tail"), Duration::from_millis(500))
        .await;
    scenario.round_trip(&format!("{label}-reuse-after-tail")).await;
    scenario.read_waiter(&format!("{label}-reuse-read-waiter")).await;
    assert_eq!(1, proxy.count());
    ReuseScenario { client, destination: destination(oversized_tail_echo_port) }
        .close_before_server_eof(&format!("{label}-reuse-oversized-tail"), Duration::from_millis(500))
        .await;
    scenario.round_trip(&format!("{label}-reuse-after-oversized-tail")).await;
    assert_eq!(2, proxy.count());
    ReuseScenario { client, destination: destination(delayed_echo_port) }
        .close_while_read_blocked(&format!("{label}-reuse-active-read-close"))
        .await;
    scenario.round_trip(&format!("{label}-reuse-after-active-read-close")).await;
    assert_eq!(2, proxy.count());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v4_client_reuse_against_local_v5() {
    for obfs_mode in [ObfsMode::None, ObfsMode::Http, ObfsMode::Tls] {
        let service_address = start_local_snell_service(v5_service(Arc::new(LocalRouteHandler), obfs_mode)).await;
        let proxy = CountingTcpProxy::start(service_address).await;
        let client = v4_client(v4::ClientOptions {
            reuse: true,
            obfs_mode,
            dialer: system_dialer(),
            server: proxy.socksaddr(),
            ..Default::default()
        });
        reuse_suite(&client, &proxy, &format!("v4-local-v5-{obfs_mode}")).await;
        client.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_client_reuse_against_local_v6() {
    for (name, mode) in V6_MODES {
        let service_address = start_local_snell_service(v6_service(Arc::new(LocalRouteHandler), mode)).await;
        let proxy = CountingTcpProxy::start(service_address).await;
        let client = v6::Client::new(v6::ClientOptions {
            psk: TEST_PSK.as_bytes().to_vec(),
            mode,
            reuse: true,
            dialer: system_dialer(),
            server: proxy.socksaddr(),
            ..Default::default()
        })
        .unwrap();
        reuse_suite(&client, &proxy, &format!("v6-local-{name}")).await;
        client.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reuse_client_close_cancels_drain() {
    let delayed_echo_port = start_tcp_half_close_echo(Duration::from_millis(750)).await;
    let destination = Socksaddr::parse_host_port("127.0.0.1", delayed_echo_port);

    let service_address = start_local_snell_service(v5_service(Arc::new(LocalRouteHandler), ObfsMode::None)).await;
    let proxy = CountingTcpProxy::start(service_address).await;
    let client = v4_client(v4::ClientOptions {
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    });
    ReuseScenario { client: &client, destination: destination.clone() }
        .close_before_server_eof("v4-reuse-close-cancel", Duration::ZERO)
        .await;
    let close_start = std::time::Instant::now();
    client.close().await.unwrap();
    assert!(close_start.elapsed() <= Duration::from_millis(250), "client close waited for draining EOF");

    for (name, mode) in V6_MODES {
        let service_address = start_local_snell_service(v6_service(Arc::new(LocalRouteHandler), mode)).await;
        let proxy = CountingTcpProxy::start(service_address).await;
        let client = v6::Client::new(v6::ClientOptions {
            psk: TEST_PSK.as_bytes().to_vec(),
            mode,
            reuse: true,
            dialer: system_dialer(),
            server: proxy.socksaddr(),
            ..Default::default()
        })
        .unwrap();
        ReuseScenario { client: &client, destination: destination.clone() }
            .close_before_server_eof(&format!("v6-reuse-close-cancel-{name}"), Duration::ZERO)
            .await;
        let close_start = std::time::Instant::now();
        client.close().await.unwrap();
        assert!(close_start.elapsed() <= Duration::from_millis(250), "client close waited for draining EOF");
    }
}

async fn bulk_round_trip(proxy_conn: Arc<dyn Conn>, len: usize) {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_transfer_loopback() {
    let echo_port = start_tcp_echo().await;
    let destination = Socksaddr::parse_host_port("127.0.0.1", echo_port);
    for obfs_mode in [ObfsMode::None, ObfsMode::Http, ObfsMode::Tls] {
        let address = start_local_snell_service(v5_service(Arc::new(LocalRouteHandler), obfs_mode)).await;
        let client = v4_client(v4::ClientOptions { obfs_mode, ..Default::default() });
        let proxy_conn = client.dial_conn(dial(&address).await, destination.clone()).await.unwrap();
        bulk_round_trip(proxy_conn, 1024 * 1024).await;
        NormalScenario { address: &address, client: &client }.half_close_echo(&format!("v4-local-{obfs_mode}")).await;
    }
    for (name, mode) in V6_MODES {
        let address = start_local_snell_service(v6_service(Arc::new(LocalRouteHandler), mode)).await;
        let client =
            v6::Client::new(v6::ClientOptions { psk: TEST_PSK.as_bytes().to_vec(), mode, ..Default::default() })
                .unwrap();
        let proxy_conn = client.dial_conn(dial(&address).await, destination.clone()).await.unwrap();
        bulk_round_trip(proxy_conn, 512 * 1024).await;
        NormalScenario { address: &address, client: &client }.half_close_echo(&format!("v6-local-{name}")).await;
    }
}

async fn vectorised_round_trip(proxy_conn: Arc<dyn Conn>) {
    assert!(proxy_conn.supports_vectorised());
    let part_a = random_bytes(700);
    let part_b = random_bytes(900);
    let buffers = vectorised_buffers(proxy_conn.as_ref(), &[&part_a, &part_b]);
    proxy_conn.write_vectorised(buffers).await.unwrap();
    let mut expected = part_a.clone();
    expected.extend_from_slice(&part_b);
    let mut received = vec![0u8; expected.len()];
    proxy_conn.set_read_deadline(deadline(10)).unwrap();
    read_full(proxy_conn.as_ref(), &mut received).await.unwrap();
    assert_eq!(expected, received);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vectorised_writer_loopback() {
    let echo_port = start_tcp_echo().await;
    let destination = Socksaddr::parse_host_port("127.0.0.1", echo_port);
    let address = start_local_snell_service(v5_service(Arc::new(LocalRouteHandler), ObfsMode::None)).await;
    let client = v4_client(Default::default());
    vectorised_round_trip(client.dial_early_conn(dial(&address).await, destination.clone())).await;
    for (_, mode) in V6_MODES {
        let address = start_local_snell_service(v6_service(Arc::new(LocalRouteHandler), mode)).await;
        let client =
            v6::Client::new(v6::ClientOptions { psk: TEST_PSK.as_bytes().to_vec(), mode, ..Default::default() })
                .unwrap();
        vectorised_round_trip(client.dial_early_conn(dial(&address).await, destination.clone())).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn v6_unshaped_large_write_buffer_first_record() {
    let echo_port = start_tcp_echo().await;
    let destination = Socksaddr::parse_host_port("127.0.0.1", echo_port);
    let address = start_local_snell_service(v6_service(Arc::new(LocalRouteHandler), v6::Mode::Unshaped)).await;
    let client = v6::Client::new(v6::ClientOptions {
        psk: TEST_PSK.as_bytes().to_vec(),
        mode: v6::Mode::Unshaped,
        ..Default::default()
    })
    .unwrap();
    let proxy_conn = client.dial_early_conn(dial(&address).await, destination.clone());
    let payload = random_bytes(80 * 1024);
    let request = snell::Request { command: snell::COMMAND_CONNECT, destination, ..Default::default() };
    let buffer = Buffer::from_slice_with_headroom(&payload, request.len(), 0);
    proxy_conn.write_buffer(buffer).await.unwrap();
    let mut received = vec![0u8; payload.len()];
    proxy_conn.set_read_deadline(deadline(20)).unwrap();
    read_full(proxy_conn.as_ref(), &mut received).await.unwrap();
    assert!(payload == received, "payload mismatch");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_loopback() {
    let echo_port = start_udp_echo().await;
    let target = Socksaddr::parse_host_port("127.0.0.1", echo_port);
    for obfs_mode in [ObfsMode::None, ObfsMode::Http] {
        let address = start_local_snell_service(v5_service(Arc::new(UdpRouteHandler), obfs_mode)).await;
        let client = v4_client(v4::ClientOptions { obfs_mode, ..Default::default() });
        let packet_conn = client.dial_packet_conn(dial(&address).await).unwrap();
        udp_rounds(packet_conn.as_ref(), target.clone(), 1200, 10).await;
        if obfs_mode == ObfsMode::None {
            let packet_conn = client.dial_packet_conn(dial(&address).await).unwrap();
            udp_batch(packet_conn.as_ref(), target.clone(), 1200).await;
        }
    }
    for (_, mode) in V6_MODES {
        let psk = b"snell-rc-udp-0371991".to_vec();
        let service: Arc<dyn Service> = Arc::new(
            v6::Service::new(v6::ServerOptions { psk: psk.clone(), mode, handler: Arc::new(UdpRouteHandler) }).unwrap(),
        );
        let address = start_local_snell_service(service).await;
        let client = v6::Client::new(v6::ClientOptions { psk, mode, ..Default::default() }).unwrap();
        let packet_conn = client.dial_packet_conn(dial(&address).await).unwrap();
        assert!(packet_conn.writer_mtu() >= 1400);
        udp_rounds(packet_conn.as_ref(), target.clone(), 1400, 10).await;
        let packet_conn = client.dial_packet_conn(dial(&address).await).unwrap();
        udp_batch(packet_conn.as_ref(), target.clone(), 1400).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_service_authentication() {
    let echo_port = start_tcp_echo().await;
    let destination = Socksaddr::parse_host_port("127.0.0.1", echo_port);

    struct UserCheckHandler(mpsc::UnboundedSender<Option<String>>);

    impl Handler for UserCheckHandler {
        fn new_connection(
            &self,
            ctx: Context,
            conn: Arc<dyn Conn>,
            source: Socksaddr,
            destination: Socksaddr,
            on_close: Option<CloseHandler>,
        ) {
            let _ = self.0.send(ctx.user::<String>().cloned());
            LocalRouteHandler.new_connection(ctx, conn, source, destination, on_close);
        }

        fn new_packet_connection(
            &self,
            ctx: Context,
            conn: Arc<dyn PacketConn>,
            source: Socksaddr,
            destination: Socksaddr,
            on_close: Option<CloseHandler>,
        ) {
            LocalEchoHandler.new_packet_connection(ctx, conn, source, destination, on_close);
        }
    }

    let (users_tx, mut users_rx) = mpsc::unbounded_channel();
    let service = v5::MultiService::<String>::new(v5::ServiceOptions {
        psk: TEST_PSK.as_bytes().to_vec(),
        obfs_mode: ObfsMode::None,
        handler: Arc::new(UserCheckHandler(users_tx.clone())),
    })
    .unwrap();
    assert!(snell::has_code(&service.update_users(vec![], vec![]).unwrap_err(), snell::ErrorCode::NoUsers));
    assert!(snell::has_code(
        &service.update_users(vec!["a".into(), "b".into()], vec![b"k".to_vec(), b"k".to_vec()]).unwrap_err(),
        snell::ErrorCode::DuplicateUserKey
    ));
    service.update_users(vec!["alice".into()], vec![b"alice-key".to_vec()]).unwrap();
    let address = start_local_snell_service(Arc::new(service)).await;
    let client = v4_client(v4::ClientOptions { user_key: b"alice-key".to_vec(), ..Default::default() });
    let proxy_conn = client.dial_conn(dial(&address).await, destination.clone()).await.unwrap();
    bulk_round_trip(proxy_conn, 64 * 1024).await;
    assert_eq!(Some("alice".to_string()), users_rx.recv().await.unwrap());
    let bad_client = v4_client(v4::ClientOptions { user_key: b"mallory".to_vec(), ..Default::default() });
    let proxy_conn = bad_client.dial_conn(dial(&address).await, destination.clone()).await.unwrap();
    proxy_conn.set_read_deadline(deadline(10)).unwrap();
    let mut one = [0u8; 1];
    assert!(proxy_conn.read(&mut one).await.is_err());

    for (_, mode) in V6_MODES {
        let service = v6::MultiService::<String>::new(v6::ServerOptions {
            psk: TEST_PSK.as_bytes().to_vec(),
            mode,
            handler: Arc::new(UserCheckHandler(users_tx.clone())),
        })
        .unwrap();
        service.update_users(vec!["bob".into()], vec![b"bob-key".to_vec()]).unwrap();
        let address = start_local_snell_service(Arc::new(service)).await;
        let client = v6::Client::new(v6::ClientOptions {
            psk: TEST_PSK.as_bytes().to_vec(),
            user_key: b"bob-key".to_vec(),
            mode,
            ..Default::default()
        })
        .unwrap();
        let proxy_conn = client.dial_conn(dial(&address).await, destination.clone()).await.unwrap();
        bulk_round_trip(proxy_conn, 64 * 1024).await;
        assert_eq!(Some("bob".to_string()), users_rx.recv().await.unwrap());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn option_validation() {
    assert!(snell::has_code(&v4::Client::new(Default::default()).err().unwrap(), snell::ErrorCode::MissingPsk));
    assert!(snell::has_code(&v6::Client::new(Default::default()).err().unwrap(), snell::ErrorCode::MissingPsk));
    let short = v6::Service::new(v6::ServerOptions {
        psk: b"short".to_vec(),
        mode: v6::Mode::Default,
        handler: Arc::new(LocalEchoHandler),
    });
    assert!(short.is_err());
    assert_eq!(v6::Mode::UnsafeRaw, v6::parse_mode("unsafe-raw").unwrap());
    assert!(v6::parse_mode("raw").is_err());
    assert_eq!(ObfsMode::Tls, snell::parse_obfs_mode("TLS").unwrap());
    assert!(snell::parse_obfs_mode("ws").is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conn_stream_copy_bidirectional() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let echo_port = start_tcp_echo().await;
    let address = start_local_snell_service(v6_service(Arc::new(LocalRouteHandler), v6::Mode::Default)).await;
    let client =
        v6::Client::new(v6::ClientOptions { psk: TEST_PSK.as_bytes().to_vec(), ..Default::default() }).unwrap();
    let proxy_conn = client.dial_early_conn(dial(&address).await, Socksaddr::parse_host_port("127.0.0.1", echo_port));
    let mut stream = snell::ConnStream::new(proxy_conn);
    let (local, mut remote) = tokio::io::duplex(64 * 1024);
    let copy = tokio::spawn(async move { tokio::io::copy_bidirectional(&mut remote, &mut stream).await });

    let payload = random_bytes(300 * 1024);
    let (mut reader, mut writer) = tokio::io::split(local);
    let write = {
        let payload = payload.clone();
        tokio::spawn(async move {
            writer.write_all(&payload).await.unwrap();
            writer.shutdown().await.unwrap();
        })
    };
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), reader.read_to_end(&mut received)).await.unwrap().unwrap();
    write.await.unwrap();
    assert!(received == payload, "payload mismatch");
    copy.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_psk_reuses_one_transport_and_rechecks_revocation() {
    let echo_port = start_tcp_echo().await;
    let destination = Socksaddr::parse_host_port("127.0.0.1", echo_port);
    let psk = b"independent-user-psk".to_vec();
    let service = Arc::new(v6::MultiPskService::<usize>::new(v6::Mode::Default, Arc::new(LocalRouteHandler)).unwrap());
    service.update_users(vec![1], vec![psk.clone()]).unwrap();
    let address = start_local_snell_service(service.clone()).await;
    let proxy = CountingTcpProxy::start(address).await;
    let client = v6::Client::new(v6::ClientOptions {
        psk,
        reuse: true,
        dialer: system_dialer(),
        server: proxy.socksaddr(),
        ..Default::default()
    })
    .unwrap();
    for label in ["first-logical-request", "second-logical-request"] {
        ReuseScenario { client: &client, destination: destination.clone() }.round_trip(label).await;
    }
    assert_eq!(1, proxy.count(), "logical requests must share a transport");
    service.update_users(vec![], vec![]).unwrap();
    let conn = client.dial_context(&Context::new(), destination).await.unwrap();
    conn.set_deadline(deadline(3)).unwrap();
    let result = async {
        conn.write(b"revoked").await?;
        let mut reply = [0; 7];
        read_full(conn.as_ref(), &mut reply).await
    }
    .await;
    assert!(result.is_err(), "revoked credential must not authorize a reused request");
    assert_eq!(1, proxy.count());
    let _ = conn.close().await;
    client.close().await.unwrap();
}
