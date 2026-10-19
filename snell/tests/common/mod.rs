#![allow(dead_code)]

pub mod server;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rand::Rng;
use snell::crypto::{Aead, derive_key, increase_nonce};
use snell::{
    Buffer, CloseHandler, Conn, Context, Dialer, Handler, PacketConn, ReadWaitOptions, Service, Socksaddr, TcpConn,
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;

pub const TEST_PSK: &str = "snell-interop-test-psk-0123456789";

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

pub fn labelled_payload(label: &str, len: usize) -> Vec<u8> {
    let mut payload = random_bytes(len);
    payload[..label.len()].copy_from_slice(label.as_bytes());
    payload
}

pub fn deadline(seconds: u64) -> Option<Instant> {
    Some(Instant::now() + Duration::from_secs(seconds))
}

pub async fn dial(address: &str) -> Arc<dyn Conn> {
    Arc::new(TcpConn::new(TcpStream::connect(address).await.unwrap()).unwrap())
}

pub async fn listen() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// Go's `io.ReadFull`.
pub async fn read_full(conn: &dyn Conn, buf: &mut [u8]) -> io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        match conn.read(&mut buf[n..]).await? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            m => n += m,
        }
    }
    Ok(())
}

/// Go's `io.ReadAll`.
pub async fn read_all(conn: &dyn Conn) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        match conn.read(&mut buf).await? {
            0 => return Ok(out),
            n => out.extend_from_slice(&buf[..n]),
        }
    }
}

pub async fn start_tcp_echo() -> u16 {
    let (listener, port) = listen().await;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.into_split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    port
}

pub async fn start_udp_echo() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 64 * 1024];
        while let Ok((n, addr)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..n], addr).await;
        }
    });
    port
}

async fn serve_half_close_echo(stream: TcpStream, tail_len: usize, close_write_delay: Duration) {
    let conn = TcpConn::new(stream).unwrap();
    let Ok(payload) = read_all(&conn).await else {
        return;
    };
    if conn.write(&payload).await.is_err() {
        return;
    }
    if tail_len > 0 && conn.write(&vec![0x5a; tail_len]).await.is_err() {
        return;
    }
    tokio::time::sleep(close_write_delay).await;
    let _ = conn.close_write().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = conn.close().await;
}

pub async fn start_tcp_half_close_echo(close_write_delay: Duration) -> u16 {
    start_tcp_half_close_tail_echo(0, close_write_delay).await
}

pub async fn start_tcp_half_close_tail_echo(tail_len: usize, close_write_delay: Duration) -> u16 {
    let (listener, port) = listen().await;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve_half_close_echo(stream, tail_len, close_write_delay));
        }
    });
    port
}

/// A TCP proxy that counts accepted connections.
pub struct CountingTcpProxy {
    pub address: String,
    pub count: Arc<AtomicI32>,
}

impl CountingTcpProxy {
    pub async fn start(target: String) -> CountingTcpProxy {
        let (listener, port) = listen().await;
        let count = Arc::new(AtomicI32::new(0));
        let accept_count = count.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                accept_count.fetch_add(1, Ordering::SeqCst);
                let target = target.clone();
                tokio::spawn(async move {
                    let Ok(upstream) = TcpStream::connect(&target).await else {
                        return;
                    };
                    let conn: Arc<dyn Conn> = Arc::new(TcpConn::new(stream).unwrap());
                    let upstream: Arc<dyn Conn> = Arc::new(TcpConn::new(upstream).unwrap());
                    let _ = copy_conn(conn, upstream).await;
                });
            }
        });
        CountingTcpProxy { address: format!("127.0.0.1:{port}"), count }
    }

    pub fn count(&self) -> i32 {
        self.count.load(Ordering::SeqCst)
    }

    pub fn socksaddr(&self) -> Socksaddr {
        Socksaddr::parse(&self.address)
    }
}

async fn copy_half(source: &Arc<dyn Conn>, destination: &Arc<dyn Conn>) -> io::Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = source.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        destination.write(&buf[..n]).await?;
    }
}

/// sing's `bufio.CopyConn`: copies both directions with half-close, then closes both.
pub async fn copy_conn(source: Arc<dyn Conn>, destination: Arc<dyn Conn>) -> io::Result<()> {
    let upload = {
        let (source, destination) = (source.clone(), destination.clone());
        async move {
            let result = copy_half(&source, &destination).await;
            match &result {
                Ok(()) => {
                    let _ = destination.close_write().await;
                }
                Err(_) => {
                    let _ = destination.close().await;
                }
            }
            result
        }
    };
    let download = {
        let (source, destination) = (source.clone(), destination.clone());
        async move {
            let result = copy_half(&destination, &source).await;
            match &result {
                Ok(()) => {
                    let _ = source.close_write().await;
                }
                Err(_) => {
                    let _ = source.close().await;
                }
            }
            result
        }
    };
    let (upload, download) = tokio::join!(upload, download);
    let _ = source.close().await;
    let _ = destination.close().await;
    upload.and(download)
}

pub async fn start_local_snell_service(service: Arc<dyn Service>) -> String {
    let (listener, port) = listen().await;
    tokio::spawn(async move {
        while let Ok((stream, addr)) = listener.accept().await {
            let service = service.clone();
            tokio::spawn(async move {
                let conn: Arc<dyn Conn> = Arc::new(TcpConn::new(stream).unwrap());
                if service.new_connection(Context::new(), conn.clone(), Socksaddr::from(addr), None).await.is_err() {
                    let _ = conn.close().await;
                }
            });
        }
    });
    format!("127.0.0.1:{port}")
}

pub struct TestDialer;

#[async_trait]
impl Dialer for TestDialer {
    async fn dial_tcp(&self, ctx: &Context, destination: &Socksaddr) -> io::Result<Arc<dyn Conn>> {
        snell::SystemDialer.dial_tcp(ctx, destination).await
    }
}

pub fn system_dialer() -> Option<Arc<dyn Dialer>> {
    Some(Arc::new(snell::SystemDialer))
}

/// Echoes the whole request after the client half-closes.
#[derive(Clone, Default)]
pub struct LocalEchoHandler;

pub fn echo_connection(conn: Arc<dyn Conn>, on_close: Option<CloseHandler>) {
    tokio::spawn(async move {
        let mut close_err = match read_all(conn.as_ref()).await {
            Ok(payload) => conn.write(&payload).await.err(),
            Err(err) => Some(err),
        };
        let write_close = conn.close_write().await;
        if close_err.is_none() {
            close_err = write_close.err();
        }
        let close = conn.close().await;
        if close_err.is_none() {
            close_err = close.err();
        }
        if let Some(on_close) = on_close {
            on_close(close_err);
        }
    });
}

pub fn echo_packet_connection(ctx: Context, conn: Arc<dyn PacketConn>, on_close: Option<CloseHandler>) {
    tokio::spawn(async move {
        let mut close_err = loop {
            if let Some(err) = ctx.err() {
                break Some(err);
            }
            let mut buffer = Buffer::with_capacity(64 * 1024);
            buffer.resize(512, 0);
            let destination = match conn.read_packet(&mut buffer).await {
                Ok(destination) => destination,
                Err(err) => break Some(err),
            };
            if let Err(err) = conn.write_packet(buffer, destination).await {
                break Some(err);
            }
        };
        let close = conn.close().await;
        if close_err.is_none() {
            close_err = close.err();
        }
        if let Some(on_close) = on_close {
            on_close(close_err);
        }
    });
}

impl Handler for LocalEchoHandler {
    fn new_connection(
        &self,
        _: Context,
        conn: Arc<dyn Conn>,
        _: Socksaddr,
        _: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        echo_connection(conn, on_close);
    }

    fn new_packet_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn PacketConn>,
        _: Socksaddr,
        _: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        echo_packet_connection(ctx, conn, on_close);
    }
}

/// Routes TCP connections to their real destination.
pub struct LocalRouteHandler;

impl Handler for LocalRouteHandler {
    fn new_connection(
        &self,
        _: Context,
        conn: Arc<dyn Conn>,
        _: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        tokio::spawn(async move {
            let result = match TcpStream::connect(destination.to_string()).await {
                Ok(upstream) => copy_conn(conn, Arc::new(TcpConn::new(upstream).unwrap())).await,
                Err(err) => Err(err),
            };
            if let Some(on_close) = on_close {
                on_close(result.err());
            }
        });
    }

    fn new_packet_connection(
        &self,
        _: Context,
        conn: Arc<dyn PacketConn>,
        _: Socksaddr,
        _: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        tokio::spawn(async move {
            let result = conn.close().await;
            if let Some(on_close) = on_close {
                on_close(result.err());
            }
        });
    }
}

/// Routes UDP packets to their real destination through one local socket.
pub struct UdpRouteHandler;

impl Handler for UdpRouteHandler {
    fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        LocalRouteHandler.new_connection(ctx, conn, source, destination, on_close);
    }

    fn new_packet_connection(
        &self,
        _: Context,
        conn: Arc<dyn PacketConn>,
        _: Socksaddr,
        _: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        tokio::spawn(async move {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let downlink = {
                let (socket, conn) = (socket.clone(), conn.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    loop {
                        let Ok((n, addr)) = socket.recv_from(&mut buf).await else {
                            return;
                        };
                        let buffer =
                            Buffer::from_slice_with_headroom(&buf[..n], conn.front_headroom(), conn.rear_headroom());
                        if conn.write_packet(buffer, Socksaddr::from(addr)).await.is_err() {
                            return;
                        }
                    }
                })
            };
            let close_err = loop {
                let mut buffer = Buffer::new_packet();
                match conn.read_packet(&mut buffer).await {
                    Ok(destination) => {
                        let target: SocketAddr = destination.socket_addr().unwrap();
                        let _ = socket.send_to(buffer.bytes(), target).await;
                    }
                    Err(err) => break Some(err),
                }
            };
            downlink.abort();
            let _ = conn.close().await;
            if let Some(on_close) = on_close {
                on_close(close_err);
            }
        });
    }
}

/// Echoes the first `echo_len` bytes, then closes before the client EOF.
pub struct PartialEchoHandler {
    pub echo_len: usize,
}

impl Handler for PartialEchoHandler {
    fn new_connection(
        &self,
        _: Context,
        conn: Arc<dyn Conn>,
        _: Socksaddr,
        _: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        let echo_len = self.echo_len;
        tokio::spawn(async move {
            let mut payload = vec![0u8; echo_len];
            let mut result = read_full(conn.as_ref(), &mut payload).await;
            if result.is_ok() {
                result = conn.write(&payload).await.map(|_| ());
            }
            let close = conn.close().await;
            if result.is_ok() {
                result = close;
            }
            if let Some(on_close) = on_close {
                on_close(result.err());
            }
        });
    }

    fn new_packet_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn PacketConn>,
        _: Socksaddr,
        _: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        echo_packet_connection(ctx, conn, on_close);
    }
}

pub struct NormalScenario<'a> {
    pub address: &'a str,
    pub client: &'a dyn snell::Method,
}

impl NormalScenario<'_> {
    pub async fn half_close_echo(&self, label: &str) {
        let echo_port = start_tcp_half_close_echo(Duration::ZERO).await;
        let server_conn = dial(self.address).await;
        let proxy_conn =
            self.client.dial_conn(server_conn, Socksaddr::parse_host_port("127.0.0.1", echo_port)).await.unwrap();
        let payload = labelled_payload(label, 4 * 1024);
        proxy_conn.write(&payload).await.unwrap();
        proxy_conn.close_write().await.unwrap();
        proxy_conn.set_read_deadline(deadline(10)).unwrap();
        let received = read_all(proxy_conn.as_ref()).await.unwrap();
        assert_eq!(payload.len(), received.len(), "{label} response length");
        assert!(payload == received, "{label} payload mismatch");
        let _ = proxy_conn.close().await;
    }
}

#[async_trait]
pub trait ReuseClient: Send + Sync {
    async fn dial_context(&self, ctx: &Context, destination: Socksaddr) -> io::Result<Arc<dyn Conn>>;
    async fn close(&self) -> io::Result<()>;
}

#[async_trait]
impl ReuseClient for snell::v4::Client {
    async fn dial_context(&self, ctx: &Context, destination: Socksaddr) -> io::Result<Arc<dyn Conn>> {
        snell::v4::Client::dial_context(self, ctx, destination).await
    }

    async fn close(&self) -> io::Result<()> {
        snell::v4::Client::close(self).await
    }
}

#[async_trait]
impl ReuseClient for snell::v6::Client {
    async fn dial_context(&self, ctx: &Context, destination: Socksaddr) -> io::Result<Arc<dyn Conn>> {
        snell::v6::Client::dial_context(self, ctx, destination).await
    }

    async fn close(&self) -> io::Result<()> {
        snell::v6::Client::close(self).await
    }
}

pub struct ReuseScenario<'a> {
    pub client: &'a dyn ReuseClient,
    pub destination: Socksaddr,
}

impl ReuseScenario<'_> {
    async fn dial(&self) -> Arc<dyn Conn> {
        tokio::time::timeout(
            Duration::from_secs(10),
            self.client.dial_context(&Context::new(), self.destination.clone()),
        )
        .await
        .unwrap()
        .unwrap()
    }

    pub async fn round_trip(&self, label: &str) {
        let payload = labelled_payload(label, 4 * 1024);
        let conn = self.dial().await;
        conn.write(&payload).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        conn.close_write().await.unwrap();
        conn.set_read_deadline(deadline(10)).unwrap();
        let received = read_all(conn.as_ref()).await.unwrap();
        assert_eq!(payload.len(), received.len(), "{label} response length");
        assert!(payload == received, "{label} payload mismatch");
        conn.close().await.unwrap();
    }

    pub async fn partial_echo_round_trip(&self, label: &str, payload_len: usize, echo_len: usize) {
        let payload = labelled_payload(label, payload_len);
        let conn = self.dial().await;
        conn.write(&payload).await.unwrap();
        conn.close_write().await.unwrap();
        conn.set_read_deadline(deadline(10)).unwrap();
        let received = read_all(conn.as_ref()).await.unwrap();
        assert!(payload[..echo_len] == received[..], "{label} payload mismatch");
        conn.close().await.unwrap();
    }

    pub async fn close_before_server_eof(&self, label: &str, wait_after_close: Duration) {
        let payload = labelled_payload(label, 4 * 1024);
        let conn = self.dial().await;
        conn.write(&payload).await.unwrap();
        conn.close_write().await.unwrap();
        conn.set_read_deadline(deadline(10)).unwrap();
        let mut received = vec![0u8; payload.len()];
        read_full(conn.as_ref(), &mut received).await.unwrap();
        assert!(payload == received, "{label} payload mismatch");
        let close_start = Instant::now();
        conn.close().await.unwrap();
        assert!(
            close_start.elapsed() <= Duration::from_millis(250),
            "{label} close waited for server EOF instead of leaving the session draining"
        );
        tokio::time::sleep(wait_after_close).await;
    }

    pub async fn close_while_read_blocked(&self, label: &str) {
        let payload = labelled_payload(label, 4 * 1024);
        let conn = self.dial().await;
        conn.write(&payload).await.unwrap();
        conn.close_write().await.unwrap();
        conn.set_read_deadline(deadline(10)).unwrap();
        let mut received = vec![0u8; payload.len()];
        read_full(conn.as_ref(), &mut received).await.unwrap();
        assert!(payload == received, "{label} payload mismatch");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let read_conn = conn.clone();
        let mut read_task = tokio::spawn(async move {
            let _ = started_tx.send(());
            let mut one = [0u8; 1];
            read_conn.read(&mut one).await
        });
        started_rx.await.unwrap();
        if let Ok(result) = tokio::time::timeout(Duration::from_millis(50), &mut read_task).await {
            panic!("{label} read returned before close: {:?}", result.unwrap());
        }

        let close_start = Instant::now();
        conn.close().await.unwrap();
        assert!(
            close_start.elapsed() <= Duration::from_millis(250),
            "{label} close waited for server EOF instead of leaving the active read to finish"
        );
        if let Ok(result) = tokio::time::timeout(Duration::from_millis(100), &mut read_task).await {
            panic!("{label} read returned before server EOF after close: {:?}", result.unwrap());
        }
        match tokio::time::timeout(Duration::from_secs(3), &mut read_task).await {
            Ok(result) => {
                let n = result.unwrap().unwrap_or_else(|err| panic!("{label} read error: {err}"));
                assert_eq!(n, 0, "{label} read bytes");
            }
            Err(_) => panic!("{label} active read did not finish after server EOF"),
        }
    }

    pub async fn read_waiter(&self, label: &str) {
        let payload = labelled_payload(label, 4 * 1024);
        let conn = self.dial().await;
        let need_copy = conn.initialize_read_waiter(ReadWaitOptions {
            front_headroom: 2048,
            rear_headroom: 256,
            mtu: 1200,
            ..Default::default()
        });
        assert!(!need_copy);
        conn.write(&payload).await.unwrap();
        conn.close_write().await.unwrap();
        conn.set_read_deadline(deadline(10)).unwrap();
        let mut received = Vec::with_capacity(payload.len());
        while received.len() < payload.len() {
            let buffer = conn.wait_read_buffer().await.unwrap().unwrap();
            assert!(buffer.start() >= 2048);
            assert!(buffer.free_len() >= 256);
            received.extend_from_slice(buffer.bytes());
        }
        assert!(payload == received, "{label} payload mismatch");
        conn.close().await.unwrap();
    }
}

pub async fn round_trip_packet(packet_conn: &dyn PacketConn, label: &str) {
    let message = random_bytes(1200);
    let target = Socksaddr::parse_host_port("203.0.113.1", 443);
    packet_conn.write_to(&message, target.clone()).await.unwrap();
    packet_conn.set_read_deadline(deadline(10)).unwrap();
    let mut received = vec![0u8; 2048];
    let (n, addr) = packet_conn.read_from(&mut received).await.unwrap();
    assert_eq!(target, addr, "{label}");
    assert!(message[..] == received[..n], "{label}");
}

pub fn vectorised_buffers(conn: &dyn Conn, parts: &[&[u8]]) -> Vec<Buffer> {
    let front = conn.front_headroom();
    let rear = conn.rear_headroom();
    parts.iter().map(|part| Buffer::from_slice_with_headroom(part, front, rear)).collect()
}

/// A hand-rolled v5 wire peer, like the Go test's `v5RawConn`.
pub struct V5RawConn {
    conn: Arc<dyn Conn>,
    psk: Vec<u8>,
    request: Option<(Aead, [u8; 12])>,
    response: Option<(Aead, [u8; 12])>,
}

#[derive(Debug)]
pub enum RawRead {
    Payload(Vec<u8>),
    ZeroChunk,
}

impl V5RawConn {
    pub fn new(conn: Arc<dyn Conn>) -> Self {
        V5RawConn { conn, psk: TEST_PSK.as_bytes().to_vec(), request: None, response: None }
    }

    fn seal_record(&mut self, payload: &[u8]) -> Vec<u8> {
        let (aead, nonce) = self.request.as_mut().unwrap();
        let mut header = vec![0u8; snell::HEADER_CIPHER_LEN];
        header[0] = snell::HEADER_VERSION;
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        aead.seal_in_place(nonce, &[], &mut header);
        increase_nonce(nonce);
        let mut record = header;
        if !payload.is_empty() {
            let mut body = payload.to_vec();
            body.extend_from_slice(&[0u8; 16]);
            aead.seal_in_place(nonce, &[], &mut body);
            increase_nonce(nonce);
            record.extend_from_slice(&body);
        }
        record
    }

    pub async fn write_first_record(&mut self, salt: &[u8], payload: &[u8]) {
        self.request = Some((Aead::new(&derive_key(&self.psk, salt)).unwrap(), [0; 12]));
        let mut wire = salt.to_vec();
        wire.extend_from_slice(&self.seal_record(payload));
        self.conn.write(&wire).await.unwrap();
    }

    pub async fn write_record(&mut self, payload: &[u8]) {
        let record = self.seal_record(payload);
        self.conn.write(&record).await.unwrap();
    }

    pub async fn read_first_record(&mut self) -> io::Result<RawRead> {
        let mut salt = [0u8; 16];
        read_full(self.conn.as_ref(), &mut salt).await?;
        self.response = Some((Aead::new(&derive_key(&self.psk, &salt)).unwrap(), [0; 12]));
        self.read_record().await
    }

    pub async fn read_record(&mut self) -> io::Result<RawRead> {
        let mut header = [0u8; snell::HEADER_CIPHER_LEN];
        read_full(self.conn.as_ref(), &mut header).await?;
        let (aead, nonce) = self.response.as_mut().unwrap();
        aead.open_in_place(nonce, &[], &mut header).unwrap();
        increase_nonce(nonce);
        assert_eq!(snell::HEADER_VERSION, header[0]);
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if payload_len == 0 {
            return Ok(RawRead::ZeroChunk);
        }
        let mut padding = vec![0u8; padding_len];
        read_full(self.conn.as_ref(), &mut padding).await?;
        let mut payload = vec![0u8; payload_len + 16];
        read_full(self.conn.as_ref(), &mut payload).await?;
        let limit = padding.len().min(payload.len());
        for index in (0..limit).step_by(2) {
            std::mem::swap(&mut padding[index], &mut payload[index]);
        }
        let n = aead.open_in_place(nonce, &[], &mut payload).unwrap();
        increase_nonce(nonce);
        payload.truncate(n);
        Ok(RawRead::Payload(payload))
    }
}

pub fn connect_request(command: u8, port: u16, payload: &[u8]) -> Vec<u8> {
    let host = "127.0.0.1";
    let mut request = vec![snell::REQUEST_VERSION, command, 0, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    request.extend_from_slice(payload);
    request
}

/// Records every byte read from the wrapped connection.
pub struct RecordingConn {
    pub conn: Arc<dyn Conn>,
    pub read_bytes: std::sync::Mutex<Vec<u8>>,
}

#[async_trait::async_trait]
impl Conn for RecordingConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.conn.read(buf).await?;
        self.read_bytes.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.conn.write(buf).await
    }

    async fn close(&self) -> io::Result<()> {
        self.conn.close().await
    }

    fn set_read_deadline(&self, deadline: Option<std::time::Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<std::time::Instant>) -> io::Result<()> {
        self.conn.set_write_deadline(deadline)
    }
}

#[derive(Debug, Default)]
pub struct PayloadGrowthMetrics {
    pub found_max_payload: bool,
    pub first_max_payload_offset: usize,
    pub payload_bytes: usize,
    pub max_payload_before_1mib: usize,
    pub record_count: usize,
}

pub fn payload_growth_metrics(wire: &[u8]) -> PayloadGrowthMetrics {
    let aead = Aead::new(&derive_key(TEST_PSK.as_bytes(), &wire[..16])).unwrap();
    let mut nonce = [0u8; 12];
    let mut offset = 16;
    let mut metrics = PayloadGrowthMetrics::default();
    while offset + snell::HEADER_CIPHER_LEN <= wire.len() {
        let mut header = wire[offset..offset + snell::HEADER_CIPHER_LEN].to_vec();
        aead.open_in_place(&nonce, &[], &mut header).unwrap();
        increase_nonce(&mut nonce);
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        if payload_len == snell::MAX_PAYLOAD_LEN && !metrics.found_max_payload {
            metrics.found_max_payload = true;
            metrics.first_max_payload_offset = metrics.payload_bytes;
        }
        if metrics.payload_bytes < 1024 * 1024 {
            metrics.max_payload_before_1mib = metrics.max_payload_before_1mib.max(payload_len);
        }
        offset += snell::HEADER_CIPHER_LEN;
        if payload_len == 0 {
            break;
        }
        assert!(offset + padding_len + payload_len + 16 <= wire.len());
        let mut padding = wire[offset..offset + padding_len].to_vec();
        offset += padding_len;
        let mut payload = wire[offset..offset + payload_len + 16].to_vec();
        offset += payload_len + 16;
        for index in (0..padding.len().min(payload.len())).step_by(2) {
            std::mem::swap(&mut padding[index], &mut payload[index]);
        }
        aead.open_in_place(&nonce, &[], &mut payload).unwrap();
        increase_nonce(&mut nonce);
        metrics.payload_bytes += payload_len;
        metrics.record_count += 1;
    }
    metrics
}

pub async fn start_continuous_download_target(payload: Arc<Vec<u8>>, release: Arc<Notify>) -> u16 {
    let (listener, port) = listen().await;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let payload = payload.clone();
            let release = release.clone();
            tokio::spawn(async move {
                let conn = snell::TcpConn::new(stream).unwrap();
                let mut trigger = [0u8; 1];
                if read_full(&conn, &mut trigger).await.is_err() {
                    return;
                }
                if conn.write(&payload).await.is_err() {
                    return;
                }
                release.notified().await;
                let _ = conn.close().await;
            });
        }
    });
    port
}
