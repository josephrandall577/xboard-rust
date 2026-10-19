//! HTTP and TLS obfuscation layers (`obfs = http` / `obfs = tls`).

use std::fmt;
use std::io;
use std::sync::{Arc, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use rand::{Rng, RngExt};
use tokio::sync::Mutex;

use crate::addr::Socksaddr;
use crate::bufio::BufReader;
use crate::error;
use crate::net::{self, Conn};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ObfsMode {
    #[default]
    None,
    Http,
    Tls,
}

// Surge 6.4.4 (10661): -[SNObfsHelperHTTP initWithPolicy:] and -[SGObfsHelperTLS initWithPolicy:]
// substitute these constants when the policy carries no obfs-host / obfs-uri.
pub const DEFAULT_OBFS_HOST: &str = "bing.com";
pub const DEFAULT_OBFS_URI: &str = "/";
pub const DEFAULT_TLS_OBFS_HOST: &str = "cloudfront.net";

// Surge 6.4.4 (10661): -[SGObfsHelperTLS encodeObfsData:] carries at most 0x400 bytes in the
// ClientHello session ticket extension and splits everything after it into 0x4000 byte records.
const TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN: usize = 0x400;
const TLS_OBFS_RECORD_PAYLOAD_LEN: usize = 0x4000;

// Surge 6.4.4 (10661): -[SGObfsHelperTLS encodeObfsData:] allocates hostname + payload + 0xd9
// bytes for the ClientHello: the payload starts at 0x8e, behind it come the 9 byte server name
// extension header, the hostname and a fixed 0x42 byte trailer. The three length fields count
// from the end of their own prefix.
const TLS_OBFS_CLIENT_HELLO_OVERHEAD: usize = 0xd9;
const TLS_OBFS_CLIENT_HELLO_PAYLOAD_OFFSET: usize = 0x8e;
const TLS_OBFS_CLIENT_HELLO_NAME_HEADER_LEN: usize = 9;
const TLS_OBFS_CLIENT_HELLO_TRAILER_LEN: usize = 0x42;
const TLS_OBFS_CLIENT_RECORD_OVERHEAD: usize = 0xd4;
const TLS_OBFS_CLIENT_HANDSHAKE_OVERHEAD: usize = 0xd0;
const TLS_OBFS_CLIENT_EXTENSIONS_OVERHEAD: usize = 0x4f;

// Surge 6.4.4 (10661): -[SGObfsHelperTLS decodeObfsData:outData:] reads the first response
// payload length at 0x69 and the payload itself at 0x6b.
const TLS_OBFS_SERVER_HELLO_PAYLOAD_OFFSET: usize = 0x6b;

const TLS_OBFS_RECORD_HEADER_LEN: usize = 5;

/// `snell.ParseObfsMode`.
pub fn parse_obfs_mode(name: &str) -> io::Result<ObfsMode> {
    match name.to_lowercase().as_str() {
        "" | "none" => Ok(ObfsMode::None),
        "http" => Ok(ObfsMode::Http),
        "tls" => Ok(ObfsMode::Tls),
        _ => Err(error::new_invalid(format!("snell: unknown obfs mode: {name}"))),
    }
}

impl ObfsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ObfsMode::None => "none",
            ObfsMode::Http => "http",
            ObfsMode::Tls => "tls",
        }
    }
}

impl fmt::Display for ObfsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ObfsMode {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_obfs_mode(s)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObfsConfig {
    pub mode: ObfsMode,
    pub host: String,
    pub uri: String,
}

impl ObfsConfig {
    pub fn client_conn(&self, conn: Arc<dyn Conn>) -> Arc<dyn Conn> {
        match self.mode {
            ObfsMode::None => conn,
            ObfsMode::Http => Arc::new(HttpObfsClientConn {
                conn,
                config: self.clone(),
                head: HttpObfsHead::new(),
                request_sent: Mutex::new(false),
            }),
            ObfsMode::Tls => Arc::new(TlsObfsClientConn {
                conn,
                config: self.clone(),
                read: Mutex::new(TlsClientReadState::default()),
                client_hello_sent: Mutex::new(false),
            }),
        }
    }

    pub fn server_conn(&self, conn: Arc<dyn Conn>) -> Arc<dyn Conn> {
        match self.mode {
            ObfsMode::None => conn,
            ObfsMode::Http => {
                Arc::new(HttpObfsServerConn { conn, head: HttpObfsHead::new(), response_sent: Mutex::new(false) })
            }
            ObfsMode::Tls => Arc::new(TlsObfsServerConn {
                conn,
                read: Mutex::new(TlsServerReadState::default()),
                server_hello_sent: Mutex::new(false),
            }),
        }
    }
}

fn unix_now() -> u32 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or_default() as u32
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

struct HttpObfsFingerprint {
    user_agent: String,
    key: String,
}

// Surge 6.4.4 (10661): the dispatch_once block of -[SNObfsHelperHTTP encodeObfsData:] derives one
// WebSocket key and one Firefox user agent for the whole process, picking 10.9 to 10.14 and
// Firefox 22 to 64.
fn http_obfs_client_fingerprint() -> &'static HttpObfsFingerprint {
    static FINGERPRINT: OnceLock<HttpObfsFingerprint> = OnceLock::new();
    FINGERPRINT.get_or_init(|| {
        let key: [u8; 16] = random_bytes();
        let mut rng = rand::rng();
        HttpObfsFingerprint {
            user_agent: format!(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.{}; rv:64.0) Gecko/20100101 Firefox/{}.0",
                9 + rng.random_range(0..6),
                22 + rng.random_range(0..43)
            ),
            key: base64::engine::general_purpose::STANDARD.encode(key),
        }
    })
}

// Surge 6.4.4 (10661): the dispatch_once block of -[SNObfsHelperServer encodeObfsData:] builds one
// fake 101 response for the whole process and dates it with localtime_r while labelling it GMT.
fn http_obfs_server_response() -> &'static [u8] {
    static RESPONSE: OnceLock<Vec<u8>> = OnceLock::new();
    RESPONSE.get_or_init(|| {
        let accept: [u8; 16] = random_bytes();
        let mut rng = rand::rng();
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.{}.{}\r\nDate: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            rng.random_range(0..14),
            rng.random_range(0..12),
            chrono::Local::now().format("%a, %d %b %Y %H:%M:%S GMT"),
            base64::engine::general_purpose::STANDARD.encode(accept)
        )
        .into_bytes()
    })
}

struct HttpHeadState {
    reader: BufReader,
    ready: bool,
}

// Surge 6.4.4 (10661): -[SNObfsHelperHTTP decodeObfsData:outData:] and
// -[SNObfsHelperServer decodeObfsData:outData:] both drop everything up to and including the first
// \r\n\r\n and never look at the request line, the status line or any header.
struct HttpObfsHead {
    state: Mutex<HttpHeadState>,
}

impl HttpObfsHead {
    fn new() -> Self {
        HttpObfsHead { state: Mutex::new(HttpHeadState { reader: BufReader::new(), ready: false }) }
    }

    async fn read(&self, upstream: &dyn Conn, p: &mut [u8]) -> io::Result<usize> {
        let mut state = self.state.lock().await;
        if !state.ready {
            const TERMINATOR: &[u8] = b"\r\n\r\n";
            let mut matched = 0;
            while matched < TERMINATOR.len() {
                let value =
                    state.reader.read_byte(upstream).await.map_err(|err| error::cause(err, "read http obfs head"))?;
                if value == TERMINATOR[matched] {
                    matched += 1;
                } else if value == TERMINATOR[0] {
                    matched = 1;
                } else {
                    matched = 0;
                }
            }
            state.ready = true;
        }
        match state.reader.read(upstream, p).await {
            Ok(n) => Ok(n),
            Err(err) if error::is_bare_eof(&err) => Ok(0),
            Err(err) => Err(err),
        }
    }
}

macro_rules! forward_conn_basics {
    () => {
        fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
            self.conn.set_read_deadline(deadline)
        }

        fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
            self.conn.set_write_deadline(deadline)
        }

        fn local_addr(&self) -> Socksaddr {
            self.conn.local_addr()
        }

        fn remote_addr(&self) -> Socksaddr {
            self.conn.remote_addr()
        }
    };
}

struct HttpObfsClientConn {
    conn: Arc<dyn Conn>,
    config: ObfsConfig,
    head: HttpObfsHead,
    request_sent: Mutex<bool>,
}

#[async_trait]
impl Conn for HttpObfsClientConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.head.read(self.conn.as_ref(), buf).await
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut request_sent = self.request_sent.lock().await;
        if *request_sent {
            return self.conn.write(buf).await;
        }
        *request_sent = true;
        let host = if self.config.host.is_empty() { DEFAULT_OBFS_HOST } else { &self.config.host };
        let uri = if self.config.uri.is_empty() { DEFAULT_OBFS_URI } else { &self.config.uri };
        let fingerprint = http_obfs_client_fingerprint();
        // Surge 6.4.4 (10661): -[SNObfsHelperHTTP encodeObfsData:] sends this request once, with the
        // whole first packet as its body, and passes everything after it through untouched.
        let mut request = format!(
            "GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: {}\r\nSec-WebSocket-Key: {}\r\n\r\n",
            fingerprint.user_agent,
            buf.len(),
            fingerprint.key
        )
        .into_bytes();
        request.extend_from_slice(buf);
        self.conn.write(&request).await.map_err(|err| error::cause(err, "write http obfs request"))?;
        Ok(buf.len())
    }

    async fn close(&self) -> io::Result<()> {
        self.conn.close().await
    }

    forward_conn_basics!();
}

struct HttpObfsServerConn {
    conn: Arc<dyn Conn>,
    head: HttpObfsHead,
    response_sent: Mutex<bool>,
}

#[async_trait]
impl Conn for HttpObfsServerConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.head.read(self.conn.as_ref(), buf).await
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut response_sent = self.response_sent.lock().await;
        if *response_sent {
            return self.conn.write(buf).await;
        }
        *response_sent = true;
        let fake_response = http_obfs_server_response();
        let mut response = Vec::with_capacity(fake_response.len() + buf.len());
        response.extend_from_slice(fake_response);
        response.extend_from_slice(buf);
        self.conn.write(&response).await.map_err(|err| error::cause(err, "write http obfs response"))?;
        Ok(buf.len())
    }

    async fn close(&self) -> io::Result<()> {
        self.conn.close().await
    }

    forward_conn_basics!();
}

/// The application_data framing that both directions use once their first
/// message has been exchanged.
fn append_records(out: &mut Vec<u8>, mut p: &[u8]) {
    while !p.is_empty() {
        let payload_len = p.len().min(TLS_OBFS_RECORD_PAYLOAD_LEN);
        out.extend_from_slice(&[0x17, 0x03, 0x03]);
        out.extend_from_slice(&(payload_len as u16).to_be_bytes());
        out.extend_from_slice(&p[..payload_len]);
        p = &p[payload_len..];
    }
}

/// Reads (part of) one record. Returns `Ok(0)` for an empty record.
async fn read_record(
    conn: &dyn Conn,
    read_remaining: &mut usize,
    p: &mut [u8],
    header_len: usize,
) -> io::Result<usize> {
    if *read_remaining > 0 {
        let size = (*read_remaining).min(p.len());
        net::read_full(conn, &mut p[..size]).await?;
        *read_remaining -= size;
        return Ok(size);
    }
    net::discard(conn, header_len - 2).await?;
    let mut length_bytes = [0u8; 2];
    net::read_full(conn, &mut length_bytes).await?;
    let payload_len = u16::from_be_bytes(length_bytes) as usize;
    if payload_len == 0 {
        return Ok(0);
    }
    if payload_len > p.len() {
        net::read_full(conn, p).await?;
        *read_remaining = payload_len - p.len();
        return Ok(p.len());
    }
    net::read_full(conn, &mut p[..payload_len]).await?;
    Ok(payload_len)
}

fn eof_to_zero(result: io::Result<usize>) -> io::Result<usize> {
    match result {
        Err(err) if error::is_bare_eof(&err) => Ok(0),
        result => result,
    }
}

#[derive(Default)]
struct TlsClientReadState {
    read_remaining: usize,
    server_hello_received: bool,
}

struct TlsObfsClientConn {
    conn: Arc<dyn Conn>,
    config: ObfsConfig,
    read: Mutex<TlsClientReadState>,
    client_hello_sent: Mutex<bool>,
}

impl TlsObfsClientConn {
    async fn read_inner(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut state = self.read.lock().await;
        let state = &mut *state;
        loop {
            let header_len = if !state.server_hello_received {
                state.server_hello_received = true;
                TLS_OBFS_SERVER_HELLO_PAYLOAD_OFFSET
            } else {
                TLS_OBFS_RECORD_HEADER_LEN
            };
            let n = read_record(self.conn.as_ref(), &mut state.read_remaining, buf, header_len).await?;
            if n > 0 {
                return Ok(n);
            }
        }
    }
}

#[async_trait]
impl Conn for TlsObfsClientConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        eof_to_zero(self.read_inner(buf).await)
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut client_hello_sent = self.client_hello_sent.lock().await;
        if *client_hello_sent {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut out = Vec::with_capacity(buf.len() + buf.len().div_ceil(TLS_OBFS_RECORD_PAYLOAD_LEN) * 5);
            append_records(&mut out, buf);
            self.conn.write(&out).await.map_err(|err| error::cause(err, "write tls obfs payload"))?;
            return Ok(buf.len());
        }
        *client_hello_sent = true;
        let host = if self.config.host.is_empty() { DEFAULT_TLS_OBFS_HOST } else { &self.config.host };
        let payload = &buf[..buf.len().min(TLS_OBFS_CLIENT_HELLO_PAYLOAD_LEN)];
        let random: [u8; 28] = random_bytes();
        let session_id: [u8; 32] = random_bytes();
        // Surge 6.4.4 (10661): -[SGObfsHelperTLS encodeObfsData:] patches this ClientHello template with
        // the current time, fresh randomness, the first 0x400 payload bytes as a session ticket and the
        // obfs hostname as the server name, then appends the remaining payload as normal records.
        let mut out =
            Vec::with_capacity(TLS_OBFS_CLIENT_HELLO_OVERHEAD + host.len() + buf.len() + TLS_OBFS_RECORD_HEADER_LEN);
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&((TLS_OBFS_CLIENT_RECORD_OVERHEAD + host.len() + payload.len()) as u16).to_be_bytes());
        out.extend_from_slice(&[0x01, 0x00]);
        out.extend_from_slice(
            &((TLS_OBFS_CLIENT_HANDSHAKE_OVERHEAD + host.len() + payload.len()) as u16).to_be_bytes(),
        );
        out.extend_from_slice(&[0x03, 0x03]);
        out.extend_from_slice(&unix_now().to_be_bytes());
        out.extend_from_slice(&random);
        out.push(0x20);
        out.extend_from_slice(&session_id);
        out.extend_from_slice(&0x0038u16.to_be_bytes());
        out.extend_from_slice(&[
            0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
            0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
            0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f,
            0x00, 0xff,
        ]);
        out.extend_from_slice(&[0x01, 0x00]);
        out.extend_from_slice(
            &((TLS_OBFS_CLIENT_EXTENSIONS_OVERHEAD + host.len() + payload.len()) as u16).to_be_bytes(),
        );
        out.extend_from_slice(&0x0023u16.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&0x0000u16.to_be_bytes());
        out.extend_from_slice(&((host.len() + 5) as u16).to_be_bytes());
        out.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        out.push(0x00);
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host.as_bytes());
        out.extend_from_slice(&[
            0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17,
            0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01,
            0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01,
            0x02, 0x02, 0x02, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
        ]);
        append_records(&mut out, &buf[payload.len()..]);
        self.conn.write(&out).await.map_err(|err| error::cause(err, "write tls obfs client hello"))?;
        Ok(buf.len())
    }

    async fn close(&self) -> io::Result<()> {
        self.conn.close().await
    }

    forward_conn_basics!();
}

#[derive(Default)]
struct TlsServerReadState {
    read_remaining: usize,
    client_hello_received: bool,
    session_name_skipped: bool,
}

struct TlsObfsServerConn {
    conn: Arc<dyn Conn>,
    read: Mutex<TlsServerReadState>,
    server_hello_sent: Mutex<bool>,
}

impl TlsObfsServerConn {
    async fn read_inner(&self, buf: &mut [u8]) -> io::Result<usize> {
        let conn = self.conn.as_ref();
        let mut state = self.read.lock().await;
        let state = &mut *state;
        loop {
            let n = if !state.client_hello_received {
                state.client_hello_received = true;
                read_record(conn, &mut state.read_remaining, buf, TLS_OBFS_CLIENT_HELLO_PAYLOAD_OFFSET).await?
            } else {
                if !state.session_name_skipped && state.read_remaining == 0 {
                    state.session_name_skipped = true;
                    // Surge 6.4.4 (10661): -[SGObfsHelperTLS encodeObfsData:] puts the 9 byte server name
                    // extension header, the hostname and a fixed 0x42 byte extension trailer behind the session
                    // ticket that carries the first payload.
                    net::discard(conn, TLS_OBFS_CLIENT_HELLO_NAME_HEADER_LEN - 2).await?;
                    let mut length_bytes = [0u8; 2];
                    net::read_full(conn, &mut length_bytes).await?;
                    net::discard(conn, u16::from_be_bytes(length_bytes) as usize + TLS_OBFS_CLIENT_HELLO_TRAILER_LEN)
                        .await?;
                }
                read_record(conn, &mut state.read_remaining, buf, TLS_OBFS_RECORD_HEADER_LEN).await?
            };
            if n > 0 {
                return Ok(n);
            }
        }
    }
}

#[async_trait]
impl Conn for TlsObfsServerConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        eof_to_zero(self.read_inner(buf).await)
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut server_hello_sent = self.server_hello_sent.lock().await;
        if *server_hello_sent {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut out = Vec::with_capacity(buf.len() + buf.len().div_ceil(TLS_OBFS_RECORD_PAYLOAD_LEN) * 5);
            append_records(&mut out, buf);
            self.conn.write(&out).await.map_err(|err| error::cause(err, "write tls obfs payload"))?;
            return Ok(buf.len());
        }
        *server_hello_sent = true;
        let payload = &buf[..buf.len().min(TLS_OBFS_RECORD_PAYLOAD_LEN)];
        let random: [u8; 28] = random_bytes();
        let session_id: [u8; 32] = random_bytes();
        // Surge 6.4.4 (10661): -[SGObfsHelperTLS decodeObfsData:outData:] never parses this response, it
        // only requires the first payload length at 0x69 and the payload itself at 0x6b.
        let mut out = Vec::with_capacity(TLS_OBFS_SERVER_HELLO_PAYLOAD_OFFSET + buf.len() + TLS_OBFS_RECORD_HEADER_LEN);
        out.extend_from_slice(&[0x16, 0x03, 0x01]);
        out.extend_from_slice(&91u16.to_be_bytes());
        out.extend_from_slice(&[0x02, 0x00, 0x00, 0x57, 0x03, 0x03]);
        out.extend_from_slice(&unix_now().to_be_bytes());
        out.extend_from_slice(&random);
        out.push(0x20);
        out.extend_from_slice(&session_id);
        out.extend_from_slice(&[
            0xcc, 0xa8, 0x00, //
            0x00, 0x00, //
            0xff, 0x01, 0x00, 0x01, 0x00, //
            0x00, 0x17, 0x00, 0x00, //
            0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, //
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, //
            0x16, 0x03, 0x03,
        ]);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        append_records(&mut out, &buf[payload.len()..]);
        self.conn.write(&out).await.map_err(|err| error::cause(err, "write tls obfs server hello"))?;
        Ok(buf.len())
    }

    async fn close(&self) -> io::Result<()> {
        self.conn.close().await
    }

    forward_conn_basics!();
}
