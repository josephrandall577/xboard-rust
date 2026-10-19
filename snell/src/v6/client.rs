use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::OnceCell;

use super::handshake::Framing;
use super::profile::Profile;
use super::reuse::ReuseSession;
use super::{MAX_PAYLOAD, Mode};
use crate::COMMAND_CONNECT_V2;
use crate::addr::Socksaddr;
use crate::buf::Buffer;
use crate::error::{self, ErrorCode, SharedResult};
use crate::net::{Conn, Dialer, Method, PacketConn, ReadWaitOptions};
use crate::request::Request;
use crate::reuse::{Pool, RecordReader, RecordWriter, eof_to_none, eof_to_zero, parse_reply};

#[derive(Clone, Default)]
pub struct ClientOptions {
    pub psk: Vec<u8>,
    pub user_key: Vec<u8>,
    pub mode: Mode,
    pub reuse: bool,
    pub dialer: Option<Arc<dyn Dialer>>,
    pub server: Socksaddr,
}

/// Immutable client settings shared with connections and sessions.
pub(crate) struct ClientConfig {
    pub(crate) framing: Framing,
    pub(crate) user_key: Vec<u8>,
}

impl ClientConfig {
    pub(crate) fn request(&self, destination: &Socksaddr) -> Request {
        // Surge 6.7.0 (11520): SNConnectorV4::targetHandshakeData: writes command 5
        // for v6 TCP handshakes even when connector reuse is disabled.
        Request { command: COMMAND_CONNECT_V2, client_id: self.user_key.clone(), destination: destination.clone() }
    }

    pub(crate) fn front_headroom(&self, destination: &Socksaddr) -> usize {
        self.request(destination).len() + self.framing.first_front_headroom()
    }
}

pub(crate) struct ClientInner {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) reuse: bool,
    pub(crate) dialer: Option<Arc<dyn Dialer>>,
    pub(crate) server: Socksaddr,
    pub(crate) pool: Pool<Arc<ReuseSession>>,
    pub(crate) close_idle: AtomicBool,
}

/// The snell v6 client.
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
}

impl Client {
    pub fn new(options: ClientOptions) -> io::Result<Client> {
        if options.psk.is_empty() {
            return Err(ErrorCode::MissingPsk.into());
        }
        if options.user_key.len() > 255 {
            return Err(error::new_invalid("snell: user key too long"));
        }
        let profile = (options.mode == Mode::Default).then(|| Arc::new(Profile::new(&options.psk)));
        let inner = ClientInner {
            config: Arc::new(ClientConfig {
                framing: Framing { mode: options.mode, psk: options.psk.into(), profile },
                user_key: options.user_key,
            }),
            reuse: options.reuse,
            dialer: options.dialer,
            server: options.server,
            pool: Pool::default(),
            close_idle: AtomicBool::new(false),
        };
        if options.reuse {
            inner.pool.init();
        }
        Ok(Client { inner: Arc::new(inner) })
    }

    /// Wraps `conn` and writes the request immediately.
    pub async fn dial_conn(&self, conn: Arc<dyn Conn>, destination: Socksaddr) -> io::Result<Arc<ClientConn>> {
        let client_conn = self.dial_early_conn(conn, destination);
        client_conn.write_request(&[]).await?;
        Ok(client_conn)
    }

    /// Wraps `conn`; the request is sent together with the first write.
    pub fn dial_early_conn(&self, conn: Arc<dyn Conn>, destination: Socksaddr) -> Arc<ClientConn> {
        Arc::new(ClientConn::new(conn, self.inner.config.clone(), destination))
    }

    pub fn dial_packet_conn(&self, conn: Arc<dyn Conn>) -> io::Result<Arc<super::ClientPacketConn>> {
        Ok(Arc::new(super::ClientPacketConn::new(conn, self.inner.config.clone())))
    }
}

#[async_trait]
impl Method for Client {
    async fn dial_conn(&self, conn: Arc<dyn Conn>, destination: Socksaddr) -> io::Result<Arc<dyn Conn>> {
        Ok(Client::dial_conn(self, conn, destination).await?)
    }

    fn dial_early_conn(&self, conn: Arc<dyn Conn>, destination: Socksaddr) -> Arc<dyn Conn> {
        Client::dial_early_conn(self, conn, destination)
    }

    fn dial_packet_conn(&self, conn: Arc<dyn Conn>) -> io::Result<Arc<dyn PacketConn>> {
        Ok(Client::dial_packet_conn(self, conn)?)
    }
}

/// A non-reusable client connection.
pub struct ClientConn {
    conn: Arc<dyn Conn>,
    config: Arc<ClientConfig>,
    destination: Socksaddr,

    access: tokio::sync::Mutex<()>,
    writer: OnceLock<Arc<dyn RecordWriter>>,
    reply_access: tokio::sync::Mutex<()>,
    reader: OnceLock<Arc<dyn RecordReader>>,
    read_wait_options: Mutex<ReadWaitOptions>,
    close_write: OnceCell<SharedResult>,
}

impl ClientConn {
    fn new(conn: Arc<dyn Conn>, config: Arc<ClientConfig>, destination: Socksaddr) -> Self {
        ClientConn {
            conn,
            config,
            destination,
            access: tokio::sync::Mutex::new(()),
            writer: OnceLock::new(),
            reply_access: tokio::sync::Mutex::new(()),
            reader: OnceLock::new(),
            read_wait_options: Mutex::new(ReadWaitOptions::default()),
            close_write: OnceCell::new(),
        }
    }

    async fn write_request(&self, payload: &[u8]) -> io::Result<()> {
        let request = self.config.request(&self.destination);
        let mut buffer = Buffer::with_capacity(request.len() + payload.len());
        request.write(&mut buffer)?;
        if !payload.is_empty() {
            buffer.write_all(payload);
        }
        let data = buffer.bytes();
        let first = &data[..data.len().min(MAX_PAYLOAD)];
        let writer = self
            .config
            .framing
            .write_first_record(&self.conn, first)
            .await
            .map_err(|err| error::cause(err, "write request"))?;
        let writer = self.writer.get_or_init(|| writer);
        if data.len() > first.len() {
            writer.write(&data[first.len()..]).await.map_err(|err| error::cause(err, "write request"))?;
        }
        Ok(())
    }

    async fn write_request_buffer(&self, mut buffer: Buffer) -> io::Result<()> {
        let request = self.config.request(&self.destination).encode()?;
        buffer.extend_header(request.len()).copy_from_slice(&request);
        let writer = self
            .config
            .framing
            .write_first_record_buffer(&self.conn, buffer)
            .await
            .map_err(|err| error::cause(err, "write request"))?;
        let _ = self.writer.set(writer);
        Ok(())
    }

    async fn read_response(&self) -> io::Result<&Arc<dyn RecordReader>> {
        if let Some(reader) = self.reader.get() {
            return Ok(reader);
        }
        let _guard = self.reply_access.lock().await;
        if let Some(reader) = self.reader.get() {
            return Ok(reader);
        }
        let options = *self.read_wait_options.lock().unwrap();
        let (reader, record) = self
            .config
            .framing
            .read_first_record(&self.conn, options)
            .await
            .map_err(|err| error::cause(err, "read reply"))?;
        let cached = parse_reply(record)?;
        reader.set_cache(cached);
        Ok(self.reader.get_or_init(|| reader))
    }
}

#[async_trait]
impl Conn for ClientConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let reader = self.read_response().await?;
        if buf.is_empty() {
            return Ok(0);
        }
        eof_to_zero(reader.read(buf).await)
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if let Some(writer) = self.writer.get() {
            return writer.write(buf).await;
        }
        let guard = self.access.lock().await;
        if let Some(writer) = self.writer.get() {
            drop(guard);
            return writer.write(buf).await;
        }
        self.write_request(buf).await?;
        Ok(buf.len())
    }

    async fn close(&self) -> io::Result<()> {
        self.conn.close().await
    }

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
        self.destination.clone()
    }

    async fn close_write(&self) -> io::Result<()> {
        self.close_write
            .get_or_init(|| async {
                let _guard = self.access.lock().await;
                if self.writer.get().is_none()
                    && let Err(err) = self.write_request(&[]).await
                {
                    return SharedResult::new(Err(err));
                }
                SharedResult::new(self.writer.get().unwrap().write_zero_chunk().await)
            })
            .await
            .get()
    }

    async fn read_buffer(&self, buffer: &mut Buffer) -> io::Result<usize> {
        let reader = self.read_response().await?;
        if buffer.free_len() == 0 {
            return Err(error::short_buffer());
        }
        eof_to_zero(reader.read_buffer(buffer).await)
    }

    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        if let Some(writer) = self.writer.get() {
            return writer.write_buffer(buffer).await;
        }
        let guard = self.access.lock().await;
        if let Some(writer) = self.writer.get() {
            drop(guard);
            return writer.write_buffer(buffer).await;
        }
        self.write_request_buffer(buffer).await
    }

    fn supports_vectorised(&self) -> bool {
        self.conn.supports_vectorised()
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        if !self.conn.supports_vectorised() {
            for buffer in buffers {
                self.write_buffer(buffer).await?;
            }
            return Ok(());
        }
        if let Some(writer) = self.writer.get() {
            return writer.write_vectorised(buffers).await;
        }
        let guard = self.access.lock().await;
        if let Some(writer) = self.writer.get() {
            drop(guard);
            return writer.write_vectorised(buffers).await;
        }
        let mut buffers = buffers.into_iter();
        while let Some(buffer) = buffers.next() {
            if buffer.is_empty() {
                continue;
            }
            self.write_request_buffer(buffer).await?;
            let rest: Vec<Buffer> = buffers.collect();
            if !rest.is_empty() {
                let writer = self.writer.get().unwrap().clone();
                drop(guard);
                return writer.write_vectorised(rest).await;
            }
            return Ok(());
        }
        Ok(())
    }

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        *self.read_wait_options.lock().unwrap() = options;
        if let Some(reader) = self.reader.get() {
            reader.initialize_read_waiter(options);
        }
        false
    }

    async fn wait_read_buffer(&self) -> io::Result<Option<Buffer>> {
        let reader = self.read_response().await?;
        eof_to_none(reader.wait_read_buffer().await)
    }

    fn front_headroom(&self) -> usize {
        if let Some(writer) = self.writer.get() {
            return writer.front_headroom();
        }
        self.config.front_headroom(&self.destination)
    }

    fn rear_headroom(&self) -> usize {
        if let Some(writer) = self.writer.get() {
            return writer.rear_headroom();
        }
        self.config.framing.rear_headroom()
    }

    fn writer_mtu(&self) -> usize {
        if let Some(writer) = self.writer.get() {
            return writer.writer_mtu();
        }
        self.config.framing.writer_mtu()
    }

    fn need_handshake_for_read(&self) -> bool {
        self.reader.get().is_none()
    }

    fn need_handshake_for_write(&self) -> bool {
        self.writer.get().is_none()
    }

    fn need_additional_read_deadline(&self) -> bool {
        self.reader.get().is_none()
    }
}
