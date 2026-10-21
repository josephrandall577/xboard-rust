use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::OnceCell;

use super::handshake::Framing;
use super::packet::ServerPacketConn;
use super::profile::Profile;
use super::reuse::ServerReuseSession;
use super::{MAX_PAYLOAD, Mode};
use crate::addr::Socksaddr;
use crate::auth::{Authenticator, UserMap, build_user_map, user_authenticator};
use crate::buf::Buffer;
use crate::error::{self, ErrorCode, SharedResult};
use crate::net::{self, CachedPacketConn, CloseHandler, Conn, Context, Handler, ReadWaitOptions, ServerError};
use crate::request::{Request, read_server_request};
use crate::reuse::{RecordReader, RecordWriter, eof_to_none, eof_to_zero};
use crate::{COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_PING, COMMAND_UDP, REPLY_PONG, REPLY_TUNNEL};

pub struct ServerOptions {
    pub psk: Vec<u8>,
    pub mode: Mode,
    pub handler: Arc<dyn Handler>,
}

pub(crate) struct ServiceInner {
    pub(crate) framing: Framing,
    pub(crate) handler: Arc<dyn Handler>,
    pub(crate) authenticator: Option<Box<Authenticator>>,
}

pub(crate) fn err_invalid_udp_tunnel_request() -> io::Error {
    error::new_error("snell: invalid udp tunnel request")
}

fn new_service_inner(options: ServerOptions, authenticator: Option<Box<Authenticator>>) -> io::Result<ServiceInner> {
    if options.psk.is_empty() {
        return Err(ErrorCode::MissingPsk.into());
    }
    // snell-server v6.0.0b4: FUN_00138120: rejects PSKs outside the 12..255-byte range.
    if options.psk.len() < 12 || options.psk.len() > 255 {
        return Err(error::new_invalid("snell: psk length must be between 12 and 255 bytes"));
    }
    let profile = (options.mode == Mode::Default).then(|| Arc::new(Profile::new(&options.psk)));
    Ok(ServiceInner {
        framing: Framing { mode: options.mode, psk: options.psk.into(), profile },
        handler: options.handler,
        authenticator,
    })
}

/// The snell v6 server.
#[derive(Clone)]
pub struct Service {
    inner: Arc<ServiceInner>,
}

impl Service {
    pub fn new(options: ServerOptions) -> io::Result<Service> {
        Ok(Service { inner: Arc::new(new_service_inner(options, None)?) })
    }

    pub async fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> Result<(), ServerError> {
        self.inner.serve(ctx, conn, source, on_close).await
    }
}

#[async_trait]
impl net::Service for Service {
    async fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> Result<(), ServerError> {
        Service::new_connection(self, ctx, conn, source, on_close).await
    }
}

/// The snell v6 server with per-user keys.
pub struct MultiService<U> {
    inner: Arc<ServiceInner>,
    users: UserMap<U>,
}

impl<U> Clone for MultiService<U> {
    fn clone(&self) -> Self {
        MultiService { inner: self.inner.clone(), users: self.users.clone() }
    }
}

impl<U: Clone + Eq + Hash + Send + Sync + 'static> MultiService<U> {
    pub fn new(options: ServerOptions) -> io::Result<MultiService<U>> {
        let users = Arc::new(RwLock::new(Arc::new(HashMap::new())));
        let inner = new_service_inner(options, Some(user_authenticator(users.clone())))?;
        Ok(MultiService { inner: Arc::new(inner), users })
    }

    pub fn update_users(&self, users: Vec<U>, user_keys: Vec<Vec<u8>>) -> io::Result<()> {
        let user_map = build_user_map(users, user_keys)?;
        *self.users.write().unwrap() = Arc::new(user_map);
        Ok(())
    }

    pub async fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> Result<(), ServerError> {
        self.inner.serve(ctx, conn, source, on_close).await
    }
}

#[async_trait]
impl<U: Clone + Eq + Hash + Send + Sync + 'static> net::Service for MultiService<U> {
    async fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> Result<(), ServerError> {
        MultiService::new_connection(self, ctx, conn, source, on_close).await
    }
}

impl ServiceInner {
    async fn serve(
        self: &Arc<Self>,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> Result<(), ServerError> {
        match self.new_connection_inner(ctx, conn.clone(), source.clone(), on_close).await {
            Ok(()) => Ok(()),
            Err(cause) => Err(ServerError { conn, source, cause }),
        }
    }

    pub(crate) fn authenticate(&self, ctx: &Context, request: &Request) -> Option<io::Result<Context>> {
        self.authenticator.as_ref().map(|authenticator| authenticator(ctx, request))
    }

    async fn new_connection_inner(
        self: &Arc<Self>,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> io::Result<()> {
        let (reader, record) = self
            .framing
            .read_first_record(&conn, ReadWaitOptions::default())
            .await
            .map_err(|err| error::cause(err, "read request"))?;
        self.serve_record(ctx, conn, source, on_close, reader, record).await
    }

    pub(crate) async fn serve_record(
        self: &Arc<Self>,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
        reader: Arc<dyn RecordReader>,
        mut record: Buffer,
    ) -> io::Result<()> {
        let request = read_server_request(&mut record).map_err(|err| error::cause(err, "decode request"))?;

        match request.command {
            COMMAND_CONNECT => {
                let request_ctx = match self.authenticate(&ctx, &request) {
                    Some(result) => result?,
                    None => ctx,
                };
                let server_conn = Arc::new(ServerConn::new(conn, self.clone(), reader.clone()));
                if !record.is_empty() {
                    reader.set_cache(Some(record));
                }
                self.handler.new_connection(request_ctx, server_conn, source, request.destination, on_close);
                Ok(())
            }
            COMMAND_CONNECT_V2 => {
                let session = Arc::new(ServerReuseSession::new(conn, self.clone(), reader));
                session.serve(ctx, source, on_close, record, request).await
            }
            COMMAND_UDP => {
                let request_ctx = match self.authenticate(&ctx, &request) {
                    Some(result) => result?,
                    None => ctx,
                };
                // snell-server v6.0.0b4: FUN_00141bc0 rejects UDP tunnel requests when the
                // first UDP datagram starts in the same decrypted frame as the tunnel request.
                if !record.is_empty() {
                    let _ = conn.close().await;
                    return Err(err_invalid_udp_tunnel_request());
                }
                let packet_conn = Arc::new(ServerPacketConn::new(conn, self.framing.clone(), reader, None));
                let mut on_close = on_close;
                self.new_packet_connection(request_ctx, packet_conn, source, &mut on_close).await
            }
            COMMAND_PING => {
                let result = self.framing.write_first_record(&conn, &[REPLY_PONG]).await;
                let close_result = conn.close().await;
                result?;
                close_result
            }
            command => Err(error::extend_code(ErrorCode::UnsupportedCommand, command)),
        }
    }

    pub(crate) async fn new_packet_connection(
        &self,
        ctx: Context,
        packet_conn: Arc<ServerPacketConn>,
        source: Socksaddr,
        on_close: &mut Option<CloseHandler>,
    ) -> io::Result<()> {
        packet_conn.write_tunnel_reply().await?;
        let mut first_packet = Buffer::new_packet();
        let destination = net::PacketConn::read_packet(packet_conn.as_ref(), &mut first_packet)
            .await
            .map_err(|err| error::cause(err, "read first packet"))?;
        let cached = Arc::new(CachedPacketConn::new(packet_conn, first_packet, destination.clone()));
        self.handler.new_packet_connection(ctx, cached, source, destination, on_close.take());
        Ok(())
    }
}

/// A non-reusable (command 1) server connection.
pub(crate) struct ServerConn {
    conn: Arc<dyn Conn>,
    service: Arc<ServiceInner>,
    reader: Arc<dyn RecordReader>,

    access: tokio::sync::Mutex<()>,
    writer: Mutex<Option<Arc<dyn RecordWriter>>>,

    close_write: OnceCell<SharedResult>,
}

impl ServerConn {
    fn new(conn: Arc<dyn Conn>, service: Arc<ServiceInner>, reader: Arc<dyn RecordReader>) -> Self {
        ServerConn {
            conn,
            service,
            reader,
            access: tokio::sync::Mutex::new(()),
            writer: Mutex::new(None),
            close_write: OnceCell::new(),
        }
    }

    fn writer(&self) -> Option<Arc<dyn RecordWriter>> {
        self.writer.lock().unwrap().clone()
    }

    async fn write_response(&self, payload: &[u8]) -> io::Result<()> {
        let first = &payload[..payload.len().min(MAX_PAYLOAD - 1)];
        let mut reply = Vec::with_capacity(1 + first.len());
        reply.push(REPLY_TUNNEL);
        reply.extend_from_slice(first);
        let writer = self
            .service
            .framing
            .write_first_record(&self.conn, &reply)
            .await
            .map_err(|err| error::cause(err, "write reply"))?;
        *self.writer.lock().unwrap() = Some(writer.clone());
        if payload.len() > first.len() {
            writer.write(&payload[first.len()..]).await?;
        }
        Ok(())
    }

    async fn write_response_buffer(&self, mut buffer: Buffer) -> io::Result<()> {
        buffer.extend_header(1)[0] = REPLY_TUNNEL;
        let writer = self
            .service
            .framing
            .write_first_record_buffer(&self.conn, buffer)
            .await
            .map_err(|err| error::cause(err, "write reply"))?;
        *self.writer.lock().unwrap() = Some(writer);
        Ok(())
    }
}

#[async_trait]
impl Conn for ServerConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        eof_to_zero(self.reader.read(buf).await)
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let guard = self.access.lock().await;
        if let Some(writer) = self.writer() {
            drop(guard);
            return writer.write(buf).await;
        }
        self.write_response(buf).await?;
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
        self.conn.remote_addr()
    }

    async fn close_write(&self) -> io::Result<()> {
        self.close_write
            .get_or_init(|| async {
                let _guard = self.access.lock().await;
                // snell-server v6.0.0b4 closes non-reusable command-1 tunnels on upstream EOF instead of writing a Snell zero chunk.
                SharedResult::new(self.conn.close().await)
            })
            .await
            .get()
    }

    async fn read_buffer(&self, buffer: &mut Buffer) -> io::Result<usize> {
        if buffer.free_len() == 0 {
            return Err(error::short_buffer());
        }
        eof_to_zero(self.reader.read_buffer(buffer).await)
    }

    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let guard = self.access.lock().await;
        if let Some(writer) = self.writer() {
            drop(guard);
            return writer.write_buffer(buffer).await;
        }
        self.write_response_buffer(buffer).await
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
        let guard = self.access.lock().await;
        if let Some(writer) = self.writer() {
            drop(guard);
            return writer.write_vectorised(buffers).await;
        }
        let mut buffers = buffers.into_iter();
        while let Some(buffer) = buffers.next() {
            if buffer.is_empty() {
                continue;
            }
            self.write_response_buffer(buffer).await?;
            let rest: Vec<Buffer> = buffers.collect();
            if !rest.is_empty() {
                let writer = self.writer().unwrap();
                drop(guard);
                return writer.write_vectorised(rest).await;
            }
            return Ok(());
        }
        Ok(())
    }

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        self.reader.initialize_read_waiter(options)
    }

    async fn wait_read_buffer(&self) -> io::Result<Option<Buffer>> {
        eof_to_none(self.reader.wait_read_buffer().await)
    }

    fn front_headroom(&self) -> usize {
        if let Some(writer) = self.writer() {
            return writer.front_headroom();
        }
        1 + self.service.framing.first_front_headroom()
    }

    fn rear_headroom(&self) -> usize {
        if let Some(writer) = self.writer() {
            return writer.rear_headroom();
        }
        self.service.framing.rear_headroom()
    }

    fn writer_mtu(&self) -> usize {
        if let Some(writer) = self.writer() {
            return writer.writer_mtu();
        }
        self.service.framing.writer_mtu()
    }
}
