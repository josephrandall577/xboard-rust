use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

use super::MAX_PAYLOAD;
use super::client::{Client, ClientConfig, ClientInner};
use super::packet::ServerPacketConn;
use super::server::{ServiceInner, err_invalid_udp_tunnel_request};
use crate::addr::Socksaddr;
use crate::buf::Buffer;
use crate::error::{self, ErrorCode, SharedResult};
use crate::net::{CloseHandler, Conn, Context, ReadWaitOptions};
use crate::request::{Request, read_server_request};
use crate::reuse::{
    self, CountGuard, REMOTE_EOF_CODE, REMOTE_EOF_MESSAGE, RecordReader, RecordWriter, Session, State,
    WAITING_DISCARD_LIMIT, eof_to_none, eof_to_zero, parse_reply,
};
use crate::{COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_PING, COMMAND_UDP, REPLY_ERROR, REPLY_PONG, REPLY_TUNNEL};

impl Client {
    /// Dials `destination` through the server, reusing an idle session when
    /// reuse is enabled.
    pub async fn dial_context(&self, ctx: &Context, destination: Socksaddr) -> io::Result<Arc<dyn Conn>> {
        let inner = &self.inner;
        if inner.reuse {
            let session = self.reuse_session(ctx).await?;
            if ctx.keep_session() {
                session.keep_once.store(true, Ordering::SeqCst);
            }
            return match session.dial_conn(destination) {
                Ok(conn) => Ok(conn),
                Err(err) => {
                    let _ = session.close().await;
                    Err(err)
                }
            };
        }
        if inner.pool.is_closed() {
            return Err(error::closed());
        }
        let Some(dialer) = &inner.dialer else {
            return Err(error::new_invalid("snell: missing dialer"));
        };
        let conn = dialer.dial_tcp(ctx, &inner.server).await?;
        // Surge 6.4.4 (10661): -[SNConnectorV4 targetHandshakeData] appends the connector early data to
        // the handshake buffer, so the first record carries both.
        Ok(self.dial_early_conn(conn, destination))
    }

    async fn reuse_session(&self, ctx: &Context) -> io::Result<Arc<ReuseSession>> {
        let inner = &self.inner;
        let (session, closed) = inner.pool.take().await;
        if closed {
            return Err(error::closed());
        }
        let Some(dialer) = &inner.dialer else {
            return Err(error::new_invalid("snell: missing dialer"));
        };
        if let Some(session) = session {
            return Ok(session);
        }
        let conn = dialer.dial_tcp(ctx, &inner.server).await?;
        if inner.pool.is_closed() {
            let _ = conn.close().await;
            return Err(error::closed());
        }
        let session = ReuseSession::new(inner, conn);
        State::store(&session.state, State::Active);
        Ok(session)
    }

    /// Closes all idle sessions.
    pub async fn reset(&self) {
        if self.inner.reuse {
            self.inner.pool.reset().await;
        }
    }

    pub async fn set_keep_idle_connections(&self, keep: bool) {
        self.inner.close_idle.store(!keep, Ordering::SeqCst);
        if !keep {
            self.close_idle_connections().await;
        }
    }

    pub async fn close_idle_connections(&self) {
        if self.inner.reuse {
            self.inner.pool.reset().await;
        }
    }

    pub async fn close(&self) -> io::Result<()> {
        self.inner.pool.close().await
    }
}

pub(crate) struct ReuseSession {
    conn: Arc<dyn Conn>,
    config: Arc<ClientConfig>,
    client: Weak<ClientInner>,

    state: AtomicU32,
    keep_once: AtomicBool,
    reader: Mutex<Option<Arc<dyn RecordReader>>>,
    writer: Mutex<Option<Arc<dyn RecordWriter>>>,
}

#[async_trait]
impl Session for Arc<ReuseSession> {
    async fn close(&self) -> io::Result<()> {
        ReuseSession::close(self).await
    }

    fn reuse_state(&self) -> &AtomicU32 {
        &self.state
    }
}

impl ReuseSession {
    fn new(client: &Arc<ClientInner>, conn: Arc<dyn Conn>) -> Arc<Self> {
        Arc::new(ReuseSession {
            conn,
            config: client.config.clone(),
            client: Arc::downgrade(client),
            state: AtomicU32::new(State::Ready as u32),
            keep_once: AtomicBool::new(false),
            reader: Mutex::new(None),
            writer: Mutex::new(None),
        })
    }

    fn reader(&self) -> Option<Arc<dyn RecordReader>> {
        self.reader.lock().unwrap().clone()
    }

    fn writer(&self) -> Option<Arc<dyn RecordWriter>> {
        self.writer.lock().unwrap().clone()
    }

    fn dial_conn(self: &Arc<Self>, destination: Socksaddr) -> io::Result<Arc<dyn Conn>> {
        let state = State::load(&self.state);
        if state == State::Closed {
            return Err(error::closed());
        }
        if state != State::Active {
            return Err(error::new_error("snell: reuse session is busy"));
        }
        Ok(Arc::new(ReuseConn::new(self.clone(), destination)))
    }

    fn close_idle(&self) -> bool {
        let close_idle = self.client.upgrade().is_some_and(|client| client.close_idle.load(Ordering::SeqCst));
        close_idle && !self.keep_once.swap(false, Ordering::SeqCst)
    }

    async fn move_to_pool(self: &Arc<Self>, state: State, drain: bool) -> bool {
        match self.client.upgrade() {
            Some(client) => client.pool.move_to_pool(self.clone(), state, drain).await,
            None => {
                let _ = self.close().await;
                false
            }
        }
    }

    async fn release(self: &Arc<Self>, reusable: bool) {
        if !reusable || self.close_idle() {
            let _ = self.close().await;
            return;
        }
        if !State::compare_and_swap(&self.state, State::Active, State::Ready) {
            if State::load(&self.state) != State::Closed {
                let _ = self.close().await;
            }
            return;
        }
        self.move_to_pool(State::Ready, false).await;
    }

    async fn close(&self) -> io::Result<()> {
        if State::swap(&self.state, State::Closed) == State::Closed {
            return Ok(());
        }
        self.conn.close().await
    }

    async fn start_drain(self: &Arc<Self>) {
        if self.close_idle() {
            let _ = self.close().await;
            return;
        }
        if !State::compare_and_swap(&self.state, State::Active, State::Waiting) {
            if State::load(&self.state) != State::Closed {
                let _ = self.close().await;
            }
            return;
        }
        let Some(client) = self.client.upgrade() else {
            let _ = self.close().await;
            return;
        };
        if !client.pool.move_to_pool(self.clone(), State::Waiting, true).await {
            return;
        }
        let pool = client.pool.clone();
        let session = self.clone();
        tokio::spawn(async move {
            session.drain().await;
            pool.drain_done();
        });
    }

    async fn drain(&self) {
        let reader = self.reader().expect("snell: draining session without reader");
        let mut discarded = 0;
        loop {
            match reader.next_record().await {
                Err(err) if error::is_eof(&err) => {
                    State::compare_and_swap(&self.state, State::Waiting, State::Ready);
                    return;
                }
                Err(_) => {
                    let _ = self.close().await;
                    return;
                }
                Ok(record) => {
                    // Surge 6.7.0 (11520): SNConnectorV4::socket:didReadData: discards data
                    // received while waiting for server EOF and closes after 0x80001 bytes.
                    discarded += record.len();
                    if discarded >= WAITING_DISCARD_LIMIT {
                        let _ = self.close().await;
                        return;
                    }
                }
            }
        }
    }
}

/// A logical connection carried by a reusable session.
pub struct ReuseConn {
    session: Arc<ReuseSession>,
    destination: Socksaddr,

    access: tokio::sync::Mutex<()>,
    writer: OnceLock<Arc<dyn RecordWriter>>,
    close_write: OnceCell<SharedResult>,
    close: OnceCell<SharedResult>,
    reply_access: tokio::sync::Mutex<()>,
    reply_read: AtomicBool,
    read_wait_options: Mutex<ReadWaitOptions>,
    closed: AtomicBool,
    read_action_count: AtomicI32,
    read_closed: AtomicBool,
}

enum Discard {
    Continue,
    Return(io::Result<()>),
}

impl ReuseConn {
    fn new(session: Arc<ReuseSession>, destination: Socksaddr) -> Self {
        ReuseConn {
            session,
            destination,
            access: tokio::sync::Mutex::new(()),
            writer: OnceLock::new(),
            close_write: OnceCell::new(),
            close: OnceCell::new(),
            reply_access: tokio::sync::Mutex::new(()),
            reply_read: AtomicBool::new(false),
            read_wait_options: Mutex::new(ReadWaitOptions::default()),
            closed: AtomicBool::new(false),
            read_action_count: AtomicI32::new(0),
            read_closed: AtomicBool::new(false),
        }
    }

    fn reader(&self) -> Arc<dyn RecordReader> {
        self.session.reader().expect("snell: reply not read")
    }

    async fn read_response(&self) -> io::Result<()> {
        if self.reply_read.load(Ordering::SeqCst) {
            return Ok(());
        }
        let _guard = self.reply_access.lock().await;
        if self.reply_read.load(Ordering::SeqCst) {
            return Ok(());
        }
        let session = &self.session;
        let (reader, record) = match session.reader() {
            Some(reader) => {
                let record = reader.read_record().await.map_err(|err| error::cause(err, "read reply"))?;
                (reader, record)
            }
            None => {
                let options = *self.read_wait_options.lock().unwrap();
                let (reader, record) = session
                    .config
                    .framing
                    .read_first_record(&session.conn, options)
                    .await
                    .map_err(|err| error::cause(err, "read reply"))?;
                *session.reader.lock().unwrap() = Some(reader.clone());
                (reader, record)
            }
        };
        let cached = parse_reply(record)?;
        reader.set_cache(cached);
        self.reply_read.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Handles a read result after the logical connection was closed: data is
    /// discarded until the server EOF.
    async fn after_close(&self, result: &io::Result<usize>, discarded: &mut usize) -> Discard {
        match result {
            Ok(n) => {
                *discarded += n;
                if *discarded >= WAITING_DISCARD_LIMIT {
                    let _ = self.session.close().await;
                    return Discard::Return(Err(error::new_error("snell: read too much data after client EOF")));
                }
                Discard::Continue
            }
            Err(err) if error::is_eof(err) => {
                self.read_closed.store(true, Ordering::SeqCst);
                State::compare_and_swap(&self.session.state, State::Waiting, State::Ready);
                Discard::Return(Ok(()))
            }
            Err(_) => {
                let _ = self.session.close().await;
                Discard::Return(Ok(()))
            }
        }
    }

    fn begin_read(&self) -> io::Result<CountGuard<'_>> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(error::closed());
        }
        let guard = CountGuard::new(&self.read_action_count);
        if self.closed.load(Ordering::SeqCst) {
            return Err(error::closed());
        }
        Ok(guard)
    }

    fn finish_read<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Err(err) = &result
            && error::is_eof(err)
        {
            self.read_closed.store(true, Ordering::SeqCst);
        }
        result
    }

    async fn write_request(&self, payload: &[u8]) -> io::Result<()> {
        let request = self.session.config.request(&self.destination);
        let mut buffer = Buffer::with_capacity(request.len() + payload.len());
        request.write(&mut buffer)?;
        if !payload.is_empty() {
            buffer.write_all(payload);
        }
        let session = &self.session;
        let mut data = buffer.bytes();
        let writer = match session.writer() {
            Some(writer) => writer,
            None => {
                let first = &data[..data.len().min(MAX_PAYLOAD)];
                let writer = match session.config.framing.write_first_record(&session.conn, first).await {
                    Ok(writer) => writer,
                    Err(err) => {
                        session.release(false).await;
                        return Err(error::cause(err, "write request"));
                    }
                };
                *session.writer.lock().unwrap() = Some(writer.clone());
                data = &data[first.len()..];
                writer
            }
        };
        if !data.is_empty()
            && let Err(err) = writer.write(data).await
        {
            session.release(false).await;
            return Err(error::cause(err, "write request"));
        }
        let _ = self.writer.set(writer);
        Ok(())
    }

    async fn write_request_buffer(&self, mut buffer: Buffer) -> io::Result<()> {
        let request = self.session.config.request(&self.destination).encode()?;
        buffer.extend_header(request.len()).copy_from_slice(&request);
        let session = &self.session;
        let result = match session.writer() {
            None => match session.config.framing.write_first_record_buffer(&session.conn, buffer).await {
                Ok(writer) => {
                    *session.writer.lock().unwrap() = Some(writer.clone());
                    Ok(writer)
                }
                Err(err) => Err(err),
            },
            Some(writer) => writer.write_buffer(buffer).await.map(|_| writer),
        };
        match result {
            Ok(writer) => {
                let _ = self.writer.set(writer);
                Ok(())
            }
            Err(err) => {
                session.release(false).await;
                Err(error::cause(err, "write request"))
            }
        }
    }

    async fn close_inner(&self) -> SharedResult {
        let session = &self.session;
        self.closed.store(true, Ordering::SeqCst);
        if !self.reply_read.load(Ordering::SeqCst) {
            session.release(false).await;
            return SharedResult::default();
        }
        if let Err(err) = self.close_write().await {
            session.release(false).await;
            return SharedResult::new(Err(err));
        }
        let _ = session.conn.set_read_deadline(None);
        let _ = session.conn.set_write_deadline(None);
        if self.read_closed.load(Ordering::SeqCst) {
            session.release(true).await;
            return SharedResult::default();
        }
        if session.close_idle() {
            let _ = session.close().await;
            return SharedResult::default();
        }
        // Surge 6.7.0 (11520): SNConnectorV4::readServerEOFIfNotInReadState: starts waiting-state EOF
        // reads when _socketReadActionCounter is 0.
        if self.read_action_count.load(Ordering::SeqCst) > 0 {
            if !State::compare_and_swap(&session.state, State::Active, State::Waiting) {
                if State::load(&session.state) != State::Closed {
                    let _ = session.close().await;
                }
                return SharedResult::default();
            }
            let mut pool_state = State::Waiting;
            if self.read_closed.load(Ordering::SeqCst) {
                State::compare_and_swap(&session.state, State::Waiting, State::Ready);
                pool_state = State::Ready;
            }
            session.move_to_pool(pool_state, false).await;
            return SharedResult::default();
        }
        session.start_drain().await;
        SharedResult::default()
    }
}

#[async_trait]
impl Conn for ReuseConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let _guard = self.begin_read()?;
        self.read_response().await?;
        let reader = self.reader();
        let mut discarded = 0;
        loop {
            let result = reader.read(buf).await;
            if self.closed.load(Ordering::SeqCst) {
                match self.after_close(&result, &mut discarded).await {
                    Discard::Continue => continue,
                    Discard::Return(Ok(())) => return reuse::eof_to_zero(result.map(|_| 0)),
                    Discard::Return(Err(err)) => return Err(err),
                }
            }
            return reuse::eof_to_zero(self.finish_read(result));
        }
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
        self.close.get_or_init(|| self.close_inner()).await.get()
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.session.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.session.conn.set_write_deadline(deadline)
    }

    fn local_addr(&self) -> Socksaddr {
        self.session.conn.local_addr()
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
        let _guard = self.begin_read()?;
        self.read_response().await?;
        if buffer.free_len() == 0 {
            return Err(error::short_buffer());
        }
        let reader = self.reader();
        let mut discarded = 0;
        loop {
            let buffer_len = buffer.len();
            let result = reader.read_buffer(buffer).await;
            if self.closed.load(Ordering::SeqCst) {
                let result = result.map(|_| buffer.len() - buffer_len);
                buffer.truncate(buffer_len);
                match self.after_close(&result, &mut discarded).await {
                    Discard::Continue => continue,
                    Discard::Return(Ok(())) => return reuse::eof_to_zero(result.map(|_| 0)),
                    Discard::Return(Err(err)) => return Err(err),
                }
            }
            return reuse::eof_to_zero(self.finish_read(result));
        }
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
        self.session.conn.supports_vectorised()
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        if !self.session.conn.supports_vectorised() {
            for buffer in buffers {
                self.write_buffer(buffer).await?;
            }
            return Ok(());
        }
        if let Some(writer) = self.writer.get() {
            return writer.write_vectorised(buffers).await;
        }
        let _guard = self.access.lock().await;
        if let Some(writer) = self.writer.get() {
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
                return self.writer.get().unwrap().write_vectorised(rest).await;
            }
            return Ok(());
        }
        Ok(())
    }

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        *self.read_wait_options.lock().unwrap() = options;
        if let Some(reader) = self.session.reader() {
            reader.initialize_read_waiter(options);
        }
        false
    }

    async fn wait_read_buffer(&self) -> io::Result<Option<Buffer>> {
        let _guard = self.begin_read()?;
        self.read_response().await?;
        let reader = self.reader();
        let mut discarded = 0;
        loop {
            let result = reader.wait_read_buffer().await;
            if self.closed.load(Ordering::SeqCst) {
                let result = result.map(|buffer| buffer.len());
                match self.after_close(&result, &mut discarded).await {
                    Discard::Continue => continue,
                    Discard::Return(Ok(())) => return result.map(|_| None).or_else(|err| eof_to_none(Err(err))),
                    Discard::Return(Err(err)) => return Err(err),
                }
            }
            return eof_to_none(self.finish_read(result));
        }
    }

    fn front_headroom(&self) -> usize {
        if let Some(writer) = self.writer.get() {
            return writer.front_headroom();
        }
        self.session.config.front_headroom(&self.destination)
    }

    fn rear_headroom(&self) -> usize {
        if let Some(writer) = self.writer.get() {
            return writer.rear_headroom();
        }
        self.session.config.framing.rear_headroom()
    }

    fn writer_mtu(&self) -> usize {
        if let Some(writer) = self.writer.get() {
            return writer.writer_mtu();
        }
        self.session.config.framing.writer_mtu()
    }

    fn need_handshake_for_read(&self) -> bool {
        !self.reply_read.load(Ordering::SeqCst)
    }

    fn need_handshake_for_write(&self) -> bool {
        self.writer.get().is_none()
    }

    fn need_additional_read_deadline(&self) -> bool {
        !self.reply_read.load(Ordering::SeqCst)
    }
}

pub(crate) struct ServerReuseSession {
    conn: Arc<dyn Conn>,
    service: Arc<ServiceInner>,
    reader: Arc<dyn RecordReader>,
    writer: Mutex<Option<Arc<dyn RecordWriter>>>,
}

impl ServerReuseSession {
    pub(crate) fn new(conn: Arc<dyn Conn>, service: Arc<ServiceInner>, reader: Arc<dyn RecordReader>) -> Self {
        ServerReuseSession { conn, service, reader, writer: Mutex::new(None) }
    }

    fn writer(&self) -> Option<Arc<dyn RecordWriter>> {
        self.writer.lock().unwrap().clone()
    }

    fn set_writer(&self, writer: Arc<dyn RecordWriter>) {
        *self.writer.lock().unwrap() = Some(writer);
    }

    async fn close_conn(&self) {
        let _ = self.conn.close().await;
    }

    pub(crate) async fn serve(
        self: &Arc<Self>,
        ctx: Context,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
        record: Buffer,
        request: Request,
    ) -> io::Result<()> {
        let mut on_close = on_close;
        let result = self.serve_loop(ctx, source, &mut on_close, record, request).await;
        if let Some(on_close) = on_close {
            return match result {
                Ok(()) => {
                    on_close(None);
                    Ok(())
                }
                Err(err) => {
                    let (reported, returned) = error::duplicate(err);
                    on_close(Some(reported));
                    Err(returned)
                }
            };
        }
        result
    }

    async fn serve_loop(
        self: &Arc<Self>,
        ctx: Context,
        source: Socksaddr,
        on_close: &mut Option<CloseHandler>,
        mut record: Buffer,
        mut request: Request,
    ) -> io::Result<()> {
        loop {
            let mut request_ctx = ctx.clone();
            if request.command != COMMAND_PING
                && let Some(result) = self.service.authenticate(&ctx, &request)
            {
                match result {
                    Ok(authenticated) => request_ctx = authenticated,
                    Err(err) => {
                        self.close_conn().await;
                        return Err(err);
                    }
                }
            }
            match request.command {
                COMMAND_CONNECT | COMMAND_CONNECT_V2 => {}
                COMMAND_UDP => {
                    // snell-server v6.0.0b4: FUN_00141bc0 rejects UDP tunnel requests when the
                    // first UDP datagram starts in the same decrypted frame as the tunnel request.
                    if !record.is_empty() {
                        self.close_conn().await;
                        return Err(err_invalid_udp_tunnel_request());
                    }
                    let packet_conn = Arc::new(ServerPacketConn::new(
                        self.conn.clone(),
                        self.service.framing.clone(),
                        self.reader.clone(),
                        self.writer(),
                    ));
                    if let Err(err) =
                        self.service.new_packet_connection(request_ctx, packet_conn.clone(), source, on_close).await
                    {
                        self.close_conn().await;
                        return Err(err);
                    }
                    if let Some(writer) = packet_conn.writer() {
                        self.set_writer(writer);
                    }
                    return Ok(());
                }
                COMMAND_PING => {
                    let result = match self.writer() {
                        None => match self.service.framing.write_first_record(&self.conn, &[REPLY_PONG]).await {
                            Ok(writer) => {
                                self.set_writer(writer);
                                Ok(())
                            }
                            Err(err) => Err(err),
                        },
                        Some(writer) => writer.write(&[REPLY_PONG]).await.map(|_| ()),
                    };
                    self.close_conn().await;
                    return result;
                }
                command => {
                    self.close_conn().await;
                    return Err(error::extend_code(ErrorCode::UnsupportedCommand, command));
                }
            }
            let server_conn = Arc::new(ServerReuseConn::new(self.clone()));
            if !record.is_empty() {
                self.reader.set_cache(Some(record));
            }
            let completion = server_conn.completion.clone();
            self.service.handler.new_connection(
                request_ctx.clone(),
                server_conn.clone(),
                source.clone(),
                request.destination.clone(),
                Some(Box::new(move |_| completion.cancel())),
            );
            tokio::select! {
                _ = server_conn.completion.cancelled() => {}
                _ = request_ctx.done() => {
                    self.close_conn().await;
                    return Err(error::canceled());
                }
            }
            if let Err(err) = server_conn.close_write().await {
                self.close_conn().await;
                return Err(err);
            }
            if server_conn.aborted.load(Ordering::SeqCst) {
                return Ok(());
            }
            if !server_conn.read_closed.load(Ordering::SeqCst) {
                // snell-server v6.0.0b4: after writing the EOF packet, FUN_00141bc0 keeps
                // consuming client records (forwarding them into the still writable
                // outgoing socket) until the zero chunk reaches FUN_001419e0 ->
                // FUN_001402c0 -> FUN_001401b0, which resets the tunnel stage so the
                // next record is parsed as a request. The handler has already released
                // the upstream, so discard instead, capped like the client waiting state.
                let mut discarded = 0;
                let drain_err = loop {
                    match self.reader.next_record().await {
                        Err(err) => break err,
                        Ok(drain_record) => {
                            discarded += drain_record.len();
                            if discarded >= WAITING_DISCARD_LIMIT {
                                self.close_conn().await;
                                return Err(error::new_error("snell: read too much data after request end"));
                            }
                        }
                    }
                };
                if !error::is_eof(&drain_err) {
                    self.close_conn().await;
                    return Err(error::cause(drain_err, "drain request"));
                }
            }
            record = match self.reader.read_record().await {
                Ok(record) => record,
                Err(err) if error::is_eof(&err) => return Ok(()),
                Err(err) => {
                    self.close_conn().await;
                    return Err(error::cause(err, "read request"));
                }
            };
            request = match read_server_request(&mut record) {
                Ok(request) => request,
                Err(err) => {
                    self.close_conn().await;
                    return Err(error::cause(err, "decode request"));
                }
            };
        }
    }
}

#[derive(Default)]
struct WriteState {
    reply_written: bool,
    write_closed: bool,
}

pub(crate) struct ServerReuseConn {
    session: Arc<ServerReuseSession>,

    access: tokio::sync::Mutex<WriteState>,
    reply_written: AtomicBool,
    close_write: OnceCell<SharedResult>,
    close: OnceCell<SharedResult>,
    read_closed: AtomicBool,
    aborted: AtomicBool,
    completion: CancellationToken,
}

impl ServerReuseConn {
    fn new(session: Arc<ServerReuseSession>) -> Self {
        ServerReuseConn {
            session,
            access: tokio::sync::Mutex::new(WriteState::default()),
            reply_written: AtomicBool::new(false),
            close_write: OnceCell::new(),
            close: OnceCell::new(),
            read_closed: AtomicBool::new(false),
            aborted: AtomicBool::new(false),
            completion: CancellationToken::new(),
        }
    }

    fn mark_reply_written(&self, state: &mut WriteState) {
        state.reply_written = true;
        self.reply_written.store(true, Ordering::SeqCst);
    }

    /// Writes `reply` as the first record of the session, or as a normal record.
    async fn write_reply_record(&self, reply: &[u8], context: &str) -> io::Result<Arc<dyn RecordWriter>> {
        let session = &self.session;
        let result = match session.writer() {
            None => match session.service.framing.write_first_record(&session.conn, reply).await {
                Ok(writer) => {
                    session.set_writer(writer.clone());
                    Ok(writer)
                }
                Err(err) => Err(err),
            },
            Some(writer) => writer.write(reply).await.map(|_| writer),
        };
        result.map_err(|err| error::cause(err, context.to_string()))
    }

    async fn write_response(&self, state: &mut WriteState, payload: &[u8]) -> io::Result<()> {
        let first = &payload[..payload.len().min(MAX_PAYLOAD - 1)];
        let mut reply = Vec::with_capacity(1 + first.len());
        reply.push(REPLY_TUNNEL);
        reply.extend_from_slice(first);
        let writer = self.write_reply_record(&reply, "write reply").await?;
        self.mark_reply_written(state);
        if payload.len() > first.len() {
            writer.write(&payload[first.len()..]).await?;
        }
        Ok(())
    }

    async fn write_response_buffer(&self, state: &mut WriteState, mut buffer: Buffer) -> io::Result<()> {
        let session = &self.session;
        buffer.extend_header(1)[0] = REPLY_TUNNEL;
        match session.writer() {
            Some(writer) => writer.write_buffer(buffer).await.map_err(|err| error::cause(err, "write reply"))?,
            None => {
                let writer = session
                    .service
                    .framing
                    .write_first_record_buffer(&session.conn, buffer)
                    .await
                    .map_err(|err| error::cause(err, "write reply"))?;
                session.set_writer(writer);
            }
        }
        self.mark_reply_written(state);
        Ok(())
    }

    async fn write_error_response(&self) -> io::Result<()> {
        let mut reply = Vec::with_capacity(3 + REMOTE_EOF_MESSAGE.len());
        reply.push(REPLY_ERROR);
        reply.push(REMOTE_EOF_CODE);
        reply.push(REMOTE_EOF_MESSAGE.len() as u8);
        reply.extend_from_slice(REMOTE_EOF_MESSAGE.as_bytes());
        self.write_reply_record(&reply, "write error reply").await.map(|_| ())
    }

    fn finish_read<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if let Err(err) = &result
            && error::is_eof(err)
        {
            self.read_closed.store(true, Ordering::SeqCst);
        }
        result
    }
}

#[async_trait]
impl Conn for ServerReuseConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        eof_to_zero(self.finish_read(self.session.reader.read(buf).await))
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.access.lock().await;
        if state.write_closed {
            return Err(error::closed());
        }
        if state.reply_written {
            return self.session.writer().unwrap().write(buf).await;
        }
        self.write_response(&mut state, buf).await?;
        Ok(buf.len())
    }

    async fn close(&self) -> io::Result<()> {
        // The handler may close this side while its peer copy is still reading.
        // on_close owns completion and runs only after both copy directions exit.
        self.close.get_or_init(|| async { SharedResult::new(self.close_write().await) }).await.get()
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.session.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.session.conn.set_write_deadline(deadline)
    }

    fn local_addr(&self) -> Socksaddr {
        self.session.conn.local_addr()
    }

    fn remote_addr(&self) -> Socksaddr {
        self.session.conn.remote_addr()
    }

    async fn close_write(&self) -> io::Result<()> {
        self.close_write
            .get_or_init(|| async {
                let mut state = self.access.lock().await;
                state.write_closed = true;
                // snell-server v6.0.0b4: FUN_001414e0 -> FUN_00140390 reports upstream EOF
                // before any payload as ReplyError 0x65 "Remote EOF", marks the context
                // aborted, and FUN_00141390 closes the tunnel after the error data is written.
                if !state.reply_written {
                    let mut result = self.write_error_response().await;
                    if result.is_ok() {
                        self.aborted.store(true, Ordering::SeqCst);
                        result = self.session.conn.close().await;
                    }
                    return SharedResult::new(result);
                }
                SharedResult::new(self.session.writer().unwrap().write_zero_chunk().await)
            })
            .await
            .get()
    }

    async fn read_buffer(&self, buffer: &mut Buffer) -> io::Result<usize> {
        if buffer.free_len() == 0 {
            return Err(error::short_buffer());
        }
        eof_to_zero(self.finish_read(self.session.reader.read_buffer(buffer).await))
    }

    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let mut state = self.access.lock().await;
        if state.write_closed {
            return Err(error::closed());
        }
        if state.reply_written {
            return self.session.writer().unwrap().write_buffer(buffer).await;
        }
        self.write_response_buffer(&mut state, buffer).await
    }

    fn supports_vectorised(&self) -> bool {
        self.session.conn.supports_vectorised()
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        if !self.session.conn.supports_vectorised() {
            for buffer in buffers {
                self.write_buffer(buffer).await?;
            }
            return Ok(());
        }
        let mut state = self.access.lock().await;
        if state.write_closed {
            return Err(error::closed());
        }
        if state.reply_written {
            return self.session.writer().unwrap().write_vectorised(buffers).await;
        }
        let mut buffers = buffers.into_iter();
        while let Some(buffer) = buffers.next() {
            if buffer.is_empty() {
                continue;
            }
            self.write_response_buffer(&mut state, buffer).await?;
            let rest: Vec<Buffer> = buffers.collect();
            if !rest.is_empty() {
                return self.session.writer().unwrap().write_vectorised(rest).await;
            }
            return Ok(());
        }
        Ok(())
    }

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        self.session.reader.initialize_read_waiter(options)
    }

    async fn wait_read_buffer(&self) -> io::Result<Option<Buffer>> {
        eof_to_none(self.finish_read(self.session.reader.wait_read_buffer().await))
    }

    fn front_headroom(&self) -> usize {
        let writer = self.session.writer();
        if self.reply_written.load(Ordering::SeqCst)
            && let Some(writer) = &writer
        {
            return writer.front_headroom();
        }
        if let Some(writer) = &writer {
            return 1 + writer.front_headroom();
        }
        1 + self.session.service.framing.first_front_headroom()
    }

    fn rear_headroom(&self) -> usize {
        if let Some(writer) = self.session.writer() {
            return writer.rear_headroom();
        }
        self.session.service.framing.rear_headroom()
    }

    fn writer_mtu(&self) -> usize {
        if let Some(writer) = self.session.writer() {
            return writer.writer_mtu();
        }
        self.session.service.framing.writer_mtu()
    }
}
