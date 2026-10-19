use std::io;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::OnceCell;

use super::client::{Client, ClientConfig, ClientInner};
use super::{MAX_INITIAL_PADDING_LEN, MAX_PAYLOAD, Reader, Writer, new_reader};
use crate::addr::Socksaddr;
use crate::buf::Buffer;
use crate::error::{self, SharedResult};
use crate::net::{Conn, Context, ReadWaitOptions};
use crate::reuse::{
    self, CountGuard, RecordReader, RecordWriter, Session, State, WAITING_DISCARD_LIMIT, eof_to_none, parse_reply,
};
use crate::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, SALT_LEN};

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
        // the handshake buffer, and -[SNConnectorV4 firstDataPacket] encrypts and obfuscates the result
        // in one piece, so the first record, and with obfs the first HTTP request body, carries both.
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
    reader: OnceLock<Arc<Reader>>,
    writer: OnceLock<Arc<Writer>>,
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
            conn: client.config.obfs.client_conn(conn),
            config: client.config.clone(),
            client: Arc::downgrade(client),
            state: AtomicU32::new(State::Ready as u32),
            keep_once: AtomicBool::new(false),
            reader: OnceLock::new(),
            writer: OnceLock::new(),
        })
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
        let reader = self.reader.get().expect("snell: draining session without reader");
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
    writer: OnceLock<Arc<Writer>>,
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

    fn reader(&self) -> &Arc<Reader> {
        self.session.reader.get().expect("snell: reply not read")
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
        let reader = session.reader.get_or_init(|| {
            let reader = new_reader(session.conn.clone(), session.config.psk.clone());
            reader.initialize_read_waiter(*self.read_wait_options.lock().unwrap());
            Arc::new(reader)
        });
        let record = reader.read_record().await.map_err(|err| error::cause(err, "read reply"))?;
        let cached = parse_reply(record)?;
        if cached.is_some() {
            reader.set_cache(cached);
        }
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
        let writer =
            session.writer.get_or_init(|| Arc::new(Writer::new(session.conn.clone(), session.config.psk.clone())));
        if let Err(err) = writer.write(buffer.bytes()).await {
            session.release(false).await;
            return Err(error::cause(err, "write request"));
        }
        let _ = self.writer.set(writer.clone());
        Ok(())
    }

    async fn write_request_buffer(&self, mut buffer: Buffer) -> io::Result<()> {
        let request = self.session.config.request(&self.destination).encode()?;
        buffer.extend_header(request.len()).copy_from_slice(&request);
        let session = &self.session;
        let writer =
            session.writer.get_or_init(|| Arc::new(Writer::new(session.conn.clone(), session.config.psk.clone())));
        if let Err(err) = writer.write_buffer(buffer).await {
            session.release(false).await;
            return Err(error::cause(err, "write request"));
        }
        let _ = self.writer.set(writer.clone());
        Ok(())
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
        if let Some(reader) = self.session.reader.get() {
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
        self.session.config.request(&self.destination).len() + SALT_LEN + HEADER_CIPHER_LEN + MAX_INITIAL_PADDING_LEN
    }

    fn rear_headroom(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn writer_mtu(&self) -> usize {
        MAX_PAYLOAD
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
