//! Connection abstractions: the Rust counterparts of `net.Conn`, sing's
//! extended connection interfaces, `N.PacketConn`, dialers, handlers and
//! contexts.

use std::any::Any;
use std::fmt;
use std::future::Future;
use std::io::{self, IoSlice};
use std::net::Shutdown;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::addr::Socksaddr;
use crate::buf::{self, Buffer};
use crate::error;

/// `time.Now().Unix()`.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}

const MAX_POOLED_BUFFER_SIZE: usize = (1 << 16) + (1 << 13);

/// sing's `N.ReadWaitOptions`: how buffers returned by
/// [`Conn::wait_read_buffer`] should be laid out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadWaitOptions {
    pub front_headroom: usize,
    pub rear_headroom: usize,
    pub mtu: usize,
    pub read_overhead: usize,
    pub increase_buffer: bool,
    pub batch_size: usize,
}

impl ReadWaitOptions {
    pub fn need_headroom(&self) -> bool {
        self.front_headroom > 0 || self.rear_headroom > 0
    }

    /// Copies `buffer` into a new buffer when it lacks the requested headroom.
    pub fn copy(&self, buffer: Buffer) -> Buffer {
        if self.front_headroom > buffer.start() || self.rear_headroom > buffer.free_len() {
            let mut new_buffer = Buffer::with_capacity(buffer.len() + self.front_headroom + self.rear_headroom);
            if self.front_headroom > 0 {
                new_buffer.resize(self.front_headroom, 0);
            }
            new_buffer.write(buffer.bytes());
            new_buffer
        } else {
            buffer
        }
    }

    fn finish(&self, size: usize) -> Buffer {
        let mut buffer = Buffer::with_capacity(size);
        if self.front_headroom > 0 {
            buffer.resize(self.front_headroom, 0);
        }
        if self.rear_headroom > 0 {
            buffer.reserve(self.rear_headroom);
        }
        buffer
    }

    pub fn new_buffer(&self) -> Buffer {
        let mut buffer_size = buf::BUFFER_SIZE;
        if self.increase_buffer {
            if self.mtu > 0 {
                buffer_size = self.mtu + self.read_overhead + self.front_headroom + self.rear_headroom;
            } else {
                buffer_size = 65535;
            }
            buffer_size = buffer_size.min(MAX_POOLED_BUFFER_SIZE);
        } else if self.mtu > 0 {
            buffer_size = buffer_size.min(self.mtu + self.read_overhead + self.front_headroom + self.rear_headroom);
        }
        buffer_size = buffer_size.max(self.front_headroom + self.rear_headroom + 1);
        self.finish(buffer_size)
    }

    pub fn new_packet_buffer(&self) -> Buffer {
        let mut buffer_size = buf::UDP_BUFFER_SIZE;
        if self.mtu > 0 {
            buffer_size = self.mtu + self.read_overhead + self.front_headroom + self.rear_headroom;
        }
        buffer_size = buffer_size.max(self.front_headroom + self.rear_headroom + 1);
        self.finish(buffer_size)
    }

    pub fn new_buffer_size(&self, size: usize) -> Buffer {
        self.finish(size + self.front_headroom + self.rear_headroom)
    }

    pub fn post_return(&self, buffer: &mut Buffer) {
        if self.rear_headroom > 0 {
            buffer.over_cap(self.rear_headroom);
        }
    }
}

/// A stream connection: `net.Conn` plus sing's optional extensions.
///
/// All methods take `&self`, so a connection can be shared between tasks the
/// same way a Go `net.Conn` is shared between goroutines: one task may read
/// while another writes or closes.
///
/// [`Conn::read`] follows the Rust convention and returns `Ok(0)` at EOF.
#[async_trait]
pub trait Conn: Send + Sync {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Writes all of `buf`, returning its length.
    async fn write(&self, buf: &[u8]) -> io::Result<usize>;

    async fn close(&self) -> io::Result<()>;

    /// Sets the read deadline for pending and future reads. `None` clears it.
    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()>;

    /// Sets the write deadline for pending and future writes. `None` clears it.
    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()>;

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.set_read_deadline(deadline)?;
        self.set_write_deadline(deadline)
    }

    fn local_addr(&self) -> Socksaddr {
        Socksaddr::default()
    }

    fn remote_addr(&self) -> Socksaddr {
        Socksaddr::default()
    }

    /// Half-closes the write side (`N.CloseWrite`). Connections without
    /// half-close support do nothing.
    async fn close_write(&self) -> io::Result<()> {
        Ok(())
    }

    /// `ReadBuffer`: reads into the free space of `buffer`. Returns `Ok(0)` at EOF.
    async fn read_buffer(&self, buffer: &mut Buffer) -> io::Result<usize> {
        if buffer.free_len() == 0 {
            return Err(error::short_buffer());
        }
        let len = buffer.len();
        let n = self.read(buffer.free_bytes_mut()).await?;
        buffer.truncate(len + n);
        Ok(n)
    }

    /// `WriteBuffer`: writes the content of `buffer`, possibly using its headroom.
    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        self.write(buffer.bytes()).await.map(|_| ())
    }

    /// Whether [`Conn::write_vectorised`] is backed by a real vectorised writer
    /// (`bufio.CreateVectorisedWriter` succeeding in Go).
    fn supports_vectorised(&self) -> bool {
        false
    }

    /// `WriteVectorised`. Without vectorised support, the buffers are written
    /// one by one with [`Conn::write_buffer`], like sing's copy fallback.
    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        for buffer in buffers {
            self.write_buffer(buffer).await?;
        }
        Ok(())
    }

    /// `InitializeReadWaiter`: returns whether buffers must be copied.
    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        let _ = options;
        true
    }

    /// `WaitReadBuffer`: returns `Ok(None)` at EOF.
    async fn wait_read_buffer(&self) -> io::Result<Option<Buffer>> {
        let mut buffer = Buffer::new();
        match self.read_buffer(&mut buffer).await? {
            0 => Ok(None),
            _ => Ok(Some(buffer)),
        }
    }

    fn front_headroom(&self) -> usize {
        0
    }

    fn rear_headroom(&self) -> usize {
        0
    }

    fn writer_mtu(&self) -> usize {
        0
    }

    fn need_handshake_for_read(&self) -> bool {
        false
    }

    fn need_handshake_for_write(&self) -> bool {
        false
    }

    fn need_additional_read_deadline(&self) -> bool {
        false
    }
}

/// A packet connection: sing's `N.PacketConn` plus its optional extensions.
///
/// Reads report EOF as an error for which [`crate::is_eof`] returns true.
#[async_trait]
pub trait PacketConn: Send + Sync {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr>;

    async fn write_packet(&self, buffer: Buffer, destination: Socksaddr) -> io::Result<()>;

    async fn close(&self) -> io::Result<()>;

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()>;

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()>;

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.set_read_deadline(deadline)?;
        self.set_write_deadline(deadline)
    }

    fn local_addr(&self) -> Socksaddr {
        Socksaddr::default()
    }

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        let _ = options;
        true
    }

    async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
        let mut buffer = Buffer::new_packet();
        let destination = self.read_packet(&mut buffer).await?;
        Ok((buffer, destination))
    }

    /// Whether [`PacketConn::write_packet_batch`] is backed by a real batch
    /// writer (`bufio.CreatePacketBatchWriter` succeeding in Go).
    fn supports_packet_batch(&self) -> bool {
        false
    }

    async fn write_packet_batch(&self, buffers: Vec<Buffer>, destinations: Vec<Socksaddr>) -> io::Result<()> {
        if buffers.is_empty() || buffers.len() != destinations.len() {
            return Err(error::invalid());
        }
        for (buffer, destination) in buffers.into_iter().zip(destinations) {
            self.write_packet(buffer, destination).await?;
        }
        Ok(())
    }

    fn front_headroom(&self) -> usize {
        0
    }

    fn rear_headroom(&self) -> usize {
        0
    }

    fn writer_mtu(&self) -> usize {
        0
    }

    /// `net.PacketConn.ReadFrom`, as provided by `bufio.NewNetPacketConn`.
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut buffer = Buffer::with_capacity(p.len());
        let destination = self.read_packet(&mut buffer).await?;
        let n = buffer.len();
        p[..n].copy_from_slice(buffer.bytes());
        Ok((n, destination))
    }

    /// `net.PacketConn.WriteTo`, as provided by `bufio.NewNetPacketConn`.
    async fn write_to(&self, p: &[u8], destination: Socksaddr) -> io::Result<usize> {
        let buffer = Buffer::from_slice_with_headroom(p, self.front_headroom(), self.rear_headroom());
        self.write_packet(buffer, destination).await?;
        Ok(p.len())
    }
}

/// Go's `io.ReadFull` over a [`Conn`]: EOF when nothing was read,
/// unexpected EOF when the stream ended early.
pub(crate) async fn read_full(conn: &dyn Conn, buf: &mut [u8]) -> io::Result<()> {
    let mut n = 0;
    while n < buf.len() {
        match conn.read(&mut buf[n..]).await {
            Ok(0) => return Err(if n == 0 { error::eof() } else { error::unexpected_eof() }),
            Ok(m) => n += m,
            Err(err) => {
                return Err(if n > 0 && error::is_bare_eof(&err) { error::unexpected_eof() } else { err });
            }
        }
    }
    Ok(())
}

/// Go's `io.CopyN(io.Discard, conn, n)`: EOF when the stream ended early.
pub(crate) async fn discard(conn: &dyn Conn, mut n: usize) -> io::Result<()> {
    let mut scratch = [0u8; 512];
    while n > 0 {
        let size = n.min(scratch.len());
        match conn.read(&mut scratch[..size]).await {
            Ok(0) => return Err(error::eof()),
            Ok(m) => n -= m,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// A `context.Context` subset: cancellation, the keep-session flag and the
/// authenticated user.
#[derive(Clone, Default)]
pub struct Context {
    token: Option<CancellationToken>,
    keep_session: bool,
    user: Option<Arc<dyn Any + Send + Sync>>,
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("cancellable", &self.token.is_some())
            .field("keep_session", &self.keep_session)
            .field("has_user", &self.user.is_some())
            .finish()
    }
}

impl Context {
    /// `context.Background()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attaches a cancellation token; [`Context::done`] completes when it is cancelled.
    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.token = Some(token);
        self
    }

    /// `snell.ContextWithKeepSession`.
    pub fn with_keep_session(mut self) -> Self {
        self.keep_session = true;
        self
    }

    /// `snell.KeepSessionFromContext`.
    pub fn keep_session(&self) -> bool {
        self.keep_session
    }

    /// `auth.ContextWithUser`.
    pub fn with_user<U: Any + Send + Sync>(mut self, user: U) -> Self {
        self.user = Some(Arc::new(user));
        self
    }

    /// `auth.UserFromContext`.
    pub fn user<U: Any + Send + Sync>(&self) -> Option<&U> {
        self.user.as_ref().and_then(|user| user.downcast_ref::<U>())
    }

    /// `ctx.Done()`: completes when the context is cancelled, never otherwise.
    pub async fn done(&self) {
        match &self.token {
            Some(token) => token.cancelled().await,
            None => std::future::pending().await,
        }
    }

    pub fn is_done(&self) -> bool {
        self.token.as_ref().is_some_and(|token| token.is_cancelled())
    }

    /// `ctx.Err()`.
    pub fn err(&self) -> Option<io::Error> {
        if self.is_done() { Some(error::canceled()) } else { None }
    }

    /// Runs `future` until it completes or the context is cancelled.
    pub(crate) async fn run<T>(&self, future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
        tokio::select! {
            result = future => result,
            _ = self.done() => Err(error::canceled()),
        }
    }
}

/// `N.Dialer`, restricted to TCP.
#[async_trait]
pub trait Dialer: Send + Sync {
    async fn dial_tcp(&self, ctx: &Context, destination: &Socksaddr) -> io::Result<Arc<dyn Conn>>;
}

/// `N.SystemDialer`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDialer;

#[async_trait]
impl Dialer for SystemDialer {
    async fn dial_tcp(&self, ctx: &Context, destination: &Socksaddr) -> io::Result<Arc<dyn Conn>> {
        let conn = ctx
            .run(async {
                match destination.socket_addr() {
                    Some(addr) => TcpConn::connect(addr).await,
                    None => {
                        let stream = TcpStream::connect((destination.fqdn.as_str(), destination.port)).await?;
                        TcpConn::new(stream)
                    }
                }
            })
            .await?;
        Ok(Arc::new(conn))
    }
}

/// `N.CloseHandlerFunc`.
pub type CloseHandler = Box<dyn FnOnce(Option<io::Error>) + Send + Sync>;

/// `snell.Handler`: receives the connections accepted by a service.
pub trait Handler: Send + Sync {
    fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    );

    fn new_packet_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn PacketConn>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    );
}

/// `snell.Service`.
#[async_trait]
pub trait Service: Send + Sync {
    async fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> Result<(), ServerError>;
}

/// `snell.Method`.
#[async_trait]
pub trait Method: Send + Sync {
    async fn dial_conn(&self, conn: Arc<dyn Conn>, destination: Socksaddr) -> io::Result<Arc<dyn Conn>>;
    fn dial_early_conn(&self, conn: Arc<dyn Conn>, destination: Socksaddr) -> Arc<dyn Conn>;
    fn dial_packet_conn(&self, conn: Arc<dyn Conn>) -> io::Result<Arc<dyn PacketConn>>;
}

/// `snell.ServerError`.
///
/// snell-server v6.0.0b4: FUN_00141bc0: malformed handshakes are torn down abruptly.
pub struct ServerError {
    pub conn: Arc<dyn Conn>,
    pub source: Socksaddr,
    pub cause: io::Error,
}

impl fmt::Debug for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerError").field("source", &self.source).field("cause", &self.cause).finish()
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "snell: serve {}: {}", self.source, self.cause)
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

const MAX_IOV: usize = 1024;

/// A TCP connection with `net.TCPConn` semantics: concurrent reads and
/// writes, deadlines, and a close that interrupts pending operations.
pub struct TcpConn {
    stream: TcpStream,
    closed: CancellationToken,
    close_once: AtomicBool,
    read_deadline: watch::Sender<Option<Instant>>,
    write_deadline: watch::Sender<Option<Instant>>,
    local: Socksaddr,
    remote: Socksaddr,
}

impl fmt::Debug for TcpConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpConn").field("local", &self.local).field("remote", &self.remote).finish()
    }
}

impl TcpConn {
    /// Wraps `stream`, applying Go's `net` defaults for TCP connections:
    /// `TCP_NODELAY` and a 15 second keep-alive.
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(15))
            .with_interval(std::time::Duration::from_secs(15));
        let _ = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive);
        let local = stream.local_addr().map(Socksaddr::from).unwrap_or_default();
        let remote = stream.peer_addr().map(Socksaddr::from).unwrap_or_default();
        Ok(TcpConn {
            stream,
            closed: CancellationToken::new(),
            close_once: AtomicBool::new(false),
            read_deadline: watch::Sender::new(None),
            write_deadline: watch::Sender::new(None),
            local,
            remote,
        })
    }

    pub async fn connect(addr: std::net::SocketAddr) -> io::Result<Self> {
        Self::new(TcpStream::connect(addr).await?)
    }

    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    fn check(&self, deadline: Option<Instant>) -> io::Result<()> {
        if self.closed.is_cancelled() {
            return Err(error::closed());
        }
        if let Some(deadline) = deadline
            && deadline <= Instant::now()
        {
            return Err(error::timeout());
        }
        Ok(())
    }

    async fn write_slices(&self, slices: &mut [IoSlice<'_>]) -> io::Result<()> {
        let mut slices = slices;
        IoSlice::advance_slices(&mut slices, 0);
        let mut deadline_rx = self.write_deadline.subscribe();
        while !slices.is_empty() {
            let deadline = *deadline_rx.borrow_and_update();
            self.check(deadline)?;
            tokio::select! {
                biased;
                _ = self.closed.cancelled() => return Err(error::closed()),
                _ = deadline_rx.changed() => continue,
                _ = sleep_until(deadline) => return Err(error::timeout()),
                ready = self.stream.writable() => {
                    ready?;
                    let count = slices.len().min(MAX_IOV);
                    let result = if count == 1 {
                        self.stream.try_write(&slices[0])
                    } else {
                        self.stream.try_write_vectored(&slices[..count])
                    };
                    match result {
                        Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                        Ok(n) => IoSlice::advance_slices(&mut slices, n),
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(err) => return Err(err),
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl Conn for TcpConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut deadline_rx = self.read_deadline.subscribe();
        loop {
            let deadline = *deadline_rx.borrow_and_update();
            self.check(deadline)?;
            if buf.is_empty() {
                return Ok(0);
            }
            tokio::select! {
                biased;
                _ = self.closed.cancelled() => return Err(error::closed()),
                _ = deadline_rx.changed() => continue,
                _ = sleep_until(deadline) => return Err(error::timeout()),
                ready = self.stream.readable() => {
                    ready?;
                    match self.stream.try_read(buf) {
                        Ok(n) => return Ok(n),
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(err) => return Err(err),
                    }
                }
            }
        }
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.write_slices(&mut [IoSlice::new(buf)]).await?;
        Ok(buf.len())
    }

    async fn close(&self) -> io::Result<()> {
        if self.close_once.swap(true, Ordering::SeqCst) {
            return Err(error::closed());
        }
        self.closed.cancel();
        let _ = socket2::SockRef::from(&self.stream).shutdown(Shutdown::Both);
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.read_deadline.send_replace(deadline);
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.write_deadline.send_replace(deadline);
        Ok(())
    }

    fn local_addr(&self) -> Socksaddr {
        self.local.clone()
    }

    fn remote_addr(&self) -> Socksaddr {
        self.remote.clone()
    }

    async fn close_write(&self) -> io::Result<()> {
        if self.closed.is_cancelled() {
            return Err(error::closed());
        }
        socket2::SockRef::from(&self.stream).shutdown(Shutdown::Write)
    }

    fn supports_vectorised(&self) -> bool {
        true
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        let mut slices: Vec<IoSlice<'_>> = buffers.iter().map(|buffer| IoSlice::new(buffer.bytes())).collect();
        self.write_slices(&mut slices).await
    }
}

/// `bufio.NewCachedPacketConn`: returns `buffer` from `destination` on the
/// first read, then reads from the wrapped connection.
pub struct CachedPacketConn {
    conn: Arc<dyn PacketConn>,
    cached: Mutex<Option<(Buffer, Socksaddr)>>,
}

impl CachedPacketConn {
    pub fn new(conn: Arc<dyn PacketConn>, buffer: Buffer, destination: Socksaddr) -> Self {
        CachedPacketConn { conn, cached: Mutex::new(Some((buffer, destination))) }
    }

    fn take_cached(&self) -> Option<(Buffer, Socksaddr)> {
        self.cached.lock().unwrap().take()
    }
}

#[async_trait]
impl PacketConn for CachedPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        if let Some((cached, destination)) = self.take_cached() {
            if buffer.is_full() {
                return Err(error::short_buffer());
            }
            buffer.write(cached.bytes());
            return Ok(destination);
        }
        self.conn.read_packet(buffer).await
    }

    async fn write_packet(&self, buffer: Buffer, destination: Socksaddr) -> io::Result<()> {
        self.conn.write_packet(buffer, destination).await
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

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        self.conn.initialize_read_waiter(options)
    }

    async fn wait_read_packet(&self) -> io::Result<(Buffer, Socksaddr)> {
        if let Some(cached) = self.take_cached() {
            return Ok(cached);
        }
        self.conn.wait_read_packet().await
    }

    fn supports_packet_batch(&self) -> bool {
        self.conn.supports_packet_batch()
    }

    async fn write_packet_batch(&self, buffers: Vec<Buffer>, destinations: Vec<Socksaddr>) -> io::Result<()> {
        self.conn.write_packet_batch(buffers, destinations).await
    }

    fn front_headroom(&self) -> usize {
        self.conn.front_headroom()
    }

    fn rear_headroom(&self) -> usize {
        self.conn.rear_headroom()
    }

    fn writer_mtu(&self) -> usize {
        self.conn.writer_mtu()
    }
}

type BoxFuture<T> = std::pin::Pin<Box<dyn Future<Output = T> + Send>>;

const CONN_STREAM_READ_SIZE: usize = 32 * 1024;

/// Adapts a [`Conn`] to tokio's [`AsyncRead`](tokio::io::AsyncRead) and
/// [`AsyncWrite`](tokio::io::AsyncWrite), for use with
/// `tokio::io::copy_bidirectional` and similar helpers.
///
/// `poll_shutdown` half-closes the connection with [`Conn::close_write`].
/// As with most future-based adapters, a write that returned `Pending` keeps
/// the bytes it was first called with.
pub struct ConnStream {
    conn: Arc<dyn Conn>,
    read: Option<BoxFuture<io::Result<Vec<u8>>>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    write: Option<BoxFuture<io::Result<usize>>>,
    shutdown: Option<BoxFuture<io::Result<()>>>,
}

impl ConnStream {
    pub fn new(conn: Arc<dyn Conn>) -> Self {
        ConnStream { conn, read: None, read_buf: Vec::new(), read_pos: 0, write: None, shutdown: None }
    }

    pub fn conn(&self) -> &Arc<dyn Conn> {
        &self.conn
    }

    fn poll_pending_write(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<usize>> {
        let Some(write) = self.write.as_mut() else {
            return std::task::Poll::Ready(Ok(0));
        };
        let result = std::task::ready!(write.as_mut().poll(cx));
        self.write = None;
        std::task::Poll::Ready(result)
    }
}

impl tokio::io::AsyncRead for ConnStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        if this.read_pos < this.read_buf.len() {
            let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
            buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
            this.read_pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        if buf.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        let read = this.read.get_or_insert_with(|| {
            let conn = this.conn.clone();
            Box::pin(async move {
                let mut data = vec![0u8; CONN_STREAM_READ_SIZE];
                let n = conn.read(&mut data).await?;
                data.truncate(n);
                Ok(data)
            })
        });
        let result = std::task::ready!(read.as_mut().poll(cx));
        this.read = None;
        let data = result?;
        let n = data.len().min(buf.remaining());
        buf.put_slice(&data[..n]);
        this.read_buf = data;
        this.read_pos = n;
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for ConnStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.write.is_none() {
            if buf.is_empty() {
                return std::task::Poll::Ready(Ok(0));
            }
            let conn = this.conn.clone();
            let data = buf.to_vec();
            this.write = Some(Box::pin(async move { conn.write(&data).await }));
        }
        this.poll_pending_write(cx)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.poll_pending_write(cx).map_ok(|_| ())
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::ready!(self.poll_pending_write(cx))?;
        let this = &mut *self;
        let shutdown = this.shutdown.get_or_insert_with(|| {
            let conn = this.conn.clone();
            Box::pin(async move { conn.close_write().await })
        });
        let result = std::task::ready!(shutdown.as_mut().poll(cx));
        this.shutdown = None;
        std::task::Poll::Ready(result)
    }
}
