//! Connection reuse shared by the v4 and v6 clients, and the record
//! reader/writer interfaces shared by the servers.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::buf::Buffer;
use crate::error::{self, ErrorCode};
use crate::net::ReadWaitOptions;
use crate::request::read_server_error;
use crate::{REPLY_ERROR, REPLY_TUNNEL};

pub(crate) const POOL_SIZE: usize = 10;
pub(crate) const POOL_MAX_AGE: Duration = Duration::from_secs(180);
pub(crate) const POOL_TIMER_INTERVAL: Duration = Duration::from_secs(20);
// Surge 6.7.0 (11520): SNConnectorV4::readServerEOFIfNotInReadState: closes a waiting connector after 0x80001 bytes are read after client EOF.
pub(crate) const WAITING_DISCARD_LIMIT: usize = 0x80001;
// snell-server v5.0.1: FUN_0013f020: writes ReplyError code 0x65 with message "Remote EOF" when the server side closes before replying.
pub(crate) const REMOTE_EOF_CODE: u8 = 0x65;
pub(crate) const REMOTE_EOF_MESSAGE: &str = "Remote EOF";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum State {
    Ready = 0,
    Active = 1,
    Waiting = 2,
    Closed = 3,
}

impl State {
    pub(crate) fn load(state: &AtomicU32) -> State {
        match state.load(Ordering::SeqCst) {
            0 => State::Ready,
            1 => State::Active,
            2 => State::Waiting,
            _ => State::Closed,
        }
    }

    pub(crate) fn store(state: &AtomicU32, value: State) {
        state.store(value as u32, Ordering::SeqCst);
    }

    pub(crate) fn swap(state: &AtomicU32, value: State) -> State {
        match state.swap(value as u32, Ordering::SeqCst) {
            0 => State::Ready,
            1 => State::Active,
            2 => State::Waiting,
            _ => State::Closed,
        }
    }

    pub(crate) fn compare_and_swap(state: &AtomicU32, current: State, new: State) -> bool {
        state.compare_exchange(current as u32, new as u32, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    }
}

#[async_trait]
pub(crate) trait Session: Clone + Send + Sync + 'static {
    async fn close(&self) -> io::Result<()>;
    fn reuse_state(&self) -> &AtomicU32;
}

/// A `sync.WaitGroup`.
#[derive(Default)]
pub(crate) struct WaitGroup {
    count: Mutex<usize>,
    notify: Notify,
}

impl WaitGroup {
    pub(crate) fn add(&self, n: usize) {
        *self.count.lock().unwrap() += n;
    }

    pub(crate) fn done(&self) {
        let mut count = self.count.lock().unwrap();
        *count -= 1;
        if *count == 0 {
            self.notify.notify_waiters();
        }
    }

    pub(crate) async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if *self.count.lock().unwrap() == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct PoolEntry<S> {
    session: S,
    time: Instant,
}

struct PoolState<S> {
    initialized: bool,
    closed: bool,
    entries: VecDeque<PoolEntry<S>>,
    ticking: bool,
}

struct PoolInner<S> {
    state: Mutex<PoolState<S>>,
    stop: CancellationToken,
    drain: WaitGroup,
}

/// The idle session pool (`reuse.Pool`).
pub(crate) struct Pool<S> {
    inner: Arc<PoolInner<S>>,
}

impl<S> Clone for Pool<S> {
    fn clone(&self) -> Self {
        Pool { inner: self.inner.clone() }
    }
}

impl<S: Session> Default for Pool<S> {
    fn default() -> Self {
        Pool {
            inner: Arc::new(PoolInner {
                state: Mutex::new(PoolState {
                    initialized: false,
                    closed: false,
                    entries: VecDeque::new(),
                    ticking: false,
                }),
                stop: CancellationToken::new(),
                drain: WaitGroup::default(),
            }),
        }
    }
}

/// Removes closed and expired entries, returning the expired sessions.
fn cleanup<S: Session>(entries: &mut VecDeque<PoolEntry<S>>, now: Instant) -> Vec<S> {
    let mut expired = Vec::new();
    entries.retain(|entry| {
        if State::load(entry.session.reuse_state()) == State::Closed {
            return false;
        }
        if now.duration_since(entry.time) > POOL_MAX_AGE {
            expired.push(entry.session.clone());
            return false;
        }
        true
    });
    expired
}

async fn close_all<S: Session>(sessions: Vec<S>) {
    for session in sessions {
        let _ = session.close().await;
    }
}

impl<S: Session> Pool<S> {
    pub(crate) fn init(&self) {
        let mut state = self.inner.state.lock().unwrap();
        state.initialized = true;
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.inner.state.lock().unwrap().closed
    }

    /// Takes a ready session. Returns `(session, closed)`.
    pub(crate) async fn take(&self) -> (Option<S>, bool) {
        let mut found = None;
        let (closed, expired) = {
            let mut state = self.inner.state.lock().unwrap();
            let closed = state.closed;
            let mut expired = Vec::new();
            if !closed {
                let now = Instant::now();
                let entries = std::mem::take(&mut state.entries);
                for entry in entries {
                    let entry_state = State::load(entry.session.reuse_state());
                    if entry_state == State::Closed {
                        continue;
                    }
                    if now.duration_since(entry.time) > POOL_MAX_AGE {
                        expired.push(entry.session);
                        continue;
                    }
                    if found.is_none()
                        && entry_state == State::Ready
                        && State::compare_and_swap(entry.session.reuse_state(), State::Ready, State::Active)
                    {
                        found = Some(entry.session);
                        continue;
                    }
                    state.entries.push_back(entry);
                }
            }
            (closed, expired)
        };
        close_all(expired).await;
        (found, closed)
    }

    pub(crate) async fn move_to_pool(&self, session: S, session_state: State, drain: bool) -> bool {
        let (added, expired) = {
            let mut state = self.inner.state.lock().unwrap();
            let closed = state.closed;
            let now = Instant::now();
            let expired = if closed { Vec::new() } else { cleanup(&mut state.entries, now) };
            let mut added = false;
            if !closed && state.initialized && state.entries.len() < POOL_SIZE {
                state.entries.push_back(PoolEntry { session: session.clone(), time: now });
                if session_state == State::Waiting && drain {
                    self.inner.drain.add(1);
                }
                added = true;
                if !state.ticking {
                    state.ticking = true;
                    tokio::spawn(expire_loop(Arc::downgrade(&self.inner), self.inner.stop.clone()));
                }
            }
            (added, expired)
        };
        close_all(expired).await;
        if !added {
            let _ = session.close().await;
        }
        added
    }

    pub(crate) fn drain_done(&self) {
        self.inner.drain.done();
    }

    pub(crate) async fn reset(&self) {
        let sessions: Vec<S> = {
            let mut state = self.inner.state.lock().unwrap();
            if state.closed {
                return;
            }
            state.entries.drain(..).map(|entry| entry.session).collect()
        };
        close_all(sessions).await;
    }

    pub(crate) async fn close(&self) -> io::Result<()> {
        let sessions: Vec<S> = {
            let mut state = self.inner.state.lock().unwrap();
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            let sessions = state.entries.drain(..).map(|entry| entry.session).collect();
            if state.initialized {
                self.inner.stop.cancel();
            }
            sessions
        };
        let mut close_err = None;
        for session in sessions {
            close_err = error::first_error(close_err, session.close().await);
        }
        self.inner.drain.wait().await;
        match close_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

async fn expire_loop<S: Session>(inner: Weak<PoolInner<S>>, stop: CancellationToken) {
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + POOL_TIMER_INTERVAL, POOL_TIMER_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let Some(inner) = inner.upgrade() else {
                    return;
                };
                let (expired, finished) = {
                    let mut state = inner.state.lock().unwrap();
                    if state.closed {
                        state.ticking = false;
                        return;
                    }
                    let expired = cleanup(&mut state.entries, Instant::now());
                    let finished = state.entries.is_empty();
                    if finished {
                        state.ticking = false;
                    }
                    (expired, finished)
                };
                close_all(expired).await;
                if finished {
                    return;
                }
            }
            _ = stop.cancelled() => return,
        }
    }
}

/// `reuse.RecordReader`. Methods report EOF as an error, like Go.
#[async_trait]
pub(crate) trait RecordReader: Send + Sync {
    async fn read_record(&self) -> io::Result<Buffer>;
    async fn next_record(&self) -> io::Result<Buffer>;
    fn set_cache(&self, cache: Option<Buffer>);
    async fn read(&self, p: &mut [u8]) -> io::Result<usize>;
    async fn read_buffer(&self, buffer: &mut Buffer) -> io::Result<usize>;
    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool;
    async fn wait_read_buffer(&self) -> io::Result<Buffer>;
}

/// `reuse.RecordWriter`.
#[async_trait]
pub(crate) trait RecordWriter: Send + Sync {
    async fn write(&self, p: &[u8]) -> io::Result<usize>;
    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()>;
    /// `CreateVectorisedWriterFor(upstream).WriteVectorised(buffers)`.
    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()>;
    /// `CreatePacketVectorisedWriterFor(upstream).WriteVectorised(buffers)`.
    async fn write_packet_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()>;
    async fn write_packet_buffer(&self, buffer: Buffer) -> io::Result<()>;
    async fn write_zero_chunk(&self) -> io::Result<()>;
    fn front_headroom(&self) -> usize;
    fn rear_headroom(&self) -> usize;
    fn writer_mtu(&self) -> usize;
}

/// The record decoding part of a reader.
#[async_trait]
pub(crate) trait RecordSource: Send + Sync {
    async fn read_record(&self, options: ReadWaitOptions) -> io::Result<Buffer>;
}

/// The record caching part shared by every reader (`baseReader`).
pub(crate) struct BaseReader<S> {
    pub(crate) source: S,
    cache: Mutex<Option<Buffer>>,
    options: Mutex<ReadWaitOptions>,
}

impl<S: RecordSource> BaseReader<S> {
    pub(crate) fn new(source: S) -> Self {
        BaseReader { source, cache: Mutex::new(None), options: Mutex::new(ReadWaitOptions::default()) }
    }

    fn options(&self) -> ReadWaitOptions {
        *self.options.lock().unwrap()
    }

    fn take_cache(&self) -> Option<Buffer> {
        self.cache.lock().unwrap().take()
    }
}

#[async_trait]
impl<S: RecordSource> RecordReader for BaseReader<S> {
    async fn read_record(&self) -> io::Result<Buffer> {
        self.source.read_record(self.options()).await
    }

    async fn next_record(&self) -> io::Result<Buffer> {
        if let Some(record) = self.take_cache()
            && !record.is_empty()
        {
            return Ok(record);
        }
        self.read_record().await
    }

    fn set_cache(&self, cache: Option<Buffer>) {
        *self.cache.lock().unwrap() = cache;
    }

    async fn read(&self, p: &mut [u8]) -> io::Result<usize> {
        loop {
            {
                let mut cache = self.cache.lock().unwrap();
                if let Some(record) = cache.as_mut() {
                    if record.is_empty() {
                        *cache = None;
                    } else {
                        let n = record.len().min(p.len());
                        p[..n].copy_from_slice(&record.bytes()[..n]);
                        record.advance(n);
                        return Ok(n);
                    }
                }
            }
            let record = self.read_record().await?;
            *self.cache.lock().unwrap() = Some(record);
        }
    }

    async fn read_buffer(&self, buffer: &mut Buffer) -> io::Result<usize> {
        loop {
            {
                let mut cache = self.cache.lock().unwrap();
                if let Some(record) = cache.as_mut() {
                    if record.is_empty() {
                        *cache = None;
                    } else {
                        let n = buffer.write(record.bytes());
                        record.advance(n);
                        return Ok(n);
                    }
                }
            }
            let record = self.read_record().await?;
            *self.cache.lock().unwrap() = Some(record);
        }
    }

    fn initialize_read_waiter(&self, options: ReadWaitOptions) -> bool {
        *self.options.lock().unwrap() = options;
        false
    }

    async fn wait_read_buffer(&self) -> io::Result<Buffer> {
        loop {
            let Some(buffer) = self.take_cache() else {
                return self.read_record().await;
            };
            if buffer.is_empty() {
                continue;
            }
            let options = self.options();
            if buffer.start() >= options.front_headroom && buffer.free_len() >= options.rear_headroom {
                return Ok(buffer);
            }
            return Ok(options.copy(buffer));
        }
    }
}

/// `reuse.ParseReply`: returns the payload carried by a tunnel reply, if any.
pub(crate) fn parse_reply(mut record: Buffer) -> io::Result<Option<Buffer>> {
    let reply = record.read_byte()?;
    match reply {
        REPLY_TUNNEL => {
            if record.is_empty() {
                Ok(None)
            } else {
                Ok(Some(record))
            }
        }
        REPLY_ERROR => Err(read_server_error(&mut record)),
        reply => Err(error::extend_code(ErrorCode::UnexpectedReply, reply)),
    }
}

/// Decrements an atomic counter when dropped (`defer count.Add(-1)`).
pub(crate) struct CountGuard<'a>(pub(crate) &'a std::sync::atomic::AtomicI32);

impl<'a> CountGuard<'a> {
    pub(crate) fn new(counter: &'a std::sync::atomic::AtomicI32) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        CountGuard(counter)
    }
}

impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Converts a Go-style read result (EOF as an error) into a Rust-style one.
pub(crate) fn eof_to_zero(result: io::Result<usize>) -> io::Result<usize> {
    match result {
        Err(err) if error::is_bare_eof(&err) => Ok(0),
        result => result,
    }
}

/// Converts a Go-style buffer read result into an optional buffer.
pub(crate) fn eof_to_none(result: io::Result<Buffer>) -> io::Result<Option<Buffer>> {
    match result {
        Ok(buffer) => Ok(Some(buffer)),
        Err(err) if error::is_bare_eof(&err) => Ok(None),
        Err(err) => Err(err),
    }
}
