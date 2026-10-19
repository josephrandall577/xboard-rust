use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::OnceCell;

use super::packet::ServerPacketConn;
use super::record::{Writer, new_reader};
use super::reuse::ServerReuseSession;
use super::{MAX_INITIAL_PADDING_LEN, MAX_PAYLOAD};
use crate::addr::Socksaddr;
use crate::auth::{Authenticator, UserMap, build_user_map, user_authenticator};
use crate::buf::Buffer;
use crate::crypto::{Aead, derive_key, random_salt};
use crate::error::{self, ErrorCode, SharedResult};
use crate::net::{self, CachedPacketConn, CloseHandler, Conn, Context, Handler, ReadWaitOptions, ServerError};
use crate::obfs::{ObfsConfig, ObfsMode};
use crate::request::{Request, read_server_request};
use crate::reuse::{RecordReader, RecordWriter, eof_to_none, eof_to_zero};
use crate::{
    AEAD_TAG_LEN, COMMAND_CONNECT, COMMAND_CONNECT_V2, COMMAND_PING, COMMAND_UDP, HEADER_CIPHER_LEN, NONCE_LEN,
    REPLY_ERROR, REPLY_PONG, REPLY_TUNNEL, SALT_LEN,
};

// snell-server v5.0.1: FUN_0014c020 initializes two 500000-entry Bloom generations
// with false-positive probability 1e-10 for first-record salt replay detection.
const SALT_REPLAY_CACHE_GENERATION_SIZE: usize = 500000;
const SALT_REPLAY_CACHE_FALSE_POSITIVE_RATE: f64 = 1e-10;
const SALT_REPLAY_CACHE_MURMUR_HASH_DEFAULT_SEED: u32 = 0x9747b28c;

const NON_REUSABLE_EOF_CODE: u8 = 0xff;
const NON_REUSABLE_EOF_MESSAGE: &str = "end of file";

#[derive(Default)]
struct SaltReplayBloom {
    bits: Vec<u8>,
    bit_count: u32,
    hash_count: usize,
}

impl SaltReplayBloom {
    fn initialize(&mut self, expected_entries: usize, false_positive_rate: f64) {
        let ln2 = std::f64::consts::LN_2;
        let bits_per_entry = -false_positive_rate.ln() / (ln2 * ln2);
        self.bit_count = (expected_entries as f64 * bits_per_entry) as u32;
        self.hash_count = (bits_per_entry * ln2).ceil() as usize;
        self.bits = vec![0; self.bit_count.div_ceil(8) as usize];
    }

    fn contains(&self, data: &[u8]) -> bool {
        let first_hash = murmur_hash(data, SALT_REPLAY_CACHE_MURMUR_HASH_DEFAULT_SEED);
        let hash_step = murmur_hash(data, first_hash);
        let mut hash_value = first_hash;
        for _ in 0..self.hash_count {
            let bit_index = hash_value % self.bit_count;
            if self.bits[(bit_index >> 3) as usize] & (1 << (bit_index & 7)) == 0 {
                return false;
            }
            hash_value = hash_value.wrapping_add(hash_step);
        }
        true
    }

    fn add(&mut self, data: &[u8]) {
        let first_hash = murmur_hash(data, SALT_REPLAY_CACHE_MURMUR_HASH_DEFAULT_SEED);
        let hash_step = murmur_hash(data, first_hash);
        let mut hash_value = first_hash;
        for _ in 0..self.hash_count {
            let bit_index = hash_value % self.bit_count;
            self.bits[(bit_index >> 3) as usize] |= 1 << (bit_index & 7);
            hash_value = hash_value.wrapping_add(hash_step);
        }
    }

    fn clear(&mut self) {
        self.bits.fill(0);
    }
}

/// MurmurHash2.
fn murmur_hash(mut data: &[u8], seed: u32) -> u32 {
    const M: u32 = 0x5bd1e995;
    let mut hash_value = seed ^ data.len() as u32;
    while data.len() >= 4 {
        let mut chunk = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        chunk = chunk.wrapping_mul(M);
        chunk ^= chunk >> 24;
        chunk = chunk.wrapping_mul(M);
        hash_value = hash_value.wrapping_mul(M);
        hash_value ^= chunk;
        data = &data[4..];
    }
    match data.len() {
        3 => {
            hash_value ^= (data[2] as u32) << 16;
            hash_value ^= (data[1] as u32) << 8;
            hash_value ^= data[0] as u32;
            hash_value = hash_value.wrapping_mul(M);
        }
        2 => {
            hash_value ^= (data[1] as u32) << 8;
            hash_value ^= data[0] as u32;
            hash_value = hash_value.wrapping_mul(M);
        }
        1 => {
            hash_value ^= data[0] as u32;
            hash_value = hash_value.wrapping_mul(M);
        }
        _ => {}
    }
    hash_value ^= hash_value >> 13;
    hash_value = hash_value.wrapping_mul(M);
    hash_value ^= hash_value >> 15;
    hash_value
}

#[derive(Default)]
struct SaltReplayCacheState {
    current: usize,
    counts: [usize; 2],
    filters: [SaltReplayBloom; 2],
}

#[derive(Default)]
struct SaltReplayCache {
    state: Mutex<SaltReplayCacheState>,
}

impl SaltReplayCache {
    fn check_and_add(&self, salt: &[u8]) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.filters[0].bits.is_empty() {
            state.filters[0].initialize(SALT_REPLAY_CACHE_GENERATION_SIZE, SALT_REPLAY_CACHE_FALSE_POSITIVE_RATE);
            state.filters[1].initialize(SALT_REPLAY_CACHE_GENERATION_SIZE, SALT_REPLAY_CACHE_FALSE_POSITIVE_RATE);
        }
        if state.filters[0].contains(salt) || state.filters[1].contains(salt) {
            return true;
        }
        let current = state.current;
        state.filters[current].add(salt);
        state.counts[current] += 1;
        if state.counts[current] >= SALT_REPLAY_CACHE_GENERATION_SIZE {
            state.counts[current] = 0;
            state.current ^= 1;
            let current = state.current;
            state.filters[current].clear();
        }
        false
    }
}

pub(crate) struct ServiceInner {
    pub(crate) psk: Arc<[u8]>,
    obfs: ObfsConfig,
    pub(crate) handler: Arc<dyn Handler>,
    salt_cache: SaltReplayCache,
    authenticator: Option<Box<Authenticator>>,
}

pub struct ServiceOptions {
    pub psk: Vec<u8>,
    pub obfs_mode: ObfsMode,
    pub handler: Arc<dyn Handler>,
}

fn new_service_inner(options: ServiceOptions, authenticator: Option<Box<Authenticator>>) -> io::Result<ServiceInner> {
    if options.psk.is_empty() {
        return Err(ErrorCode::MissingPsk.into());
    }
    Ok(ServiceInner {
        psk: options.psk.into(),
        obfs: ObfsConfig { mode: options.obfs_mode, ..Default::default() },
        handler: options.handler,
        salt_cache: SaltReplayCache::default(),
        authenticator,
    })
}

/// The snell v5 server.
#[derive(Clone)]
pub struct Service {
    inner: Arc<ServiceInner>,
}

impl Service {
    pub fn new(options: ServiceOptions) -> io::Result<Service> {
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

/// The snell v5 server with per-user keys.
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
    pub fn new(options: ServiceOptions) -> io::Result<MultiService<U>> {
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

#[cfg(test)]
pub(crate) fn test_service_inner(handler: Arc<dyn Handler>) -> Arc<ServiceInner> {
    Arc::new(
        new_service_inner(ServiceOptions { psk: b"test".to_vec(), obfs_mode: ObfsMode::None, handler }, None).unwrap(),
    )
}

/// Creates a response writer with a fresh salt.
pub(crate) fn new_response_writer(psk: &[u8], conn: &Arc<dyn Conn>) -> io::Result<([u8; SALT_LEN], Writer)> {
    let salt = random_salt();
    let aead = Aead::new(&derive_key(psk, &salt))?;
    Ok((salt, Writer::new(conn.clone(), aead, [0; NONCE_LEN])))
}

pub(crate) fn error_reply(code: u8, message: &str) -> Vec<u8> {
    let mut reply = Vec::with_capacity(3 + message.len());
    reply.push(REPLY_ERROR);
    reply.push(code);
    reply.push(message.len() as u8);
    reply.extend_from_slice(message.as_bytes());
    reply
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
        let conn = self.obfs.server_conn(conn);
        let mut salt = [0u8; SALT_LEN];
        net::read_full(conn.as_ref(), &mut salt).await?;
        let aead = Aead::new(&derive_key(&self.psk, &salt))?;
        let reader: Arc<dyn RecordReader> = Arc::new(new_reader(conn.clone(), aead, [0; NONCE_LEN]));
        let mut record = reader.read_record().await.map_err(|err| error::cause(err, "read request"))?;
        // snell-server v5.0.1: initial request path: checks the first record salt after decryption
        // and aborts with "Duplicated salt detected" when it was recently seen.
        if self.salt_cache.check_and_add(&salt) {
            return Err(error::new_error("snell: duplicated salt"));
        }
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
                let packet_conn = Arc::new(ServerPacketConn::new(conn, self.clone(), reader, None));
                let mut on_close = on_close;
                self.new_packet_connection(request_ctx, packet_conn, source, &mut on_close).await
            }
            COMMAND_PING => {
                let result = self.write_pong(&conn).await;
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
        let destination = crate::net::PacketConn::read_packet(packet_conn.as_ref(), &mut first_packet)
            .await
            .map_err(|err| error::cause(err, "read first packet"))?;
        let cached = Arc::new(CachedPacketConn::new(packet_conn, first_packet, destination.clone()));
        self.handler.new_packet_connection(ctx, cached, source, destination, on_close.take());
        Ok(())
    }

    pub(crate) async fn write_pong(&self, conn: &Arc<dyn Conn>) -> io::Result<()> {
        let (salt, writer) = new_response_writer(&self.psk, conn)?;
        writer.write_first(&salt, &[REPLY_PONG]).await
    }
}

/// A non-reusable (command 1) server connection.
pub(crate) struct ServerConn {
    conn: Arc<dyn Conn>,
    service: Arc<ServiceInner>,
    reader: Arc<dyn RecordReader>,

    access: tokio::sync::Mutex<()>,
    writer: OnceLock<Arc<Writer>>,

    close_write: OnceCell<SharedResult>,
    close: OnceCell<SharedResult>,
}

impl ServerConn {
    fn new(conn: Arc<dyn Conn>, service: Arc<ServiceInner>, reader: Arc<dyn RecordReader>) -> Self {
        ServerConn {
            conn,
            service,
            reader,
            access: tokio::sync::Mutex::new(()),
            writer: OnceLock::new(),
            close_write: OnceCell::new(),
            close: OnceCell::new(),
        }
    }

    async fn write_first(&self, reply: &[u8], context: &str) -> io::Result<()> {
        let (salt, writer) = new_response_writer(&self.service.psk, &self.conn)?;
        writer.write_first(&salt, reply).await.map_err(|err| error::cause(err, context.to_string()))?;
        let _ = self.writer.set(Arc::new(writer));
        Ok(())
    }

    async fn write_response(&self, payload: &[u8]) -> io::Result<()> {
        let mut reply = Vec::with_capacity(1 + payload.len());
        reply.push(REPLY_TUNNEL);
        reply.extend_from_slice(payload);
        self.write_first(&reply, "write reply").await
    }

    async fn write_error_response(&self, code: u8, message: &str) -> io::Result<()> {
        self.write_first(&error_reply(code, message), "write error reply").await
    }

    async fn write_response_buffer(&self, mut buffer: Buffer) -> io::Result<()> {
        buffer.extend_header(1)[0] = REPLY_TUNNEL;
        self.write_first(buffer.bytes(), "write reply").await
    }

    async fn close_inner(&self) -> SharedResult {
        self.close.get_or_init(|| async { SharedResult::new(self.conn.close().await) }).await.clone()
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
        if let Some(writer) = self.writer.get() {
            return writer.write(buf).await;
        }
        let guard = self.access.lock().await;
        if let Some(writer) = self.writer.get() {
            drop(guard);
            return writer.write(buf).await;
        }
        self.write_response(buf).await?;
        Ok(buf.len())
    }

    async fn close(&self) -> io::Result<()> {
        self.close_inner().await.get()
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
                if self.writer.get().is_none() {
                    // snell-server v5.0.1: FUN_0013f020 uses the generic network-error
                    // path for command-1 EOF before the first response; UV_EOF maps to
                    // ReplyError 0xff "end of file".
                    let result = self.write_error_response(NON_REUSABLE_EOF_CODE, NON_REUSABLE_EOF_MESSAGE).await;
                    let close_result = self.close_inner().await;
                    return match result {
                        Ok(()) => close_result,
                        Err(err) => SharedResult::new(Err(err)),
                    };
                }
                // snell-server v5.0.1: FUN_0013f020 closes non-reusable command-1 tunnels
                // on upstream EOF instead of writing a Snell zero chunk.
                self.close_inner().await
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
        if let Some(writer) = self.writer.get() {
            return writer.write_buffer(buffer).await;
        }
        let guard = self.access.lock().await;
        if let Some(writer) = self.writer.get() {
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
            self.write_response_buffer(buffer).await?;
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
        self.reader.initialize_read_waiter(options)
    }

    async fn wait_read_buffer(&self) -> io::Result<Option<Buffer>> {
        eof_to_none(self.reader.wait_read_buffer().await)
    }

    fn front_headroom(&self) -> usize {
        if self.writer.get().is_none() {
            return 1 + SALT_LEN + HEADER_CIPHER_LEN + MAX_INITIAL_PADDING_LEN;
        }
        HEADER_CIPHER_LEN
    }

    fn rear_headroom(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn writer_mtu(&self) -> usize {
        MAX_PAYLOAD
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::*;

    /// Compares against the Go reference's `TestDumpVectors` (`tests/fixtures/v5_vectors.txt`).
    #[test]
    fn salt_replay_bloom_matches_go_reference() {
        let mut bloom = SaltReplayBloom::default();
        bloom.initialize(SALT_REPLAY_CACHE_GENERATION_SIZE, SALT_REPLAY_CACHE_FALSE_POSITIVE_RATE);
        let mut actual = String::new();
        writeln!(actual, "bloom {} {}", bloom.bit_count, bloom.hash_count).unwrap();
        for input in ["", "a", "ab", "abc", "abcd", "abcde", "0123456789abcdef", "snell-interop-test-psk-0123456789"] {
            let first = murmur_hash(input.as_bytes(), SALT_REPLAY_CACHE_MURMUR_HASH_DEFAULT_SEED);
            writeln!(actual, "murmur {input:?} {first} {}", murmur_hash(input.as_bytes(), first)).unwrap();
        }
        assert_eq!(include_str!("../../tests/fixtures/v5_vectors.txt"), actual);
    }

    #[test]
    fn salt_replay_cache_detects_duplicates() {
        let cache = SaltReplayCache::default();
        assert!(!cache.check_and_add(b"0123456789abcdef"));
        assert!(cache.check_and_add(b"0123456789abcdef"));
        assert!(!cache.check_and_add(b"fedcba9876543210"));
    }
}
