//! Single-port v6 default-mode service with independently authenticated PSKs.
//!
//! Salt-block fingerprints only select a candidate. Identity is established by
//! verifying its first AEAD record, never by the request's client_id.

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use blake2::{Blake2b, Digest, digest::consts::U32};

use super::Mode;
use super::handshake::Framing;
use super::profile::Profile;
use super::server::ServiceInner;
use super::shaped::new_shaped_reader_with_salt;
use crate::error;
use crate::net::{self, CloseHandler, Conn, Context, Handler, ReadWaitOptions, ServerError};
use crate::reuse::RecordReader;
use crate::{Buffer, SALT_LEN, Socksaddr};

const MIN_BLOCK: usize = 32;
const MAX_BLOCK: usize = 144;
const READ_STEP: usize = 16;
const REPLAY_GENERATION: usize = 500_000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

type UserTable<U> = Arc<RwLock<Arc<CredentialTable<U>>>>;

struct CredentialTable<U> {
    by_psk: HashMap<Vec<u8>, Arc<Credential<U>>>,
    by_length: [Vec<Arc<Credential<U>>>; MAX_BLOCK - MIN_BLOCK + 1],
}

impl<U> Default for CredentialTable<U> {
    fn default() -> Self {
        Self { by_psk: HashMap::new(), by_length: std::array::from_fn(|_| Vec::new()) }
    }
}

impl<U> CredentialTable<U> {
    fn identify(&self, block: &[u8], checked: &mut usize) -> Option<Arc<Credential<U>>> {
        while *checked <= block.len() {
            for entry in &self.by_length[*checked - MIN_BLOCK] {
                if entry.fingerprint.iter().all(|&(i, byte)| block[i] == byte) {
                    return Some(entry.clone());
                }
            }
            *checked += 1;
        }
        None
    }
}

struct Credential<U> {
    user: U,
    framing: Framing,
    fingerprint: Vec<(usize, u8)>,
}

// Bounded, exact two-generation cache, shared across users and user updates.
// Hashing PSK + salt namespaces salts by credential without retaining secrets.
#[derive(Default)]
struct ReplayCache {
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
}

impl ReplayCache {
    fn check_and_add(&mut self, psk: &[u8], salt: &[u8; SALT_LEN]) -> io::Result<()> {
        let mut digest = Blake2b::<U32>::new();
        digest.update(psk);
        digest.update(salt);
        let key: [u8; 32] = digest.finalize().into();
        if self.current.contains(&key) || self.previous.contains(&key) {
            return Err(error::new_invalid("snell: replayed v6 salt"));
        }
        if self.current.len() >= REPLAY_GENERATION {
            self.previous = std::mem::take(&mut self.current);
        }
        self.current.insert(key);
        Ok(())
    }
}

/// Per-user PSK authentication for Surge clients which send no client_id.
/// Only v6 [`Mode::Default`] has the salt-block fingerprint used here.
/// Empty user sets are supported and reject all connections.
pub struct MultiPskService<U> {
    users: UserTable<U>,
    handler: Arc<dyn Handler>,
    replay: Arc<Mutex<ReplayCache>>,
}

impl<U> Clone for MultiPskService<U> {
    fn clone(&self) -> Self {
        Self { users: self.users.clone(), handler: self.handler.clone(), replay: self.replay.clone() }
    }
}

impl<U: Clone + Send + Sync + 'static> MultiPskService<U> {
    pub fn new(mode: Mode, handler: Arc<dyn Handler>) -> io::Result<Self> {
        if mode != Mode::Default {
            return Err(error::new_invalid("snell: per-user PSKs require v6 default mode"));
        }
        Ok(Self {
            users: Arc::new(RwLock::new(Arc::new(CredentialTable::default()))),
            handler,
            replay: Arc::new(Mutex::new(ReplayCache::default())),
        })
    }

    /// Validates and atomically replaces credentials. Unchanged PSKs reuse the
    /// existing profile and fingerprint; no Argon2 derivation happens here.
    pub fn update_users(&self, users: Vec<U>, psks: Vec<Vec<u8>>) -> io::Result<()> {
        if users.len() != psks.len() {
            return Err(error::new_invalid("snell: user/psk count mismatch"));
        }
        let previous = self.users.read().unwrap().clone();
        let mut next = CredentialTable::default();
        next.by_psk.reserve(users.len());
        for (user, psk) in users.into_iter().zip(psks) {
            if !(12..=255).contains(&psk.len()) {
                return Err(error::new_invalid("snell: user psk length must be between 12 and 255 bytes"));
            }
            if next.by_psk.contains_key(&psk) {
                return Err(error::new_invalid("snell: duplicate user psk"));
            }
            let framing = match previous.by_psk.get(&psk) {
                Some(entry) => entry.framing.clone(),
                None => Framing {
                    mode: Mode::Default,
                    profile: Some(Arc::new(Profile::new(&psk))),
                    psk: psk.clone().into(),
                },
            };
            let fingerprint = match previous.by_psk.get(&psk) {
                Some(entry) => entry.fingerprint.clone(),
                None => framing.profile.as_ref().unwrap().salt_fingerprint(),
            };
            if fingerprint.len() < 16 {
                return Err(error::new_invalid("snell: insufficient salt-block fingerprint"));
            }
            let block_len = framing.profile.as_ref().unwrap().salt_block_len;
            if !(MIN_BLOCK..=MAX_BLOCK).contains(&block_len) {
                return Err(error::new_invalid("snell: unsupported salt block length"));
            }
            let entry = Arc::new(Credential { user, framing, fingerprint });
            next.by_length[block_len - MIN_BLOCK].push(entry.clone());
            next.by_psk.insert(psk, entry);
        }
        *self.users.write().unwrap() = Arc::new(next);
        Ok(())
    }

    pub async fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> Result<(), ServerError> {
        self.serve(ctx, conn.clone(), source.clone(), on_close).await.map_err(|cause| ServerError {
            conn,
            source,
            cause,
        })
    }

    async fn serve(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> io::Result<()> {
        let (entry, conn, reader, record) = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.read_hello(&conn))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "snell: psk handshake timed out"))??;
        let users = self.users.clone();
        let psk = entry.framing.psk.clone();
        let service = Arc::new(ServiceInner {
            framing: entry.framing.clone(),
            handler: self.handler.clone(),
            authenticator: Some(Box::new(move |ctx, _request| {
                let users = users.read().unwrap();
                let entry = users.by_psk.get(psk.as_ref()).ok_or_else(|| error::new_invalid("snell: revoked psk"))?;
                Ok(ctx.clone().with_user(entry.user.clone()))
            })),
        });
        // Revalidate even PING if a user update raced with the handshake.
        let ctx = service.authenticate(&ctx, &crate::request::Request::default()).unwrap()?;
        service.serve_record(ctx, conn, source, on_close, reader, record).await
    }

    async fn read_hello(
        &self,
        conn: &Arc<dyn Conn>,
    ) -> io::Result<(Arc<Credential<U>>, Arc<dyn Conn>, Arc<dyn RecordReader>, Buffer)> {
        let users = self.users.read().unwrap().clone();
        if users.by_psk.is_empty() {
            return Err(error::new_invalid("snell: no user credentials"));
        }
        let mut block = [0; MAX_BLOCK];
        net::read_full(conn.as_ref(), &mut block[..MIN_BLOCK]).await?;
        let mut filled = MIN_BLOCK;
        let mut checked = MIN_BLOCK;
        let entry = loop {
            if let Some(entry) = users.identify(&block[..filled], &mut checked) {
                break entry;
            }
            if filled == MAX_BLOCK {
                return Err(error::new_invalid("snell: unknown psk fingerprint"));
            }
            // Read in 16-byte steps, checking every newly covered profile
            // length: real salt blocks need not be a multiple of sixteen.
            // Up to fifteen overread record bytes are fed back below.
            let next = (filled + READ_STEP).min(MAX_BLOCK);
            net::read_full(conn.as_ref(), &mut block[filled..next]).await?;
            filled = next;
        };
        drop(users);
        let profile = entry.framing.profile.as_ref().unwrap().clone();
        let salt = profile.extract_salt(&block[..profile.salt_block_len]);
        let conn: Arc<dyn Conn> = Arc::new(PrefixedConn {
            upstream: conn.clone(),
            prefix: Mutex::new(Buffer::from_vec(block[profile.salt_block_len..filled].to_vec())),
        });
        let reader = new_shaped_reader_with_salt(conn.clone(), entry.framing.psk.clone(), profile, &salt)?;
        reader.initialize_read_waiter(ReadWaitOptions::default());
        let record = reader.read_record().await?;
        // Do not let unauthenticated fingerprints poison the salt cache.
        self.replay.lock().unwrap().check_and_add(&entry.framing.psk, &salt)?;
        Ok((entry, conn, Arc::new(reader), record))
    }
}

#[async_trait]
impl<U: Clone + Send + Sync + 'static> net::Service for MultiPskService<U> {
    async fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        on_close: Option<CloseHandler>,
    ) -> Result<(), ServerError> {
        MultiPskService::new_connection(self, ctx, conn, source, on_close).await
    }
}

/// Returns bytes consumed by detection before reading the transport again.
struct PrefixedConn {
    upstream: Arc<dyn Conn>,
    prefix: Mutex<Buffer>,
}

#[async_trait]
impl Conn for PrefixedConn {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        {
            let mut prefix = self.prefix.lock().unwrap();
            if !prefix.is_empty() || buf.is_empty() {
                let n = buf.len().min(prefix.len());
                buf[..n].copy_from_slice(&prefix.bytes()[..n]);
                prefix.advance(n);
                return Ok(n);
            }
        }
        self.upstream.read(buf).await
    }
    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.upstream.write(buf).await
    }
    async fn close(&self) -> io::Result<()> {
        self.upstream.close().await
    }
    async fn close_write(&self) -> io::Result<()> {
        self.upstream.close_write().await
    }
    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.upstream.set_read_deadline(deadline)
    }
    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.upstream.set_write_deadline(deadline)
    }
    fn local_addr(&self) -> Socksaddr {
        self.upstream.local_addr()
    }
    fn remote_addr(&self) -> Socksaddr {
        self.upstream.remote_addr()
    }
    fn supports_vectorised(&self) -> bool {
        self.upstream.supports_vectorised()
    }
    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        self.upstream.write_vectorised(buffers).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::PacketConn;
    use crate::request::Request;
    use crate::test_util::CaptureConn;
    use crate::{COMMAND_CONNECT, COMMAND_PING, REPLY_PONG};

    struct IdHandler(tokio::sync::mpsc::UnboundedSender<usize>);
    impl Handler for IdHandler {
        fn new_connection(
            &self,
            ctx: Context,
            conn: Arc<dyn Conn>,
            _: Socksaddr,
            _: Socksaddr,
            _: Option<CloseHandler>,
        ) {
            self.0.send(*ctx.user::<usize>().unwrap()).unwrap();
            tokio::spawn(async move {
                let _ = conn.close().await;
            });
        }
        fn new_packet_connection(
            &self,
            _: Context,
            _: Arc<dyn PacketConn>,
            _: Socksaddr,
            _: Socksaddr,
            _: Option<CloseHandler>,
        ) {
            panic!("unexpected UDP");
        }
    }

    struct Input {
        bytes: Mutex<std::io::Cursor<Vec<u8>>>,
        max_read: usize,
        output: CaptureConn,
        requests: Mutex<Vec<usize>>,
    }
    impl Input {
        fn new(bytes: Vec<u8>, max_read: usize) -> Self {
            Self {
                bytes: Mutex::new(std::io::Cursor::new(bytes)),
                max_read,
                output: CaptureConn::default(),
                requests: Mutex::new(Vec::new()),
            }
        }
    }
    #[async_trait]
    impl Conn for Input {
        async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.requests.lock().unwrap().push(buf.len());
            let size = buf.len().min(self.max_read);
            std::io::Read::read(&mut *self.bytes.lock().unwrap(), &mut buf[..size])
        }
        async fn write(&self, buf: &[u8]) -> io::Result<usize> {
            self.output.write(buf).await
        }
        async fn close(&self) -> io::Result<()> {
            Ok(())
        }
        fn set_read_deadline(&self, _: Option<Instant>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_deadline(&self, _: Option<Instant>) -> io::Result<()> {
            Ok(())
        }
    }

    fn framing(psk: &[u8]) -> Framing {
        Framing { mode: Mode::Default, psk: psk.into(), profile: Some(Arc::new(Profile::new(psk))) }
    }

    async fn hello(psk: &[u8], command: u8, client_id: &[u8]) -> Vec<u8> {
        let capture = Arc::new(CaptureConn::default());
        let conn: Arc<dyn Conn> = capture.clone();
        let request =
            Request { command, client_id: client_id.to_vec(), destination: Socksaddr::parse("example.com:443") };
        framing(psk).write_first_record(&conn, &request.encode().unwrap()).await.unwrap();
        capture.wire()
    }

    fn service() -> (MultiPskService<usize>, tokio::sync::mpsc::UnboundedReceiver<usize>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (MultiPskService::new(Mode::Default, Arc::new(IdHandler(tx))).unwrap(), rx)
    }

    #[test]
    fn fingerprints_cover_variable_lengths_and_only_ignore_salt() {
        let mut lengths = HashSet::new();
        for i in 0..1000 {
            let profile = Profile::new(format!("unique-user-psk-{i}").as_bytes());
            lengths.insert(profile.salt_block_len);
            let fingerprint = profile.salt_fingerprint();
            assert_eq!(profile.salt_block_len - SALT_LEN, fingerprint.len());
            assert!(fingerprint.len() >= 16);
            let mut block = vec![0; profile.salt_block_len];
            profile.fill_padding(u32::MAX, &mut block);
            for salt in [[0; SALT_LEN], [255; SALT_LEN], [42; SALT_LEN]] {
                profile.write_salt_block(&salt, &mut block);
                assert_eq!(salt, profile.extract_salt(&block));
                assert!(fingerprint.iter().all(|&(i, byte)| block[i] == byte));
            }
            block[fingerprint[0].0] ^= 1;
            assert!(!fingerprint.iter().all(|&(i, byte)| block[i] == byte));
        }
        assert!(lengths.len() > 60, "lengths must not be quantized to 16 bytes");
    }

    #[tokio::test]
    async fn identifies_users_with_empty_or_forged_client_id_and_fragmented_hellos() {
        let (service, mut ids) = service();
        let psks: Vec<_> = (0..1000).map(|i| format!("unique-user-psk-{i}").into_bytes()).collect();
        service.update_users((0..1000).collect(), psks.clone()).unwrap();
        for (i, psk) in psks.iter().enumerate().step_by(31) {
            for max_read in [1, 7, 16, 144] {
                let input = Arc::new(Input::new(hello(psk, COMMAND_CONNECT, b"another-user").await, max_read));
                service.new_connection(Context::new(), input, Socksaddr::default(), None).await.unwrap();
                assert_eq!(Some(i), ids.recv().await);
            }
        }
        let input = Arc::new(Input::new(hello(&psks[0], COMMAND_CONNECT, b"").await, 144));
        service.new_connection(Context::new(), input, Socksaddr::default(), None).await.unwrap();
        assert_eq!(Some(0), ids.recv().await);
    }

    #[tokio::test]
    async fn replay_rejected_across_updates_and_invalid_aead_does_not_poison_cache() {
        let (service, mut ids) = service();
        let psk = b"alice-unique-psk".to_vec();
        service.update_users(vec![1], vec![psk.clone()]).unwrap();
        let wire = hello(&psk, COMMAND_CONNECT, b"").await;
        let mut corrupt = wire.clone();
        corrupt[Profile::new(&psk).salt_block_len + Profile::new(&psk).record_prefix_len(0)] ^= 1;
        let source = Socksaddr::default();
        let serve =
            |bytes| service.new_connection(Context::new(), Arc::new(Input::new(bytes, 144)), source.clone(), None);
        assert!(serve(corrupt).await.is_err());
        assert!(ids.try_recv().is_err());
        serve(wire.clone()).await.unwrap();
        assert_eq!(Some(1), ids.recv().await);
        service.update_users(vec![1], vec![psk.clone()]).unwrap();
        assert!(serve(wire).await.is_err());
        assert!(ids.try_recv().is_err());
        // Failed replacement must leave the current credential snapshot usable.
        assert!(service.update_users(vec![2, 3], vec![psk.clone(), psk.clone()]).is_err());
        serve(hello(&psk, COMMAND_CONNECT, b"").await).await.unwrap();
        assert_eq!(Some(1), ids.recv().await);
    }

    #[tokio::test]
    async fn unknown_truncated_and_tampered_fingerprints_are_rejected() {
        let (service, mut ids) = service();
        let psk = b"alice-unique-psk".to_vec();
        service.update_users(vec![1], vec![psk.clone()]).unwrap();
        let wire = hello(&psk, COMMAND_CONNECT, b"").await;
        let mut corrupt = wire.clone();
        corrupt[Profile::new(&psk).salt_fingerprint()[0].0] ^= 1;
        for bytes in [hello(b"unknown-user-psk", COMMAND_CONNECT, b"").await, wire[..31].to_vec(), corrupt] {
            let result = service
                .new_connection(Context::new(), Arc::new(Input::new(bytes, 144)), Socksaddr::default(), None)
                .await;
            assert!(result.is_err());
        }
        assert!(ids.try_recv().is_err());
        service.update_users(vec![], vec![]).unwrap();
        assert!(
            service
                .new_connection(Context::new(), Arc::new(Input::new(wire, 144)), Socksaddr::default(), None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn ping_uses_selected_psk_for_response() {
        let (service, _) = service();
        let psk = b"alice-unique-psk".to_vec();
        service.update_users(vec![1], vec![psk.clone()]).unwrap();
        let input = Arc::new(Input::new(hello(&psk, COMMAND_PING, b"").await, 1));
        service.new_connection(Context::new(), input.clone(), Socksaddr::default(), None).await.unwrap();
        let response: Arc<dyn Conn> = Arc::new(Input::new(input.output.wire(), 3));
        let (_, record) = framing(&psk).read_first_record(&response, ReadWaitOptions::default()).await.unwrap();
        assert_eq!(&[REPLY_PONG], record.bytes());
    }

    #[test]
    fn validates_mode_lengths_and_counts() {
        let (tx, _) = tokio::sync::mpsc::unbounded_channel();
        for mode in [Mode::Unshaped, Mode::UnsafeRaw] {
            assert!(MultiPskService::<usize>::new(mode, Arc::new(IdHandler(tx.clone()))).is_err());
        }
        let (service, _) = service();
        for len in [0, 11, 256] {
            assert!(service.update_users(vec![1], vec![vec![b'a'; len]]).is_err());
        }
        for len in [12, 255] {
            service.update_users(vec![1], vec![vec![b'a'; len]]).unwrap();
        }
        assert!(service.update_users(vec![1], vec![]).is_err());
    }

    #[tokio::test]
    async fn detection_reads_32_then_16_and_returns_overread_bytes_to_the_reader() {
        let (service, mut ids) = service();
        let psk = (0..1000)
            .map(|i| format!("step-read-user-psk-{i}").into_bytes())
            .find(|psk| !Profile::new(psk).salt_block_len.is_multiple_of(READ_STEP))
            .unwrap();
        let block_len = Profile::new(&psk).salt_block_len;
        service.update_users(vec![1], vec![psk.clone()]).unwrap();
        let input = Arc::new(Input::new(hello(&psk, COMMAND_CONNECT, b"").await, MAX_BLOCK));
        service.new_connection(Context::new(), input.clone(), Socksaddr::default(), None).await.unwrap();
        // Successful AEAD verification and decoding prove the bytes consumed
        // beyond this non-aligned block were returned in the correct order.
        assert_eq!(Some(1), ids.recv().await);
        let steps = (block_len - MIN_BLOCK).div_ceil(READ_STEP);
        let requests = input.requests.lock().unwrap();
        assert_eq!(MIN_BLOCK, requests[0]);
        assert!(requests[1..=steps].iter().all(|&size| size == READ_STEP));
    }

    /// Run explicitly with --release --ignored --nocapture. Timings are local
    /// measurements, never correctness thresholds or protocol guarantees.
    #[test]
    #[ignore = "manual release performance measurement"]
    fn benchmark_1000_user_psk_selection() {
        use std::hint::black_box;

        let (service, _) = service();
        let psks: Vec<_> = (0..1000).map(|i| format!("benchmark-user-psk-{i}").into_bytes()).collect();
        let start = Instant::now();
        service.update_users((0..psks.len()).collect(), psks.clone()).unwrap();
        eprintln!("1000 profile/fingerprint registrations: {:.3} ms", start.elapsed().as_secs_f64() * 1000.0);

        let users = service.users.read().unwrap().clone();
        let noise = [0xa5; MAX_BLOCK];
        let mut checked = MIN_BLOCK;
        assert!(users.identify(&noise, &mut checked).is_none());
        let start = Instant::now();
        const SCANS: usize = 10_000;
        for _ in 0..SCANS {
            let mut checked = MIN_BLOCK;
            black_box(users.identify(black_box(&noise), &mut checked));
        }
        eprintln!("1000-user full fingerprint scan: {:.3} us", start.elapsed().as_secs_f64() * 1e6 / SCANS as f64);

        let start = Instant::now();
        const DERIVATIONS: usize = 1000;
        for _ in 0..DERIVATIONS {
            black_box(crate::crypto::derive_key(black_box(&psks[0]), black_box(&[42; SALT_LEN])));
        }
        eprintln!("single Argon2id derivation: {:.3} us", start.elapsed().as_secs_f64() * 1e6 / DERIVATIONS as f64);
    }

    /// Supply a reassembled client-to-server TCP stream and an exact-byte PSK
    /// file. This verifies an external hello without forwarding any traffic.
    #[tokio::test]
    #[ignore = "requires a real Surge capture and its private PSK file"]
    async fn verify_external_surge_hello() {
        let capture_path = std::env::var_os("SNELL_CAPTURE_FILE").expect("set SNELL_CAPTURE_FILE");
        let psk_path = std::env::var_os("SNELL_PSK_FILE").expect("set SNELL_PSK_FILE");
        let wire = std::fs::read(capture_path).expect("read reassembled raw TCP payload");
        let psk = std::fs::read(psk_path).expect("read exact PSK bytes (no trailing newline)");
        assert!((12..=255).contains(&psk.len()), "PSK must be 12..=255 bytes");
        let profile = Arc::new(Profile::new(&psk));
        let block_len = profile.salt_block_len;
        assert!(wire.len() >= block_len, "capture is shorter than its salt block");
        assert!(profile.salt_fingerprint().iter().all(|&(i, byte)| wire[i] == byte), "salt fingerprint mismatch");
        let salt = profile.extract_salt(&wire[..block_len]);
        let input: Arc<dyn Conn> = Arc::new(Input::new(wire[block_len..].to_vec(), MAX_BLOCK));
        let reader = new_shaped_reader_with_salt(input, psk.into(), profile, &salt).unwrap();
        let mut record = reader.read_record().await.expect("verify first AEAD record");
        assert_eq!(record.bytes().get(2), Some(&0), "capture unexpectedly declares a client_id");
        let request = crate::request::read_server_request(&mut record).expect("decode authenticated Snell request");
        assert!(
            matches!(request.command, COMMAND_CONNECT | crate::COMMAND_CONNECT_V2 | crate::COMMAND_UDP),
            "capture an actual relay request rather than a latency probe"
        );
        eprintln!("verified external hello: mode=default, salt_block={block_len} bytes, client_id=empty");
    }

    #[test]
    fn replay_cache_namespaces_users_and_rotates_at_a_bounded_size() {
        let mut cache = ReplayCache::default();
        cache.check_and_add(b"alice-unique-psk", &[42; SALT_LEN]).unwrap();
        cache.check_and_add(b"bob-unique-psk", &[42; SALT_LEN]).unwrap();
        assert!(cache.check_and_add(b"alice-unique-psk", &[42; SALT_LEN]).is_err());
        // Fill with unique already-digested keys to exercise the real boundary.
        for i in 0u64..REPLAY_GENERATION as u64 {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&i.to_le_bytes());
            cache.current.insert(key);
        }
        cache.check_and_add(b"alice-unique-psk", &[43; SALT_LEN]).unwrap();
        assert!(cache.current.len() <= REPLAY_GENERATION);
        assert!(cache.check_and_add(b"alice-unique-psk", &[42; SALT_LEN]).is_err());
    }
}
