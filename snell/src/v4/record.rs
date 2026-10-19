use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use rand::{Rng, RngExt};
use tokio::sync::Mutex;

use super::{
    FIRST_RECORD_OVERHEAD, FRAME_PAYLOAD_RESET_INTERVAL, FRAME_SIZE, INITIAL_PADDING_MIN, INITIAL_PADDING_SPAN,
    MAX_INITIAL_PADDING_LEN, MAX_PAYLOAD, RESET_RECORD_OVERHEAD,
};
use crate::buf::Buffer;
use crate::bufio::BufReader;
use crate::crypto::{Aead, Nonce, derive_key, increase_nonce};
use crate::error::{self, ErrorCode};
use crate::net::{Conn, ReadWaitOptions, unix_now};
use crate::padding::{TargetFormula, fill_padding, swap_even};
use crate::reuse::{BaseReader, RecordSource, RecordWriter};
use crate::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, HEADER_VERSION, NONCE_LEN, SALT_LEN};

pub(crate) type Reader = BaseReader<Source>;

pub(crate) fn new_reader(upstream: Arc<dyn Conn>, psk: Arc<[u8]>) -> Reader {
    BaseReader::new(Source {
        upstream,
        psk,
        state: Mutex::new(SourceState { buffered: BufReader::new(), cipher: None, nonce: [0; NONCE_LEN] }),
    })
}

struct SourceState {
    buffered: BufReader,
    cipher: Option<Aead>,
    nonce: Nonce,
}

pub(crate) struct Source {
    upstream: Arc<dyn Conn>,
    psk: Arc<[u8]>,
    state: Mutex<SourceState>,
}

#[async_trait]
impl RecordSource for Source {
    async fn read_record(&self, options: ReadWaitOptions) -> io::Result<Buffer> {
        let upstream = self.upstream.as_ref();
        let mut guard = self.state.lock().await;
        let state = &mut *guard;
        if state.cipher.is_none() {
            let mut salt = [0u8; SALT_LEN];
            state.buffered.read_full(upstream, &mut salt).await?;
            state.cipher = Some(Aead::new(&derive_key(&self.psk, &salt))?);
            state.nonce = [0; NONCE_LEN];
        }
        let cipher = state.cipher.as_ref().unwrap();
        let mut header = [0u8; HEADER_CIPHER_LEN];
        state.buffered.read_full(upstream, &mut header).await?;
        cipher.open_in_place(&state.nonce, &[], &mut header).map_err(|err| error::cause(err, "open record header"))?;
        increase_nonce(&mut state.nonce);
        if header[0] != HEADER_VERSION {
            return Err(error::extend_code(ErrorCode::BadVersion, header[0]));
        }
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;

        if payload_len == 0 {
            // Surge 6.7.0 (11520): SNConnectorEngineAdapterV4::decryptData:outData:
            // returns "ZERO CHUNK with remaining data." when the EOF record leaves
            // bytes in the internal decrypt input buffer.
            if state.buffered.buffered() > 0 {
                return Err(error::new_error("snell: zero chunk has trailing data"));
            }
            return Err(error::eof());
        }

        let mut padding = vec![0u8; padding_len];
        if padding_len > 0 {
            state.buffered.read_full(upstream, &mut padding).await?;
        }
        let mut body = options.new_buffer_size(payload_len + AEAD_TAG_LEN);
        state.buffered.read_full(upstream, body.extend(payload_len + AEAD_TAG_LEN)).await?;
        if padding_len > 0 {
            swap_even(&mut padding, body.bytes_mut());
        }
        cipher
            .open_in_place(&state.nonce, &[], body.bytes_mut())
            .map_err(|err| error::cause(err, "open record payload"))?;
        increase_nonce(&mut state.nonce);
        body.truncate(payload_len);
        options.post_return(&mut body);
        Ok(body)
    }
}

struct WriterState {
    cipher: Option<Aead>,
    nonce: Nonce,
    salt: [u8; SALT_LEN],
    salt_sent: bool,
    initial_padding_len: usize,
    payload_limit: usize,
    last_write_unix: i64,
}

pub(crate) struct Writer {
    upstream: Arc<dyn Conn>,
    psk: Arc<[u8]>,
    state: Mutex<WriterState>,
    salt_sent: AtomicBool,
}

fn check_payload_limit(payload_limit: usize) {
    assert!(payload_limit > 0 && payload_limit <= MAX_PAYLOAD, "snell: invalid v4 payload limit");
}

fn seal_header(cipher: &Aead, nonce: &mut Nonce, header: &mut [u8], padding_len: usize, payload_len: usize) {
    header[0] = HEADER_VERSION;
    header[1] = 0;
    header[2] = 0;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    cipher.seal_in_place(nonce, &[], &mut header[..HEADER_CIPHER_LEN]);
    increase_nonce(nonce);
}

impl Writer {
    pub(crate) fn new(upstream: Arc<dyn Conn>, psk: Arc<[u8]>) -> Self {
        Writer {
            upstream,
            psk,
            state: Mutex::new(WriterState {
                cipher: None,
                nonce: [0; NONCE_LEN],
                salt: [0; SALT_LEN],
                salt_sent: false,
                initial_padding_len: 0,
                payload_limit: 0,
                last_write_unix: 0,
            }),
            salt_sent: AtomicBool::new(false),
        }
    }

    fn initialize(&self, state: &mut WriterState) -> io::Result<()> {
        if state.cipher.is_some() {
            return Ok(());
        }
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let aead = Aead::new(&derive_key(&self.psk, &salt))?;
        let padding_delta = rand::rng().random_range(0..INITIAL_PADDING_SPAN);
        state.cipher = Some(aead);
        state.nonce = [0; NONCE_LEN];
        state.salt = salt;
        state.initial_padding_len = INITIAL_PADDING_MIN + padding_delta;
        Ok(())
    }

    /// Fixes the random initial padding length, for the wire-shape tests.
    #[cfg(test)]
    pub(crate) async fn force_initial_padding_len(&self, len: usize) {
        let mut state = self.state.lock().await;
        self.initialize(&mut state).unwrap();
        state.initial_padding_len = len;
    }

    fn payload_limit_for(state: &WriterState, now_unix: i64) -> usize {
        if !state.salt_sent {
            return FRAME_SIZE - FIRST_RECORD_OVERHEAD - state.initial_padding_len;
        }
        if state.last_write_unix != 0 && now_unix - state.last_write_unix < FRAME_PAYLOAD_RESET_INTERVAL {
            if state.payload_limit > 0 {
                return state.payload_limit;
            }
            return FRAME_SIZE - RESET_RECORD_OVERHEAD;
        }
        FRAME_SIZE - RESET_RECORD_OVERHEAD
    }

    fn advance_payload_limit(state: &mut WriterState, payload_limit: usize, now_unix: i64) {
        state.last_write_unix = now_unix;
        if payload_limit < MAX_PAYLOAD {
            let next_payload_limit = payload_limit + FRAME_SIZE - RESET_RECORD_OVERHEAD;
            state.payload_limit = next_payload_limit.min(MAX_PAYLOAD);
        } else {
            state.payload_limit = MAX_PAYLOAD;
        }
    }

    fn frame_padding_len(state: &WriterState, payload_len: usize) -> usize {
        if state.salt_sent || payload_len == 0 {
            return 0;
        }
        state.initial_padding_len
    }

    /// Takes the next payload limit and advances the growth window.
    fn next_payload_limit(&self, state: &mut WriterState) -> io::Result<usize> {
        self.initialize(state)?;
        let now_unix = unix_now();
        let payload_limit = Self::payload_limit_for(state, now_unix);
        check_payload_limit(payload_limit);
        Self::advance_payload_limit(state, payload_limit, now_unix);
        Ok(payload_limit)
    }

    async fn write_bytes_locked(&self, state: &mut WriterState, mut p: &[u8]) -> io::Result<usize> {
        // Surge 6.7.0 (11520): SNConnectorEngineAdapterV4::encryptData:outData: updates the next payload limit once for
        // each encryptData call, then splits that call using the same limit.
        let payload_limit = self.next_payload_limit(state)?;
        let mut n = 0;
        while !p.is_empty() {
            let data_len = p.len().min(payload_limit);
            let padding_len = Self::frame_padding_len(state, data_len);
            let record = self.make_slice_record_locked(state, &p[..data_len], padding_len)?;
            self.write_record(record).await?;
            n += data_len;
            p = &p[data_len..];
        }
        Ok(n)
    }

    fn mark_salt_sent(&self, state: &mut WriterState) {
        state.salt_sent = true;
        self.salt_sent.store(true, Ordering::SeqCst);
    }

    fn make_slice_record_locked(
        &self,
        state: &mut WriterState,
        payload: &[u8],
        padding_len: usize,
    ) -> io::Result<Buffer> {
        self.initialize(state)?;
        assert!(payload.len() <= MAX_PAYLOAD && padding_len <= MAX_PAYLOAD, "snell: v4 record exceeds maximum");
        assert!(!payload.is_empty() || padding_len == 0, "snell: zero-length v4 record carries padding");
        let salt_len = if state.salt_sent { 0 } else { SALT_LEN };
        let payload_cipher_len = if payload.is_empty() { 0 } else { payload.len() + AEAD_TAG_LEN };
        let mut out = Buffer::with_capacity(salt_len + HEADER_CIPHER_LEN + padding_len + payload_cipher_len);
        if salt_len > 0 {
            out.write_all(&state.salt);
            self.mark_salt_sent(state);
        }
        let cipher = state.cipher.as_ref().unwrap();
        seal_header(cipher, &mut state.nonce, out.extend(HEADER_CIPHER_LEN), padding_len, payload.len());
        out.extend(padding_len);
        if !payload.is_empty() {
            let payload_cipher = out.extend(payload_cipher_len);
            payload_cipher[..payload.len()].copy_from_slice(payload);
            cipher.seal_in_place(&state.nonce, &[], payload_cipher);
            increase_nonce(&mut state.nonce);
            if padding_len > 0 {
                let front_len = salt_len + HEADER_CIPHER_LEN;
                let (front, payload_cipher) = out.bytes_mut().split_at_mut(front_len + padding_len);
                let padding = &mut front[front_len..];
                fill_padding(padding, payload_cipher, TargetFormula::V4);
                swap_even(padding, payload_cipher);
            }
        }
        Ok(out)
    }

    fn make_buffer_record_locked(
        &self,
        state: &mut WriterState,
        mut buffer: Buffer,
        padding_len: usize,
    ) -> io::Result<Buffer> {
        self.initialize(state)?;
        let data_len = buffer.len();
        assert!(data_len <= MAX_PAYLOAD && padding_len <= MAX_PAYLOAD, "snell: v4 record exceeds maximum");
        assert!(data_len > 0 || padding_len == 0, "snell: zero-length v4 record carries padding");
        let salt_len = if state.salt_sent { 0 } else { SALT_LEN };
        let front_len = salt_len + HEADER_CIPHER_LEN + padding_len;
        buffer.extend_header(front_len);
        if data_len > 0 {
            buffer.extend(AEAD_TAG_LEN);
        }
        let salt = state.salt;
        if salt_len > 0 {
            self.mark_salt_sent(state);
        }
        let cipher = state.cipher.as_ref().unwrap();
        let (prefix, payload_cipher) = buffer.bytes_mut().split_at_mut(front_len);
        if salt_len > 0 {
            prefix[..SALT_LEN].copy_from_slice(&salt);
        }
        seal_header(
            cipher,
            &mut state.nonce,
            &mut prefix[salt_len..salt_len + HEADER_CIPHER_LEN],
            padding_len,
            data_len,
        );
        if data_len > 0 {
            cipher.seal_in_place(&state.nonce, &[], payload_cipher);
            increase_nonce(&mut state.nonce);
            if padding_len > 0 {
                let padding = &mut prefix[salt_len + HEADER_CIPHER_LEN..];
                fill_padding(padding, payload_cipher, TargetFormula::V4);
                swap_even(padding, payload_cipher);
            }
        }
        Ok(buffer)
    }

    async fn write_record(&self, record: Buffer) -> io::Result<()> {
        self.upstream.write(record.bytes()).await.map(|_| ())
    }

    async fn write_zero_chunk_locked(&self, state: &mut WriterState) -> io::Result<()> {
        // Surge 6.7.0 (11520): FUN_100012944 advances the growth window before
        // calling FUN_100012b24 even when encrypting a zero-length EOF record.
        self.next_payload_limit(state)?;
        let record = self.make_slice_record_locked(state, &[], 0)?;
        self.write_record(record).await
    }
}

#[async_trait]
impl RecordWriter for Writer {
    async fn write(&self, p: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().await;
        if p.is_empty() {
            self.write_zero_chunk_locked(&mut state).await?;
            return Ok(0);
        }
        self.write_bytes_locked(&mut state, p).await
    }

    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let data_len = buffer.len();
        if data_len == 0 {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        self.initialize(&mut state)?;
        let now_unix = unix_now();
        let payload_limit = Self::payload_limit_for(&state, now_unix);
        check_payload_limit(payload_limit);
        if data_len > payload_limit {
            self.write_bytes_locked(&mut state, buffer.bytes()).await?;
            return Ok(());
        }
        Self::advance_payload_limit(&mut state, payload_limit, now_unix);
        let padding_len = Self::frame_padding_len(&state, data_len);
        let record = self.make_buffer_record_locked(&mut state, buffer, padding_len)?;
        self.write_record(record).await
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        let mut state = self.state.lock().await;
        let mut records = Vec::new();
        let mut payload_limit = 0;
        for buffer in buffers {
            if buffer.is_empty() {
                continue;
            }
            if payload_limit == 0 {
                // Surge 6.7.0 (11520): SNConnectorEngineAdapterV4::encryptData:outData: advances the growth window once per
                // call; a vectorised write is one caller-visible write here.
                payload_limit = self.next_payload_limit(&mut state)?;
            }
            let data_len = buffer.len();
            if data_len <= payload_limit {
                let padding_len = Self::frame_padding_len(&state, data_len);
                records.push(self.make_buffer_record_locked(&mut state, buffer, padding_len)?);
                continue;
            }
            let mut data = buffer.bytes();
            while !data.is_empty() {
                let record_len = data.len().min(payload_limit);
                let padding_len = Self::frame_padding_len(&state, record_len);
                records.push(self.make_slice_record_locked(&mut state, &data[..record_len], padding_len)?);
                data = &data[record_len..];
            }
        }
        if records.is_empty() {
            return Ok(());
        }
        self.upstream.write_vectorised(records).await
    }

    async fn write_packet_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        let mut state = self.state.lock().await;
        self.initialize(&mut state)?;
        let mut records = Vec::new();
        for buffer in buffers {
            if buffer.is_empty() {
                continue;
            }
            let now_unix = unix_now();
            let payload_limit = Self::payload_limit_for(&state, now_unix);
            check_payload_limit(payload_limit);
            let data_len = buffer.len();
            if data_len > payload_limit {
                return Err(ErrorCode::PayloadTooLarge.into());
            }
            Self::advance_payload_limit(&mut state, payload_limit, now_unix);
            let padding_len = Self::frame_padding_len(&state, data_len);
            records.push(self.make_buffer_record_locked(&mut state, buffer, padding_len)?);
        }
        if records.is_empty() {
            return Ok(());
        }
        self.upstream.write_vectorised(records).await
    }

    async fn write_packet_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let data_len = buffer.len();
        let mut state = self.state.lock().await;
        self.initialize(&mut state)?;
        let now_unix = unix_now();
        let payload_limit = Self::payload_limit_for(&state, now_unix);
        check_payload_limit(payload_limit);
        if data_len > payload_limit {
            return Err(ErrorCode::PayloadTooLarge.into());
        }
        Self::advance_payload_limit(&mut state, payload_limit, now_unix);
        let padding_len = Self::frame_padding_len(&state, data_len);
        let mut front_headroom = HEADER_CIPHER_LEN + padding_len;
        if !state.salt_sent {
            front_headroom += SALT_LEN;
        }
        let record = if buffer.start() < front_headroom || buffer.free_len() < AEAD_TAG_LEN {
            self.make_slice_record_locked(&mut state, buffer.bytes(), padding_len)?
        } else {
            self.make_buffer_record_locked(&mut state, buffer, padding_len)?
        };
        self.write_record(record).await
    }

    async fn write_zero_chunk(&self) -> io::Result<()> {
        let mut state = self.state.lock().await;
        self.write_zero_chunk_locked(&mut state).await
    }

    fn front_headroom(&self) -> usize {
        if self.salt_sent.load(Ordering::SeqCst) {
            return HEADER_CIPHER_LEN;
        }
        SALT_LEN + HEADER_CIPHER_LEN + MAX_INITIAL_PADDING_LEN
    }

    fn rear_headroom(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn writer_mtu(&self) -> usize {
        MAX_PAYLOAD
    }
}

const _: () = assert!(HEADER_PLAIN_LEN + AEAD_TAG_LEN == HEADER_CIPHER_LEN);
