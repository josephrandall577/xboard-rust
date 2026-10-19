//! v6 default-mode (shaped) records.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::MAX_PAYLOAD;
use super::profile::{Profile, SALT_LEN};
use super::record::{put_header, validate_packet_vector_buffers};
use crate::buf::Buffer;
use crate::crypto::{Aead, Nonce, derive_key, increase_nonce};
use crate::error::{self, ErrorCode};
use crate::net::{self, Conn, ReadWaitOptions, unix_now};
use crate::reuse::{BaseReader, RecordSource, RecordWriter};
use crate::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, HEADER_VERSION, NONCE_LEN};

struct ShapedState {
    cipher: Aead,
    salt: [u8; SALT_LEN],
    nonce: Nonce,
    seq: u32,
    salt_sent: bool,
    chunk_size: i64,
    last_write_unix: i64,
}

pub(crate) struct ShapedWriter {
    upstream: Arc<dyn Conn>,
    profile: Arc<Profile>,
    state: Mutex<ShapedState>,
    salt_sent: AtomicBool,
}

impl ShapedWriter {
    pub(crate) fn new(upstream: Arc<dyn Conn>, profile: Arc<Profile>, salt: [u8; SALT_LEN], aead: Aead) -> Self {
        ShapedWriter {
            upstream,
            profile,
            state: Mutex::new(ShapedState {
                cipher: aead,
                salt,
                nonce: [0; NONCE_LEN],
                seq: 0,
                salt_sent: false,
                chunk_size: 0,
                last_write_unix: 0,
            }),
            salt_sent: AtomicBool::new(false),
        }
    }

    /// Returns the salt block length and its prefix length for the next record.
    fn salt_block(&self, state: &ShapedState) -> (usize, usize) {
        if state.salt_sent {
            (0, 0)
        } else {
            let salt_block_len = self.profile.salt_block_len;
            (salt_block_len, salt_block_len - SALT_LEN)
        }
    }

    fn write_salt_block(&self, state: &mut ShapedState, block: &mut [u8]) {
        // Surge 6.7.0 (11520): FUN_100014610: fills the salt block with shaped padding
        // at sentinel sequence 0xffffffff before overwriting the salt positions.
        self.profile.fill_padding(0xffffffff, block);
        self.profile.write_salt_block(&state.salt, block);
        state.salt_sent = true;
        self.salt_sent.store(true, Ordering::SeqCst);
    }

    /// Fills the prefix, seals the header and the payload, and mixes the padding.
    /// `record` starts at the prefix and holds the plaintext payload at its end.
    fn seal_record(
        &self,
        state: &mut ShapedState,
        record: &mut [u8],
        prefix_len: usize,
        padding_len: usize,
        payload_len: usize,
    ) {
        let profile = &self.profile;
        let seq = state.seq;
        let (prefix, rest) = record.split_at_mut(prefix_len);
        profile.fill_padding(seq, prefix);
        let (header, rest) = rest.split_at_mut(HEADER_CIPHER_LEN);
        put_header(header, padding_len, payload_len);
        state.cipher.seal_in_place(&state.nonce, prefix, header);
        increase_nonce(&mut state.nonce);
        let (padding, region) = rest.split_at_mut(padding_len);
        profile.fill_padding(seq, padding);
        if payload_len > 0 {
            state.cipher.seal_in_place(&state.nonce, padding, region);
            increase_nonce(&mut state.nonce);
            profile.mix_padding_payload(seq, padding, region);
        }
        state.seq = state.seq.wrapping_add(1);
    }

    fn make_slice_record(&self, state: &mut ShapedState, payload: &[u8]) -> Buffer {
        let prefix_len = self.profile.record_prefix_len(state.seq);
        let (salt_block_len, salt_prefix_len) = self.salt_block(state);
        let padding_len =
            self.profile.padding_len(state.seq, payload.len(), prefix_len, salt_prefix_len, salt_block_len);
        let payload_cipher_len = if payload.is_empty() { 0 } else { payload.len() + AEAD_TAG_LEN };
        let mut out =
            Buffer::with_capacity(salt_block_len + prefix_len + HEADER_CIPHER_LEN + padding_len + payload_cipher_len);
        if salt_block_len > 0 {
            self.write_salt_block(state, out.extend(salt_block_len));
        }
        out.extend(prefix_len + HEADER_CIPHER_LEN + padding_len);
        if !payload.is_empty() {
            out.extend(payload_cipher_len)[..payload.len()].copy_from_slice(payload);
        }
        self.seal_record(state, out.from_offset_mut(salt_block_len), prefix_len, padding_len, payload.len());
        out
    }

    fn make_buffer_record(&self, state: &mut ShapedState, mut buffer: Buffer) -> Buffer {
        let data_len = buffer.len();
        let prefix_len = self.profile.record_prefix_len(state.seq);
        let (salt_block_len, salt_prefix_len) = self.salt_block(state);
        let padding_len = self.profile.padding_len(state.seq, data_len, prefix_len, salt_prefix_len, salt_block_len);
        let front_len = salt_block_len + prefix_len + HEADER_CIPHER_LEN + padding_len;
        buffer.extend_header(front_len);
        if data_len > 0 {
            buffer.extend(AEAD_TAG_LEN);
        }
        if salt_block_len > 0 {
            let block = &mut buffer.bytes_mut()[..salt_block_len];
            self.write_salt_block(state, block);
        }
        self.seal_record(state, buffer.from_offset_mut(salt_block_len), prefix_len, padding_len, data_len);
        buffer
    }

    async fn write_records(&self, records: Vec<Buffer>) -> io::Result<()> {
        if records.len() == 1 {
            return self.upstream.write(records[0].bytes()).await.map(|_| ());
        }
        let mut out = Buffer::with_capacity(records.iter().map(Buffer::len).sum());
        for record in &records {
            out.write_all(record.bytes());
        }
        self.upstream.write(out.bytes()).await.map(|_| ())
    }

    fn payload_limit_for(&self, state: &mut ShapedState, now_unix: i64) -> usize {
        let profile = &self.profile;
        // Surge 6.7.0 (11520): FUN_1000142d4/FUN_100014610: v6 writer idle reset is second-granular.
        if state.last_write_unix == 0 || now_unix - state.last_write_unix > profile.idle_reset_sec {
            state.chunk_size = profile.chunk_initial;
        }
        if state.chunk_size == 0 {
            state.chunk_size = profile.chunk_initial;
        }
        let mut payload_limit = profile.chunk_payload_limit(state.seq, state.chunk_size);
        if state.seq == 0 {
            payload_limit = payload_limit.min(profile.first_record_cap);
        }
        state.chunk_size = profile.next_chunk_size(state.chunk_size);
        state.last_write_unix = now_unix;
        payload_limit.min(MAX_PAYLOAD as i64).max(1) as usize
    }

    /// The first record of a connection without payload.
    pub(crate) async fn write_first_empty(&self) -> io::Result<()> {
        let mut state = self.state.lock().await;
        self.payload_limit_for(&mut state, unix_now());
        let record = self.make_slice_record(&mut state, &[]);
        self.upstream.write(record.bytes()).await.map(|_| ())
    }
}

#[async_trait]
impl RecordWriter for ShapedWriter {
    async fn write(&self, mut p: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().await;
        let now_unix = unix_now();
        let original_len = p.len();
        let mut records = Vec::new();
        while !p.is_empty() {
            let payload_limit = self.payload_limit_for(&mut state, now_unix);
            let record_len = p.len().min(payload_limit);
            records.push(self.make_slice_record(&mut state, &p[..record_len]));
            p = &p[record_len..];
        }
        if records.is_empty() {
            return Ok(0);
        }
        self.write_records(records).await?;
        Ok(original_len)
    }

    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let data_len = buffer.len();
        if data_len == 0 {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        let now_unix = unix_now();
        let mut payload_limit = self.payload_limit_for(&mut state, now_unix);
        if data_len <= payload_limit {
            let record = self.make_buffer_record(&mut state, buffer);
            return self.upstream.write(record.bytes()).await.map(|_| ());
        }
        let mut records = Vec::new();
        let mut data = buffer.bytes();
        while !data.is_empty() {
            let record_len = data.len().min(payload_limit);
            records.push(self.make_slice_record(&mut state, &data[..record_len]));
            data = &data[record_len..];
            if !data.is_empty() {
                payload_limit = self.payload_limit_for(&mut state, now_unix);
            }
        }
        self.write_records(records).await
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        let mut state = self.state.lock().await;
        let mut records = Vec::new();
        for buffer in buffers {
            let data_len = buffer.len();
            if data_len == 0 {
                continue;
            }
            let mut offset = 0;
            let mut buffer = Some(buffer);
            while offset < data_len {
                let payload_limit = self.payload_limit_for(&mut state, unix_now());
                let record_len = (data_len - offset).min(payload_limit);
                if offset == 0 && data_len <= payload_limit {
                    records.push(self.make_buffer_record(&mut state, buffer.take().unwrap()));
                    break;
                }
                let data = buffer.as_ref().unwrap().bytes();
                let record = self.make_slice_record(&mut state, &data[offset..offset + record_len]);
                records.push(record);
                offset += record_len;
            }
        }
        if records.is_empty() {
            return Ok(());
        }
        self.upstream.write_vectorised(records).await
    }

    async fn write_packet_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        validate_packet_vector_buffers(&buffers)?;
        let mut state = self.state.lock().await;
        let mut records = Vec::new();
        for buffer in buffers {
            if buffer.is_empty() {
                continue;
            }
            self.payload_limit_for(&mut state, unix_now());
            records.push(self.make_buffer_record(&mut state, buffer));
        }
        if records.is_empty() {
            return Ok(());
        }
        self.upstream.write_vectorised(records).await
    }

    async fn write_packet_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let data_len = buffer.len();
        if data_len == 0 {
            return Ok(());
        }
        if data_len > MAX_PAYLOAD {
            return Err(ErrorCode::PayloadTooLarge.into());
        }
        let mut state = self.state.lock().await;
        // snell-server v6.0.0rc: UDP packet mode still advances the dynamic chunk
        // state, but emits each complete datagram as one record regardless of the
        // current stream chunk limit.
        self.payload_limit_for(&mut state, unix_now());
        let record = self.make_buffer_record(&mut state, buffer);
        self.upstream.write(record.bytes()).await.map(|_| ())
    }

    async fn write_zero_chunk(&self) -> io::Result<()> {
        let mut state = self.state.lock().await;
        self.payload_limit_for(&mut state, unix_now());
        let record = self.make_slice_record(&mut state, &[]);
        self.upstream.write(record.bytes()).await.map(|_| ())
    }

    fn front_headroom(&self) -> usize {
        let mut headroom = self.profile.record_prefix_max + HEADER_CIPHER_LEN + self.profile.pad_max_headroom;
        if !self.salt_sent.load(Ordering::SeqCst) {
            headroom += self.profile.salt_block_len;
        }
        headroom
    }

    fn rear_headroom(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn writer_mtu(&self) -> usize {
        self.profile.chunk_max as usize
    }
}

pub(crate) type ShapedReader = BaseReader<ShapedSource>;

pub(crate) fn new_shaped_reader(upstream: Arc<dyn Conn>, psk: Arc<[u8]>, profile: Arc<Profile>) -> ShapedReader {
    BaseReader::new(ShapedSource {
        upstream,
        psk,
        profile,
        state: Mutex::new(ShapedReaderState { cipher: None, nonce: [0; NONCE_LEN], seq: 0 }),
    })
}

struct ShapedReaderState {
    cipher: Option<Aead>,
    nonce: Nonce,
    seq: u32,
}

pub(crate) struct ShapedSource {
    upstream: Arc<dyn Conn>,
    psk: Arc<[u8]>,
    profile: Arc<Profile>,
    state: Mutex<ShapedReaderState>,
}

#[async_trait]
impl RecordSource for ShapedSource {
    async fn read_record(&self, options: ReadWaitOptions) -> io::Result<Buffer> {
        let upstream = self.upstream.as_ref();
        let profile = &self.profile;
        let mut guard = self.state.lock().await;
        let state = &mut *guard;
        if state.cipher.is_none() {
            let mut block = vec![0u8; profile.salt_block_len];
            net::read_full(upstream, &mut block).await?;
            let salt = profile.extract_salt(&block);
            state.cipher = Some(Aead::new(&derive_key(&self.psk, &salt))?);
        }
        let cipher = state.cipher.as_ref().unwrap();

        let prefix_len = profile.record_prefix_len(state.seq);
        let mut head = vec![0u8; prefix_len + HEADER_CIPHER_LEN];
        net::read_full(upstream, &mut head).await?;
        let (prefix, header) = head.split_at_mut(prefix_len);
        cipher.open_in_place(&state.nonce, prefix, header).map_err(|err| error::cause(err, "open shaped header"))?;
        increase_nonce(&mut state.nonce);
        if header[0] != HEADER_VERSION {
            return Err(error::extend_code(ErrorCode::BadVersion, header[0]));
        }
        // Surge 6.7.0 (11520): FUN_100013abc: default-shaped reader ignores the two reserved header bytes.
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let seq = state.seq;
        state.seq = state.seq.wrapping_add(1);

        if payload_len == 0 {
            if padding_len > 0 {
                let mut discard = vec![0u8; padding_len];
                net::read_full(upstream, &mut discard).await?;
            }
            return Err(error::eof());
        }

        let mut padding = vec![0u8; padding_len];
        if padding_len > 0 {
            net::read_full(upstream, &mut padding).await?;
        }
        let mut body = options.new_buffer_size(payload_len + AEAD_TAG_LEN);
        net::read_full(upstream, body.extend(payload_len + AEAD_TAG_LEN)).await?;
        profile.mix_padding_payload(seq, &mut padding, body.bytes_mut());
        cipher
            .open_in_place(&state.nonce, &padding, body.bytes_mut())
            .map_err(|err| error::cause(err, "open shaped payload"))?;
        increase_nonce(&mut state.nonce);
        body.truncate(payload_len);
        options.post_return(&mut body);
        Ok(body)
    }
}

const _: () = assert!(HEADER_PLAIN_LEN + AEAD_TAG_LEN == HEADER_CIPHER_LEN);
