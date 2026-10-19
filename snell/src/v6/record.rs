//! v6 unshaped and unsafe-raw records.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::MAX_PAYLOAD;
use crate::buf::Buffer;
use crate::crypto::{Aead, Nonce, increase_nonce};
use crate::error::{self, ErrorCode};
use crate::net::{self, Conn, ReadWaitOptions};
use crate::reuse::{BaseReader, RecordSource, RecordWriter};
use crate::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, HEADER_VERSION};

/// Surge 6.7.0 (11520): FUN_100015c54/FUN_1000156e0: non-default records require zero padding length.
fn err_record_padding() -> io::Error {
    error::new_error("snell: unexpected padding in non-default record")
}

pub(crate) fn parse_header(header: &[u8]) -> io::Result<(usize, usize)> {
    if header[0] != HEADER_VERSION {
        return Err(error::extend_code(ErrorCode::BadVersion, header[0]));
    }
    if header[1] != 0 || header[2] != 0 {
        return Err(ErrorCode::ReservedNonZero.into());
    }
    Ok((u16::from_be_bytes([header[3], header[4]]) as usize, u16::from_be_bytes([header[5], header[6]]) as usize))
}

pub(crate) fn put_header(header: &mut [u8], padding_len: usize, payload_len: usize) {
    header[0] = HEADER_VERSION;
    header[1] = 0;
    header[2] = 0;
    header[3..5].copy_from_slice(&(padding_len as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
}

pub(crate) fn validate_packet_vector_buffers(buffers: &[Buffer]) -> io::Result<()> {
    if buffers.iter().any(|buffer| buffer.len() > MAX_PAYLOAD) {
        return Err(ErrorCode::PayloadTooLarge.into());
    }
    Ok(())
}

pub(crate) type UnshapedReader = BaseReader<UnshapedSource>;

pub(crate) fn new_unshaped_reader(upstream: Arc<dyn Conn>, aead: Aead, nonce: Nonce) -> UnshapedReader {
    BaseReader::new(UnshapedSource { upstream, state: Mutex::new(UnshapedState { cipher: aead, nonce }) })
}

pub(crate) struct UnshapedState {
    cipher: Aead,
    nonce: Nonce,
}

pub(crate) struct UnshapedSource {
    upstream: Arc<dyn Conn>,
    state: Mutex<UnshapedState>,
}

#[async_trait]
impl RecordSource for UnshapedSource {
    async fn read_record(&self, options: ReadWaitOptions) -> io::Result<Buffer> {
        let upstream = self.upstream.as_ref();
        let mut guard = self.state.lock().await;
        let state = &mut *guard;
        let mut header = [0u8; HEADER_CIPHER_LEN];
        net::read_full(upstream, &mut header).await?;
        state
            .cipher
            .open_in_place(&state.nonce, &[], &mut header)
            .map_err(|err| error::cause(err, "open record header"))?;
        increase_nonce(&mut state.nonce);
        let (padding_len, payload_len) = parse_header(&header[..HEADER_PLAIN_LEN])?;
        if padding_len != 0 {
            return Err(err_record_padding());
        }
        if payload_len == 0 {
            return Err(error::eof());
        }
        let mut body = options.new_buffer_size(payload_len + AEAD_TAG_LEN);
        net::read_full(upstream, body.extend(payload_len + AEAD_TAG_LEN)).await?;
        state
            .cipher
            .open_in_place(&state.nonce, &[], body.bytes_mut())
            .map_err(|err| error::cause(err, "open record payload"))?;
        increase_nonce(&mut state.nonce);
        body.truncate(payload_len);
        options.post_return(&mut body);
        Ok(body)
    }
}

pub(crate) struct UnshapedWriter {
    upstream: Arc<dyn Conn>,
    state: Mutex<UnshapedState>,
}

impl UnshapedState {
    pub(crate) fn seal_header(&mut self, header: &mut [u8], payload_len: usize) {
        put_header(header, 0, payload_len);
        self.cipher.seal_in_place(&self.nonce, &[], &mut header[..HEADER_CIPHER_LEN]);
        increase_nonce(&mut self.nonce);
    }

    fn seal_payload(&mut self, payload_cipher: &mut [u8]) {
        self.cipher.seal_in_place(&self.nonce, &[], payload_cipher);
        increase_nonce(&mut self.nonce);
    }

    fn make_slice_record(&mut self, payload: &[u8]) -> Buffer {
        let mut record = Buffer::with_capacity(HEADER_CIPHER_LEN + payload.len() + AEAD_TAG_LEN);
        self.seal_header(record.extend(HEADER_CIPHER_LEN), payload.len());
        let payload_cipher = record.extend(payload.len() + AEAD_TAG_LEN);
        payload_cipher[..payload.len()].copy_from_slice(payload);
        self.seal_payload(payload_cipher);
        record
    }

    fn make_buffer_record(&mut self, mut buffer: Buffer) -> Buffer {
        let data_len = buffer.len();
        buffer.extend_header(HEADER_CIPHER_LEN);
        buffer.extend(AEAD_TAG_LEN);
        let (header, payload_cipher) = buffer.bytes_mut().split_at_mut(HEADER_CIPHER_LEN);
        self.seal_header(header, data_len);
        self.seal_payload(payload_cipher);
        buffer
    }
}

impl UnshapedWriter {
    pub(crate) fn new(upstream: Arc<dyn Conn>, aead: Aead, nonce: Nonce) -> Self {
        UnshapedWriter { upstream, state: Mutex::new(UnshapedState { cipher: aead, nonce }) }
    }

    /// Seals the first record header right behind the salt in `out`.
    pub(crate) async fn with_state<T>(&self, f: impl FnOnce(&mut UnshapedState) -> T) -> T {
        let mut state = self.state.lock().await;
        f(&mut state)
    }

    pub(crate) fn seal_first_records(&self, state: &mut UnshapedState, out: &mut Buffer, payload: &[u8]) {
        // Surge 6.7.0 (11520): FUN_10001596c: emits the salt once, then splits the first
        // unshaped payload into 0xffff-byte records.
        let mut remaining = payload;
        loop {
            let record_len = remaining.len().min(MAX_PAYLOAD);
            state.seal_header(out.extend(HEADER_CIPHER_LEN), record_len);
            if record_len > 0 {
                let payload_cipher = out.extend(record_len + AEAD_TAG_LEN);
                payload_cipher[..record_len].copy_from_slice(&remaining[..record_len]);
                state.seal_payload(payload_cipher);
                remaining = &remaining[record_len..];
                if !remaining.is_empty() {
                    continue;
                }
            }
            break;
        }
    }

    pub(crate) fn seal_first_buffer(&self, state: &mut UnshapedState, buffer: &mut Buffer, salt: &[u8]) {
        let data_len = buffer.len();
        buffer.extend_header(salt.len() + HEADER_CIPHER_LEN);
        buffer.extend(AEAD_TAG_LEN);
        let (front, payload_cipher) = buffer.bytes_mut().split_at_mut(salt.len() + HEADER_CIPHER_LEN);
        front[..salt.len()].copy_from_slice(salt);
        state.seal_header(&mut front[salt.len()..], data_len);
        state.seal_payload(payload_cipher);
    }
}

#[async_trait]
impl RecordWriter for UnshapedWriter {
    async fn write(&self, mut p: &[u8]) -> io::Result<usize> {
        let mut n = 0;
        while !p.is_empty() {
            let data_len = p.len().min(MAX_PAYLOAD);
            let data = &p[..data_len];
            p = &p[data_len..];
            let mut state = self.state.lock().await;
            let record = state.make_slice_record(data);
            let result = self.upstream.write(record.bytes()).await;
            drop(state);
            result?;
            n += data_len;
        }
        Ok(n)
    }

    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let data_len = buffer.len();
        if data_len == 0 {
            return Ok(());
        }
        if data_len > MAX_PAYLOAD {
            return self.write(buffer.bytes()).await.map(|_| ());
        }
        let mut state = self.state.lock().await;
        let record = state.make_buffer_record(buffer);
        self.upstream.write(record.bytes()).await.map(|_| ())
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        let mut state = self.state.lock().await;
        let mut records = Vec::new();
        for buffer in buffers {
            let data_len = buffer.len();
            if data_len == 0 {
                continue;
            }
            if data_len <= MAX_PAYLOAD {
                records.push(state.make_buffer_record(buffer));
                continue;
            }
            for chunk in buffer.bytes().chunks(MAX_PAYLOAD) {
                records.push(state.make_slice_record(chunk));
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
            records.push(state.make_buffer_record(buffer));
        }
        if records.is_empty() {
            return Ok(());
        }
        self.upstream.write_vectorised(records).await
    }

    async fn write_packet_buffer(&self, buffer: Buffer) -> io::Result<()> {
        if buffer.len() > MAX_PAYLOAD {
            return Err(ErrorCode::PayloadTooLarge.into());
        }
        self.write_buffer(buffer).await
    }

    async fn write_zero_chunk(&self) -> io::Result<()> {
        let mut buffer = Buffer::with_capacity(HEADER_CIPHER_LEN);
        let mut state = self.state.lock().await;
        state.seal_header(buffer.extend(HEADER_CIPHER_LEN), 0);
        self.upstream.write(buffer.bytes()).await.map(|_| ())
    }

    fn front_headroom(&self) -> usize {
        HEADER_CIPHER_LEN
    }

    fn rear_headroom(&self) -> usize {
        AEAD_TAG_LEN
    }

    fn writer_mtu(&self) -> usize {
        MAX_PAYLOAD
    }
}

pub(crate) type RawReader = BaseReader<RawSource>;

pub(crate) fn new_raw_reader(upstream: Arc<dyn Conn>) -> RawReader {
    BaseReader::new(RawSource { upstream, access: Mutex::new(()) })
}

pub(crate) struct RawSource {
    upstream: Arc<dyn Conn>,
    access: Mutex<()>,
}

#[async_trait]
impl RecordSource for RawSource {
    async fn read_record(&self, options: ReadWaitOptions) -> io::Result<Buffer> {
        let upstream = self.upstream.as_ref();
        let _guard = self.access.lock().await;
        let mut header = [0u8; HEADER_PLAIN_LEN];
        net::read_full(upstream, &mut header).await?;
        let (padding_len, payload_len) = parse_header(&header)?;
        if padding_len != 0 {
            return Err(err_record_padding());
        }
        if payload_len == 0 {
            return Err(error::eof());
        }
        let mut body = options.new_buffer_size(payload_len);
        net::read_full(upstream, body.extend(payload_len)).await?;
        options.post_return(&mut body);
        Ok(body)
    }
}

pub(crate) struct RawWriter {
    upstream: Arc<dyn Conn>,
    access: Mutex<()>,
}

fn make_raw_slice_record(payload: &[u8]) -> Buffer {
    let mut record = Buffer::with_capacity(HEADER_PLAIN_LEN + payload.len());
    put_header(record.extend(HEADER_PLAIN_LEN), 0, payload.len());
    record.write_all(payload);
    record
}

fn make_raw_buffer_record(mut buffer: Buffer) -> Buffer {
    let data_len = buffer.len();
    put_header(buffer.extend_header(HEADER_PLAIN_LEN), 0, data_len);
    buffer
}

impl RawWriter {
    pub(crate) fn new(upstream: Arc<dyn Conn>) -> Self {
        RawWriter { upstream, access: Mutex::new(()) }
    }
}

#[async_trait]
impl RecordWriter for RawWriter {
    async fn write(&self, mut p: &[u8]) -> io::Result<usize> {
        let mut n = 0;
        while !p.is_empty() {
            let data_len = p.len().min(MAX_PAYLOAD);
            let record = make_raw_slice_record(&p[..data_len]);
            p = &p[data_len..];
            let guard = self.access.lock().await;
            let result = self.upstream.write(record.bytes()).await;
            drop(guard);
            result?;
            n += data_len;
        }
        Ok(n)
    }

    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let data_len = buffer.len();
        if data_len == 0 {
            return Ok(());
        }
        if data_len > MAX_PAYLOAD {
            return self.write(buffer.bytes()).await.map(|_| ());
        }
        let _guard = self.access.lock().await;
        let record = make_raw_buffer_record(buffer);
        self.upstream.write(record.bytes()).await.map(|_| ())
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        let _guard = self.access.lock().await;
        let mut records = Vec::new();
        for buffer in buffers {
            let data_len = buffer.len();
            if data_len == 0 {
                continue;
            }
            if data_len <= MAX_PAYLOAD {
                records.push(make_raw_buffer_record(buffer));
                continue;
            }
            for chunk in buffer.bytes().chunks(MAX_PAYLOAD) {
                records.push(make_raw_slice_record(chunk));
            }
        }
        if records.is_empty() {
            return Ok(());
        }
        self.upstream.write_vectorised(records).await
    }

    async fn write_packet_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        validate_packet_vector_buffers(&buffers)?;
        let _guard = self.access.lock().await;
        let records: Vec<Buffer> =
            buffers.into_iter().filter(|buffer| !buffer.is_empty()).map(make_raw_buffer_record).collect();
        if records.is_empty() {
            return Ok(());
        }
        self.upstream.write_vectorised(records).await
    }

    async fn write_packet_buffer(&self, buffer: Buffer) -> io::Result<()> {
        if buffer.len() > MAX_PAYLOAD {
            return Err(ErrorCode::PayloadTooLarge.into());
        }
        self.write_buffer(buffer).await
    }

    async fn write_zero_chunk(&self) -> io::Result<()> {
        let mut buffer = Buffer::with_capacity(HEADER_PLAIN_LEN);
        put_header(buffer.extend(HEADER_PLAIN_LEN), 0, 0);
        let _guard = self.access.lock().await;
        self.upstream.write(buffer.bytes()).await.map(|_| ())
    }

    fn front_headroom(&self) -> usize {
        HEADER_PLAIN_LEN
    }

    fn rear_headroom(&self) -> usize {
        0
    }

    fn writer_mtu(&self) -> usize {
        MAX_PAYLOAD
    }
}
