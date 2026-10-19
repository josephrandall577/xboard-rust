use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use rand::RngExt;
use tokio::sync::Mutex;

use super::{
    FIRST_RECORD_OVERHEAD, FRAME_PAYLOAD_RESET_INTERVAL, FRAME_PAYLOAD_STEP, FRAME_SIZE, INITIAL_PADDING_MIN,
    INITIAL_PADDING_SPAN, MAX_PAYLOAD, STREAM_PAYLOAD_BATCH_SIZE,
};
use crate::buf::Buffer;
use crate::crypto::{Aead, Nonce, increase_nonce};
use crate::error::{self, ErrorCode};
use crate::net::{self, Conn, ReadWaitOptions, unix_now};
use crate::padding::{TargetFormula, fill_padding, swap_even};
use crate::reuse::{BaseReader, RecordSource, RecordWriter};
use crate::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, HEADER_VERSION};

pub(crate) type Reader = BaseReader<Source>;

pub(crate) fn new_reader(upstream: Arc<dyn Conn>, aead: Aead, nonce: Nonce) -> Reader {
    BaseReader::new(Source { upstream, state: Mutex::new(SourceState { cipher: aead, nonce }) })
}

struct SourceState {
    cipher: Aead,
    nonce: Nonce,
}

pub(crate) struct Source {
    upstream: Arc<dyn Conn>,
    state: Mutex<SourceState>,
}

#[async_trait]
impl RecordSource for Source {
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
        if header[0] != HEADER_VERSION {
            return Err(error::extend_code(ErrorCode::BadVersion, header[0]));
        }
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;

        if payload_len == 0 {
            return Err(error::eof());
        }

        let mut padding = vec![0u8; padding_len];
        if padding_len > 0 {
            net::read_full(upstream, &mut padding).await?;
        }
        let mut body = options.new_buffer_size(payload_len + AEAD_TAG_LEN);
        net::read_full(upstream, body.extend(payload_len + AEAD_TAG_LEN)).await?;
        if padding_len > 0 {
            swap_even(&mut padding, body.bytes_mut());
        }
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

struct WriterState {
    cipher: Aead,
    nonce: Nonce,
    last_frame_unix: i64,
    frame_payload_len: usize,
    stream_payload_len: usize,
    stream_payload_left: usize,
}

pub(crate) struct Writer {
    upstream: Arc<dyn Conn>,
    initial_padding_len: usize,
    state: Mutex<WriterState>,
}

fn seal_record_into(cipher: &Aead, nonce: &mut Nonce, output: &mut Buffer, payload: &[u8], padding_len: usize) {
    assert!(payload.len() <= MAX_PAYLOAD && padding_len <= MAX_PAYLOAD, "snell: v5 record exceeds maximum");
    assert!(!payload.is_empty() || padding_len == 0, "snell: zero-length v5 record carries padding");
    let start = output.len();
    seal_header(cipher, nonce, output.extend(HEADER_CIPHER_LEN), padding_len, payload.len());
    output.extend(padding_len);
    let payload_cipher = output.extend(payload.len() + AEAD_TAG_LEN);
    payload_cipher[..payload.len()].copy_from_slice(payload);
    cipher.seal_in_place(nonce, &[], payload_cipher);
    increase_nonce(nonce);
    if padding_len > 0 {
        let record = output.from_offset_mut(start + HEADER_CIPHER_LEN);
        let (padding, payload_cipher) = record.split_at_mut(padding_len);
        fill_padding(padding, payload_cipher, TargetFormula::V5);
        swap_even(padding, payload_cipher);
    }
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

impl WriterState {
    fn current_packet_limit(&self, initial_padding_len: usize, now: i64) -> usize {
        if self.last_frame_unix == 0 {
            FRAME_SIZE - FIRST_RECORD_OVERHEAD - initial_padding_len
        } else if now - self.last_frame_unix < FRAME_PAYLOAD_RESET_INTERVAL {
            if self.frame_payload_len == 0 { FRAME_PAYLOAD_STEP } else { self.frame_payload_len }
        } else {
            FRAME_PAYLOAD_STEP
        }
    }

    fn next_payload_limit(&mut self, initial_padding_len: usize) -> usize {
        let now = unix_now();
        let payload_limit = self.current_packet_limit(initial_padding_len, now);
        self.last_frame_unix = now;
        self.mark_payload_limit_used(payload_limit);
        payload_limit
    }

    fn mark_payload_limit_used(&mut self, payload_limit: usize) {
        self.frame_payload_len = (payload_limit + FRAME_PAYLOAD_STEP).min(MAX_PAYLOAD);
        if self.last_frame_unix == 0 {
            self.last_frame_unix = unix_now();
        }
    }

    fn next_stream_payload_batch(&mut self, initial_padding_len: usize, data_len: usize) -> (usize, usize) {
        let now = unix_now();
        if self.stream_payload_left == 0
            || self.last_frame_unix != 0 && now - self.last_frame_unix >= FRAME_PAYLOAD_RESET_INTERVAL
        {
            self.stream_payload_len = self.next_payload_limit(initial_padding_len);
            self.stream_payload_left = STREAM_PAYLOAD_BATCH_SIZE;
        } else {
            // The virtual batch can span several copy buffers. Keep the 31-second
            // reset tied to actual stream activity rather than the first buffer only.
            self.last_frame_unix = now;
        }
        let payload_limit = self.stream_payload_len;
        let batch_len = data_len.min(self.stream_payload_left);
        self.stream_payload_left -= batch_len;
        (payload_limit, batch_len)
    }

    /// Accounts one packet record (`WritePacketBuffer` and the packet vectorised writer).
    fn take_packet_limit(&mut self, initial_padding_len: usize, data_len: usize) -> io::Result<()> {
        let now = unix_now();
        let payload_limit = self.current_packet_limit(initial_padding_len, now);
        if data_len > payload_limit {
            return Err(ErrorCode::PayloadTooLarge.into());
        }
        self.stream_payload_left = 0;
        self.last_frame_unix = now;
        self.mark_payload_limit_used(payload_limit);
        Ok(())
    }

    fn make_slice_record(&mut self, payload: &[u8], padding_len: usize) -> Buffer {
        let mut record = Buffer::with_capacity(HEADER_CIPHER_LEN + padding_len + payload.len() + AEAD_TAG_LEN);
        seal_record_into(&self.cipher, &mut self.nonce, &mut record, payload, padding_len);
        record
    }

    fn make_buffer_record(&mut self, mut buffer: Buffer, padding_len: usize) -> Buffer {
        let data_len = buffer.len();
        assert!(data_len <= MAX_PAYLOAD && padding_len <= MAX_PAYLOAD, "snell: v5 record exceeds maximum");
        assert!(data_len > 0 || padding_len == 0, "snell: zero-length v5 record carries padding");
        let front_len = HEADER_CIPHER_LEN + padding_len;
        buffer.extend_header(front_len);
        buffer.extend(AEAD_TAG_LEN);
        let (prefix, payload_cipher) = buffer.bytes_mut().split_at_mut(front_len);
        seal_header(&self.cipher, &mut self.nonce, &mut prefix[..HEADER_CIPHER_LEN], padding_len, data_len);
        self.cipher.seal_in_place(&self.nonce, &[], payload_cipher);
        increase_nonce(&mut self.nonce);
        if padding_len > 0 {
            let padding = &mut prefix[HEADER_CIPHER_LEN..];
            fill_padding(padding, payload_cipher, TargetFormula::V5);
            swap_even(padding, payload_cipher);
        }
        buffer
    }

    /// Seals one batch of slice records into a single output buffer.
    fn seal_batch(&mut self, batch: &[u8], payload_limit: usize) -> Buffer {
        let record_count = batch.len().div_ceil(payload_limit);
        let mut output = Buffer::with_capacity(batch.len() + record_count * (HEADER_CIPHER_LEN + AEAD_TAG_LEN));
        for chunk in batch.chunks(payload_limit) {
            seal_record_into(&self.cipher, &mut self.nonce, &mut output, chunk, 0);
        }
        output
    }
}

impl Writer {
    pub(crate) fn new(upstream: Arc<dyn Conn>, aead: Aead, nonce: Nonce) -> Self {
        let padding_delta = rand::rng().random_range(0..INITIAL_PADDING_SPAN);
        Writer {
            upstream,
            initial_padding_len: INITIAL_PADDING_MIN + padding_delta,
            state: Mutex::new(WriterState {
                cipher: aead,
                nonce,
                last_frame_unix: 0,
                frame_payload_len: 0,
                stream_payload_len: 0,
                stream_payload_left: 0,
            }),
        }
    }

    /// Fixes the random initial padding length, for the wire-shape tests.
    #[cfg(test)]
    pub(crate) fn with_initial_padding_len(mut self, len: usize) -> Self {
        self.initial_padding_len = len;
        self
    }

    /// Writes the salt and the first record(s), carrying the initial padding.
    pub(crate) async fn write_first(&self, salt: &[u8], mut payload: &[u8]) -> io::Result<()> {
        let mut state = self.state.lock().await;
        if payload.is_empty() {
            state.stream_payload_left = 0;
            state.next_payload_limit(self.initial_padding_len);
            let mut record = Buffer::with_capacity(salt.len() + HEADER_CIPHER_LEN);
            record.write_all(salt);
            let state = &mut *state;
            seal_header(&state.cipher, &mut state.nonce, record.extend(HEADER_CIPHER_LEN), 0, 0);
            return self.upstream.write(record.bytes()).await.map(|_| ());
        }
        let mut first_record = true;
        while !payload.is_empty() {
            let (payload_limit, batch_len) = state.next_stream_payload_batch(self.initial_padding_len, payload.len());
            let record_count = batch_len.div_ceil(payload_limit);
            let mut output_size = batch_len + record_count * (HEADER_CIPHER_LEN + AEAD_TAG_LEN);
            if first_record {
                output_size += salt.len() + self.initial_padding_len;
            }
            let mut output = Buffer::with_capacity(output_size);
            if first_record {
                output.write_all(salt);
            }
            for chunk in payload[..batch_len].chunks(payload_limit) {
                let padding_len = if first_record { self.initial_padding_len } else { 0 };
                let state = &mut *state;
                seal_record_into(&state.cipher, &mut state.nonce, &mut output, chunk, padding_len);
                first_record = false;
            }
            self.upstream.write(output.bytes()).await?;
            payload = &payload[batch_len..];
        }
        Ok(())
    }
}

#[async_trait]
impl RecordWriter for Writer {
    async fn write(&self, mut p: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().await;
        let mut n = 0;
        while !p.is_empty() {
            let (payload_limit, batch_len) = state.next_stream_payload_batch(self.initial_padding_len, p.len());
            let output = state.seal_batch(&p[..batch_len], payload_limit);
            self.upstream.write(output.bytes()).await?;
            n += batch_len;
            p = &p[batch_len..];
        }
        Ok(n)
    }

    async fn write_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let data_len = buffer.len();
        if data_len == 0 {
            return Ok(());
        }
        let mut state = self.state.lock().await;
        let mut offset = 0;
        while offset < data_len {
            let (payload_limit, batch_len) =
                state.next_stream_payload_batch(self.initial_padding_len, data_len - offset);
            if offset == 0 && batch_len == data_len && data_len <= payload_limit {
                let record = state.make_buffer_record(buffer, 0);
                return self.upstream.write(record.bytes()).await.map(|_| ());
            }
            let output = state.seal_batch(&buffer.bytes()[offset..offset + batch_len], payload_limit);
            self.upstream.write(output.bytes()).await?;
            offset += batch_len;
        }
        Ok(())
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
                let (payload_limit, batch_len) =
                    state.next_stream_payload_batch(self.initial_padding_len, data_len - offset);
                if offset == 0 && batch_len == data_len && data_len <= payload_limit {
                    records.push(state.make_buffer_record(buffer.take().unwrap(), 0));
                    break;
                }
                let data = buffer.as_ref().unwrap().bytes();
                for chunk in data[offset..offset + batch_len].chunks(payload_limit) {
                    let record = state.make_slice_record(chunk, 0);
                    records.push(record);
                }
                offset += batch_len;
            }
        }
        if records.is_empty() {
            return Ok(());
        }
        self.upstream.write_vectorised(records).await
    }

    async fn write_packet_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        let mut state = self.state.lock().await;
        let mut records = Vec::new();
        for buffer in buffers {
            let data_len = buffer.len();
            if data_len == 0 {
                continue;
            }
            state.take_packet_limit(self.initial_padding_len, data_len)?;
            records.push(state.make_buffer_record(buffer, 0));
        }
        if records.is_empty() {
            return Ok(());
        }
        self.upstream.write_vectorised(records).await
    }

    async fn write_packet_buffer(&self, buffer: Buffer) -> io::Result<()> {
        let mut state = self.state.lock().await;
        state.take_packet_limit(self.initial_padding_len, buffer.len())?;
        let record = state.make_buffer_record(buffer, 0);
        self.upstream.write(record.bytes()).await.map(|_| ())
    }

    async fn write_zero_chunk(&self) -> io::Result<()> {
        let mut buffer = Buffer::with_capacity(HEADER_CIPHER_LEN);
        let mut state = self.state.lock().await;
        // snell-server v5.0.1: FUN_0013def0 calls FUN_00139670 even for an empty
        // payload, so EOF records consume one growth-window step.
        state.stream_payload_left = 0;
        state.next_payload_limit(self.initial_padding_len);
        let state = &mut *state;
        seal_header(&state.cipher, &mut state.nonce, buffer.extend(HEADER_CIPHER_LEN), 0, 0);
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
