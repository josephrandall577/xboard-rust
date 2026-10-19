//! The first record of each v6 direction, which carries the salt.

use std::io;
use std::sync::Arc;

use super::profile::Profile;
use super::record::{RawWriter, UnshapedWriter, new_raw_reader, new_unshaped_reader, put_header};
use super::shaped::{ShapedWriter, new_shaped_reader};
use super::{MAX_PAYLOAD, Mode};
use crate::buf::Buffer;
use crate::crypto::{Aead, derive_key, random_salt};
use crate::net::{self, Conn, ReadWaitOptions};
use crate::reuse::{RecordReader, RecordWriter};
use crate::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, HEADER_PLAIN_LEN, NONCE_LEN, SALT_LEN};

/// The settings needed to frame a v6 connection.
#[derive(Clone)]
pub(crate) struct Framing {
    pub(crate) mode: Mode,
    pub(crate) psk: Arc<[u8]>,
    pub(crate) profile: Option<Arc<Profile>>,
}

impl Framing {
    fn profile(&self) -> &Arc<Profile> {
        self.profile.as_ref().expect("snell: missing v6 profile")
    }

    pub(crate) async fn write_first_record(
        &self,
        conn: &Arc<dyn Conn>,
        payload: &[u8],
    ) -> io::Result<Arc<dyn RecordWriter>> {
        match self.mode {
            Mode::UnsafeRaw => {
                let writer = Arc::new(RawWriter::new(conn.clone()));
                // Surge 6.7.0 (11520): FUN_1000154e0: chunks unsafe-raw payloads larger than the
                // 16-bit record payload field instead of truncating the length.
                if payload.len() > MAX_PAYLOAD {
                    writer.write(payload).await?;
                    return Ok(writer);
                }
                let mut out = Buffer::with_capacity(HEADER_PLAIN_LEN + payload.len());
                put_header(out.extend(HEADER_PLAIN_LEN), 0, payload.len());
                out.write_all(payload);
                conn.write(out.bytes()).await?;
                Ok(writer)
            }
            Mode::Unshaped => {
                let salt = random_salt();
                let aead = Aead::new(&derive_key(&self.psk, &salt))?;
                let record_count = if payload.is_empty() { 1 } else { payload.len().div_ceil(MAX_PAYLOAD) };
                let mut payload_cipher_len = payload.len();
                if !payload.is_empty() {
                    payload_cipher_len += record_count * AEAD_TAG_LEN;
                }
                let mut out = Buffer::with_capacity(SALT_LEN + record_count * HEADER_CIPHER_LEN + payload_cipher_len);
                out.write_all(&salt);
                let writer = Arc::new(UnshapedWriter::new(conn.clone(), aead, [0; NONCE_LEN]));
                writer.with_state(|state| writer.seal_first_records(state, &mut out, payload)).await;
                conn.write(out.bytes()).await?;
                Ok(writer)
            }
            Mode::Default => {
                let salt = random_salt();
                let aead = Aead::new(&derive_key(&self.psk, &salt))?;
                let writer = Arc::new(ShapedWriter::new(conn.clone(), self.profile().clone(), salt, aead));
                if payload.is_empty() {
                    writer.write_first_empty().await?;
                } else {
                    writer.write(payload).await?;
                }
                Ok(writer)
            }
        }
    }

    pub(crate) async fn write_first_record_buffer(
        &self,
        conn: &Arc<dyn Conn>,
        mut buffer: Buffer,
    ) -> io::Result<Arc<dyn RecordWriter>> {
        match self.mode {
            Mode::UnsafeRaw => {
                let writer = Arc::new(RawWriter::new(conn.clone()));
                writer.write_buffer(buffer).await?;
                Ok(writer)
            }
            Mode::Unshaped => {
                if buffer.len() > MAX_PAYLOAD {
                    return self.write_first_record(conn, buffer.bytes()).await;
                }
                let salt = random_salt();
                let aead = Aead::new(&derive_key(&self.psk, &salt))?;
                let writer = Arc::new(UnshapedWriter::new(conn.clone(), aead, [0; NONCE_LEN]));
                writer.with_state(|state| writer.seal_first_buffer(state, &mut buffer, &salt)).await;
                conn.write(buffer.bytes()).await?;
                Ok(writer)
            }
            Mode::Default => {
                let salt = random_salt();
                let aead = Aead::new(&derive_key(&self.psk, &salt))?;
                let writer = Arc::new(ShapedWriter::new(conn.clone(), self.profile().clone(), salt, aead));
                writer.write_buffer(buffer).await?;
                Ok(writer)
            }
        }
    }

    pub(crate) async fn read_first_record(
        &self,
        conn: &Arc<dyn Conn>,
        options: ReadWaitOptions,
    ) -> io::Result<(Arc<dyn RecordReader>, Buffer)> {
        match self.mode {
            Mode::UnsafeRaw => {
                let reader = new_raw_reader(conn.clone());
                reader.initialize_read_waiter(options);
                let record = reader.read_record().await?;
                Ok((Arc::new(reader), record))
            }
            Mode::Unshaped => {
                let mut salt = [0u8; SALT_LEN];
                net::read_full(conn.as_ref(), &mut salt).await?;
                let aead = Aead::new(&derive_key(&self.psk, &salt))?;
                let reader = new_unshaped_reader(conn.clone(), aead, [0; NONCE_LEN]);
                reader.initialize_read_waiter(options);
                let record = reader.read_record().await?;
                Ok((Arc::new(reader), record))
            }
            Mode::Default => {
                let reader = new_shaped_reader(conn.clone(), self.psk.clone(), self.profile().clone());
                reader.initialize_read_waiter(options);
                let record = reader.read_record().await?;
                Ok((Arc::new(reader), record))
            }
        }
    }

    /// The front headroom before the first record is written.
    pub(crate) fn first_front_headroom(&self) -> usize {
        match self.mode {
            Mode::UnsafeRaw => HEADER_PLAIN_LEN,
            Mode::Unshaped => SALT_LEN + HEADER_CIPHER_LEN,
            Mode::Default => {
                let profile = self.profile();
                profile.salt_block_len + profile.record_prefix_max + HEADER_CIPHER_LEN + profile.pad_max_headroom
            }
        }
    }

    /// The front headroom of a non-first record.
    pub(crate) fn packet_front_headroom(&self) -> usize {
        match self.mode {
            Mode::UnsafeRaw => HEADER_PLAIN_LEN,
            Mode::Unshaped => HEADER_CIPHER_LEN,
            Mode::Default => {
                let profile = self.profile();
                profile.record_prefix_max + HEADER_CIPHER_LEN + profile.pad_max_headroom
            }
        }
    }

    pub(crate) fn rear_headroom(&self) -> usize {
        if self.mode == Mode::UnsafeRaw { 0 } else { AEAD_TAG_LEN }
    }

    pub(crate) fn writer_mtu(&self) -> usize {
        if self.mode == Mode::Default { self.profile().chunk_max as usize } else { MAX_PAYLOAD }
    }
}
