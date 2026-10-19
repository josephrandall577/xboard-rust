//! Helpers for the wire-shape tests that compare against the Go reference.

use std::fmt::Write as _;
use std::io;
use std::sync::Mutex;
use std::time::Instant;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::buf::Buffer;
use crate::crypto::{Aead, derive_key, increase_nonce};
use crate::net::Conn;
use crate::padding::swap_even;
use crate::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, SALT_LEN};

/// A connection that records everything written to it.
#[derive(Default)]
pub(crate) struct CaptureConn {
    pub(crate) data: Mutex<Vec<u8>>,
}

impl CaptureConn {
    pub(crate) fn wire(&self) -> Vec<u8> {
        self.data.lock().unwrap().clone()
    }
}

#[async_trait]
impl Conn for CaptureConn {
    async fn read(&self, _: &mut [u8]) -> io::Result<usize> {
        std::future::pending().await
    }

    async fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.data.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
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

    fn supports_vectorised(&self) -> bool {
        true
    }

    async fn write_vectorised(&self, buffers: Vec<Buffer>) -> io::Result<()> {
        let mut data = self.data.lock().unwrap();
        for buffer in buffers {
            data.extend_from_slice(buffer.bytes());
        }
        Ok(())
    }
}

/// The payload pattern used by the Go fixture generators.
pub(crate) fn pattern(n: usize, seed: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31) + seed * 7 + 3) as u8).collect()
}

pub(crate) fn short(data: &[u8]) -> String {
    Sha256::digest(data)[..6].iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn new_buffer(front_headroom: usize, payload: &[u8]) -> Buffer {
    Buffer::from_slice_with_headroom(payload, front_headroom, AEAD_TAG_LEN)
}

/// Lists the records of a v4/v5 stream: padding length, payload length and payload hash.
pub(crate) fn describe_v4_wire(psk: &[u8], wire: &[u8]) -> String {
    let mut out = String::new();
    let aead = Aead::new(&derive_key(psk, &wire[..SALT_LEN])).unwrap();
    let mut nonce = [0u8; 12];
    let mut offset = SALT_LEN;
    let mut index = 0;
    while offset < wire.len() {
        let mut header = wire[offset..offset + HEADER_CIPHER_LEN].to_vec();
        aead.open_in_place(&nonce, &[], &mut header).unwrap();
        increase_nonce(&mut nonce);
        offset += HEADER_CIPHER_LEN;
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut padding = wire[offset..offset + padding_len].to_vec();
        offset += padding_len;
        let mut plain = Vec::new();
        if payload_len > 0 {
            let mut cipher = wire[offset..offset + payload_len + AEAD_TAG_LEN].to_vec();
            offset += payload_len + AEAD_TAG_LEN;
            swap_even(&mut padding, &mut cipher);
            let n = aead.open_in_place(&nonce, &[], &mut cipher).unwrap();
            increase_nonce(&mut nonce);
            cipher.truncate(n);
            plain = cipher;
        }
        writeln!(out, "record {index} {padding_len} {payload_len} {}", short(&plain)).unwrap();
        index += 1;
    }
    out
}

pub(crate) fn assert_fixture(fixture: &str, actual: &str) {
    for (line, (want, got)) in fixture.lines().zip(actual.lines()).enumerate() {
        assert_eq!(want, got, "line {line}");
    }
    assert_eq!(fixture.lines().count(), actual.lines().count());
}
