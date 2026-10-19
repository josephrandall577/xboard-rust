//! Compares the default-mode record shaping against the Go reference
//! (`tests/fixtures/v6_wire_shape.txt`). Apart from the salt and the AEAD
//! output, default-mode shaping is deterministic, so every record's prefix,
//! padding and payload length, and the prefix and padding bytes, must match.

use std::fmt::Write as _;
use std::sync::Arc;

use super::handshake::Framing;
use super::profile::Profile;
use super::{Client, ClientOptions, Mode};
use crate::crypto::{Aead, derive_key, increase_nonce};
use crate::net::Conn;
use crate::test_util::{CaptureConn, assert_fixture, new_buffer, pattern, short};
use crate::{AEAD_TAG_LEN, HEADER_CIPHER_LEN, Socksaddr};

fn describe_wire(profile: &Profile, psk: &[u8], wire: &[u8]) -> String {
    let mut out = String::new();
    let salt = profile.extract_salt(&wire[..profile.salt_block_len]);
    let aead = Aead::new(&derive_key(psk, &salt)).unwrap();
    let mut nonce = [0u8; 12];
    let mut offset = profile.salt_block_len;
    let mut seq = 0u32;
    while offset < wire.len() {
        let prefix_len = profile.record_prefix_len(seq);
        let prefix = &wire[offset..offset + prefix_len];
        let mut header = wire[offset + prefix_len..offset + prefix_len + HEADER_CIPHER_LEN].to_vec();
        aead.open_in_place(&nonce, prefix, &mut header).unwrap();
        increase_nonce(&mut nonce);
        offset += prefix_len + HEADER_CIPHER_LEN;
        let padding_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut padding = wire[offset..offset + padding_len].to_vec();
        offset += padding_len;
        let mut plain = Vec::new();
        if payload_len > 0 {
            let mut cipher = wire[offset..offset + payload_len + AEAD_TAG_LEN].to_vec();
            offset += payload_len + AEAD_TAG_LEN;
            profile.mix_padding_payload(seq, &mut padding, &mut cipher);
            let n = aead.open_in_place(&nonce, &padding, &mut cipher).unwrap();
            increase_nonce(&mut nonce);
            cipher.truncate(n);
            plain = cipher;
        }
        let mut shaped = prefix.to_vec();
        shaped.extend_from_slice(&padding);
        writeln!(out, "record {seq} {prefix_len} {padding_len} {payload_len} {} {}", short(&shaped), short(&plain))
            .unwrap();
        seq += 1;
    }
    out
}

const WRITE_SIZES: [usize; 6] = [1, 100, 1400, 5000, 20000, 70000];

async fn dump(psk: &str) -> String {
    let profile = Arc::new(Profile::new(psk.as_bytes()));
    let framing = Framing { mode: Mode::Default, psk: psk.as_bytes().into(), profile: Some(profile.clone()) };
    let client =
        Client::new(ClientOptions { psk: psk.as_bytes().to_vec(), mode: Mode::Default, ..Default::default() }).unwrap();
    let destination = Socksaddr::parse_host_port("example.com", 443);
    let mut out = String::new();
    {
        let capture = Arc::new(CaptureConn::default());
        let conn = client.dial_early_conn(capture.clone(), destination.clone());
        conn.write(&pattern(3000, 0)).await.unwrap();
        for (index, size) in WRITE_SIZES.iter().enumerate() {
            conn.write(&pattern(*size, index + 1)).await.unwrap();
        }
        conn.close_write().await.unwrap();
        let wire = capture.wire();
        write!(out, "scenario {psk} write\n{}", describe_wire(&profile, psk.as_bytes(), &wire)).unwrap();
    }
    {
        let capture = Arc::new(CaptureConn::default());
        let conn = client.dial_early_conn(capture.clone(), destination.clone());
        conn.write_buffer(new_buffer(conn.front_headroom(), &pattern(200, 0))).await.unwrap();
        for (index, size) in WRITE_SIZES.iter().enumerate() {
            conn.write_buffer(new_buffer(conn.front_headroom(), &pattern(*size, index + 1))).await.unwrap();
        }
        conn.close_write().await.unwrap();
        let wire = capture.wire();
        write!(out, "scenario {psk} buffer\n{}", describe_wire(&profile, psk.as_bytes(), &wire)).unwrap();
    }
    {
        let capture: Arc<CaptureConn> = Arc::new(CaptureConn::default());
        let upstream: Arc<dyn Conn> = capture.clone();
        let writer = framing.write_first_record(&upstream, &pattern(40, 0)).await.unwrap();
        let buffers = WRITE_SIZES
            .iter()
            .enumerate()
            .map(|(index, size)| new_buffer(writer.front_headroom(), &pattern(*size, index + 1)))
            .collect();
        writer.write_vectorised(buffers).await.unwrap();
        writer.write_zero_chunk().await.unwrap();
        let wire = capture.wire();
        write!(out, "scenario {psk} vectorised\n{}", describe_wire(&profile, psk.as_bytes(), &wire)).unwrap();
    }
    {
        let capture: Arc<CaptureConn> = Arc::new(CaptureConn::default());
        let upstream: Arc<dyn Conn> = capture.clone();
        let writer = framing.write_first_record(&upstream, &pattern(3, 0)).await.unwrap();
        for (index, size) in [20, 600, 1400, 1500, 9000, 0xffff].iter().enumerate() {
            writer.write_packet_buffer(new_buffer(writer.front_headroom(), &pattern(*size, index + 1))).await.unwrap();
        }
        let buffers = [100, 1450, 3000]
            .iter()
            .enumerate()
            .map(|(index, size)| new_buffer(writer.front_headroom(), &pattern(*size, index + 10)))
            .collect();
        writer.write_packet_vectorised(buffers).await.unwrap();
        let wire = capture.wire();
        write!(out, "scenario {psk} packet\n{}", describe_wire(&profile, psk.as_bytes(), &wire)).unwrap();
    }
    out
}

#[tokio::test]
async fn wire_shape_matches_go_reference() {
    let fixture = include_str!("../../tests/fixtures/v6_wire_shape.txt");
    let mut actual = String::new();
    for psk in ["snell-interop-test-psk-0123456789", "snell-rc-udp-0371991", "generated-psk-7-d885"] {
        actual.push_str(&dump(psk).await);
    }
    assert_fixture(fixture, &actual);
}
