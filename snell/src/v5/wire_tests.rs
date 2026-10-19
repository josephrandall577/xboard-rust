//! Compares the v5 server record batching and payload limit growth against the
//! Go reference (`tests/fixtures/v5_wire_shape.txt`), with the random initial
//! padding length fixed.

use std::fmt::Write as _;
use std::sync::Arc;

use super::record::Writer;
use crate::crypto::{Aead, derive_key};
use crate::reuse::RecordWriter;
use crate::test_util::{CaptureConn, assert_fixture, describe_v4_wire, new_buffer, pattern};

#[tokio::test]
async fn wire_shape_matches_go_reference() {
    let psk = b"snell-interop-test-psk-0123456789";
    let salt = b"0123456789abcdef";
    let mut actual = String::new();
    for initial_padding in [256, 300, 511] {
        for first_len in [0, 1, 3000] {
            let capture = Arc::new(CaptureConn::default());
            let aead = Aead::new(&derive_key(psk, salt)).unwrap();
            let w = Writer::new(capture.clone(), aead, [0; 12]).with_initial_padding_len(initial_padding);
            w.write_first(salt, &pattern(first_len, 0)).await.unwrap();
            for (index, size) in [1, 100, 1400, 2900, 5000, 20000, 70000, 300000].into_iter().enumerate() {
                w.write(&pattern(size, index + 1)).await.unwrap();
            }
            for (index, size) in [10, 1500, 16383, 40000, 250000].into_iter().enumerate() {
                w.write_buffer(new_buffer(w.front_headroom(), &pattern(size, index + 20))).await.unwrap();
            }
            let buffers = [500, 0, 16000, 33000, 200000]
                .into_iter()
                .enumerate()
                .map(|(index, size)| new_buffer(w.front_headroom(), &pattern(size, index + 30)))
                .collect();
            w.write_vectorised(buffers).await.unwrap();
            for (index, size) in [20, 1200, 16383].into_iter().enumerate() {
                // Like the Go generator, which ignores ErrPayloadTooLarge for oversized datagrams.
                let _ = w.write_packet_buffer(new_buffer(w.front_headroom(), &pattern(size, index + 40))).await;
            }
            let buffers = [100, 1450]
                .into_iter()
                .enumerate()
                .map(|(index, size)| new_buffer(w.front_headroom(), &pattern(size, index + 50)))
                .collect();
            let _ = w.write_packet_vectorised(buffers).await;
            w.write_zero_chunk().await.unwrap();
            write!(actual, "scenario v5 {initial_padding} {first_len}\n{}", describe_v4_wire(psk, &capture.wire()))
                .unwrap();
        }
    }
    assert_fixture(include_str!("../../tests/fixtures/v5_wire_shape.txt"), &actual);
}
