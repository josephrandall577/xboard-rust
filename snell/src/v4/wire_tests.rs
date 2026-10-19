//! Compares the v4 record splitting and payload limit growth against the Go
//! reference (`tests/fixtures/v4_wire_shape.txt`), with the random initial
//! padding length fixed.

use std::fmt::Write as _;
use std::sync::Arc;

use super::Writer;
use crate::reuse::RecordWriter;
use crate::test_util::{CaptureConn, assert_fixture, describe_v4_wire, new_buffer, pattern};

#[tokio::test]
async fn wire_shape_matches_go_reference() {
    let psk: Arc<[u8]> = b"snell-interop-test-psk-0123456789".as_slice().into();
    let mut actual = String::new();
    for initial_padding in [256, 300, 511] {
        let capture = Arc::new(CaptureConn::default());
        let w = Writer::new(capture.clone(), psk.clone());
        w.force_initial_padding_len(initial_padding).await;
        w.write(&pattern(3000, 0)).await.unwrap();
        for (index, size) in [1, 100, 1400, 2900, 5000, 20000, 70000].into_iter().enumerate() {
            w.write(&pattern(size, index + 1)).await.unwrap();
        }
        for (index, size) in [10, 1500, 16383, 40000].into_iter().enumerate() {
            w.write_buffer(new_buffer(w.front_headroom(), &pattern(size, index + 20))).await.unwrap();
        }
        let buffers = [500, 0, 16000, 33000]
            .into_iter()
            .enumerate()
            .map(|(index, size)| new_buffer(w.front_headroom(), &pattern(size, index + 30)))
            .collect();
        w.write_vectorised(buffers).await.unwrap();
        for (index, size) in [20, 1200, 16383].into_iter().enumerate() {
            w.write_packet_buffer(new_buffer(w.front_headroom(), &pattern(size, index + 40))).await.unwrap();
        }
        let buffers = [100, 1450]
            .into_iter()
            .enumerate()
            .map(|(index, size)| new_buffer(w.front_headroom(), &pattern(size, index + 50)))
            .collect();
        w.write_packet_vectorised(buffers).await.unwrap();
        w.write(&[]).await.unwrap();
        write!(actual, "scenario v4 {initial_padding}\n{}", describe_v4_wire(&psk, &capture.wire())).unwrap();
    }
    assert_fixture(include_str!("../../tests/fixtures/v4_wire_shape.txt"), &actual);
}
