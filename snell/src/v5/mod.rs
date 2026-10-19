//! The snell v5 server. v5 clients are served by [`crate::v4::Client`].

mod packet;
mod record;
mod reuse;
mod server;
#[cfg(test)]
mod wire_tests;

pub use server::{MultiService, Service, ServiceOptions};

use crate::MAX_PAYLOAD_LEN;

// snell-server v5.0.1: FUN_0013bbe0 calls getsockopt(TCP_MAXSEG) on the
// accepted client socket but, on the normal success path, passes 0x5b4 to
// FUN_00139080; FUN_00139670 then computes the first payload limit as
// frameSize - 0x37 - paddingLen, and uses frameSize - 0x27 for growth.
pub(crate) const MAX_PAYLOAD: usize = MAX_PAYLOAD_LEN;
pub(crate) const FRAME_SIZE: usize = 0x5b4;
pub(crate) const FIRST_RECORD_OVERHEAD: usize = 0x37;
pub(crate) const RESET_RECORD_OVERHEAD: usize = 0x27;
pub(crate) const INITIAL_PADDING_MIN: usize = 0x100;
pub(crate) const INITIAL_PADDING_SPAN: usize = 0x100;
pub(crate) const MAX_INITIAL_PADDING_LEN: usize = INITIAL_PADDING_MIN + INITIAL_PADDING_SPAN - 1;
pub(crate) const FRAME_PAYLOAD_STEP: usize = FRAME_SIZE - RESET_RECORD_OVERHEAD;
pub(crate) const FRAME_PAYLOAD_RESET_INTERVAL: i64 = 31;
// snell-server v5.0.1: FUN_0013a700 caps a stream read at four times
// libuv 1.48.0's 64 KiB suggestion, while actual callbacks are commonly
// partial. A three-suggestion pacing window matches the observed growth
// envelope without coupling it to small copy buffers.
pub(crate) const STREAM_PAYLOAD_BATCH_SIZE: usize = 3 * 64 * 1024;
