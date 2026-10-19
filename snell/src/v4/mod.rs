//! The snell v4 client. It also speaks to v5 servers.

mod client;
mod packet;
mod record;
mod reuse;
#[cfg(test)]
mod wire_tests;

pub use client::{Client, ClientConn, ClientOptions};
pub use packet::ClientPacketConn;
pub use reuse::ReuseConn;

pub(crate) use record::{Reader, Writer, new_reader};

use crate::MAX_PAYLOAD_LEN;

// Surge 6.7.0 (11520): SNConnectorEngineAdapterV4::encryptData:outData: uses these v4 frame sizing constants.
pub(crate) const MAX_PAYLOAD: usize = MAX_PAYLOAD_LEN;
pub(crate) const FRAME_SIZE: usize = 1460;
pub(crate) const FIRST_RECORD_OVERHEAD: usize = 55;
pub(crate) const RESET_RECORD_OVERHEAD: usize = 39;
pub(crate) const INITIAL_PADDING_MIN: usize = 0x100;
pub(crate) const INITIAL_PADDING_SPAN: usize = 0x100;
pub(crate) const MAX_INITIAL_PADDING_LEN: usize = INITIAL_PADDING_MIN + INITIAL_PADDING_SPAN - 1;
// Surge 6.7.0 (11520): FUN_100012944 compares time(0) deltas against 0x1f.
pub(crate) const FRAME_PAYLOAD_RESET_INTERVAL: i64 = 31;
