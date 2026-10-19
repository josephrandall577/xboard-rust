//! [Surge snell](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell) implemented in Rust.
//!
//! This crate is a port of the Go library `sing-snell`. Wire behavior, record
//! shaping and connection reuse follow the Go implementation (which in turn
//! follows the official implementation) as closely as possible.
//!
//! * [`v4`]: the v4 client (also used against v5 servers) with optional
//!   connection reuse and HTTP/TLS obfuscation.
//! * [`v5`]: the v5 server.
//! * [`v6`]: the v6 client and server (`default`, `unshaped` and `unsafe-raw` modes).

pub mod addr;
pub mod address;
mod auth;
pub mod buf;
mod bufio;
pub mod crypto;
pub mod error;
pub mod net;
pub mod obfs;
mod padding;
pub mod request;
mod reuse;
#[cfg(test)]
mod test_util;
pub mod v4;
pub mod v5;
pub mod v6;

pub use addr::Socksaddr;
pub use address::{
    read_connect_address, read_udp_request_address, read_udp_response_address, write_connect_address,
    write_udp_request_address, write_udp_response_address,
};
pub use buf::Buffer;
pub use crypto::{Aead, derive_key, increase_nonce, new_aead};
pub use error::{ErrorCode, has_code, is_closed, is_eof};
pub use net::{
    CachedPacketConn, CloseHandler, Conn, ConnStream, Context, Dialer, Handler, Method, PacketConn, ReadWaitOptions,
    ServerError, Service, SystemDialer, TcpConn,
};
pub use obfs::{DEFAULT_OBFS_HOST, DEFAULT_OBFS_URI, DEFAULT_TLS_OBFS_HOST, ObfsConfig, ObfsMode, parse_obfs_mode};
pub use request::{Request, read_request, read_server_error};

pub const HEADER_VERSION: u8 = 0x04;
pub const HEADER_PLAIN_LEN: usize = 7;
pub const AEAD_TAG_LEN: usize = 16;
pub const HEADER_CIPHER_LEN: usize = HEADER_PLAIN_LEN + AEAD_TAG_LEN;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const MAX_PAYLOAD_LEN: usize = 0x3fff;

pub const REQUEST_VERSION: u8 = 0x01;

pub const COMMAND_PING: u8 = 0x00;
pub const COMMAND_CONNECT: u8 = 0x01;
pub const COMMAND_CONNECT_V2: u8 = 0x05;
pub const COMMAND_UDP: u8 = 0x06;

pub const REPLY_TUNNEL: u8 = 0x00;
pub const REPLY_PONG: u8 = 0x01;
pub const REPLY_ERROR: u8 = 0x02;

pub const UDP_COMMAND_FORWARD: u8 = 0x01;
pub const ADDRESS_TYPE_IPV4: u8 = 0x04;
pub const ADDRESS_TYPE_IPV6: u8 = 0x06;
