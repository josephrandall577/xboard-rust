//! The snell v6 client and server.

mod client;
mod handshake;
mod multi_psk;
mod packet;
mod profile;
mod record;
mod reuse;
mod server;
mod shaped;
#[cfg(test)]
mod wire_tests;

use std::fmt;
use std::io;

pub use client::{Client, ClientConn, ClientOptions};
pub use multi_psk::{HandshakeLimits, MultiPskService, validate_psks};
pub use packet::ClientPacketConn;
pub use profile::Profile;
pub use reuse::ReuseConn;
pub use server::{MultiService, ServerOptions, Service};

use crate::error;

/// The v6 record mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Mode {
    #[default]
    Default,
    Unshaped,
    UnsafeRaw,
}

/// `snellv6.ParseMode`.
pub fn parse_mode(name: &str) -> io::Result<Mode> {
    match name {
        "" | "default" => Ok(Mode::Default),
        "unshaped" => Ok(Mode::Unshaped),
        "unsafe-raw" => Ok(Mode::UnsafeRaw),
        _ => Err(error::new_invalid(format!("snell: unknown v6 mode: {name}"))),
    }
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Default => "default",
            Mode::Unshaped => "unshaped",
            Mode::UnsafeRaw => "unsafe-raw",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Mode {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_mode(s)
    }
}

pub(crate) const MAX_PAYLOAD: usize = 0xffff;
