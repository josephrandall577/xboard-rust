//! Xboard-compatible Snell v6 node backend.
//!
//! The node runs the Snell v6 server from the `snell` crate and adds the
//! parts a landing server needs to be operated by Xboard or standalone:
//!
//! * per-user credentials (`uuid` becomes the Snell v6 user key),
//! * per-user traffic accounting, quotas, device limits and speed limits,
//! * a SQLite store that survives restarts,
//! * a local admin API,
//! * an Xboard panel client for user sync and traffic reporting (V1 and V2).

pub mod accounting;
pub mod admin;
pub mod config;
pub mod node;
pub mod panel;
pub mod relay;
pub mod server;
pub mod store;
pub mod ws;

pub use node::Node;

use std::sync::OnceLock;
use std::time::Instant;

static START: OnceLock<Instant> = OnceLock::new();

pub fn mark_start() {
    START.get_or_init(Instant::now);
}

pub fn uptime_seconds() -> u64 {
    START.get().map(|start| start.elapsed().as_secs()).unwrap_or_default()
}

pub use config::{Config, User, UserSpec};
pub use store::Store;
