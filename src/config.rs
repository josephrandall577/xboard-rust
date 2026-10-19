//! Shared types for the Snell v6 Xboard node backend.
//!
//! The user model mirrors the fields Xboard sends to its nodes
//! (`id`, `uuid`, `speed_limit`, `device_limit`) plus the local quota
//! bookkeeping the node needs to enforce limits on its own.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A node user as stored locally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub uuid: String,
    /// Xboard `speed_limit`, in Mbps. `0` means unlimited.
    pub speed_limit: u64,
    /// Xboard `device_limit`, in distinct source IPs. `0` means unlimited.
    pub device_limit: u32,
    /// Total traffic allowance in bytes. `0` means unlimited.
    pub transfer_enable: u64,
    /// Unix timestamp after which the user is disabled. `0` means never.
    pub expired_at: i64,
    pub enabled: bool,
    pub upload: u64,
    pub download: u64,
}

impl User {
    pub fn key(&self) -> &[u8] {
        self.uuid.as_bytes()
    }

    pub fn used(&self) -> u64 {
        self.upload.saturating_add(self.download)
    }

    /// Whether the user may open new connections right now.
    pub fn is_active(&self, now: i64) -> bool {
        self.enabled
            && (self.expired_at == 0 || now < self.expired_at)
            && (self.transfer_enable == 0 || self.used() < self.transfer_enable)
    }

    /// Remaining bytes, or `None` when unlimited.
    pub fn remaining(&self) -> Option<u64> {
        (self.transfer_enable > 0).then(|| self.transfer_enable.saturating_sub(self.used()))
    }
}

/// A user as returned by the panel or configured locally.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserSpec {
    pub id: i64,
    pub uuid: String,
    #[serde(default)]
    pub speed_limit: u64,
    #[serde(default)]
    pub device_limit: u32,
    #[serde(default)]
    pub transfer_enable: u64,
    #[serde(default)]
    pub expired_at: i64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl From<UserSpec> for User {
    fn from(spec: UserSpec) -> Self {
        User {
            id: spec.id,
            uuid: spec.uuid,
            speed_limit: spec.speed_limit,
            device_limit: spec.device_limit,
            transfer_enable: spec.transfer_enable,
            expired_at: spec.expired_at,
            enabled: spec.enabled,
            upload: 0,
            download: 0,
        }
    }
}

impl From<&User> for UserSpec {
    fn from(user: &User) -> Self {
        UserSpec {
            id: user.id,
            uuid: user.uuid.clone(),
            speed_limit: user.speed_limit,
            device_limit: user.device_limit,
            transfer_enable: user.transfer_enable,
            expired_at: user.expired_at,
            enabled: user.enabled,
        }
    }
}

/// Identity of an authenticated user inside the Snell v6 service.
///
/// Only the fields that identify the user participate in equality and
/// hashing. The service stores this value in the per-connection context and
/// in its user map, so changing limits or counters must not change identity.
#[derive(Clone, Debug)]
pub struct UserEntry {
    pub user: User,
    pub key: Vec<u8>,
}

impl PartialEq for UserEntry {
    fn eq(&self, other: &Self) -> bool {
        self.user.id == other.user.id && self.user.uuid == other.user.uuid
    }
}

impl Eq for UserEntry {}

impl std::hash::Hash for UserEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.user.id.hash(state);
        self.user.uuid.hash(state);
    }
}

impl From<&User> for UserEntry {
    fn from(user: &User) -> Self {
        UserEntry { user: user.clone(), key: user.key().to_vec() }
    }
}

/// Per-user traffic delta in `[upload, download]` order, matching the
/// Xboard report format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Traffic {
    pub upload: u64,
    pub download: u64,
}

impl Traffic {
    pub fn total(&self) -> u64 {
        self.upload.saturating_add(self.download)
    }

    pub fn add(&mut self, other: Traffic) {
        self.upload = self.upload.saturating_add(other.upload);
        self.download = self.download.saturating_add(other.download);
    }

    pub fn is_zero(&self) -> bool {
        self.upload == 0 && self.download == 0
    }
}

/// A flushed report ready to send to the panel.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub traffic: Vec<(i64, Traffic)>,
    pub alive: Vec<(i64, Vec<String>)>,
    pub online: Vec<(i64, usize)>,
}

impl Report {
    pub fn is_empty(&self) -> bool {
        self.traffic.is_empty() && self.alive.is_empty() && self.online.is_empty()
    }
}

/// Node runtime configuration, from the TOML file.
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub node: NodeConfig,
    pub panel: Option<PanelConfig>,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Server PSK. Must be 12..=255 bytes, like the official server.
    pub psk: String,
    /// `default`, `unshaped` or `unsafe-raw`.
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Optional local users, used when no panel is configured.
    #[serde(default)]
    pub users: Vec<UserSpec>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig { listen: default_listen(), psk: String::new(), mode: default_mode(), users: Vec::new() }
    }
}

fn default_listen() -> String {
    "0.0.0.0:6160".into()
}

fn default_mode() -> String {
    "default".into()
}

#[derive(Clone, Debug, Deserialize)]
pub struct PanelConfig {
    pub url: String,
    pub token: String,
    #[serde(default)]
    pub node_id: i64,
    /// Poll interval in seconds for config/user refresh.
    #[serde(default = "default_pull_interval")]
    pub pull_interval: u64,
    /// Report interval in seconds for traffic/alive/status.
    #[serde(default = "default_push_interval")]
    pub push_interval: u64,
    /// Xboard API generation: `1` (`/api/v1/server/UniProxy/*`) or `2`
    /// (`/api/v2/server/*`). Defaults to `2`.
    #[serde(default = "default_api_version")]
    pub api_version: u8,
    /// Optional WebSocket endpoint for panel push events.
    #[serde(default)]
    pub ws_url: Option<String>,
    #[serde(default)]
    pub machine_id: Option<i64>,
}

fn default_pull_interval() -> u64 {
    60
}

fn default_push_interval() -> u64 {
    60
}

fn default_api_version() -> u8 {
    2
}

#[derive(Clone, Debug, Deserialize)]
pub struct AdminConfig {
    #[serde(default = "default_admin_listen")]
    pub listen: String,
    /// Bearer token for the admin API. Empty disables authentication
    /// (not recommended outside loopback).
    #[serde(default)]
    pub token: String,
    /// Disable the admin API entirely.
    #[serde(default)]
    pub disabled: bool,
}

impl Default for AdminConfig {
    fn default() -> Self {
        AdminConfig { listen: default_admin_listen(), token: String::new(), disabled: false }
    }
}

fn default_admin_listen() -> String {
    "127.0.0.1:6161".into()
}

#[derive(Clone, Debug, Deserialize)]
pub struct LimitsConfig {
    /// How long a source IP counts as an active device after its last
    /// connection closes, in seconds.
    #[serde(default = "default_device_ttl")]
    pub device_ttl: u64,
    /// Refuse new connections once the user's traffic allowance is used up.
    #[serde(default = "default_true")]
    pub enforce_quota: bool,
    /// Extra bytes allowed beyond the quota so a connection is not cut
    /// exactly at the limit.
    #[serde(default)]
    pub quota_grace: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig { device_ttl: default_device_ttl(), enforce_quota: default_true(), quota_grace: 0 }
    }
}

fn default_device_ttl() -> u64 {
    300
}

#[derive(Clone, Debug, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_storage_path")]
    pub path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig { path: default_storage_path() }
    }
}

fn default_storage_path() -> String {
    "snell-xboard-node.db".into()
}

#[derive(Clone, Debug, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig { level: default_log_level() }
    }
}

fn default_log_level() -> String {
    "info".into()
}

impl Config {
    pub fn load(path: &str) -> Result<Config, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|err| ConfigError::Read(path.into(), err))?;
        let mut config: Config = toml::from_str(&content).map_err(|err| ConfigError::Parse(err.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let len = self.node.psk.len();
        if !(12..=255).contains(&len) {
            return Err(ConfigError::InvalidPsk(len));
        }
        if snell::v6::parse_mode(&self.node.mode).is_err() {
            return Err(ConfigError::InvalidMode(self.node.mode.clone()));
        }
        let mut seen = std::collections::HashSet::new();
        for user in &mut self.node.users {
            if user.uuid.is_empty() || user.uuid.len() > 255 {
                return Err(ConfigError::InvalidUuid(user.id));
            }
            if !seen.insert(user.uuid.clone()) {
                return Err(ConfigError::DuplicateUuid(user.uuid.clone()));
            }
            user.enabled = user.enabled && user.expired_at == 0 || user.enabled;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Read(String, std::io::Error),
    Parse(String),
    InvalidPsk(usize),
    InvalidMode(String),
    InvalidUuid(i64),
    DuplicateUuid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read(path, err) => write!(f, "read {path}: {err}"),
            ConfigError::Parse(err) => write!(f, "parse config: {err}"),
            ConfigError::InvalidPsk(len) => {
                write!(f, "psk must be 12..=255 bytes long (got {len})")
            }
            ConfigError::InvalidMode(mode) => write!(f, "unknown snell v6 mode: {mode}"),
            ConfigError::InvalidUuid(id) => write!(f, "user {id}: uuid must be 1..=255 bytes"),
            ConfigError::DuplicateUuid(uuid) => write!(f, "duplicate user uuid: {uuid}"),
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_activity_rules() {
        let mut user = User {
            id: 1,
            uuid: "u".into(),
            speed_limit: 0,
            device_limit: 0,
            transfer_enable: 100,
            expired_at: 0,
            enabled: true,
            upload: 0,
            download: 0,
        };
        assert!(user.is_active(0));
        user.upload = 60;
        user.download = 40;
        assert!(!user.is_active(0), "quota exhausted");
        assert_eq!(Some(0), user.remaining());
        user.transfer_enable = 0;
        assert!(user.is_active(0), "unlimited quota ignores usage");
        assert_eq!(None, user.remaining());
        user.enabled = false;
        assert!(!user.is_active(0));
        user.enabled = true;
        user.expired_at = 10;
        assert!(!user.is_active(10));
        assert!(user.is_active(9));
    }

    #[test]
    fn example_config_is_valid() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml");
        let mut config = Config::load(path).expect("example config must parse");
        // The example ships a panel block; standalone operation only needs
        // the panel table removed.
        assert_eq!("default", config.node.mode);
        assert!(config.node.psk.len() >= 12);
        config.panel = None;
        config.validate().unwrap();
    }

    #[test]
    fn config_rejects_short_psk() {
        let mut config = Config {
            node: NodeConfig { psk: "short".into(), ..Default::default() },
            panel: None,
            admin: Default::default(),
            limits: Default::default(),
            storage: Default::default(),
            log: Default::default(),
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPsk(5))));
        config.node.psk = "0123456789ab".into();
        assert!(config.validate().is_ok());
    }
}
