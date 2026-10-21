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

/// A user as returned by the panel.
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

/// Reject an invalid full credential snapshot before it reaches storage or the listener.
pub(crate) fn validate_user_psks(users: &[UserSpec]) -> std::io::Result<()> {
    let mut keys = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    for user in users {
        if !(12..=255).contains(&user.uuid.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("user {} PSK (uuid) must be 12..=255 bytes", user.id),
            ));
        }
        if !keys.insert(&user.uuid) || !ids.insert(user.id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("duplicate user identity or PSK at user {}", user.id),
            ));
        }
    }
    Ok(())
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
    /// Independent panel-backed nodes served by one process.
    #[serde(default)]
    pub nodes: Vec<ManagedNodeConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ManagedNodeConfig {
    pub name: String,
    pub listen: String,
    #[serde(default)]
    pub psk: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    pub panel: PanelConfig,
    pub admin: AdminConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Legacy setting, ignored. Clients use their panel UUID as their PSK.
    #[serde(default)]
    pub psk: String,
    /// Only `default` supports per-user PSK identification.
    #[serde(default = "default_mode")]
    pub mode: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig { listen: default_listen(), psk: String::new(), mode: default_mode() }
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

const LEGACY_DEFAULT_STORAGE_PATH: &str = "snell-xboard-node.db";

fn default_storage_path() -> String {
    "xboard-snell.db".into()
}

fn storage_path_was_specified(document: &toml::Value) -> bool {
    document.get("storage").and_then(toml::Value::as_table).is_some_and(|storage| storage.contains_key("path"))
}

fn preserve_legacy_default_database(
    storage: &mut StorageConfig,
    directory: &std::path::Path,
    storage_path_explicit: bool,
) {
    if storage_path_explicit || storage.path != default_storage_path() {
        return;
    }
    let current = directory.join(&storage.path);
    let legacy = directory.join(LEGACY_DEFAULT_STORAGE_PATH);
    if !current.exists() && legacy.is_file() {
        storage.path = LEGACY_DEFAULT_STORAGE_PATH.into();
    }
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
        let document: toml::Value = toml::from_str(&content).map_err(|err| ConfigError::Parse(err.to_string()))?;
        let storage_path_explicit = storage_path_was_specified(&document);
        let mut config: Config =
            document.try_into().map_err(|err: toml::de::Error| ConfigError::Parse(err.to_string()))?;
        preserve_legacy_default_database(&mut config.storage, std::path::Path::new("."), storage_path_explicit);
        config.validate()?;
        Ok(config)
    }

    pub fn managed_node_config(&self, node: &ManagedNodeConfig) -> Result<Config, ConfigError> {
        let mut config = self.clone();
        config.node = NodeConfig { listen: node.listen.clone(), psk: node.psk.clone(), mode: node.mode.clone() };
        config.panel = Some(node.panel.clone());
        config.admin = node.admin.clone();
        config.nodes.clear();
        config.storage.path = managed_storage_path(&self.storage.path, &node.name);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&mut self) -> Result<(), ConfigError> {
        if !self.nodes.is_empty() {
            let legacy_node_configured =
                self.node.listen != default_listen() || self.node.mode != default_mode() || !self.node.psk.is_empty();
            let default_admin = AdminConfig::default();
            let legacy_admin_configured = self.admin.listen != default_admin.listen
                || self.admin.token != default_admin.token
                || self.admin.disabled != default_admin.disabled;
            if self.panel.is_some() || legacy_node_configured || legacy_admin_configured {
                return Err(ConfigError::MixedNodeConfiguration);
            }
            let mut names = std::collections::HashSet::new();
            let mut ips = std::collections::HashSet::new();
            let mut listeners = Vec::new();
            let mut admins = Vec::new();
            let mut panels = std::collections::HashSet::new();
            for node in &self.nodes {
                if node.name.is_empty()
                    || !node.name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                    || !names.insert(node.name.to_ascii_lowercase())
                {
                    return Err(ConfigError::InvalidNodeName(node.name.clone()));
                }
                let address: std::net::SocketAddr =
                    node.listen.parse().map_err(|_| ConfigError::InvalidNodeListen(node.name.clone()))?;
                let mapped = matches!(address.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some());
                if mapped || address.ip().is_unspecified() || !ips.insert(address.ip()) {
                    return Err(ConfigError::DuplicateNodeIp(node.listen.clone()));
                }
                listeners.push(address);
                if !node.admin.disabled {
                    if node.admin.token.is_empty() {
                        return Err(ConfigError::InvalidAdminToken(node.name.clone()));
                    }
                    let admin: std::net::SocketAddr =
                        node.admin.listen.parse().map_err(|_| ConfigError::InvalidAdminListen(node.name.clone()))?;
                    admins.push(admin);
                }
                let panel_identity = (
                    node.panel.url.trim_end_matches('/').to_string(),
                    node.panel.token.clone(),
                    node.panel.node_id,
                    node.panel.machine_id,
                );
                if !panels.insert(panel_identity) {
                    return Err(ConfigError::DuplicatePanelNode(node.name.clone()));
                }
                validate_node_credentials(&node.psk, &node.mode)?;
                validate_panel(&node.panel, &node.name)?;
            }
            for (index, &admin) in admins.iter().enumerate() {
                if listeners.iter().any(|&listener| listen_addresses_overlap(admin, listener))
                    || admins[..index].iter().any(|&other| listen_addresses_overlap(admin, other))
                {
                    return Err(ConfigError::DuplicateAdminListen(admin.to_string()));
                }
            }
            return Ok(());
        }
        validate_node_credentials(&self.node.psk, &self.node.mode)?;
        let panel = self.panel.as_ref().ok_or(ConfigError::MissingPanel)?;
        validate_panel(panel, "default")?;
        Ok(())
    }
}

fn listen_addresses_overlap(first: std::net::SocketAddr, second: std::net::SocketAddr) -> bool {
    if first.port() == 0 || first.port() != second.port() {
        return false;
    }
    let first_ip = first.ip().to_canonical();
    let second_ip = second.ip().to_canonical();
    // IPv6 wildcard sockets may also accept IPv4 on supported platforms.
    first_ip == second_ip
        || first_ip == std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        || second_ip == std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        || (first_ip.is_ipv4() && second_ip.is_ipv4() && (first_ip.is_unspecified() || second_ip.is_unspecified()))
}

fn managed_storage_path(base: &str, name: &str) -> String {
    let path = std::path::Path::new(base);
    let stem = path.file_stem().and_then(|value| value.to_str()).unwrap_or("xboard-snell");
    let extension = path.extension().and_then(|value| value.to_str());
    let filename = match extension {
        Some(extension) => format!("{stem}-{name}.{extension}"),
        None => format!("{stem}-{name}"),
    };
    path.with_file_name(filename).to_string_lossy().into_owned()
}

fn validate_panel(panel: &PanelConfig, name: &str) -> Result<(), ConfigError> {
    let valid_url = url::Url::parse(&panel.url)
        .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some());
    if !valid_url
        || panel.token.trim().is_empty()
        || !matches!(panel.api_version, 1 | 2)
        || panel.pull_interval == 0
        || panel.push_interval == 0
    {
        return Err(ConfigError::InvalidPanel(name.into()));
    }
    Ok(())
}

fn validate_node_credentials(psk: &str, mode: &str) -> Result<(), ConfigError> {
    if !psk.is_empty() && !(12..=255).contains(&psk.len()) {
        return Err(ConfigError::InvalidPsk(psk.len()));
    }
    if snell::v6::parse_mode(mode).ok() != Some(snell::v6::Mode::Default) {
        return Err(ConfigError::InvalidMode(mode.to_string()));
    }
    Ok(())
}

#[derive(Debug)]
pub enum ConfigError {
    Read(String, std::io::Error),
    Parse(String),
    InvalidPsk(usize),
    InvalidMode(String),
    MissingPanel,
    MixedNodeConfiguration,
    InvalidNodeName(String),
    InvalidNodeListen(String),
    DuplicateNodeIp(String),
    DuplicateAdminListen(String),
    InvalidPanel(String),
    InvalidAdminListen(String),
    DuplicatePanelNode(String),
    InvalidAdminToken(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Read(path, err) => write!(f, "read {path}: {err}"),
            ConfigError::Parse(err) => write!(f, "parse config: {err}"),
            ConfigError::InvalidPsk(len) => {
                write!(f, "psk must be 12..=255 bytes long (got {len})")
            }
            ConfigError::InvalidMode(mode) => write!(f, "per-user PSKs require snell v6 default mode (got {mode})"),
            ConfigError::MissingPanel => {
                write!(f, "panel configuration is required; standalone mode is no longer supported")
            }
            ConfigError::MixedNodeConfiguration => {
                write!(f, "managed nodes cannot be combined with top-level node, panel or admin settings")
            }
            ConfigError::InvalidNodeName(name) => {
                write!(f, "invalid or duplicate managed node name: {name}")
            }
            ConfigError::InvalidNodeListen(name) => {
                write!(f, "node {name}: listen must be a literal IP socket address")
            }
            ConfigError::DuplicateNodeIp(listen) => {
                write!(f, "managed nodes require distinct, specific, non-mapped listen IPs: {listen}")
            }
            ConfigError::DuplicateAdminListen(listen) => {
                write!(f, "duplicate managed-node admin listen address: {listen}")
            }
            ConfigError::InvalidPanel(name) => write!(
                f,
                "node {name}: panel requires an HTTP(S) URL, non-empty token, API version 1 or 2 and positive pull/push intervals"
            ),
            ConfigError::InvalidAdminListen(name) => {
                write!(f, "node {name}: admin listen must be a socket address")
            }
            ConfigError::DuplicatePanelNode(name) => {
                write!(f, "node {name}: another managed node uses the same panel credentials and ID")
            }
            ConfigError::InvalidAdminToken(name) => {
                write!(f, "node {name}: enabled admin API requires a non-empty token")
            }
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
    fn existing_legacy_default_database_is_selected_without_overwriting_new_data() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = temp.path().join("snell-xboard-node.db");
        std::fs::write(&legacy, b"existing database").unwrap();
        let mut storage = StorageConfig::default();
        preserve_legacy_default_database(&mut storage, temp.path(), false);
        assert_eq!("snell-xboard-node.db", storage.path);

        storage.path = default_storage_path();
        preserve_legacy_default_database(&mut storage, temp.path(), true);
        assert_eq!("xboard-snell.db", storage.path);

        let current = temp.path().join("xboard-snell.db");
        std::fs::write(&current, b"new database").unwrap();
        storage.path = default_storage_path();
        preserve_legacy_default_database(&mut storage, temp.path(), false);
        assert_eq!("xboard-snell.db", storage.path);

        storage.path = "custom.db".into();
        preserve_legacy_default_database(&mut storage, temp.path(), false);
        assert_eq!("custom.db", storage.path);
    }

    #[test]
    fn storage_path_presence_distinguishes_omitted_and_explicit_default() {
        let omitted: toml::Value = toml::from_str("[node]\npsk = \"123456789012\"\n").unwrap();
        let table_without_path: toml::Value = toml::from_str("[storage]\n").unwrap();
        let explicit_default: toml::Value = toml::from_str("[storage]\npath = \"xboard-snell.db\"\n").unwrap();
        assert!(!storage_path_was_specified(&omitted));
        assert!(!storage_path_was_specified(&table_without_path));
        assert!(storage_path_was_specified(&explicit_default));
    }

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
        assert_eq!("default", config.node.mode);
        assert!(config.node.psk.is_empty());
        config.panel = None;
        assert!(matches!(config.validate(), Err(ConfigError::MissingPanel)));
    }

    #[test]
    fn nodes_reject_modes_without_psk_fingerprints() {
        let mut config = Config::load(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml")).unwrap();
        for mode in ["unshaped", "unsafe-raw", "invalid"] {
            config.node.mode = mode.into();
            assert!(matches!(config.validate(), Err(ConfigError::InvalidMode(_))));
        }
    }

    #[test]
    fn managed_node_example_is_valid_and_uses_separate_databases() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/config.multi-node.example.toml");
        let config = Config::load(path).expect("multi-node example must parse and validate");
        assert_eq!(2, config.nodes.len());
        let first = config.managed_node_config(&config.nodes[0]).unwrap();
        let second = config.managed_node_config(&config.nodes[1]).unwrap();
        assert_ne!(first.storage.path, second.storage.path);
        assert!(first.storage.path.ends_with("xboard-snell-edge-a.db"));
        assert_eq!(1, first.panel.unwrap().node_id);
        assert_eq!(2, second.panel.unwrap().node_id);
    }

    #[test]
    fn managed_nodes_reject_wildcard_duplicate_ips_and_admin_endpoints() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/config.multi-node.example.toml");
        let mut config = Config::load(path).unwrap();
        config.nodes[1].listen = "192.0.2.10:6161".into();
        assert!(matches!(config.validate(), Err(ConfigError::DuplicateNodeIp(_))));

        let mut config = Config::load(path).unwrap();
        config.nodes[0].listen = "0.0.0.0:6160".into();
        assert!(matches!(config.validate(), Err(ConfigError::DuplicateNodeIp(_))));

        let mut config = Config::load(path).unwrap();
        config.nodes[1].name = "EDGE-A".into();
        assert!(matches!(config.validate(), Err(ConfigError::InvalidNodeName(_))));

        let mut config = Config::load(path).unwrap();
        config.nodes[1].admin.listen = config.nodes[0].admin.listen.clone();
        assert!(matches!(config.validate(), Err(ConfigError::DuplicateAdminListen(_))));

        let mut config = Config::load(path).unwrap();
        config.nodes[0].admin.token.clear();
        assert!(matches!(config.validate(), Err(ConfigError::InvalidAdminToken(_))));

        let mut config = Config::load(path).unwrap();
        config.nodes[1].panel.token = config.nodes[0].panel.token.clone();
        config.nodes[1].panel.node_id = config.nodes[0].panel.node_id;
        assert!(matches!(config.validate(), Err(ConfigError::DuplicatePanelNode(_))));

        let mut config = Config::load(path).unwrap();
        config.node.listen = "127.0.0.1:6160".into();
        assert!(matches!(config.validate(), Err(ConfigError::MixedNodeConfiguration)));

        let mut config = Config::load(path).unwrap();
        config.admin.disabled = true;
        assert!(matches!(config.validate(), Err(ConfigError::MixedNodeConfiguration)));

        let mut config = Config::load(path).unwrap();
        config.panel = Some(PanelConfig {
            url: "https://example.com".into(),
            token: "legacy".into(),
            ..config.nodes[0].panel.clone()
        });
        assert!(matches!(config.validate(), Err(ConfigError::MixedNodeConfiguration)));
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
            nodes: Vec::new(),
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPsk(5))));
        config.node.psk = "0123456789ab".into();
        assert!(matches!(config.validate(), Err(ConfigError::MissingPanel)));
    }
}
