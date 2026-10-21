//! Xboard panel client.
//!
//! Implements the node side of the panel's server API, following the
//! reference node implementation:
//!
//! * V2 (current): `POST /api/v2/server/handshake`, `GET /api/v2/server/config`,
//!   `GET /api/v2/server/user`, `POST /api/v2/server/report`.
//! * V1 (legacy): `GET /api/v1/server/UniProxy/{config,user,alivelist}`,
//!   `POST /api/v1/server/UniProxy/{push,alive,status}`.
//!
//! Authentication is `token` + `node_id` (or `machine_id` + `token` in
//! machine mode), passed as query parameters for GET and as body fields for
//! POST, exactly like the panel expects.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::warn;

use crate::config::{PanelConfig, Traffic, UserSpec};

#[derive(Debug)]
pub enum PanelError {
    Request(reqwest::Error),
    Status { status: u16, body: String },
    Decode(String),
}

impl std::fmt::Display for PanelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PanelError::Request(err) => write!(f, "panel request: {err}"),
            PanelError::Status { status, body } => write!(f, "panel status {status}: {body}"),
            PanelError::Decode(message) => write!(f, "panel response: {message}"),
        }
    }
}

impl std::error::Error for PanelError {}

impl From<reqwest::Error> for PanelError {
    fn from(err: reqwest::Error) -> Self {
        PanelError::Request(err)
    }
}

/// Node configuration returned by the panel.
#[derive(Clone, Debug, Deserialize)]
pub struct NodeConfig {
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub listen_ip: String,
    #[serde(default)]
    pub server_port: u16,
    #[serde(default)]
    pub base_config: BaseConfig,
    #[serde(default)]
    pub cert_config: Option<Value>,
    #[serde(default)]
    pub routes: Value,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BaseConfig {
    #[serde(default)]
    pub push_interval: u64,
    #[serde(default)]
    pub pull_interval: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Handshake {
    #[serde(default)]
    pub websocket: WebSocketConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct WebSocketConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub ws_url: String,
}

/// The panel API client.
pub struct PanelClient {
    config: PanelConfig,
    http: reqwest::Client,
    base: String,
}

impl PanelClient {
    pub fn new(config: PanelConfig) -> Result<PanelClient, PanelError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("xboard-snell/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let base = config.url.trim_end_matches('/').to_string();
        Ok(PanelClient { config, http, base })
    }

    fn auth_query(&self) -> Vec<(String, String)> {
        let mut query = vec![("token".to_string(), self.config.token.clone())];
        match self.config.machine_id {
            Some(machine_id) => {
                query.push(("machine_id".to_string(), machine_id.to_string()));
                if self.config.node_id > 0 {
                    query.push(("node_id".to_string(), self.config.node_id.to_string()));
                }
            }
            None => query.push(("node_id".to_string(), self.config.node_id.to_string())),
        }
        query
    }

    fn auth_fields(&self) -> serde_json::Map<String, Value> {
        let mut fields = serde_json::Map::new();
        fields.insert("token".into(), json!(self.config.token));
        match self.config.machine_id {
            Some(machine_id) => {
                fields.insert("machine_id".into(), json!(machine_id));
                if self.config.node_id > 0 {
                    fields.insert("node_id".into(), json!(self.config.node_id));
                }
            }
            None => {
                fields.insert("node_id".into(), json!(self.config.node_id));
            }
        }
        fields
    }

    fn config_path(&self) -> &'static str {
        if self.config.api_version >= 2 { "/api/v2/server/config" } else { "/api/v1/server/UniProxy/config" }
    }

    fn user_path(&self) -> &'static str {
        if self.config.api_version >= 2 { "/api/v2/server/user" } else { "/api/v1/server/UniProxy/user" }
    }

    async fn get_json(&self, path: &str) -> Result<Value, PanelError> {
        let mut url = reqwest::Url::parse(&format!("{}{}", self.base, path))
            .map_err(|err| PanelError::Decode(err.to_string()))?;
        url.query_pairs_mut().extend_pairs(self.auth_query());
        let response = self.http.get(url).send().await?;
        self.decode(response).await
    }

    async fn post_json(&self, path: &str, body: Value) -> Result<Value, PanelError> {
        let response = self.http.post(format!("{}{}", self.base, path)).json(&body).send().await?;
        self.decode(response).await
    }

    async fn decode(&self, response: reqwest::Response) -> Result<Value, PanelError> {
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(PanelError::Status { status: status.as_u16(), body: truncate(&body) });
        }
        if body.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&body).map_err(|err| PanelError::Decode(err.to_string()))
    }

    pub async fn handshake(&self) -> Result<Handshake, PanelError> {
        let mut body = serde_json::Map::new();
        body.extend(self.auth_fields());
        let value = self.post_json("/api/v2/server/handshake", Value::Object(body)).await?;
        serde_json::from_value(value).map_err(|err| PanelError::Decode(err.to_string()))
    }

    pub async fn fetch_config(&self) -> Result<NodeConfig, PanelError> {
        let value = self.get_json(self.config_path()).await?;
        serde_json::from_value(value).map_err(|err| PanelError::Decode(err.to_string()))
    }

    pub async fn fetch_users(&self) -> Result<Vec<UserSpec>, PanelError> {
        let value = self.get_json(self.user_path()).await?;
        let users =
            value.get("users").cloned().ok_or_else(|| PanelError::Decode("missing users in panel response".into()))?;
        let users: Vec<PanelUser> = serde_json::from_value(users).map_err(|err| PanelError::Decode(err.to_string()))?;
        Ok(users.into_iter().map(Into::into).collect())
    }

    /// Sends one combined report: traffic, alive IPs, connection counts,
    /// system status and node metrics.
    pub async fn report(
        &self,
        traffic: &[(i64, Traffic)],
        alive: &[(i64, Vec<String>)],
        online: &[(i64, usize)],
        status: SystemStatus,
        metrics: Value,
    ) -> Result<(), PanelError> {
        let mut body = self.auth_fields();
        if !traffic.is_empty() {
            let mut map = serde_json::Map::new();
            for (id, traffic) in traffic {
                map.insert(id.to_string(), json!([traffic.upload, traffic.download]));
            }
            body.insert("traffic".into(), Value::Object(map));
        }
        if !alive.is_empty() {
            let mut map = serde_json::Map::new();
            for (id, ips) in alive {
                map.insert(id.to_string(), json!(ips));
            }
            body.insert("alive".into(), Value::Object(map));
        }
        if !online.is_empty() {
            let mut map = serde_json::Map::new();
            for (id, count) in online {
                map.insert(id.to_string(), json!(count));
            }
            body.insert("online".into(), Value::Object(map));
        }
        body.insert("status".into(), status.to_json());
        body.insert("metrics".into(), metrics);
        self.post_json("/api/v2/server/report", Value::Object(body)).await.map(|_| ())
    }

    /// V1 traffic push.
    pub async fn push_traffic(&self, traffic: &[(i64, Traffic)]) -> Result<(), PanelError> {
        if traffic.is_empty() {
            return Ok(());
        }
        let mut body = self.auth_fields();
        for (id, traffic) in traffic {
            body.insert(id.to_string(), json!([traffic.upload, traffic.download]));
        }
        self.post_json("/api/v1/server/UniProxy/push", Value::Object(body)).await.map(|_| ())
    }

    /// V1 alive IP push.
    pub async fn push_alive(&self, alive: &[(i64, Vec<String>)]) -> Result<(), PanelError> {
        if alive.is_empty() {
            return Ok(());
        }
        let mut body = self.auth_fields();
        for (id, ips) in alive {
            body.insert(id.to_string(), json!(ips));
        }
        self.post_json("/api/v1/server/UniProxy/alive", Value::Object(body)).await.map(|_| ())
    }

    /// V1 status push.
    pub async fn push_status(&self, status: SystemStatus) -> Result<(), PanelError> {
        let mut body = self.auth_fields();
        if let Value::Object(status) = status.to_json() {
            body.extend(status);
        }
        self.post_json("/api/v1/server/UniProxy/status", Value::Object(body)).await.map(|_| ())
    }

    pub async fn machine_nodes(&self) -> Result<Value, PanelError> {
        let mut body = self.auth_fields();
        body.remove("node_id");
        self.post_json("/api/v2/server/machine/nodes", Value::Object(body)).await
    }

    pub async fn report_machine_status(&self, status: SystemStatus) -> Result<(), PanelError> {
        let mut body = self.auth_fields();
        body.remove("node_id");
        if let Value::Object(status) = status.to_json() {
            body.extend(status);
        }
        self.post_json("/api/v2/server/machine/status", Value::Object(body)).await.map(|_| ())
    }

    pub fn api_version(&self) -> u8 {
        self.config.api_version
    }
}

fn truncate(body: &str) -> String {
    const LIMIT: usize = 4096;
    if body.len() <= LIMIT { body.to_string() } else { format!("{}…", &body[..LIMIT]) }
}

#[derive(Deserialize)]
pub(crate) struct PanelUser {
    id: i64,
    #[serde(default)]
    uuid: String,
    // Xboard sends null for groups whose limit is unset.
    #[serde(default, deserialize_with = "null_as_zero")]
    speed_limit: u64,
    #[serde(default, deserialize_with = "null_as_zero")]
    device_limit: u32,
    #[serde(default, deserialize_with = "null_as_zero")]
    transfer_enable: u64,
    #[serde(default, deserialize_with = "null_as_zero")]
    expired_at: i64,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

fn default_enabled() -> bool {
    true
}

fn null_as_zero<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

impl From<PanelUser> for UserSpec {
    fn from(user: PanelUser) -> Self {
        UserSpec {
            id: user.id,
            uuid: user.uuid,
            speed_limit: user.speed_limit,
            device_limit: user.device_limit,
            transfer_enable: user.transfer_enable,
            expired_at: user.expired_at,
            enabled: user.enabled,
        }
    }
}

/// System status reported to the panel (`/status`, `/report`).
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct SystemStatus {
    pub cpu: f64,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disk_total: u64,
    pub disk_used: u64,
}

impl SystemStatus {
    fn to_json(self) -> Value {
        json!({
            "cpu": self.cpu,
            "mem": {"total": self.mem_total, "used": self.mem_used},
            "swap": {"total": self.swap_total, "used": self.swap_used},
            "disk": {"total": self.disk_total, "used": self.disk_used},
        })
    }
}

/// Builds the metrics object the panel stores for a node.
pub fn build_metrics(
    uptime: u64,
    active_connections: u64,
    total_connections: u64,
    total_users: usize,
    active_users: usize,
    upload_speed: u64,
    download_speed: u64,
) -> Value {
    json!({
        "uptime": uptime,
        "goroutines": 0,
        "active_connections": active_connections,
        "total_connections": total_connections,
        "total_users": total_users,
        "active_users": active_users,
        "inbound_speed": download_speed,
        "outbound_speed": upload_speed,
        "limits": {
            "device_limit_events": 0,
            "speed_limited_users": 0,
        },
    })
}

/// Reads the local system status from `/proc`-independent sources where
/// available, falling back to zeros on platforms without them.
pub fn system_status() -> SystemStatus {
    #[cfg(target_os = "linux")]
    {
        linux_status()
    }
    #[cfg(not(target_os = "linux"))]
    {
        SystemStatus::default()
    }
}

#[cfg(target_os = "linux")]
fn linux_status() -> SystemStatus {
    fn read_meminfo() -> Option<(u64, u64, u64, u64)> {
        let content = std::fs::read_to_string("/proc/meminfo").ok()?;
        let mut total = 0;
        let mut available = 0;
        let mut swap_total = 0;
        let mut swap_free = 0;
        for line in content.lines() {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            let value: u64 = fields.next()?.parse::<u64>().ok()? * 1024;
            match key {
                "MemTotal:" => total = value,
                "MemAvailable:" => available = value,
                "SwapTotal:" => swap_total = value,
                "SwapFree:" => swap_free = value,
                _ => {}
            }
        }
        Some((total, total.saturating_sub(available), swap_total, swap_total.saturating_sub(swap_free)))
    }
    fn load_average() -> f64 {
        std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|content| content.split_whitespace().next().and_then(|v| v.parse().ok()))
            .unwrap_or(0.0)
    }
    fn cpu_count() -> f64 {
        std::thread::available_parallelism().map(|n| n.get() as f64).unwrap_or(1.0)
    }
    let mut status = SystemStatus { cpu: (load_average() / cpu_count() * 100.0).min(100.0), ..Default::default() };
    if let Some((total, used, swap_total, swap_used)) = read_meminfo() {
        status.mem_total = total;
        status.mem_used = used;
        status.swap_total = swap_total;
        status.swap_used = swap_used;
    }
    status
}

/// Logs a panel failure but never aborts the node: a panel outage must not
/// drop live connections.
pub fn log_panel_error(context: &str, err: &PanelError) {
    warn!(context, error = %err, "panel request failed");
}

pub type SharedPanel = Arc<PanelClient>;

#[allow(dead_code)]
fn _debug(_: &dyn std::fmt::Debug) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_user_maps_limits() {
        let user: UserSpec =
            serde_json::from_str::<PanelUser>(r#"{"id":5,"uuid":"abc","speed_limit":100,"device_limit":3}"#)
                .map(Into::into)
                .unwrap();
        assert_eq!(5, user.id);
        assert_eq!("abc", user.uuid);
        assert_eq!(100, user.speed_limit);
        assert_eq!(3, user.device_limit);
    }

    #[test]
    fn status_json_matches_panel_schema() {
        let status = SystemStatus {
            cpu: 12.5,
            mem_total: 100,
            mem_used: 40,
            swap_total: 0,
            swap_used: 0,
            disk_total: 1000,
            disk_used: 250,
        };
        let json = status.to_json();
        assert_eq!(12.5, json["cpu"]);
        assert_eq!(100, json["mem"]["total"]);
        assert_eq!(40, json["mem"]["used"]);
        assert_eq!(1000, json["disk"]["total"]);
    }

    #[test]
    fn metrics_contain_panel_fields() {
        let metrics = build_metrics(10, 2, 3, 4, 1, 100, 200);
        for key in [
            "uptime",
            "goroutines",
            "active_connections",
            "total_connections",
            "total_users",
            "active_users",
            "inbound_speed",
            "outbound_speed",
            "limits",
        ] {
            assert!(metrics.get(key).is_some(), "missing {key}");
        }
    }
}
