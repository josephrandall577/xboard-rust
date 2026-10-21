//! The node controller: startup, the user-sync loop and the report loop.
//!
//! The node is designed so the data plane never depends on the panel:
//! panel requests run in background tasks, and a panel outage only delays
//! synchronization. Traffic deltas that fail to reach the panel are restored
//! to the pending buffer and retried on the next report tick.

use std::net::{SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, OnceCell, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::accounting::{Counters, Registry};
use crate::admin::AdminState;
use crate::config::Config;
use crate::panel::{PanelClient, build_metrics, log_panel_error, system_status};
use crate::server::SnellServer;
use crate::store::Store;

/// Shared handles for the running node.
/// Records the process start time used by the uptime metric.
pub fn mark_start() {
    crate::mark_start();
}

pub struct Node {
    pub name: String,
    pub config: Config,
    pub store: Store,
    pub registry: Arc<Registry>,
    pub counters: Arc<Counters>,
    pub panel: Arc<PanelClient>,
    pub server: Arc<RwLock<Option<Arc<SnellServer>>>>,
    cancel: CancellationToken,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    report_lock: Arc<Mutex<()>>,
    stopped: OnceCell<()>,
}

impl Node {
    pub async fn start_many(mut config: Config) -> Result<Vec<Arc<Node>>, Box<dyn std::error::Error + Send + Sync>> {
        config.validate()?;
        if config.nodes.is_empty() {
            return Ok(vec![Self::start(config).await?]);
        }
        let definitions = std::mem::take(&mut config.nodes);
        let mut nodes = Vec::with_capacity(definitions.len());
        for definition in definitions {
            let name = definition.name.clone();
            let node_config = config.managed_node_config(&definition)?;
            let listen: SocketAddr = node_config.node.listen.parse()?;
            let outbound = match listen {
                SocketAddr::V4(address) => SocketAddr::V4(std::net::SocketAddrV4::new(*address.ip(), 0)),
                SocketAddr::V6(address) => {
                    SocketAddr::V6(SocketAddrV6::new(*address.ip(), 0, address.flowinfo(), address.scope_id()))
                }
            };
            match Self::start_inner(node_config, name, Some(outbound)).await {
                Ok(node) => nodes.push(node),
                Err(err) => {
                    for node in &nodes {
                        node.shutdown().await;
                    }
                    return Err(err);
                }
            }
        }
        Ok(nodes)
    }

    pub async fn start(mut config: Config) -> Result<Arc<Node>, Box<dyn std::error::Error + Send + Sync>> {
        config.validate()?;
        if !config.nodes.is_empty() {
            return Err("use Node::start_many for a multi-node configuration".into());
        }
        Self::start_inner(config, "default".into(), None).await
    }

    async fn start_inner(
        config: Config,
        name: String,
        outbound: Option<SocketAddr>,
    ) -> Result<Arc<Node>, Box<dyn std::error::Error + Send + Sync>> {
        crate::mark_start();
        let panel_config = config.panel.as_ref().ok_or(crate::config::ConfigError::MissingPanel)?;
        let panel = Arc::new(PanelClient::new(panel_config.clone())?);
        let store = Store::open(&config.storage.path)?;
        let registry = Arc::new(Registry::new(Duration::from_secs(config.limits.device_ttl)));
        let counters = Arc::new(Counters::default());
        let users = store.list_users()?;
        registry.apply_users(&users);

        // Bind every required endpoint before reporting startup success.
        let admin_listener =
            if config.admin.disabled { None } else { Some(tokio::net::TcpListener::bind(&config.admin.listen).await?) };
        let server = SnellServer::start(
            &config,
            registry.clone(),
            counters.clone(),
            config.limits.enforce_quota,
            config.limits.quota_grace,
            outbound,
        )
        .await?;
        let server = Arc::new(RwLock::new(Some(Arc::new(server))));
        let admin_state = AdminState {
            store: store.clone(),
            registry: registry.clone(),
            counters: counters.clone(),
            token: Arc::from(config.admin.token.clone()),
        };

        let cancel = CancellationToken::new();
        let mut node = Node {
            name,
            config,
            store,
            registry,
            counters,
            panel,
            server,
            cancel: cancel.clone(),
            tasks: Mutex::new(Vec::new()),
            report_lock: Arc::new(Mutex::new(())),
            stopped: OnceCell::new(),
        };

        node.tasks.get_mut().push({
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let Some(listener) = admin_listener else {
                    return;
                };
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    result = crate::admin::serve_listener(listener, admin_state) => {
                        if let Err(err) = result {
                            error!(error = %err, "admin api stopped");
                        }
                    }
                }
            })
        });

        node.spawn_panel_tasks();

        Ok(Arc::new(node))
    }

    fn spawn_panel_tasks(&mut self) {
        let panel = self.panel.clone();
        let panel_config = self.config.panel.as_ref().expect("validated panel configuration");
        let pull_interval = Duration::from_secs(panel_config.pull_interval);
        let push_interval = Duration::from_secs(panel_config.push_interval);

        let cancel = self.cancel.clone();
        let store = self.store.clone();
        let registry = self.registry.clone();
        let server = self.server.clone();
        let panel_clone = panel.clone();
        self.tasks.get_mut().push(tokio::spawn(async move {
            pull_loop(panel_clone, store, registry, server, pull_interval, cancel).await;
        }));

        let cancel = self.cancel.clone();
        let store = self.store.clone();
        let registry = self.registry.clone();
        let counters = self.counters.clone();
        let panel_clone = panel.clone();
        let report_lock = self.report_lock.clone();
        self.tasks.get_mut().push(tokio::spawn(async move {
            push_loop(panel_clone, store, registry, counters, push_interval, cancel, report_lock).await;
        }));

        // Panel WebSocket push (optional): polling above stays the baseline,
        // so a missing socket only adds latency to user changes.
        if let Some(ws_url) = panel_config.ws_url.clone() {
            let cancel = self.cancel.clone();
            let store = self.store.clone();
            let registry = self.registry.clone();
            let server = self.server.clone();
            let token = panel_config.token.clone();
            let node_id = panel_config.node_id;
            let machine_id = panel_config.machine_id;
            let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<crate::config::UserSpec>>();
            let events_store = store.clone();
            self.tasks.get_mut().push(tokio::spawn(async move {
                crate::ws::run(ws_url, token, node_id, machine_id, store, events_tx, cancel).await;
            }));
            let cancel = self.cancel.clone();
            self.tasks.get_mut().push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        users = events_rx.recv() => {
                            let Some(_users) = users else { break };
                            // Reload the synchronized users together with their persisted counters.
                            match events_store.list_users() {
                                Ok(users) => apply_users(&registry, &server, users).await,
                                Err(err) => warn!(error = %err, "failed to reload users after ws sync"),
                            }
                        }
                    }
                }
            }));
        }
    }

    /// Stops and joins metered connections before persisting final usage.
    /// Failed panel deliveries remain in the durable outbox for retry.
    pub async fn shutdown(&self) {
        self.stopped
            .get_or_init(|| async {
                info!("shutting down");
                self.counters.set_shutting_down();
                if let Some(server) = self.server.write().await.take() {
                    server.stop();
                    server.wait().await;
                }
                self.cancel.cancel();
                // Let an in-flight report finish before taking its final snapshot.
                let _guard = self.report_lock.lock().await;
                report_pending(&self.panel, &self.store, &self.registry, &self.counters).await;
                let tasks = std::mem::take(&mut *self.tasks.lock().await);
                for task in &tasks {
                    task.abort();
                }
                for task in tasks {
                    let _ = task.await;
                }
            })
            .await;
    }

    pub async fn wait_for_signal(&self) {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut terminate = match signal(SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

/// Applies a user set to the registry and the live Snell listener.
async fn apply_users(
    registry: &Registry,
    server: &Arc<RwLock<Option<Arc<SnellServer>>>>,
    users: Vec<crate::config::User>,
) {
    let count = users.len();
    let guard = server.read().await;
    if let Some(server) = guard.as_ref()
        && let Err(err) = server.update_users(&users)
    {
        warn!(error = %err, "failed to apply users to listener");
        return;
    }
    registry.apply_users(&users);
    debug!(users = count, "user set applied");
}

async fn pull_loop(
    panel: Arc<PanelClient>,
    store: Store,
    registry: Arc<Registry>,
    server: Arc<RwLock<Option<Arc<SnellServer>>>>,
    interval: Duration,
    cancel: CancellationToken,
) {
    // Initial handshake: verifies credentials early and logs WS availability.
    match panel.handshake().await {
        Ok(handshake) => {
            if handshake.websocket.enabled {
                info!(url = %handshake.websocket.ws_url, "panel supports websocket push; polling remains active");
            }
        }
        Err(err) => log_panel_error("handshake", &err),
    }
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticks.tick() => {}
        }
        match panel.fetch_users().await {
            Ok(users) => {
                if let Err(err) = crate::config::validate_user_psks(&users) {
                    warn!(error = %err, "invalid panel credentials; keeping previous user set");
                    continue;
                }
                if let Err(err) = store.replace_users(&users) {
                    warn!(error = %err, "failed to store panel users");
                    continue;
                }
                match store.list_users() {
                    Ok(users) => {
                        apply_users(&registry, &server, users).await;
                        debug!("panel user sync complete");
                    }
                    Err(err) => warn!(error = %err, "failed to load users after sync"),
                }
            }
            Err(err) => log_panel_error("user sync", &err),
        }
    }
}

async fn push_loop(
    panel: Arc<PanelClient>,
    store: Store,
    registry: Arc<Registry>,
    counters: Arc<Counters>,
    interval: Duration,
    cancel: CancellationToken,
    report_lock: Arc<Mutex<()>>,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(interval) => {}
        }
        let _guard = report_lock.lock().await;
        if cancel.is_cancelled() {
            break;
        }
        report_pending(&panel, &store, &registry, &counters).await;
    }
}

/// Local accounting and the durable panel outbox commit together. Callers
/// serialize delivery, so shutdown never drains a periodic report's bytes.
async fn report_pending(panel: &PanelClient, store: &Store, registry: &Registry, counters: &Counters) {
    if let Err(err) = registry.persist_pending(|deltas| store.stage_traffic(deltas)) {
        warn!(error = %err, "failed to persist panel traffic");
        return;
    }
    let traffic = match store.pending_traffic() {
        Ok(traffic) => traffic,
        Err(err) => {
            warn!(error = %err, "failed to load panel traffic");
            return;
        }
    };
    if traffic.is_empty() {
        return;
    }
    let result = match panel.api_version() {
        1 => panel.push_traffic(&traffic).await,
        _ => {
            let online = collect_online(registry);
            let alive = collect_alive(registry);
            let metrics = current_metrics(registry, counters, store.list_users().map(|users| users.len()).unwrap_or(0));
            panel.report(&traffic, &alive, &online, system_status(), metrics).await
        }
    };
    if let Err(err) = result {
        log_panel_error("traffic report", &err);
        return;
    }
    if let Err(err) = store.acknowledge_traffic(&traffic) {
        warn!(error = %err, "failed to acknowledge panel traffic");
    }
    if panel.api_version() == 1 {
        if let Err(err) = panel.push_alive(&collect_alive(registry)).await {
            log_panel_error("alive push", &err);
        }
        if let Err(err) = panel.push_status(system_status()).await {
            log_panel_error("status push", &err);
        }
    }
}

fn collect_alive(registry: &Registry) -> Vec<(i64, Vec<String>)> {
    let ttl = registry.device_ttl();
    let now = std::time::Instant::now();
    registry
        .users()
        .into_iter()
        .filter_map(|user| {
            let state = registry.state(user.id)?;
            let ips = state.alive_ips(ttl, now);
            (!ips.is_empty()).then_some((user.id, ips))
        })
        .collect()
}

fn collect_online(registry: &Registry) -> Vec<(i64, usize)> {
    let ttl = registry.device_ttl();
    let now = std::time::Instant::now();
    registry
        .users()
        .into_iter()
        .filter_map(|user| {
            let state = registry.state(user.id)?;
            let count = state.device_count(ttl, now);
            (count > 0).then_some((user.id, count))
        })
        .collect()
}

fn current_metrics(registry: &Registry, counters: &Counters, total_users: usize) -> serde_json::Value {
    let online = collect_online(registry);
    let active_users = online.len();
    build_metrics(
        crate::uptime_seconds(),
        counters.active.load(std::sync::atomic::Ordering::Relaxed),
        counters.total.load(std::sync::atomic::Ordering::Relaxed),
        total_users,
        active_users,
        0,
        0,
    )
}
