//! Hot-path accounting: per-user byte counters, online state, device (source
//! IP) tracking and token-bucket speed limiting.
//!
//! All state here is in-memory and lock-light. Byte counters are plain
//! atomics updated on every relayed chunk; the rest is touched only when a
//! connection opens or closes, or when the panel pushes a user update.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{Traffic, User};

/// Per-user shared accounting state.
///
/// One `UserState` exists per user record and survives user updates, so
/// counters are not lost when limits change.
pub struct UserState {
    pub id: i64,
    upload: AtomicU64,
    download: AtomicU64,

    /// Bytes accumulated since the last flush to the store.
    pending_upload: AtomicU64,
    pending_download: AtomicU64,

    devices: Mutex<Devices>,
    limit: Mutex<LimitState>,
}

#[derive(Default)]
struct Devices {
    /// Source IP -> number of connections and the last time it was seen.
    ips: HashMap<String, DeviceEntry>,
    connections: usize,
}

struct DeviceEntry {
    connections: u32,
    last_seen: Instant,
}

#[derive(Default)]
struct LimitState {
    /// Bytes per second allowed in each direction, 0 = unlimited.
    bytes_per_second: u64,
    /// Available tokens and the last refill time for each direction.
    upload: Bucket,
    download: Bucket,
}

#[derive(Default)]
struct Bucket {
    tokens: f64,
    updated: Option<Instant>,
}

impl Bucket {
    fn refill(&mut self, rate: u64, now: Instant) {
        if rate == 0 {
            self.tokens = 0.0;
            self.updated = Some(now);
            return;
        }
        let elapsed = self.updated.map(|updated| now.duration_since(updated).as_secs_f64()).unwrap_or(0.0);
        // Burst of one second's worth of traffic.
        let burst = rate as f64;
        self.tokens = (self.tokens + elapsed * rate as f64).min(burst);
        self.updated = Some(now);
    }

    /// Takes up to `want` tokens; returns how many were available.
    fn take(&mut self, want: u64) -> u64 {
        let granted = self.tokens.min(want as f64) as u64;
        self.tokens -= granted as f64;
        granted
    }
}

impl UserState {
    pub fn new(id: i64) -> UserState {
        UserState {
            id,
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            pending_upload: AtomicU64::new(0),
            pending_download: AtomicU64::new(0),
            devices: Mutex::new(Devices::default()),
            limit: Mutex::new(LimitState::default()),
        }
    }

    /// Byte totals since process start (for live stats).
    pub fn totals(&self) -> Traffic {
        Traffic { upload: self.upload.load(Ordering::Relaxed), download: self.download.load(Ordering::Relaxed) }
    }

    /// Adds relayed bytes. Called on the hot path.
    pub fn record_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
        self.pending_upload.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
        self.pending_download.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Atomically drains the unflushed counters.
    pub fn take_pending(&self) -> Traffic {
        Traffic {
            upload: self.pending_upload.swap(0, Ordering::Relaxed),
            download: self.pending_download.swap(0, Ordering::Relaxed),
        }
    }

    /// Peeks at the unflushed counters without draining them.
    pub fn pending_totals(&self) -> Traffic {
        Traffic {
            upload: self.pending_upload.load(Ordering::Relaxed),
            download: self.pending_download.load(Ordering::Relaxed),
        }
    }

    /// Restores counters after a failed flush.
    pub fn restore_pending(&self, traffic: Traffic) {
        self.pending_upload.fetch_add(traffic.upload, Ordering::Relaxed);
        self.pending_download.fetch_add(traffic.download, Ordering::Relaxed);
    }

    pub fn set_speed_limit(&self, mbps: u64) {
        let mut limit = self.limit.lock().unwrap();
        limit.bytes_per_second = mbps.saturating_mul(1_000_000) / 8;
        limit.upload = Bucket::default();
        limit.download = Bucket::default();
    }

    /// Waits until at most `bytes` may be relayed in the given direction.
    ///
    /// Returns `None` when unlimited, or how many bytes the caller may move
    /// now. The bucket is shared by all connections of the user, so
    /// concurrent streams throttle each other. Waiting happens outside the
    /// lock, and each wait is capped to recheck configuration changes.
    /// Grants are bounded by one burst; scheduling is best effort.
    pub async fn acquire(&self, upload: bool, bytes: u64) -> Option<u64> {
        loop {
            let wait = {
                let mut limit = self.limit.lock().unwrap();
                if limit.bytes_per_second == 0 {
                    return None;
                }
                if bytes == 0 {
                    return Some(0);
                }
                let rate = limit.bytes_per_second;
                let bucket = if upload { &mut limit.upload } else { &mut limit.download };
                bucket.refill(rate, Instant::now());
                // Wait for a useful bounded piece instead of issuing a tiny
                // socket write for every token that trickles in.
                let want = bytes.min(rate).min(16 * 1024);
                if bucket.tokens >= want as f64 {
                    return Some(bucket.take(bytes.min(rate)));
                }
                // Compete for and debit shared credit again after every wait.
                // Waiting alone does not grant any bytes.
                Duration::from_secs_f64((want as f64 - bucket.tokens) / rate as f64)
            };
            tokio::time::sleep(wait.min(Duration::from_millis(250))).await;
        }
    }

    /// Waits for an entire message without changing its boundaries. Requests
    /// larger than a burst consume several grants before the caller sends it.
    pub async fn acquire_all(&self, upload: bool, mut bytes: u64) {
        while bytes > 0 {
            match self.acquire(upload, bytes).await {
                Some(granted) => bytes -= granted,
                None => return,
            }
        }
    }

    /// Registers a new connection from `ip`.
    ///
    /// Returns `false` when the user's device limit would be exceeded. The
    /// connection must then be refused before any traffic is relayed.
    pub fn open_connection(&self, ip: &str, device_limit: u32, ttl: Duration, now: Instant) -> bool {
        let mut devices = self.devices.lock().unwrap();
        devices.prune(ttl, now);
        if device_limit > 0 {
            let known = devices.ips.contains_key(ip);
            if !known && devices.ips.len() >= device_limit as usize {
                return false;
            }
        }
        devices.connections += 1;
        let entry = devices.ips.entry(ip.to_string()).or_insert_with(|| DeviceEntry { connections: 0, last_seen: now });
        entry.connections += 1;
        entry.last_seen = now;
        true
    }

    pub fn close_connection(&self, ip: &str, now: Instant) {
        let mut devices = self.devices.lock().unwrap();
        devices.connections = devices.connections.saturating_sub(1);
        if let Some(entry) = devices.ips.get_mut(ip) {
            entry.connections = entry.connections.saturating_sub(1);
            entry.last_seen = now;
            if entry.connections == 0 {
                // Keep the IP until the TTL expires so short reconnects
                // from the same device do not consume a new slot.
            }
        }
    }

    pub fn online_connections(&self) -> usize {
        self.devices.lock().unwrap().connections
    }

    pub fn alive_ips(&self, ttl: Duration, now: Instant) -> Vec<String> {
        let mut devices = self.devices.lock().unwrap();
        devices.prune(ttl, now);
        let mut ips: Vec<String> = devices.ips.keys().cloned().collect();
        ips.sort();
        ips
    }

    pub fn device_count(&self, ttl: Duration, now: Instant) -> usize {
        let mut devices = self.devices.lock().unwrap();
        devices.prune(ttl, now);
        devices.ips.len()
    }
}

impl Devices {
    fn prune(&mut self, ttl: Duration, now: Instant) {
        self.ips.retain(|_, entry| entry.connections > 0 || now.duration_since(entry.last_seen) < ttl);
    }
}

/// Registry of all users known to the running node.
///
/// Holds one `UserState` per user id and the latest `User` record used for
/// authorization decisions.
pub struct Registry {
    inner: Mutex<RegistryInner>,
    device_ttl: Duration,
}

struct RegistryInner {
    users: HashMap<i64, Arc<UserState>>,
    specs: HashMap<i64, User>,
    keys: HashMap<Vec<u8>, i64>,
    blocked: HashSet<i64>,
}

impl Registry {
    pub fn new(device_ttl: Duration) -> Registry {
        Registry {
            inner: Mutex::new(RegistryInner {
                users: HashMap::new(),
                specs: HashMap::new(),
                keys: HashMap::new(),
                blocked: HashSet::new(),
            }),
            device_ttl,
        }
    }

    /// Replaces the user set. Traffic counters of users that already exist
    /// are preserved, and so are the states of users whose keys changed.
    pub fn apply_users(&self, users: &[User]) {
        let mut inner = self.inner.lock().unwrap();
        let mut keys = HashMap::with_capacity(users.len());
        let mut specs = HashMap::with_capacity(users.len());
        for user in users {
            keys.insert(user.key().to_vec(), user.id);
            specs.insert(user.id, user.clone());
            let state = inner.users.entry(user.id).or_insert_with(|| Arc::new(UserState::new(user.id))).clone();
            state.set_speed_limit(user.speed_limit);
        }
        let ids: HashSet<i64> = specs.keys().copied().collect();
        inner.users.retain(|id, _| ids.contains(id));
        inner.keys = keys;
        inner.specs = specs;
    }

    /// The user record for a Snell client key.
    pub fn user_by_key(&self, key: &[u8]) -> Option<User> {
        let inner = self.inner.lock().unwrap();
        let id = *inner.keys.get(key)?;
        let user = inner.specs.get(&id)?.clone();
        if inner.blocked.contains(&id) { None } else { Some(user) }
    }

    pub fn state(&self, id: i64) -> Option<Arc<UserState>> {
        self.inner.lock().unwrap().users.get(&id).cloned()
    }

    pub fn spec(&self, id: i64) -> Option<User> {
        self.inner.lock().unwrap().specs.get(&id).cloned()
    }

    pub fn users(&self) -> Vec<User> {
        let inner = self.inner.lock().unwrap();
        let mut users: Vec<User> = inner.specs.values().cloned().collect();
        users.sort_by_key(|user| user.id);
        users
    }

    /// Marks a user as blocked or unblocked at the authorization gate.
    pub fn set_blocked(&self, id: i64, blocked: bool) {
        let mut inner = self.inner.lock().unwrap();
        if blocked {
            inner.blocked.insert(id);
        } else {
            inner.blocked.remove(&id);
        }
    }

    pub fn is_blocked(&self, id: i64) -> bool {
        self.inner.lock().unwrap().blocked.contains(&id)
    }

    pub fn device_ttl(&self) -> Duration {
        self.device_ttl
    }

    /// Opens a connection for `id` from `ip`, applying the device limit.
    pub fn open_connection(&self, id: i64, ip: &str) -> bool {
        let state = match self.state(id) {
            Some(state) => state,
            None => return false,
        };
        let user = match self.spec(id) {
            Some(user) => user,
            None => return false,
        };
        if self.is_blocked(id) || !user.is_active(crate::config::unix_now()) {
            return false;
        }
        state.open_connection(ip, user.device_limit, self.device_ttl, Instant::now())
    }

    pub fn close_connection(&self, id: i64, ip: &str) {
        if let Some(state) = self.state(id) {
            state.close_connection(ip, Instant::now());
        }
    }

    /// Drains pending traffic for all users.
    pub fn take_pending(&self) -> Vec<(i64, Traffic)> {
        let states: Vec<Arc<UserState>> = self.inner.lock().unwrap().users.values().cloned().collect();
        states
            .into_iter()
            .filter_map(|state| {
                let traffic = state.take_pending();
                (!traffic.is_zero()).then_some((state.id, traffic))
            })
            .collect()
    }

    /// Bytes used by a user, including deltas not yet flushed to the store.
    ///
    /// The store only knows flushed bytes; the registry's cumulative totals
    /// already contain those, so only the pending (unflushed) deltas may be
    /// added without counting the same bytes twice.
    pub fn used_bytes(&self, id: i64) -> Option<u64> {
        let inner = self.inner.lock().unwrap();
        let user = inner.specs.get(&id)?;
        let state = inner.users.get(&id)?;
        let pending = state.pending_totals();
        Some(user.used().saturating_add(pending.total()))
    }
}

/// Global counter for relayed packets, for the stats endpoint.
#[derive(Default)]
pub struct Counters {
    pub active: AtomicU64,
    pub total: AtomicU64,
    pub device_limit_hits: AtomicU64,
    pub quota_rejects: AtomicU64,
    shutting_down: AtomicBool,
}

impl Counters {
    pub fn connection_opened(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn set_shutting_down(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: i64, uuid: &str, device_limit: u32, speed_limit: u64) -> User {
        User {
            id,
            uuid: uuid.into(),
            speed_limit,
            device_limit,
            transfer_enable: 0,
            expired_at: 0,
            enabled: true,
            upload: 0,
            download: 0,
        }
    }

    #[test]
    fn device_limit_enforced_per_ip() {
        let registry = Registry::new(Duration::from_secs(60));
        registry.apply_users(&[user(1, "u1", 2, 0)]);
        assert!(registry.open_connection(1, "1.1.1.1"));
        assert!(registry.open_connection(1, "1.1.1.1"), "same IP reuses its slot");
        assert!(registry.open_connection(1, "2.2.2.2"));
        assert!(!registry.open_connection(1, "3.3.3.3"), "third distinct IP exceeds the limit");
        registry.close_connection(1, "3.3.3.3");
        assert_eq!(2, registry.state(1).unwrap().device_count(Duration::from_secs(60), Instant::now()));
        let alive = registry.state(1).unwrap().alive_ips(Duration::from_secs(60), Instant::now());
        assert_eq!(vec!["1.1.1.1", "2.2.2.2"], alive);
    }

    #[test]
    fn unlimited_devices_when_limit_zero() {
        let registry = Registry::new(Duration::from_secs(60));
        registry.apply_users(&[user(1, "u1", 0, 0)]);
        for ip in 0..10 {
            assert!(registry.open_connection(1, &format!("10.0.0.{ip}")));
        }
    }

    #[test]
    fn traffic_counters_accumulate_and_drain() {
        let registry = Registry::new(Duration::from_secs(60));
        registry.apply_users(&[user(1, "u1", 0, 0)]);
        let state = registry.state(1).unwrap();
        state.record_upload(100);
        state.record_download(200);
        assert_eq!(Traffic { upload: 100, download: 200 }, state.totals());
        let pending = registry.take_pending();
        assert_eq!(vec![(1, Traffic { upload: 100, download: 200 })], pending);
        assert!(registry.take_pending().is_empty());
        state.restore_pending(Traffic { upload: 100, download: 200 });
        assert_eq!(1, registry.take_pending().len());
    }

    #[tokio::test]
    async fn speed_limit_is_unlimited_without_limit() {
        let state = UserState::new(1);
        assert_eq!(None, state.acquire(true, 1024).await);
    }

    #[tokio::test]
    async fn speed_limit_caps_each_grant_at_one_burst() {
        let state = UserState::new(1);
        state.set_speed_limit(1); // 1 Mbps = 125_000 bytes/s
        // A 1 MiB write is granted in burst-sized pieces: the first call may
        // move at most one second worth of bytes.
        let granted = state.acquire(true, 1024 * 1024).await.unwrap();
        assert!(granted <= 125_000, "granted {granted}");
        // Once the bucket is empty the next call waits and yields a small
        // piece rather than blocking for the whole chunk.
        let start = Instant::now();
        let small = state.acquire(true, 32 * 1024).await.unwrap();
        assert!(small >= 1);
        assert!(start.elapsed() < Duration::from_millis(500), "acquire blocked too long");
    }

    #[test]
    fn bucket_keeps_fractional_credit() {
        let mut bucket = Bucket { tokens: 1.75, updated: None };
        assert_eq!(1, bucket.take(2));
        assert_eq!(0.75, bucket.tokens);
        assert_eq!(0, bucket.take(2));
        assert_eq!(0.75, bucket.tokens);
    }

    #[tokio::test]
    async fn speed_limit_waits_for_real_credit() {
        let state = UserState::new(1);
        state.set_speed_limit(1);
        let granted = state.acquire(true, 1024).await.unwrap();
        assert!(granted > 1, "must refill and debit real credit after waiting, granted {granted}");
    }

    #[tokio::test]
    async fn concurrent_requests_share_the_speed_budget() {
        let state = UserState::new(1);
        state.set_speed_limit(1);
        let start = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(state.acquire_all(true, 62_500), state.acquire_all(true, 62_500));
        })
        .await
        .expect("shared budget must make progress");
        // 125,000 total bytes at 1 Mbps need a full second from an empty bucket.
        assert!(start.elapsed() >= Duration::from_millis(900), "concurrent requests minted credit");
    }

    #[tokio::test]
    async fn waiting_request_observes_limit_removal() {
        let state = UserState::new(1);
        state.set_speed_limit(1);
        let request = state.acquire_all(true, 1024 * 1024);
        let update = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            state.set_speed_limit(0);
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(request, update);
        })
        .await
        .expect("pending request must observe limit removal");
    }

    #[test]
    fn blocked_users_are_refused() {
        let registry = Registry::new(Duration::from_secs(60));
        registry.apply_users(&[user(1, "u1", 0, 0)]);
        assert!(registry.user_by_key(b"u1").is_some());
        registry.set_blocked(1, true);
        assert!(registry.user_by_key(b"u1").is_none());
        assert!(!registry.open_connection(1, "1.1.1.1"));
    }
}
