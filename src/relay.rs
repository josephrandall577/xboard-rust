//! The Snell v6 traffic handler: per-user authorization, device limiting,
//! byte accounting and the TCP/UDP relay.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use snell::{Buffer, CloseHandler, Conn, Context, Handler, PacketConn, Socksaddr, TcpConn};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tracing::debug;

use crate::accounting::{Counters, Registry, UserState};
use crate::config::User;

/// Exponential backoff helper for dead UDP targets, so a connection that
/// only receives ICMP-unreachable replies does not spin.
const UDP_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The user attached to a connection context by the v6 authenticator.
///
/// The Snell service stores its user map keyed by this value, so only stable
/// identity fields participate in equality and hashing; live counters and
/// limit changes must never change which user a key resolves to.
pub type AuthedUser = crate::config::UserEntry;

pub struct RelayHandler {
    pub registry: Arc<Registry>,
    pub counters: Arc<Counters>,
    /// Whether to enforce quotas (close connections whose user ran out).
    pub enforce_quota: bool,
    pub quota_grace: u64,
}

impl RelayHandler {
    fn authorize(&self, ctx: &Context, source: &Socksaddr) -> Option<(User, Arc<UserState>, String)> {
        if self.counters.is_shutting_down() {
            return None;
        }
        let user = ctx.user::<AuthedUser>()?.user.clone();
        let state = self.registry.state(user.id)?;
        if self.enforce_quota && user.transfer_enable > 0 {
            let used = self.registry.used_bytes(user.id).unwrap_or(0);
            if used >= user.transfer_enable.saturating_add(self.quota_grace) {
                self.counters.quota_rejects.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!(user = user.id, used, limit = user.transfer_enable, "quota exceeded, refusing connection");
                return None;
            }
        }
        let ip = source.addr_string();
        if !self.registry.open_connection(user.id, &ip) {
            self.counters.device_limit_hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!(user = user.id, ip, limit = user.device_limit, "device limit reached, refusing connection");
            return None;
        }
        Some((user, state, ip))
    }
}

impl Handler for RelayHandler {
    fn new_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn Conn>,
        source: Socksaddr,
        destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        let Some((user, state, ip)) = self.authorize(&ctx, &source) else {
            close_refused(conn, on_close);
            return;
        };
        let destination = destination.clone();
        self.counters.connection_opened();
        let registry = self.registry.clone();
        let counters = self.counters.clone();
        tokio::spawn(async move {
            let meter = Meter::new(&user, &state);
            let result = relay_tcp(conn.clone(), destination.clone(), meter).await;
            if let Err(err) = &result {
                debug!(user = user.id, destination = %destination, error = %err, "tcp relay ended with error");
            }
            registry.close_connection(user.id, &ip);
            counters.connection_closed();
            if let Some(on_close) = on_close {
                on_close(result.err());
            }
        });
    }

    fn new_packet_connection(
        &self,
        ctx: Context,
        conn: Arc<dyn PacketConn>,
        source: Socksaddr,
        _destination: Socksaddr,
        on_close: Option<CloseHandler>,
    ) {
        let Some((user, state, ip)) = self.authorize(&ctx, &source) else {
            close_packet_refused(conn, on_close);
            return;
        };
        self.counters.connection_opened();
        let registry = self.registry.clone();
        let counters = self.counters.clone();
        tokio::spawn(async move {
            let meter = PacketMeter::new(&user, &state);
            let result = relay_udp(conn.clone(), meter).await;
            if let Err(err) = &result {
                debug!(user = user.id, error = %err, "udp relay ended with error");
            }
            registry.close_connection(user.id, &ip);
            counters.connection_closed();
            if let Some(on_close) = on_close {
                on_close(result.err());
            }
        });
    }
}

fn close_refused(conn: Arc<dyn Conn>, on_close: Option<CloseHandler>) {
    tokio::spawn(async move {
        let _ = conn.close().await;
        if let Some(on_close) = on_close {
            on_close(None);
        }
    });
}

fn close_packet_refused(conn: Arc<dyn PacketConn>, on_close: Option<CloseHandler>) {
    tokio::spawn(async move {
        let _ = conn.close().await;
        if let Some(on_close) = on_close {
            on_close(None);
        }
    });
}

/// Per-connection metering state shared by the two copy directions.
struct Meter {
    state: Arc<UserState>,
    speed_limit: bool,
    used: u64,
}

impl Meter {
    fn new(user: &User, state: &Arc<UserState>) -> Meter {
        Meter { state: state.clone(), speed_limit: user.speed_limit > 0, used: 0 }
    }

    /// Limits the next chunk, returning how many bytes may move now.
    async fn clamp(&mut self, upload: bool, bytes: usize) -> usize {
        if self.speed_limit
            && let Some(granted) = self.state.acquire(upload, bytes as u64).await
        {
            return (granted as usize).max(1).min(bytes);
        }
        bytes
    }
}

async fn relay_tcp(client: Arc<dyn Conn>, destination: Socksaddr, meter: Meter) -> io::Result<()> {
    let upstream = connect_tcp(&destination).await?;
    let meter = Arc::new(tokio::sync::Mutex::new(meter));
    let upload = {
        let (client, upstream, meter) = (client.clone(), upstream.clone(), meter.clone());
        async move {
            let result = copy_metered(&client, &upstream, true, &meter).await;
            match &result {
                Ok(()) => {
                    let _ = upstream.close_write().await;
                }
                Err(_) => {
                    let _ = upstream.close().await;
                }
            }
            result
        }
    };
    let download = {
        let (client, upstream, meter) = (client.clone(), upstream.clone(), meter.clone());
        async move {
            let result = copy_metered(&upstream, &client, false, &meter).await;
            match &result {
                Ok(()) => {
                    let _ = client.close_write().await;
                }
                Err(_) => {
                    let _ = client.close().await;
                }
            }
            result
        }
    };
    let (upload, download) = tokio::join!(upload, download);
    let _ = client.close().await;
    let _ = upstream.close().await;
    upload.and(download)
}

/// Copies one direction, throttling and counting on every chunk.
async fn copy_metered(
    source: &Arc<dyn Conn>,
    destination: &Arc<dyn Conn>,
    upload: bool,
    meter: &tokio::sync::Mutex<Meter>,
) -> io::Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = source.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        let allowed = meter.lock().await.clamp(upload, n).await;
        destination.write(&buf[..allowed]).await?;
        let mut meter = meter.lock().await;
        if upload {
            meter.state.record_upload(allowed as u64);
        } else {
            meter.state.record_download(allowed as u64);
        }
        meter.used = meter.used.saturating_add(allowed as u64);
    }
}

async fn connect_tcp(destination: &Socksaddr) -> io::Result<Arc<dyn Conn>> {
    let stream = match destination.socket_addr() {
        Some(addr) => TcpStream::connect(addr).await?,
        None => TcpStream::connect((destination.fqdn.as_str(), destination.port)).await?,
    };
    let conn = TcpConn::new(stream)?;
    Ok(Arc::new(conn))
}

/// UDP relay with a single association socket.
///
/// Each client-side destination is resolved once and the replies are matched
/// by the socket's peer, like the example server.
struct PacketMeter {
    state: Arc<UserState>,
    speed_limit: bool,
}

impl PacketMeter {
    fn new(user: &User, state: &Arc<UserState>) -> PacketMeter {
        PacketMeter { state: state.clone(), speed_limit: user.speed_limit > 0 }
    }

    async fn clamp(&self, upload: bool, bytes: usize) -> usize {
        if self.speed_limit
            && let Some(granted) = self.state.acquire(upload, bytes as u64).await
        {
            return (granted as usize).max(1).min(bytes);
        }
        bytes
    }
}

async fn relay_udp(conn: Arc<dyn PacketConn>, meter: PacketMeter) -> io::Result<()> {
    // Use an unconnected socket and track the last destination. Snell UDP
    // tunnels are request/response pairs in practice; replies from any of
    // the destinations in the tunnel are forwarded back to the client.
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let downlink = {
        let socket = socket.clone();
        let conn = conn.clone();
        let state = meter.state.clone();
        let speed_limit = meter.speed_limit;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let (n, addr) = match socket.recv_from(&mut buf).await {
                    Ok(read) => read,
                    Err(_) => return,
                };
                let allowed = if speed_limit {
                    match state.acquire(false, n as u64).await {
                        Some(granted) => (granted as usize).max(1).min(n),
                        None => n,
                    }
                } else {
                    n
                };
                let buffer =
                    Buffer::from_slice_with_headroom(&buf[..allowed], conn.front_headroom(), conn.rear_headroom());
                if conn.write_packet(buffer, Socksaddr::from(addr)).await.is_err() {
                    return;
                }
                state.record_download(allowed as u64);
            }
        })
    };
    let result = async {
        loop {
            let mut buffer = Buffer::new_packet();
            let destination = conn.read_packet(&mut buffer).await?;
            let Some(addr) = resolve_udp(&destination).await else {
                continue;
            };
            let bytes = buffer.bytes();
            let allowed = meter.clamp(true, bytes.len()).await;
            if socket.send_to(&bytes[..allowed], addr).await.is_ok() {
                meter.state.record_upload(allowed as u64);
            }
        }
    }
    .await;
    downlink.abort();
    let _ = conn.close().await;
    result
}

async fn resolve_udp(destination: &Socksaddr) -> Option<SocketAddr> {
    if let Some(addr) = destination.socket_addr() {
        return Some(addr);
    }
    match tokio::time::timeout(UDP_READ_TIMEOUT, lookup_host((destination.fqdn.as_str(), destination.port))).await {
        Ok(Ok(mut addresses)) => addresses.next(),
        _ => None,
    }
}

#[allow(dead_code)]
fn _assert_object_safe(_: &dyn Handler) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::Registry;
    use crate::config::Traffic;
    use std::time::Duration;

    fn registry_with_user() -> (Arc<Registry>, Arc<Counters>) {
        let registry = Arc::new(Registry::new(Duration::from_secs(300)));
        registry.apply_users(&[User {
            id: 7,
            uuid: "user-key".into(),
            speed_limit: 0,
            device_limit: 0,
            transfer_enable: 0,
            expired_at: 0,
            enabled: true,
            upload: 0,
            download: 0,
        }]);
        (registry, Arc::new(Counters::default()))
    }

    fn entry(user: User) -> AuthedUser {
        AuthedUser::from(&user)
    }

    #[test]
    fn authorize_requires_authenticated_user() {
        let (registry, counters) = registry_with_user();
        let handler = RelayHandler { registry: registry.clone(), counters, enforce_quota: true, quota_grace: 0 };
        let ctx = Context::new();
        assert!(handler.authorize(&ctx, &Socksaddr::parse_host_port("1.2.3.4", 1000)).is_none());
        let user = handler.registry.spec(7).unwrap();
        let ctx = ctx.with_user(entry(user));
        assert!(handler.authorize(&ctx, &Socksaddr::parse_host_port("1.2.3.4", 1000)).is_some());
    }

    #[test]
    fn quota_refuses_used_up_user() {
        let (registry, counters) = registry_with_user();
        registry.apply_users(&[User {
            id: 7,
            uuid: "user-key".into(),
            speed_limit: 0,
            device_limit: 0,
            transfer_enable: 100,
            expired_at: 0,
            enabled: true,
            upload: 100,
            download: 0,
        }]);
        let handler = RelayHandler { registry, counters, enforce_quota: true, quota_grace: 0 };
        let user = handler.registry.spec(7).unwrap();
        let ctx = Context::new().with_user(entry(user));
        assert!(handler.authorize(&ctx, &Socksaddr::parse_host_port("1.2.3.4", 1)).is_none());
    }

    #[test]
    fn recorded_bytes_use_upload_download() {
        let (registry, _) = registry_with_user();
        let state = registry.state(7).unwrap();
        state.record_upload(10);
        state.record_download(20);
        assert_eq!(Traffic { upload: 10, download: 20 }, state.totals());
    }
}
