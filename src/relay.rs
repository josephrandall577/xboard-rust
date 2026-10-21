//! The Snell v6 traffic handler: per-user authorization, device limiting,
//! byte accounting and the TCP/UDP relay.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use snell::{Buffer, CloseHandler, Conn, Context, Handler, PacketConn, Socksaddr, TcpConn};
use tokio::net::{TcpSocket, TcpStream, UdpSocket, lookup_host};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
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
    /// When set, all destination sockets bind to this listener's local IP.
    pub outbound: Option<SocketAddr>,
    pub cancel: CancellationToken,
    pub tasks: TaskTracker,
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
        let outbound = self.outbound;
        let cancel = self.cancel.clone();
        self.tasks.spawn(async move {
            let result = tokio::select! {
                _ = cancel.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "node stopped")),
                result = relay_tcp(conn.clone(), destination.clone(), state, outbound) => result,
            };
            let _ = conn.close().await;
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
        let outbound = self.outbound;
        let cancel = self.cancel.clone();
        self.tasks.spawn(async move {
            let result = tokio::select! {
                _ = cancel.cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "node stopped")),
                result = relay_udp(conn.clone(), state, outbound) => result,
            };
            let _ = conn.close().await;
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

async fn relay_tcp(
    client: Arc<dyn Conn>,
    destination: Socksaddr,
    state: Arc<UserState>,
    outbound: Option<SocketAddr>,
) -> io::Result<()> {
    let upstream = connect_tcp(&destination, outbound).await?;
    let upload = {
        let (client, upstream, state) = (client.clone(), upstream.clone(), state.clone());
        async move {
            let result = copy_metered(&client, &upstream, true, &state).await;
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
        let (client, upstream, state) = (client.clone(), upstream.clone(), state.clone());
        async move {
            let result = copy_metered(&upstream, &client, false, &state).await;
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
    state: &UserState,
) -> io::Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = source.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        let mut offset = 0;
        while offset < n {
            let allowed = state.acquire(upload, (n - offset) as u64).await.unwrap_or((n - offset) as u64) as usize;
            destination.write(&buf[offset..offset + allowed]).await?;
            if upload {
                state.record_upload(allowed as u64);
            } else {
                state.record_download(allowed as u64);
            }
            offset += allowed;
        }
    }
}

async fn connect_tcp(destination: &Socksaddr, outbound: Option<SocketAddr>) -> io::Result<Arc<dyn Conn>> {
    let stream = match outbound {
        None => match destination.socket_addr() {
            Some(addr) => TcpStream::connect(addr).await?,
            None => TcpStream::connect((destination.host()?.as_ref(), destination.port)).await?,
        },
        Some(local_addr) => {
            let addresses = match destination.socket_addr() {
                Some(address) => vec![address],
                None => lookup_host((destination.host()?.as_ref(), destination.port)).await?.collect(),
            };
            connect_bound_tcp(local_addr, addresses).await?
        }
    };
    let conn = TcpConn::new(stream)?;
    Ok(Arc::new(conn))
}

fn with_zero_port(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(address) => SocketAddr::V4(std::net::SocketAddrV4::new(*address.ip(), 0)),
        SocketAddr::V6(address) => {
            SocketAddr::V6(std::net::SocketAddrV6::new(*address.ip(), 0, address.flowinfo(), address.scope_id()))
        }
    }
}

async fn connect_bound_tcp(
    local: SocketAddr,
    addresses: impl IntoIterator<Item = SocketAddr>,
) -> io::Result<TcpStream> {
    let mut last_error = io::Error::new(io::ErrorKind::AddrNotAvailable, "no destination matching the node IP family");
    for remote in addresses.into_iter().filter(|address| address.is_ipv4() == local.is_ipv4()) {
        let socket = if local.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        socket.bind(with_zero_port(local))?;
        match socket.connect(remote).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

/// UDP relay with a single association socket.
async fn relay_udp(conn: Arc<dyn PacketConn>, state: Arc<UserState>, outbound: Option<SocketAddr>) -> io::Result<()> {
    let bind_address = outbound.map(with_zero_port).unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
    let socket = UdpSocket::bind(bind_address).await?;
    let downlink = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, addr) = socket.recv_from(&mut buf).await?;
            state.acquire_all(false, n as u64).await;
            let buffer = Buffer::from_slice_with_headroom(&buf[..n], conn.front_headroom(), conn.rear_headroom());
            conn.write_packet(buffer, Socksaddr::from(addr)).await?;
            state.record_download(n as u64);
        }
    };
    let uplink = async {
        loop {
            let mut buffer = Buffer::new_packet();
            let destination = conn.read_packet(&mut buffer).await?;
            let Some(addr) = resolve_udp(&destination, outbound).await else {
                continue;
            };
            let bytes = buffer.bytes();
            state.acquire_all(true, bytes.len() as u64).await;
            if let Ok(sent) = socket.send_to(bytes, addr).await {
                state.record_upload(sent as u64);
            }
        }
    };
    // Keep both directions in the owning task so cancellation drops the UDP
    // socket and cannot leave an unmetered downlink running after shutdown.
    let result = tokio::select! { result = uplink => result, result = downlink => result };
    let _ = conn.close().await;
    result
}

async fn resolve_udp(destination: &Socksaddr, outbound: Option<SocketAddr>) -> Option<SocketAddr> {
    let ipv4 = outbound.map(|addr| addr.is_ipv4());
    if let Some(addr) = destination.socket_addr() {
        return ipv4.is_none_or(|family| addr.is_ipv4() == family).then_some(addr);
    }
    let host = destination.host().ok()?;
    match tokio::time::timeout(UDP_READ_TIMEOUT, lookup_host((host.as_ref(), destination.port))).await {
        Ok(Ok(mut addresses)) => addresses.find(|addr| ipv4.is_none_or(|family| addr.is_ipv4() == family)),
        _ => None,
    }
}

#[allow(dead_code)]
fn _assert_object_safe(_: &dyn Handler) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bound_tcp_retries_addresses_without_changing_source_ip() {
        let refused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_address = refused.local_addr().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        drop(refused);
        let stream = connect_bound_tcp(
            "127.0.0.1:0".parse().unwrap(),
            ["[::1]:1".parse().unwrap(), refused_address, listener.local_addr().unwrap()],
        )
        .await
        .unwrap();
        let (_, peer) = listener.accept().await.unwrap();
        assert_eq!("127.0.0.1".parse::<std::net::IpAddr>().unwrap(), peer.ip());
        assert_eq!(listener.local_addr().unwrap(), stream.peer_addr().unwrap());
    }

    #[tokio::test]
    async fn bound_tcp_rejects_other_families_and_returns_connection_failures() {
        let local = "127.0.0.1:0".parse().unwrap();
        let err = connect_bound_tcp(local, ["[::1]:1".parse().unwrap()]).await.unwrap_err();
        assert_eq!(io::ErrorKind::AddrNotAvailable, err.kind());
        let refused = tokio::net::TcpListener::bind(local).await.unwrap();
        let refused_address = refused.local_addr().unwrap();
        drop(refused);
        let err = connect_bound_tcp(local, [refused_address]).await.unwrap_err();
        assert_eq!(io::ErrorKind::ConnectionRefused, err.kind());
    }
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
        let handler = RelayHandler {
            registry: registry.clone(),
            counters,
            enforce_quota: true,
            quota_grace: 0,
            outbound: None,
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
        };
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
        let handler = RelayHandler {
            registry,
            counters,
            enforce_quota: true,
            quota_grace: 0,
            outbound: None,
            cancel: CancellationToken::new(),
            tasks: TaskTracker::new(),
        };
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
