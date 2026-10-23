//! The Snell v6 service wiring: per-user PSKs and listener lifecycle.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use snell::{Conn, Context, Service, TcpConn, v6};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use crate::accounting::Registry;
use crate::config::Config;
use crate::relay::RelayHandler;

/// The running Snell v6 server.
pub struct SnellServer {
    service: v6::MultiPskService<crate::relay::AuthedUser>,
    registry: Arc<Registry>,
    cancel: CancellationToken,
    local_addr: std::net::SocketAddr,
    tasks: TaskTracker,
}

impl SnellServer {
    /// Binds the listener and starts accepting v6 connections.
    pub async fn start(
        config: &Config,
        registry: Arc<Registry>,
        counters: Arc<crate::accounting::Counters>,
        enforce_quota: bool,
        quota_grace: u64,
        outbound: Option<SocketAddr>,
    ) -> io::Result<SnellServer> {
        let mode = v6::parse_mode(&config.node.mode)?;
        let cancel = CancellationToken::new();
        let tasks = TaskTracker::new();
        let handler: Arc<dyn snell::Handler> = Arc::new(RelayHandler {
            registry: registry.clone(),
            counters,
            enforce_quota,
            quota_grace,
            outbound,
            cancel: cancel.clone(),
            tasks: tasks.clone(),
        });
        let service = v6::MultiPskService::<crate::relay::AuthedUser>::with_handshake_limits(
            mode,
            handler,
            config.limits.handshake_limits(),
        )?;
        let users = registry.users();
        apply_users(&service, &users)?;

        let listener = TcpListener::bind(&config.node.listen).await?;
        let local = listener.local_addr()?;
        info!(%local, mode = %mode, users = users.len(), "snell v6 listener started");

        {
            let cancel = cancel.clone();
            let service = service.clone();
            let connection_tasks = tasks.clone();
            tasks.spawn(async move {
                loop {
                    let (stream, addr) = tokio::select! {
                        _ = cancel.cancelled() => break,
                        accepted = listener.accept() => match accepted {
                            Ok(accepted) => accepted,
                            Err(err) => {
                                warn!(error = %err, "accept failed");
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                continue;
                            }
                        },
                    };
                    let Ok(conn) = TcpConn::new(stream) else {
                        continue;
                    };
                    let conn: Arc<dyn Conn> = Arc::new(conn);
                    // Admit before spawning: saturation must not create an
                    // unbounded queue of tasks waiting for handshake capacity.
                    let connection = match service.accept_connection(Context::new(), conn.clone(), addr.into(), None) {
                        Ok(connection) => connection,
                        Err(err) => {
                            debug!(error = %err, "snell handshake rejected");
                            continue;
                        }
                    };
                    let cancel = cancel.clone();
                    connection_tasks.spawn(async move {
                        tokio::select! {
                            _ = cancel.cancelled() => { let _ = conn.close().await; }
                            result = connection => {
                                if let Err(err) = result {
                                    let _ = err.conn.close().await;
                                    debug!(error = %err, "snell connection failed");
                                }
                            }
                        }
                    });
                }
                debug!("snell v6 listener stopped");
            })
        };

        Ok(SnellServer { service, registry, cancel, local_addr: local, tasks })
    }

    /// Replaces the accepted user set without restarting the listener.
    pub fn update_users(&self, users: &[crate::config::User]) -> io::Result<()> {
        apply_users(&self.service, users)
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// The bound listener address (useful when `listen` uses port 0).
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    /// Stops the listener and cancels active handshakes and relays.
    pub fn stop(&self) {
        self.cancel.cancel();
        self.tasks.close();
    }

    /// Waits until the listener, handshakes and metered relays have stopped.
    pub async fn wait(&self) {
        self.tasks.wait().await;
    }
}

fn apply_users(
    service: &v6::MultiPskService<crate::relay::AuthedUser>,
    users: &[crate::config::User],
) -> io::Result<()> {
    let keys: Vec<Vec<u8>> = users.iter().map(|user| user.key().to_vec()).collect();
    let entries: Vec<crate::config::UserEntry> = users.iter().map(crate::config::UserEntry::from).collect();
    service.update_users(entries, keys)
}

#[allow(dead_code)]
fn _assert_service_object_safe(_: &dyn Service) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::User;
    use snell::Socksaddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn user(id: i64, uuid: &str) -> User {
        User {
            id,
            uuid: uuid.into(),
            speed_limit: 0,
            device_limit: 0,
            transfer_enable: 0,
            expired_at: 0,
            enabled: true,
            upload: 0,
            download: 0,
        }
    }

    #[test]
    fn empty_user_set_and_invalid_psks() {
        let registry = Arc::new(Registry::new(std::time::Duration::from_secs(60)));
        let service = v6::MultiPskService::<crate::relay::AuthedUser>::new(
            v6::Mode::Default,
            Arc::new(crate::relay::RelayHandler {
                registry,
                counters: Arc::new(crate::accounting::Counters::default()),
                enforce_quota: true,
                quota_grace: 0,
                outbound: None,
                cancel: CancellationToken::new(),
                tasks: TaskTracker::new(),
            }),
        )
        .unwrap();
        apply_users(&service, &[]).unwrap();
        apply_users(&service, &[user(1, "alice-unique-psk")]).unwrap();
        assert!(apply_users(&service, &[user(1, "short")]).is_err());
        assert!(apply_users(&service, &[user(1, "alice-unique-psk"), user(2, "alice-unique-psk")]).is_err());
    }

    #[tokio::test]
    async fn listener_rejects_excess_handshakes_then_recovers_after_timeout() {
        let mut config = Config::load(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml")).unwrap();
        config.node.listen = "127.0.0.1:0".into();
        config.limits.max_handshakes = 1;
        config.limits.max_handshakes_per_ip = 0;
        config.limits.handshake_timeout = 2;
        let registry = Arc::new(Registry::new(Duration::from_secs(300)));
        registry.apply_users(&[user(1, "alice-unique-psk")]);
        let server =
            SnellServer::start(&config, registry, Arc::new(crate::accounting::Counters::default()), true, 0, None)
                .await
                .unwrap();
        let mut first = TcpStream::connect(server.local_addr()).await.unwrap();
        let mut second = TcpStream::connect(server.local_addr()).await.unwrap();
        let (mut a, mut b) = ([0; 1], [0; 1]);
        // Exactly one of the two idle connections is admitted. The other must
        // close well before the handshake deadline, regardless of accept order.
        let first_closed = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                result = first.read(&mut a) => { assert_closed(result); true }
                result = second.read(&mut b) => { assert_closed(result); false }
            }
        })
        .await
        .expect("excess handshake was not rejected promptly");
        let remaining = if first_closed { &mut second } else { &mut first };
        assert_closed(tokio::time::timeout(Duration::from_secs(3), remaining.read(&mut a)).await.unwrap());

        // A verified relay must work after the slow handshake has timed out.
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = Socksaddr::from(echo.local_addr().unwrap());
        let echo_task = tokio::spawn(async move {
            let (mut conn, _) = echo.accept().await.unwrap();
            let mut byte = [0; 1];
            conn.read_exact(&mut byte).await.unwrap();
            conn.write_all(&byte).await.unwrap();
        });
        let client =
            v6::Client::new(v6::ClientOptions { psk: b"alice-unique-psk".to_vec(), ..Default::default() }).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            let raw = Arc::new(TcpConn::new(TcpStream::connect(server.local_addr()).await.unwrap()).unwrap());
            let proxy = client.dial_conn(raw, destination).await.unwrap();
            proxy.write(&[42]).await.unwrap();
            let mut response = [0; 1];
            assert_eq!(1, proxy.read(&mut response).await.unwrap());
            assert_eq!([42], response);
            proxy.close().await.unwrap();
        })
        .await
        .unwrap();
        echo_task.await.unwrap();
        server.stop();
        tokio::time::timeout(Duration::from_secs(5), server.wait()).await.unwrap();
    }

    fn assert_closed(result: io::Result<usize>) {
        match result {
            Ok(0) => {}
            Err(err) if matches!(err.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted) => {}
            other => panic!("expected a closed connection, got {other:?}"),
        }
    }
}
