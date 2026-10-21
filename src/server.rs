//! The Snell v6 service wiring: per-user PSKs and listener lifecycle.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use snell::{Conn, Context, Service, Socksaddr, TcpConn, v6};
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
        let service = v6::MultiPskService::<crate::relay::AuthedUser>::new(mode, handler)?;
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
                    let service = service.clone();
                    let cancel = cancel.clone();
                    connection_tasks.spawn(async move {
                        let source = Socksaddr::from(addr);
                        tokio::select! {
                            _ = cancel.cancelled() => { let _ = conn.close().await; }
                            result = service.new_connection(Context::new(), conn.clone(), source, None) => {
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
}
