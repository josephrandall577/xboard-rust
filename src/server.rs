//! The Snell v6 service wiring: per-user keys, mode and listener lifecycle.

use std::io;
use std::sync::Arc;

use snell::{Conn, Context, Service, Socksaddr, TcpConn, v6};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::accounting::Registry;
use crate::config::Config;
use crate::relay::RelayHandler;

/// The running Snell v6 server.
pub struct SnellServer {
    service: v6::MultiService<crate::relay::AuthedUser>,
    registry: Arc<Registry>,
    cancel: CancellationToken,
    local_addr: std::net::SocketAddr,
}

impl SnellServer {
    /// Binds the listener and starts accepting v6 connections.
    pub async fn start(
        config: &Config,
        registry: Arc<Registry>,
        counters: Arc<crate::accounting::Counters>,
        enforce_quota: bool,
        quota_grace: u64,
    ) -> io::Result<SnellServer> {
        let mode = v6::parse_mode(&config.node.mode)?;
        let handler: Arc<dyn snell::Handler> =
            Arc::new(RelayHandler { registry: registry.clone(), counters, enforce_quota, quota_grace });
        let service = v6::MultiService::<crate::relay::AuthedUser>::new(v6::ServerOptions {
            psk: config.node.psk.as_bytes().to_vec(),
            mode,
            handler,
        })?;
        let users = registry.users();
        apply_users(&service, &users)?;

        let listener = TcpListener::bind(&config.node.listen).await?;
        let local = listener.local_addr()?;
        info!(%local, mode = %mode, users = users.len(), "snell v6 listener started");

        let cancel = CancellationToken::new();
        {
            let cancel = cancel.clone();
            let service = service.clone();
            tokio::spawn(async move {
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
                    tokio::spawn(async move {
                        let source = Socksaddr::from(addr);
                        if let Err(err) = service.new_connection(Context::new(), conn.clone(), source, None).await {
                            let _ = err.conn.close().await;
                            debug!(error = %err, "snell connection failed");
                        }
                    });
                }
                debug!("snell v6 listener stopped");
            })
        };

        Ok(SnellServer { service, registry, cancel, local_addr: local })
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

    /// Stops accepting connections.
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

fn apply_users(service: &v6::MultiService<crate::relay::AuthedUser>, users: &[crate::config::User]) -> io::Result<()> {
    let keys: Vec<Vec<u8>> = users.iter().map(|user| user.key().to_vec()).collect();
    // The Snell multi-user service rejects an empty user set; a node with no
    // active users must still start and later accept a panel push, so keep a
    // placeholder key that no client can present.
    if users.is_empty() {
        let placeholder = crate::config::User {
            id: -1,
            uuid: "\0disabled".into(),
            speed_limit: 0,
            device_limit: 0,
            transfer_enable: 0,
            expired_at: 0,
            enabled: false,
            upload: 0,
            download: 0,
        };
        let entry = crate::config::UserEntry::from(&placeholder);
        return service.update_users(vec![entry], vec![b"\0disabled".to_vec()]);
    }
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
    fn empty_user_set_uses_placeholder() {
        let registry = Arc::new(Registry::new(std::time::Duration::from_secs(60)));
        let service = v6::MultiService::<crate::relay::AuthedUser>::new(v6::ServerOptions {
            psk: b"0123456789abcdef".to_vec(),
            mode: v6::Mode::Unshaped,
            handler: Arc::new(crate::relay::RelayHandler {
                registry,
                counters: Arc::new(crate::accounting::Counters::default()),
                enforce_quota: true,
                quota_grace: 0,
            }),
        })
        .unwrap();
        apply_users(&service, &[]).unwrap();
        apply_users(&service, &[user(1, "a")]).unwrap();
    }
}
