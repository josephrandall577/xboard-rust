//! SQLite-backed user and traffic store.
//!
//! The store caches panel users for the Snell v6 listener and read-only admin
//! API, and persists local usage together with undelivered panel reports.
//! Traffic counters are aggregated into the database on a timer, not on
//! every packet, so the hot path only touches atomics.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};

use crate::config::{Traffic, User, UserSpec};

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    DuplicateUuid(String),
    Invalid(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Sqlite(err) => write!(f, "sqlite: {err}"),
            StoreError::DuplicateUuid(uuid) => write!(f, "duplicate user uuid: {uuid}"),
            StoreError::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(err: rusqlite::Error) -> Self {
        StoreError::Sqlite(err)
    }
}

/// Thread-safe handle to the user database.
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Store, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                uuid TEXT NOT NULL UNIQUE,
                speed_limit INTEGER NOT NULL DEFAULT 0,
                device_limit INTEGER NOT NULL DEFAULT 0,
                transfer_enable INTEGER NOT NULL DEFAULT 0,
                expired_at INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                upload INTEGER NOT NULL DEFAULT 0,
                download INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS pending_traffic (
                user_id INTEGER PRIMARY KEY,
                upload INTEGER NOT NULL CHECK(upload >= 0 AND typeof(upload) = 'integer'),
                download INTEGER NOT NULL CHECK(download >= 0 AND typeof(download) = 'integer')
            );
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        Ok(Store { conn: Arc::new(Mutex::new(conn)) })
    }

    pub fn open_memory() -> Result<Store, StoreError> {
        Store::open(":memory:")
    }

    fn with_conn<T>(&self, f: impl FnOnce(&mut Connection) -> Result<T, StoreError>) -> Result<T, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        f(&mut conn)
    }

    pub fn list_users(&self) -> Result<Vec<User>, StoreError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, uuid, speed_limit, device_limit, transfer_enable, expired_at, enabled, upload, download
                 FROM users ORDER BY id",
            )?;
            let rows = stmt.query_map([], row_to_user)?;
            let mut users = Vec::new();
            for row in rows {
                users.push(row?);
            }
            Ok(users)
        })
    }

    pub fn get_user(&self, id: i64) -> Result<Option<User>, StoreError> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT id, uuid, speed_limit, device_limit, transfer_enable, expired_at, enabled, upload, download
                 FROM users WHERE id = ?1",
                [id],
                row_to_user,
            )
            .optional()
            .map_err(StoreError::from)
        })
    }

    /// Replaces the full user set, preserving traffic counters for users
    /// that already exist. This is what the panel user sync uses.
    pub fn replace_users(&self, specs: &[UserSpec]) -> Result<(), StoreError> {
        self.with_conn(|conn| {
            let tx = conn.transaction()?;
            let existing = {
                let mut stmt = tx.prepare("SELECT id, upload, download FROM users")?;
                let rows = stmt.query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?))
                })?;
                let mut map = HashMap::new();
                for row in rows {
                    let (id, upload, download) = row?;
                    map.insert(id, (upload, download));
                }
                map
            };
            tx.execute("DELETE FROM users", [])?;
            for spec in specs {
                let (upload, download) = existing
                    .get(&spec.id)
                    .copied()
                    .unwrap_or((0, 0));
                tx.execute(
                    "INSERT INTO users (id, uuid, speed_limit, device_limit, transfer_enable, expired_at, enabled, upload, download)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        spec.id,
                        spec.uuid,
                        sqlite_limit(spec.speed_limit, "speed_limit")?,
                        spec.device_limit as i64,
                        sqlite_limit(spec.transfer_enable, "transfer_enable")?,
                        spec.expired_at,
                        spec.enabled as i64,
                        upload,
                        download
                    ],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
    }

    pub fn upsert_user(&self, spec: &UserSpec) -> Result<User, StoreError> {
        if spec.uuid.is_empty() || spec.uuid.len() > 255 {
            return Err(StoreError::Invalid("user uuid must be 1..=255 bytes".into()));
        }
        self.with_conn(|conn| {
            let duplicate: Option<i64> = conn
                .query_row("SELECT id FROM users WHERE uuid = ?1 AND id != ?2", params![spec.uuid, spec.id], |row| {
                    row.get(0)
                })
                .optional()?;
            if duplicate.is_some() {
                return Err(StoreError::DuplicateUuid(spec.uuid.clone()));
            }
            let existing: Option<(i64, i64)> = conn
                .query_row("SELECT upload, download FROM users WHERE id = ?1", [spec.id], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?;
            let (upload, download) = existing.unwrap_or((0, 0));
            conn.execute(
                "INSERT INTO users (id, uuid, speed_limit, device_limit, transfer_enable, expired_at, enabled, upload, download)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(id) DO UPDATE SET
                    uuid = excluded.uuid,
                    speed_limit = excluded.speed_limit,
                    device_limit = excluded.device_limit,
                    transfer_enable = excluded.transfer_enable,
                    expired_at = excluded.expired_at,
                    enabled = excluded.enabled",
                params![
                    spec.id,
                    spec.uuid,
                    sqlite_limit(spec.speed_limit, "speed_limit")?,
                    spec.device_limit as i64,
                    sqlite_limit(spec.transfer_enable, "transfer_enable")?,
                    spec.expired_at,
                    spec.enabled as i64,
                    upload,
                    download
                ],
            )?;
            conn.query_row(
                "SELECT id, uuid, speed_limit, device_limit, transfer_enable, expired_at, enabled, upload, download
                 FROM users WHERE id = ?1",
                [spec.id],
                row_to_user,
            )
            .map_err(StoreError::from)
        })
    }

    pub fn delete_user(&self, id: i64) -> Result<bool, StoreError> {
        self.with_conn(|conn| Ok(conn.execute("DELETE FROM users WHERE id = ?1", [id])? > 0))
    }

    /// Adds traffic deltas to the stored counters.
    pub fn add_traffic(&self, deltas: &[(i64, crate::config::Traffic)]) -> Result<(), StoreError> {
        if deltas.is_empty() {
            return Ok(());
        }
        self.with_conn(|conn| {
            let tx = conn.transaction()?;
            {
                let mut stmt =
                    tx.prepare("UPDATE users SET upload = upload + ?2, download = download + ?3 WHERE id = ?1")?;
                for (id, traffic) in deltas {
                    let (upload, download) = sqlite_traffic(traffic)?;
                    stmt.execute(params![id, upload, download])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Atomically persists local usage and the deltas still owed to the panel.
    pub fn stage_traffic(&self, deltas: &[(i64, Traffic)]) -> Result<(), StoreError> {
        self.with_conn(|conn| {
            let tx = conn.transaction()?;
            for (id, traffic) in deltas {
                let (upload, download) = sqlite_traffic(traffic)?;
                tx.execute(
                    "UPDATE users SET upload = upload + ?2, download = download + ?3 WHERE id = ?1",
                    params![id, upload, download],
                )?;
                tx.execute(
                    "INSERT INTO pending_traffic (user_id, upload, download) VALUES (?1, ?2, ?3)
                     ON CONFLICT(user_id) DO UPDATE SET
                     upload = upload + excluded.upload, download = download + excluded.download",
                    params![id, upload, download],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
    }

    pub fn pending_traffic(&self) -> Result<Vec<(i64, Traffic)>, StoreError> {
        self.with_conn(|conn| {
            let mut statement =
                conn.prepare("SELECT user_id, upload, download FROM pending_traffic ORDER BY user_id")?;
            let rows = statement.query_map([], |row| {
                // The outbox CHECK constraints guarantee nonnegative i64 values.
                Ok((
                    row.get(0)?,
                    Traffic { upload: row.get::<_, i64>(1)? as u64, download: row.get::<_, i64>(2)? as u64 },
                ))
            })?;
            rows.collect::<Result<Vec<_>, _>>().map_err(StoreError::from)
        })
    }

    /// Removes only the delivered snapshot, retaining bytes staged since it was read.
    pub fn acknowledge_traffic(&self, delivered: &[(i64, Traffic)]) -> Result<(), StoreError> {
        self.with_conn(|conn| {
            let tx = conn.transaction()?;
            for (id, traffic) in delivered {
                let (upload, download) = sqlite_traffic(traffic)?;
                tx.execute(
                    "UPDATE pending_traffic SET upload = upload - ?2, download = download - ?3 WHERE user_id = ?1",
                    params![id, upload, download],
                )?;
            }
            tx.execute("DELETE FROM pending_traffic WHERE upload = 0 AND download = 0", [])?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn reset_traffic(&self, id: Option<i64>) -> Result<usize, StoreError> {
        self.with_conn(|conn| match id {
            Some(id) => Ok(conn.execute("UPDATE users SET upload = 0, download = 0 WHERE id = ?1", [id])?),
            None => Ok(conn.execute("UPDATE users SET upload = 0, download = 0", [])?),
        })
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        self.with_conn(|conn| {
            conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| row.get(0))
                .optional()
                .map_err(StoreError::from)
        })
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )?;
            Ok(())
        })
    }
}

fn sqlite_limit(value: u64, field: &str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Invalid(format!("{field} exceeds SQLite integer range")))
}

fn sqlite_traffic(traffic: &Traffic) -> Result<(i64, i64), StoreError> {
    let upload =
        i64::try_from(traffic.upload).map_err(|_| StoreError::Invalid("upload exceeds SQLite integer range".into()))?;
    let download = i64::try_from(traffic.download)
        .map_err(|_| StoreError::Invalid("download exceeds SQLite integer range".into()))?;
    Ok((upload, download))
}

fn row_to_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: row.get(0)?,
        uuid: row.get(1)?,
        speed_limit: row.get::<_, i64>(2)?.max(0) as u64,
        device_limit: row.get::<_, i64>(3)?.max(0) as u32,
        transfer_enable: row.get::<_, i64>(4)?.max(0) as u64,
        expired_at: row.get(5)?,
        enabled: row.get::<_, i64>(6)? != 0,
        upload: row.get::<_, i64>(7)?.max(0) as u64,
        download: row.get::<_, i64>(8)?.max(0) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: i64, uuid: &str) -> UserSpec {
        UserSpec {
            id,
            uuid: uuid.into(),
            speed_limit: 100,
            device_limit: 2,
            transfer_enable: 1000,
            expired_at: 0,
            enabled: true,
        }
    }

    #[test]
    fn duplicate_uuid_rejected() {
        let store = Store::open_memory().unwrap();
        store.upsert_user(&spec(1, "a")).unwrap();
        let err = store.upsert_user(&spec(2, "a")).unwrap_err();
        assert!(matches!(err, StoreError::DuplicateUuid(_)));
    }

    #[test]
    fn reset_traffic_single_and_all() {
        let store = Store::open_memory().unwrap();
        store.replace_users(&[spec(1, "a"), spec(2, "b")]).unwrap();
        store
            .add_traffic(&[
                (1, crate::config::Traffic { upload: 5, download: 5 }),
                (2, crate::config::Traffic { upload: 7, download: 7 }),
            ])
            .unwrap();
        store.reset_traffic(Some(1)).unwrap();
        let users = store.list_users().unwrap();
        assert_eq!(0, users[0].used());
        assert_eq!(14, users[1].used());
        store.reset_traffic(None).unwrap();
        assert!(store.list_users().unwrap().iter().all(|u| u.used() == 0));
    }
}
