//! Durable accounting and panel outbox transactions through Store's interface.
use xboard_snell::config::Traffic;
use xboard_snell::{Store, UserSpec};

fn user(id: i64) -> UserSpec {
    UserSpec {
        id,
        uuid: format!("store-user-{id}"),
        speed_limit: 0,
        device_limit: 0,
        transfer_enable: 0,
        expired_at: 0,
        enabled: true,
    }
}

#[test]
fn acknowledged_snapshot_keeps_new_bytes_and_local_totals_across_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("outbox.db");
    let store = Store::open(&path).unwrap();
    store.upsert_user(&user(1)).unwrap();
    store.stage_traffic(&[(1, Traffic { upload: 100, download: 20 })]).unwrap();
    let delivered = store.pending_traffic().unwrap();
    store.stage_traffic(&[(1, Traffic { upload: 5, download: 7 })]).unwrap();
    store.acknowledge_traffic(&delivered).unwrap();
    drop(store);
    let store = Store::open(&path).unwrap();
    assert_eq!(132, store.get_user(1).unwrap().unwrap().used());
    assert_eq!(vec![(1, Traffic { upload: 5, download: 7 })], store.pending_traffic().unwrap());
    store.acknowledge_traffic(&store.pending_traffic().unwrap()).unwrap();
    assert!(store.pending_traffic().unwrap().is_empty());
    assert_eq!(132, store.get_user(1).unwrap().unwrap().used());
}

#[test]
fn invalid_batch_rolls_back_both_local_usage_and_delivery_queue() {
    let store = Store::open_memory().unwrap();
    store.upsert_user(&user(1)).unwrap();
    store.upsert_user(&user(2)).unwrap();
    let result = store
        .stage_traffic(&[(1, Traffic { upload: 100, download: 20 }), (2, Traffic { upload: u64::MAX, download: 0 })]);
    assert!(result.is_err());
    assert_eq!(0, store.get_user(1).unwrap().unwrap().used());
    assert_eq!(0, store.get_user(2).unwrap().unwrap().used());
    assert!(store.pending_traffic().unwrap().is_empty());
}

#[test]
fn an_acknowledgement_cannot_remove_more_than_was_staged() {
    let store = Store::open_memory().unwrap();
    store.upsert_user(&user(1)).unwrap();
    store.stage_traffic(&[(1, Traffic { upload: 10, download: 0 })]).unwrap();
    assert!(store.acknowledge_traffic(&[(1, Traffic { upload: 11, download: 0 })]).is_err());
    assert_eq!(vec![(1, Traffic { upload: 10, download: 0 })], store.pending_traffic().unwrap());
}

#[test]
fn snapshot_rotation_preserves_usage_by_id_not_by_psk() {
    let store = Store::open_memory().unwrap();
    let original = user(1);
    store.replace_users(std::slice::from_ref(&original)).unwrap();
    store.stage_traffic(&[(1, Traffic { upload: 40, download: 2 })]).unwrap();
    store.replace_users(std::slice::from_ref(&original)).unwrap();
    assert_eq!(42, store.get_user(1).unwrap().unwrap().used());
    let mut rotated = original.clone();
    rotated.uuid = "rotated-store-user".into();
    let mut other = user(2);
    other.uuid = original.uuid;
    store.replace_users(&[rotated, other]).unwrap();
    assert_eq!(42, store.get_user(1).unwrap().unwrap().used());
    assert_eq!(0, store.get_user(2).unwrap().unwrap().used());
    assert_eq!(vec![(1, Traffic { upload: 40, download: 2 })], store.pending_traffic().unwrap());
    store.replace_users(&[user(1), user(3)]).unwrap();
    assert!(store.get_user(2).unwrap().is_none());
    assert_eq!(42, store.get_user(1).unwrap().unwrap().used());
    assert_eq!(0, store.get_user(3).unwrap().unwrap().used());
}

#[test]
fn overflowing_limits_reject_updates_atomically() {
    let store = Store::open_memory().unwrap();
    store.upsert_user(&user(1)).unwrap();
    for quota in [false, true] {
        let mut invalid = user(2);
        if quota {
            invalid.transfer_enable = u64::MAX;
        } else {
            invalid.speed_limit = u64::MAX;
        }
        assert!(store.replace_users(&[user(3), invalid.clone()]).is_err());
        assert_eq!(vec![1], store.list_users().unwrap().iter().map(|u| u.id).collect::<Vec<_>>());
        assert!(store.upsert_user(&invalid).is_err());
        assert!(store.get_user(2).unwrap().is_none());
    }
}

#[test]
fn revoked_users_keep_traffic_owed_to_panel() {
    let store = Store::open_memory().unwrap();
    store.upsert_user(&user(1)).unwrap();
    store.stage_traffic(&[(1, Traffic { upload: 10, download: 20 })]).unwrap();
    store.replace_users(&[]).unwrap();
    store.stage_traffic(&[(1, Traffic { upload: 1, download: 2 })]).unwrap();
    assert_eq!(vec![(1, Traffic { upload: 11, download: 22 })], store.pending_traffic().unwrap());
}
