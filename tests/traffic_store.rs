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
