//! The local API exposes only authenticated queries over panel users.

use std::sync::Arc;
use std::time::Duration;
use xboard_snell::accounting::{Counters, Registry};
use xboard_snell::admin::AdminState;
use xboard_snell::config::UserSpec;
use xboard_snell::store::Store;

#[tokio::test]
async fn admin_api_is_read_only_and_keeps_query_authentication() {
    let store = Store::open_memory().unwrap();
    store
        .replace_users(&[UserSpec {
            id: 1,
            uuid: "panel-user".into(),
            speed_limit: 0,
            device_limit: 0,
            transfer_enable: 0,
            expired_at: 0,
            enabled: true,
        }])
        .unwrap();
    let registry = Arc::new(Registry::new(Duration::from_secs(300)));
    registry.apply_users(&store.list_users().unwrap());
    let app = xboard_snell::admin::router(AdminState {
        store,
        registry,
        counters: Arc::new(Counters::default()),
        token: Arc::new("query-test-token".into()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    assert_eq!(200, client.get(format!("{base}/health")).send().await.unwrap().status());
    assert_eq!(401, client.get(format!("{base}/api/v1/users")).send().await.unwrap().status());
    for path in ["/api/v1/stats", "/api/v1/users", "/api/v1/users/1"] {
        assert_eq!(
            200,
            client.get(format!("{base}{path}")).bearer_auth("query-test-token").send().await.unwrap().status()
        );
    }
    for (method, path) in [
        (reqwest::Method::POST, "/api/v1/users"),
        (reqwest::Method::PUT, "/api/v1/users/1"),
        (reqwest::Method::DELETE, "/api/v1/users/1"),
        (reqwest::Method::POST, "/api/v1/users/1/traffic"),
        (reqwest::Method::POST, "/api/v1/traffic/reset"),
        (reqwest::Method::PUT, "/api/v1/users/1/block"),
        (reqwest::Method::PUT, "/api/v1/users/1/unblock"),
    ] {
        let status = client
            .request(method, format!("{base}{path}"))
            .bearer_auth("query-test-token")
            .json(&serde_json::json!({"id": 1, "uuid": "local-user"}))
            .send()
            .await
            .unwrap()
            .status();
        assert!(matches!(status.as_u16(), 404 | 405), "write path {path}: {status}");
    }
    let user: serde_json::Value = client
        .get(format!("{base}/api/v1/users/1"))
        .bearer_auth("query-test-token")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!("panel-user", user["uuid"]);
    task.abort();
}
