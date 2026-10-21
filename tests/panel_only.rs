//! Panel-only operation through the configuration and node startup boundaries.

use xboard_snell::config::Config;
use xboard_snell::node::Node;

fn example() -> Config {
    Config::load(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml")).unwrap()
}

#[tokio::test]
async fn single_node_requires_panel_even_when_started_directly() {
    let temp = tempfile::tempdir().unwrap();
    let mut config = example();
    config.panel = None;
    config.node.listen = "127.0.0.1:0".into();
    config.admin.disabled = true;
    config.storage.path = temp.path().join("node.db").to_string_lossy().into_owned();
    assert!(config.validate().is_err(), "missing panel must fail validation");
    let result = Node::start(config).await;
    if let Ok(node) = &result {
        node.shutdown().await;
    }
    assert!(result.is_err(), "direct startup must also require a panel");
    assert!(!temp.path().join("node.db").exists(), "reject before creating a database");
}

#[test]
fn panel_credentials_and_polling_settings_are_required() {
    for field in ["url", "token", "api_version", "pull_interval", "push_interval"] {
        let mut config = example();
        let panel = config.panel.as_mut().unwrap();
        match field {
            "url" => panel.url = "not-a-url".into(),
            "token" => panel.token.clear(),
            "api_version" => panel.api_version = 3,
            "pull_interval" => panel.pull_interval = 0,
            "push_interval" => panel.push_interval = 0,
            _ => unreachable!(),
        }
        assert!(config.validate().is_err(), "invalid {field} must be rejected");
    }
}

#[test]
fn local_user_configuration_is_rejected_instead_of_silently_ignored() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.toml");
    let source = include_str!("../config.example.toml");
    std::fs::write(&path, format!("{source}\n[[node.users]]\nid = 1\nuuid = \"local-key\"\n")).unwrap();
    assert!(Config::load(path.to_str().unwrap()).is_err());
}
