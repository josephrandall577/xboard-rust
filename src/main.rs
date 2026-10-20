//! `xboard-snell`: an Xboard-compatible Snell v6 landing server.
//!
//! ```text
//! xboard-snell -c config.toml
//! ```

use clap::Parser;
use tracing_subscriber::EnvFilter;
use xboard_snell::config;
use xboard_snell::node;

#[derive(Parser, Debug)]
#[command(name = "xboard-snell", version, about = "Xboard-compatible Snell v6 node backend")]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(short, long, env = "SNELL_XBOARD_CONFIG", default_value = "config.toml")]
    config: String,

    /// Check the configuration and exit.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let config = match config::Config::load(&args.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        }
    };

    let filter = EnvFilter::try_new(&config.log.level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if args.check {
        tracing::info!("configuration is valid");
        return Ok(());
    }

    node::mark_start();
    let nodes = node::Node::start_many(config).await?;
    for node in &nodes {
        tracing::info!(
            name = %node.name,
            listen = %node.config.node.listen,
            database = %node.config.storage.path,
            mode = %node.config.node.mode,
            panel = node.panel.is_some(),
            "xboard-snell node started"
        );
    }
    if let Some(node) = nodes.first() {
        node.wait_for_signal().await;
    }
    for node in &nodes {
        node.shutdown().await;
    }
    Ok(())
}
