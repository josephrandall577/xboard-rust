//! `snell-xboard-node`: an Xboard-compatible Snell v6 landing server.
//!
//! ```text
//! snell-xboard-node -c config.toml
//! ```

use clap::Parser;
use snell_xboard_node::config;
use snell_xboard_node::node;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "snell-xboard-node", version, about = "Xboard-compatible Snell v6 node backend")]
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
    let node = node::Node::start(config).await?;
    tracing::info!(
        listen = %node.config.node.listen,
        database = %node.config.storage.path,
        mode = %node.config.node.mode,
        panel = node.panel.is_some(),
        "snell-xboard-node started"
    );
    node.wait_for_signal().await;
    node.shutdown().await;
    Ok(())
}
