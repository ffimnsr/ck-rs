//! `ck-server` read-only PKI server entry point.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use chainkeeper_core::init_tracing;
use chainkeeper_server::config::ServerConfig;
use chainkeeper_server::runtime::build_state;
use clap::{CommandFactory, FromArgMatches, Parser};

fn version_string() -> String {
    let dirty = if option_env!("VERGEN_GIT_DIRTY") == Some("true") {
        "-dirty"
    } else {
        ""
    };
    format!(
        "{} (commit {}{dirty}, {})",
        env!("CARGO_PKG_VERSION"),
        option_env!("VERGEN_GIT_SHA").unwrap_or("unknown"),
        option_env!("VERGEN_CARGO_TARGET_TRIPLE").unwrap_or("unknown"),
    )
}

#[derive(Debug, Parser)]
#[command(name = "ck-server", about = "Chainkeeper read-only PKI server")]
struct Cli {
    /// Address to bind the HTTP listener to.
    #[arg(long, value_name = "ADDR")]
    bind: Option<String>,

    /// Repository root to serve.
    #[arg(long, value_name = "PATH")]
    repo: Option<PathBuf>,

    /// External publish directory rebuilt by the server.
    #[arg(long, value_name = "PATH")]
    publish_dir: Option<PathBuf>,

    /// Configuration file, default `server.yaml`.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Disable coloured output.
    #[arg(long)]
    no_color: bool,
}

fn load_config(cli: &Cli) -> Result<ServerConfig> {
    let path = cli
        .config
        .clone()
        .or_else(|| std::env::var_os("CHAINKEEPER_SERVER_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("server.yaml"));
    let mut config =
        ServerConfig::read(&path).with_context(|| format!("could not load {}", path.display()))?;
    if let Some(bind) = &cli.bind {
        config.bind = bind.parse().context("invalid --bind address")?;
    }
    if let Some(repo) = &cli.repo {
        config.repo.clone_from(repo);
    }
    if let Some(publish_dir) = &cli.publish_dir {
        config.publish_dir.clone_from(publish_dir);
    }
    config.validate().context("invalid server configuration")?;
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    let command = Cli::command().version(version_string());
    let matches = command.get_matches();
    let cli = Cli::from_arg_matches(&matches)?;
    let config = load_config(&cli)?;

    init_tracing()?;
    if cli.no_color {
        tracing::debug!("colour output disabled");
    }

    let runtime =
        build_state(&config).context("could not build the server runtime from the repository")?;
    runtime.run_until_signalled().await
}
