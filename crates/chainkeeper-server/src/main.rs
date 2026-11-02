//! `ck-server` read-only PKI server entry point.
//!
//! Phase 1 wires global flags and build metadata. HTTP endpoints and the
//! repository watcher are implemented by Phase 10.

use std::path::PathBuf;

use anyhow::Result;
use chainkeeper_core::init_tracing;
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
    #[arg(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
    bind: String,

    /// Repository root to serve.
    #[arg(long, default_value = ".", value_name = "PATH")]
    repo: PathBuf,

    /// External publish directory rebuilt by the server.
    #[arg(long, value_name = "PATH")]
    publish_dir: Option<PathBuf>,

    /// Disable coloured output.
    #[arg(long)]
    no_color: bool,
}

fn main() -> Result<()> {
    let command = Cli::command().version(version_string());
    let matches = command.get_matches();
    let cli = Cli::from_arg_matches(&matches)?;

    init_tracing()?;

    if cli.no_color {
        // Colour is a CLI concern only; library crates never decide it.
        tracing::debug!("colour output disabled");
    }

    println!(
        "ck-server {}: would serve {} on {} (endpoints arrive in phase 10)",
        env!("CARGO_PKG_VERSION"),
        cli.repo.display(),
        cli.bind
    );
    if let Some(publish_dir) = cli.publish_dir {
        println!("publish directory: {}", publish_dir.display());
    }
    Ok(())
}
