//! `ck` command line entry point.
//!
//! Phase 1 wires global flags, tracing, and build metadata. Subcommands are
//! implemented by Phase 9.

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
#[command(name = "ck", about = "Chainkeeper PKI command line interface")]
struct Cli {
    /// Disable coloured output.
    #[arg(long, global = true)]
    no_color: bool,

    /// Path to the repository root. Defaults to the current directory.
    #[arg(long, global = true, value_name = "PATH")]
    repo: Option<std::path::PathBuf>,
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

    let repo = cli.repo.unwrap_or_else(|| std::path::PathBuf::from("."));
    println!(
        "ck {}: repository {} (subcommands arrive in phase 9)",
        env!("CARGO_PKG_VERSION"),
        repo.display()
    );
    Ok(())
}
