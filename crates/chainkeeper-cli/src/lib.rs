#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// The CLI intentionally keeps command modules private; only the entry points
// used by the binary and integration tests are exported.
#![allow(clippy::missing_errors_doc)]

//! `ck` command line interface.
//!
//! Command handlers consume [`chainkeeper_core::ChainkeeperService`] and a
//! [`ui::Ui`] abstraction so the complete command surface can be tested with
//! deterministic doubles.

pub mod app;
pub mod cli;
pub mod commands;
pub mod error;
mod format;
mod prompt;
pub mod selector;
pub mod service;
pub mod ui;

pub use app::{dispatch, run};
pub use cli::Cli;
pub use error::CliError;
pub use prompt::Prompter;
pub use ui::{HumanUi, JsonUi, Ui, color_enabled};

/// Version, commit, and target triple rendered by `--version`.
#[must_use]
pub fn version_string() -> String {
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
