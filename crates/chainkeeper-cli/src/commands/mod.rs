//! Command handlers.

mod analyze;
mod audit;
mod authorities;
mod diff;
mod doctor;
mod index;
mod init;
mod inspect;
mod issue;
mod publish;
mod revoke;
mod search;
mod tree;

use std::path::Path;

use chainkeeper_core::ChainkeeperService;
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::error::CliError;
use crate::format::json_value;
use crate::prompt::Prompter;
use crate::ui::Ui;

/// Shared command execution context.
pub struct Context<'a> {
    /// Service surface.
    pub service: &'a dyn ChainkeeperService,
    /// Output renderer.
    pub ui: &'a dyn Ui,
    /// Prompt behaviour.
    pub prompt: Prompter,
    /// Repository root.
    pub repo: &'a Path,
    /// Fixed command time.
    pub now: OffsetDateTime,
    /// Whether JSON output is active.
    pub json: bool,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Context")
            .field("repo", &self.repo)
            .field("now", &self.now)
            .field("json", &self.json)
            .finish_non_exhaustive()
    }
}

impl Context<'_> {
    /// Serialises a report for JSON output.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Operation`] when the report is not serialisable.
    pub fn json_value<T: Serialize>(&self, value: &T) -> Result<Value, CliError> {
        json_value(value)
    }
}

pub use analyze::run as analyze;
pub use audit::run as audit;
pub use authorities::{inspect as intermediate_inspect, intermediate, ocsp_signer, root};
pub use diff::run as diff;
pub use doctor::run as doctor;
pub use index::run as index;
pub use init::run as init;
pub use inspect::run as inspect;
pub use issue::run as issue;
pub use publish::run as publish;
pub use revoke::run as revoke;
pub use search::run as search;
pub use tree::run as tree;
