#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// Internal orchestration helpers are not part of the public API, so clippy's
// public-documentation and must-use suggestions do not apply to them.
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::option_if_let_else
)]

//! Issuance and revocation orchestration.
//!
//! The engine composes the frozen [`chainkeeper_core`] traits into the
//! [`chainkeeper_core::ChainkeeperService`] surface. It never touches OpenSSL,
//! SQLite, or Git directly: every side effect goes through an injected trait.
//! Tests therefore run against the deterministic doubles in
//! `chainkeeper-testkit`.

mod analyze;
mod authorities;
mod deps;
mod diff;
mod doctor;
mod engine;
mod init;
mod issuance;
mod maintenance;
mod messages;
mod query;
mod revocation;
mod rollback;
mod state;

pub use deps::{AuthoritySigners, EngineDependencies};
pub use engine::Engine;
pub use state::{ChangeCategory, categorize as categorize_path};

/// Default time a mutating operation waits for the repository lock.
pub const DEFAULT_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
