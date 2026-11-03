#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Publication artifact builder and CRL manager.
//!
//! [`FileCrlManager`] regenerates CRLs from canonical revocation records and
//! [`FilePublishBuilder`] renders a deterministic, private-key-free publish
//! directory from public repository artifacts.

mod builder;
mod crl;
mod deps;
mod diff;
mod fsops;
mod manifest;
mod refresh;
mod validate;

pub use builder::FilePublishBuilder;
pub use crl::FileCrlManager;
pub use deps::{AuthorityProviders, AuthoritySigners, CrlDependencies, PublishDependencies};
pub use diff::{ChangedPaths, changed_paths};
pub use manifest::read as read_manifest;
pub use refresh::refresh_after_revocation;

/// Name of the manifest inside a publish directory.
pub const MANIFEST_FILE: &str = "manifest.json";
