#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Git transactions, commit generation, and repository locking.
//!
//! [`GitRepo`] implements [`chainkeeper_core::GitRepository`]. It stages exactly
//! the paths a caller supplies, refuses to commit private keys, and honours
//! `commit.gpgsign` without ever falling back to an unsigned commit.
//!
//! [`RepositoryTransaction`] adds the exclusive lock boundary used by every
//! mutating command, plus rollback for files the transaction created.

mod identity;
mod ignore;
mod message;
mod repo;
mod signing;
mod sync;
mod transaction;

pub use identity::{GitIdentity, resolve_signature};
pub use ignore::{
    GITIGNORE_CONTENT, GITIGNORE_RULES, assert_index_has_no_private_keys,
    assert_no_staged_private_keys, ensure_gitignore, is_private_key_path,
};
pub use message::CommitMessage;
pub use repo::{GitLogEntry, GitRepo, WORKTREE};
pub use signing::{CommitSigner, GpgCommitSigner, signing_enabled};
pub use sync::SyncOutcome;
pub use transaction::{DEFAULT_TRANSACTION_TIMEOUT, RepositoryTransaction};
