#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Git transactions and repository locking.
//!
//! Implemented by Phase 5. Phase 1 only freezes the contracts in
//! [`chainkeeper_core::GitRepository`] and [`chainkeeper_core::RepositoryLock`].
