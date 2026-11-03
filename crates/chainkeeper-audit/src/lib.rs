#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Append-only audit log.
//!
//! Audit events are stored as one immutable canonical JSON file per event at
//! `audit/events/<ULID>.json`. There is no update or delete API.
//!
//! [`FileAuditLog`] implements [`chainkeeper_core::AuditLog`]. Callers inject
//! the repository lock and identifier generator, so the log is usable with the
//! production filesystem lock as well as deterministic test doubles.

mod canonical;
mod file_log;
mod verify;

pub use canonical::{from_canonical_json, to_canonical_json};
pub use file_log::{DEFAULT_LOCK_TIMEOUT, FileAuditLog};
pub use verify::{AUDIT_DUPLICATE, AUDIT_INVALID, AUDIT_SEQ_GAP, verify_events};
