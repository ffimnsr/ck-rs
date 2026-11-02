#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Canonical filesystem store and disposable SQLite index.
//!
//! The filesystem is authoritative: the index can be deleted and rebuilt from
//! canonical records without changing any query result. All paths are derived
//! from [`chainkeeper_core::RepositoryPaths`], and every public artifact write
//! goes through [`chainkeeper_core::atomic_write`].

mod canonical;
mod fsutil;
mod index;
mod layout;
mod locking;
mod parse;

pub use index::{IndexBreakdown, SqliteIndex};
pub use layout::{FileStore, init_layout};
pub use locking::FileRepositoryLock;
pub use parse::{ParsedCertificate, parse_certificate_pem, serial_matches, serials_equal};
