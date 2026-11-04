//! Production wiring for the `ck` binary.
//!
//! The composition root lives in [`chainkeeper_engine::service`] so the CLI and
//! integration tests share one object graph. This module only re-exports the
//! entry points the binary needs.

pub use chainkeeper_engine::service::{
    OpenMode, finalize_init, open, open_service, passphrase_from_env,
};

/// Environment variable holding the authority key passphrase.
pub use chainkeeper_engine::service::PASSPHRASE_ENV;
