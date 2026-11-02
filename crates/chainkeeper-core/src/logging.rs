//! Tracing initialisation shared by `ck` and `ck-server`.

use tracing_subscriber::EnvFilter;

use crate::error::ChainkeeperError;

/// Initialises tracing with the `info` default filter.
///
/// Output is JSON when `CHAINKEEPER_LOG_FORMAT=json`, human readable otherwise.
/// `RUST_LOG` overrides the default filter.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Config`] when a global subscriber is already
/// installed.
pub fn init_tracing() -> Result<(), ChainkeeperError> {
    init_tracing_with_default("info")
}

/// Initialises tracing with a caller supplied default filter.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Config`] when a global subscriber is already
/// installed.
pub fn init_tracing_with_default(default_filter: &str) -> Result<(), ChainkeeperError> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let json = std::env::var("CHAINKEEPER_LOG_FORMAT")
        .is_ok_and(|value| value.eq_ignore_ascii_case("json"));

    let result = if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).try_init()
    };

    result
        .map_err(|error| ChainkeeperError::config(format!("could not initialise tracing: {error}")))
}
