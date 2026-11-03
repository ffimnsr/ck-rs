//! CLI error and exit-code mapping.

use std::fmt;

use chainkeeper_core::ChainkeeperError;

/// Failure surfaced by a command handler.
#[derive(Debug)]
#[non_exhaustive]
pub enum CliError {
    /// Input is missing or malformed; the command never ran.
    Usage(String),
    /// The operation ran and failed.
    Operation(ChainkeeperError),
    /// The operator declined a confirmation.
    Cancelled,
}

impl CliError {
    /// Builds a usage error.
    #[must_use]
    pub fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }

    /// Process exit code for this failure.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Operation(error) => error.exit_code(),
            Self::Cancelled => 1,
        }
    }

    /// Human readable message written to stderr.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Usage(message) => message.clone(),
            Self::Operation(error) => error.to_string(),
            Self::Cancelled => "operation cancelled".to_owned(),
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Operation(error) => Some(error),
            Self::Usage(_) | Self::Cancelled => None,
        }
    }
}

impl From<ChainkeeperError> for CliError {
    fn from(error: ChainkeeperError) -> Self {
        Self::Operation(error)
    }
}
