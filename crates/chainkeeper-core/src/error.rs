//! Stable error type shared by every Chainkeeper crate.
//!
//! Display output is part of the public contract: it is asserted by tests and
//! echoed by CLI commands, so it must not change without a backlog item.

use std::error::Error as StdError;
use std::fmt;

/// Machine-readable classification of a [`ChainkeeperError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Configuration was missing, malformed, or unsupported.
    Config,
    /// Input failed syntactic validation.
    Validation,
    /// Input violated the PKI policy.
    Policy,
    /// A certificate profile was invalid.
    Profile,
    /// A cryptographic provider or signer failed.
    Crypto,
    /// Canonical filesystem storage failed.
    Storage,
    /// The disposable SQLite index failed.
    Index,
    /// The append-only audit log failed.
    Audit,
    /// A Git operation failed.
    Git,
    /// Repository locking failed.
    Lock,
    /// Publication failed.
    Publish,
    /// OCSP handling failed.
    Ocsp,
    /// The requested object does not exist.
    NotFound,
    /// The requested object already exists.
    AlreadyExists,
    /// The operation conflicts with current state.
    Conflict,
    /// The operation is not implemented.
    NotImplemented,
    /// An underlying I/O operation failed.
    Io,
}

impl ErrorKind {
    /// Every error kind, in declaration order.
    pub const ALL: [Self; 17] = [
        Self::Config,
        Self::Validation,
        Self::Policy,
        Self::Profile,
        Self::Crypto,
        Self::Storage,
        Self::Index,
        Self::Audit,
        Self::Git,
        Self::Lock,
        Self::Publish,
        Self::Ocsp,
        Self::NotFound,
        Self::AlreadyExists,
        Self::Conflict,
        Self::NotImplemented,
        Self::Io,
    ];

    /// Short stable label used in error display output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config error",
            Self::Validation => "validation error",
            Self::Policy => "policy error",
            Self::Profile => "profile error",
            Self::Crypto => "crypto error",
            Self::Storage => "storage error",
            Self::Index => "index error",
            Self::Audit => "audit error",
            Self::Git => "git error",
            Self::Lock => "lock error",
            Self::Publish => "publish error",
            Self::Ocsp => "ocsp error",
            Self::NotFound => "not found",
            Self::AlreadyExists => "already exists",
            Self::Conflict => "conflict",
            Self::NotImplemented => "not implemented",
            Self::Io => "io error",
        }
    }
}

/// Owned source error attached to a [`ChainkeeperError`].
///
/// The wrapper exists because trait object upcasting is not available on the
/// 1.85 MSRV; it lets `source()` return a plain `&dyn Error`.
#[derive(Debug)]
pub struct ErrorSource(Box<dyn StdError + Send + Sync>);

impl ErrorSource {
    /// Wraps an owned source error.
    #[must_use]
    pub fn new(source: impl StdError + Send + Sync + 'static) -> Self {
        Self(Box::new(source))
    }

    /// Rendered message of the wrapped error.
    #[must_use]
    pub fn message(&self) -> String {
        self.0.to_string()
    }
}

impl fmt::Display for ErrorSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl StdError for ErrorSource {}

/// Detail carried by every [`ChainkeeperError`] variant.
#[derive(Debug)]
#[non_exhaustive]
pub struct ErrorDetail {
    message: String,
    source: Option<ErrorSource>,
    object_id: Option<String>,
}

impl ErrorDetail {
    /// Builds a detail record with the given message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
            object_id: None,
        }
    }

    /// Human readable message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Identifier of the object the error refers to, if known.
    #[must_use]
    pub fn object_id(&self) -> Option<&str> {
        self.object_id.as_deref()
    }

    /// Attaches an underlying source error.
    #[must_use]
    pub fn with_source(mut self, source: impl StdError + Send + Sync + 'static) -> Self {
        self.source = Some(ErrorSource::new(source));
        self
    }

    /// Attaches the identifier of the object the error refers to.
    #[must_use]
    pub fn with_object_id(mut self, object_id: impl Into<String>) -> Self {
        self.object_id = Some(object_id.into());
        self
    }
}

macro_rules! define_errors {
    ($( $variant:ident => $constructor:ident, )*) => {
        /// Error type shared by every Chainkeeper crate.
        #[derive(Debug)]
        #[non_exhaustive]
        pub enum ChainkeeperError {
            $( $variant(ErrorDetail), )*
        }

        impl ChainkeeperError {
            $(
                /// Builds this error variant with the given message.
                #[must_use]
                pub fn $constructor(message: impl Into<String>) -> Self {
                    Self::$variant(ErrorDetail::new(message))
                }
            )*

            /// Builds this error variant with the given detail record.
            #[must_use]
            pub const fn from_detail(variant: ErrorKind, detail: ErrorDetail) -> Self {
                match variant {
                    $( ErrorKind::$variant => Self::$variant(detail), )*
                }
            }
        }
    };
}

define_errors! {
    Config => config,
    Validation => validation,
    Policy => policy,
    Profile => profile,
    Crypto => crypto,
    Storage => storage,
    Index => index,
    Audit => audit,
    Git => git,
    Lock => lock,
    Publish => publish,
    Ocsp => ocsp,
    NotFound => not_found_error,
    AlreadyExists => already_exists,
    Conflict => conflict,
    NotImplemented => not_implemented,
    Io => io_error,
}

impl ChainkeeperError {
    /// Classification of this error.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        match self {
            Self::Config(_) => ErrorKind::Config,
            Self::Validation(_) => ErrorKind::Validation,
            Self::Policy(_) => ErrorKind::Policy,
            Self::Profile(_) => ErrorKind::Profile,
            Self::Crypto(_) => ErrorKind::Crypto,
            Self::Storage(_) => ErrorKind::Storage,
            Self::Index(_) => ErrorKind::Index,
            Self::Audit(_) => ErrorKind::Audit,
            Self::Git(_) => ErrorKind::Git,
            Self::Lock(_) => ErrorKind::Lock,
            Self::Publish(_) => ErrorKind::Publish,
            Self::Ocsp(_) => ErrorKind::Ocsp,
            Self::NotFound(_) => ErrorKind::NotFound,
            Self::AlreadyExists(_) => ErrorKind::AlreadyExists,
            Self::Conflict(_) => ErrorKind::Conflict,
            Self::NotImplemented(_) => ErrorKind::NotImplemented,
            Self::Io(_) => ErrorKind::Io,
        }
    }

    /// Detail record carried by this error.
    #[must_use]
    pub const fn detail(&self) -> &ErrorDetail {
        match self {
            Self::Config(detail)
            | Self::Validation(detail)
            | Self::Policy(detail)
            | Self::Profile(detail)
            | Self::Crypto(detail)
            | Self::Storage(detail)
            | Self::Index(detail)
            | Self::Audit(detail)
            | Self::Git(detail)
            | Self::Lock(detail)
            | Self::Publish(detail)
            | Self::Ocsp(detail)
            | Self::NotFound(detail)
            | Self::AlreadyExists(detail)
            | Self::Conflict(detail)
            | Self::NotImplemented(detail)
            | Self::Io(detail) => detail,
        }
    }

    /// Human readable message.
    #[must_use]
    pub fn message(&self) -> &str {
        self.detail().message()
    }

    /// Identifier of the object the error refers to, if known.
    #[must_use]
    pub fn object_id(&self) -> Option<&str> {
        self.detail().object_id()
    }

    /// Prepends context to the message while preserving source and object id.
    #[must_use]
    pub fn with_context(self, message: impl Into<String>) -> Self {
        let kind = self.kind();
        let detail = self.take_detail();
        let combined = format!("{}: {}", message.into(), detail.message());
        let mut rebuilt = ErrorDetail::new(combined);
        rebuilt.source = detail.source;
        rebuilt.object_id = detail.object_id;
        Self::from_detail(kind, rebuilt)
    }

    /// Builds a `NotFound` error for the given object kind and identifier.
    #[must_use]
    pub fn not_found(object: &str, id: &str) -> Self {
        Self::NotFound(ErrorDetail::new(format!("{object} not found")).with_object_id(id))
    }

    /// Builds a `Validation` error for the given object kind and identifier.
    #[must_use]
    pub fn invalid(object: &str, id: &str, reason: impl fmt::Display) -> Self {
        Self::Validation(ErrorDetail::new(format!("invalid {object}: {reason}")).with_object_id(id))
    }

    /// Process exit code for this error.
    ///
    /// `0` is reserved for success and `2` is reserved for CLI usage errors
    /// produced by `clap`, so errors always map to `1`. Doctor findings use `3`
    /// at the CLI layer, which is not represented by this type.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        1
    }

    fn take_detail(self) -> ErrorDetail {
        match self {
            Self::Config(detail)
            | Self::Validation(detail)
            | Self::Policy(detail)
            | Self::Profile(detail)
            | Self::Crypto(detail)
            | Self::Storage(detail)
            | Self::Index(detail)
            | Self::Audit(detail)
            | Self::Git(detail)
            | Self::Lock(detail)
            | Self::Publish(detail)
            | Self::Ocsp(detail)
            | Self::NotFound(detail)
            | Self::AlreadyExists(detail)
            | Self::Conflict(detail)
            | Self::NotImplemented(detail)
            | Self::Io(detail) => detail,
        }
    }
}

impl fmt::Display for ChainkeeperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = self.detail();
        write!(f, "{}: {}", self.kind().as_str(), detail.message())?;
        if let Some(object_id) = detail.object_id() {
            write!(f, " ({object_id})")?;
        }
        Ok(())
    }
}

impl StdError for ChainkeeperError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.detail()
            .source
            .as_ref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

impl From<std::io::Error> for ChainkeeperError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(ErrorDetail::new(error.to_string()).with_source(error))
    }
}

#[cfg(test)]
mod tests {
    use super::{ChainkeeperError, ErrorKind};

    #[test]
    fn display_is_stable() {
        assert_eq!(
            ChainkeeperError::config("bad file").to_string(),
            "config error: bad file"
        );
        assert_eq!(
            ChainkeeperError::not_found("certificate", "ABCD").to_string(),
            "not found: certificate not found (ABCD)"
        );
        assert_eq!(
            ChainkeeperError::not_implemented("later").to_string(),
            "not implemented: later"
        );
    }

    #[test]
    fn display_covers_every_variant() {
        let cases = [
            (ChainkeeperError::config("x"), "config error: x"),
            (ChainkeeperError::validation("x"), "validation error: x"),
            (ChainkeeperError::policy("x"), "policy error: x"),
            (ChainkeeperError::profile("x"), "profile error: x"),
            (ChainkeeperError::crypto("x"), "crypto error: x"),
            (ChainkeeperError::storage("x"), "storage error: x"),
            (ChainkeeperError::index("x"), "index error: x"),
            (ChainkeeperError::audit("x"), "audit error: x"),
            (ChainkeeperError::git("x"), "git error: x"),
            (ChainkeeperError::lock("x"), "lock error: x"),
            (ChainkeeperError::publish("x"), "publish error: x"),
            (ChainkeeperError::ocsp("x"), "ocsp error: x"),
            (
                ChainkeeperError::not_found("certificate", "AB"),
                "not found: certificate not found (AB)",
            ),
            (ChainkeeperError::already_exists("x"), "already exists: x"),
            (ChainkeeperError::conflict("x"), "conflict: x"),
            (ChainkeeperError::not_implemented("x"), "not implemented: x"),
            (ChainkeeperError::io_error("x"), "io error: x"),
        ];
        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn every_variant_has_exit_code_one() {
        let errors = [
            ChainkeeperError::config("x"),
            ChainkeeperError::validation("x"),
            ChainkeeperError::policy("x"),
            ChainkeeperError::profile("x"),
            ChainkeeperError::crypto("x"),
            ChainkeeperError::storage("x"),
            ChainkeeperError::index("x"),
            ChainkeeperError::audit("x"),
            ChainkeeperError::git("x"),
            ChainkeeperError::lock("x"),
            ChainkeeperError::publish("x"),
            ChainkeeperError::ocsp("x"),
            ChainkeeperError::not_found("certificate", "x"),
            ChainkeeperError::already_exists("x"),
            ChainkeeperError::conflict("x"),
            ChainkeeperError::not_implemented("x"),
            ChainkeeperError::io_error("x"),
        ];
        assert_eq!(errors.len(), 17);
        for error in errors {
            assert_eq!(error.exit_code(), 1, "{}", error.kind().as_str());
        }
    }

    #[test]
    fn with_context_preserves_kind_and_object_id() {
        let error = ChainkeeperError::not_found("certificate", "AB").with_context("loading");
        assert_eq!(error.kind(), ErrorKind::NotFound);
        assert_eq!(error.object_id(), Some("AB"));
        assert_eq!(error.message(), "loading: certificate not found");
    }
}
