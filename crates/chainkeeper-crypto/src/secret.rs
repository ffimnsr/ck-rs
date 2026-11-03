//! Passphrase wrapper that never renders its contents.

use std::fmt;

/// Passphrase supplied by the binary boundary.
///
/// The value is never rendered by [`Debug`] or [`fmt::Display`], so it cannot
/// leak through logs or error messages by accident. [`expose`] is the only way
/// to read the secret and callers are expected to use it immediately.
///
/// [`expose`]: SecretString::expose
#[derive(Clone, PartialEq, Eq)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a passphrase.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrows the passphrase.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Consumes the wrapper, returning the owned passphrase.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Number of bytes in the passphrase.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the passphrase is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::SecretString;

    #[test]
    fn debug_never_contains_the_secret() {
        let secret = SecretString::new("correct horse battery staple");
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("horse"));
        assert_eq!(rendered, "SecretString(<redacted>)");
    }

    #[test]
    fn expose_returns_the_original_value() {
        let secret = SecretString::new("hunter2");
        assert_eq!(secret.expose(), "hunter2");
        assert_eq!(secret.len(), 7);
        assert!(!secret.is_empty());
    }
}
