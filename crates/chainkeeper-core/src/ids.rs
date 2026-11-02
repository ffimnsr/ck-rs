//! Validated domain identifiers.
//!
//! Every identifier is a newtype over `String` whose constructor rejects path
//! separators and traversal segments. Path builders therefore never need to
//! sanitize raw user input.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ChainkeeperError;
use crate::traits::IdGenerator;

/// Maximum serial length in hex characters.
pub const SERIAL_MAX_HEX_LEN: usize = 64;

fn validate_serial(value: &str) -> bool {
    let bytes = value.as_bytes();
    (2..=SERIAL_MAX_HEX_LEN).contains(&bytes.len())
        && bytes.len().is_multiple_of(2)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(byte))
}

fn validate_slug(value: &str, max_len: usize) -> bool {
    let bytes = value.as_bytes();
    if !(2..=max_len).contains(&bytes.len()) {
        return false;
    }
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    rest.iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// Serial number of an issued certificate.
///
/// A serial is an even-length run of `2..=64` uppercase hexadecimal
/// characters. Production serials are 16 random bytes encoded as 32 uppercase
/// hex characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Serial(String);

impl Serial {
    /// Creates a validated serial.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Validation`] when the value is empty, longer
    /// than 64 characters, odd-length, lowercase, or not hexadecimal.
    pub fn new(value: impl Into<String>) -> Result<Self, ChainkeeperError> {
        let value = value.into();
        if validate_serial(&value) {
            Ok(Self(value))
        } else {
            Err(ChainkeeperError::validation(
                "serial must be even-length uppercase hexadecimal, 2 to 64 characters",
            ))
        }
    }

    /// Encodes raw bytes as an uppercase hexadecimal serial.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            // Writing to a `String` cannot fail.
            let _ = write!(encoded, "{byte:02X}");
        }
        Self(encoded)
    }

    /// Borrowed hexadecimal value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the serial, returning the owned string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Serial {
    type Err = ChainkeeperError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for Serial {
    type Error = ChainkeeperError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Serial {
    type Error = ChainkeeperError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Serial> for String {
    fn from(value: Serial) -> Self {
        value.0
    }
}

macro_rules! define_slug_id {
    ($name:ident, $max_len:expr, $object:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Creates a validated identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ChainkeeperError::Validation`] when the value does not
            /// match `^[a-z][a-z0-9-]*$` or exceeds the allowed length.
            pub fn new(value: impl Into<String>) -> Result<Self, ChainkeeperError> {
                let value = value.into();
                if validate_slug(&value, $max_len) {
                    Ok(Self(value))
                } else {
                    Err(ChainkeeperError::validation(concat!(
                        $object,
                        " must match ^[a-z][a-z0-9-]*$ and respect the length limit"
                    )))
                }
            }

            /// Borrowed identifier value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the identifier, returning the owned string.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ChainkeeperError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ChainkeeperError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ChainkeeperError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

define_slug_id!(
    AuthorityName,
    32,
    "authority name",
    "Name of a certificate authority directory under `authorities/`.\n\nMatches `^[a-z][a-z0-9-]{1,31}$`."
);

define_slug_id!(
    ProfileName,
    32,
    "profile name",
    "Name of a certificate profile under `profiles/`.\n\nMatches `^[a-z][a-z0-9-]{1,31}$`."
);

define_slug_id!(
    TenantId,
    64,
    "tenant id",
    "Identifier of the tenant represented by a repository.\n\nMatches `^[a-z][a-z0-9-]{1,63}$`."
);

/// Identifier of an audit event, stored as a canonical ULID string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EventId(String);

impl EventId {
    /// Creates a validated audit event id.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Validation`] when the value is not a
    /// canonical 26 character Crockford base32 ULID.
    pub fn new(value: impl Into<String>) -> Result<Self, ChainkeeperError> {
        let value = value.into();
        match ulid::Ulid::from_string(&value) {
            Ok(ulid) if ulid.to_string() == value => Ok(Self(value)),
            Ok(_) | Err(_) => Err(ChainkeeperError::validation(
                "audit event id must be a canonical uppercase ULID",
            )),
        }
    }

    /// Borrowed ULID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the identifier, returning the owned string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EventId {
    type Err = ChainkeeperError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for EventId {
    type Error = ChainkeeperError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for EventId {
    type Error = ChainkeeperError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<EventId> for String {
    fn from(value: EventId) -> Self {
        value.0
    }
}

/// Production identifier generator backed by the operating system RNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProductionIdGenerator;

impl IdGenerator for ProductionIdGenerator {
    fn ulid(&self) -> String {
        ulid::Ulid::generate().to_string()
    }

    fn serial(&self) -> Serial {
        let mut bytes = [0_u8; 16];
        rand::fill(&mut bytes);
        Serial::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorityName, EventId, ProfileName, Serial, TenantId};
    use std::str::FromStr as _;

    #[test]
    fn serial_accepts_canonical_values() {
        let serial = Serial::new("00AB").expect("valid serial");
        assert_eq!(serial.as_str(), "00AB");
        assert_eq!(Serial::from_bytes(&[0x00, 0xAB]).as_str(), "00AB");
    }

    #[test]
    fn serial_rejects_invalid_values() {
        for value in ["", "0", "0g", "abcd", "AB/CD", ".."] {
            assert!(Serial::new(value).is_err(), "{value} should be rejected");
        }
    }

    #[test]
    fn slugs_reject_traversal() {
        for value in ["", "a", "..", "a/b", ".hidden", "a\\b", "Upper"] {
            assert!(AuthorityName::new(value).is_err(), "{value}");
            assert!(ProfileName::new(value).is_err(), "{value}");
            assert!(TenantId::new(value).is_err(), "{value}");
        }
        assert!(AuthorityName::new("..").is_err());
        assert!(ProfileName::new("a/b").is_err());
    }

    #[test]
    fn serial_rejects_path_inputs() {
        assert!(Serial::from_str("../etc/passwd").is_err());
        assert!(Serial::from_str("../../key").is_err());
    }

    #[test]
    fn slugs_accept_canonical_values() {
        assert_eq!(AuthorityName::new("tls").expect("valid").as_str(), "tls");
        assert_eq!(
            ProfileName::new("tls-server").expect("valid").as_str(),
            "tls-server"
        );
        assert_eq!(TenantId::new("corp-a").expect("valid").as_str(), "corp-a");
    }

    #[test]
    fn event_id_requires_canonical_ulid() {
        assert!(EventId::new("01J00000000000000000000001").is_ok());
        assert!(EventId::new("01j00000000000000000000001").is_err());
        assert!(EventId::new("not-a-ulid").is_err());
    }
}
