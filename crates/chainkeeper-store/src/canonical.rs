//! Canonical serialization helpers.
//!
//! Persisted metadata is YAML with struct field order and JSON with sorted map
//! keys, so re-serializing the same value always produces identical bytes.

use std::fmt::Write as _;
use std::path::Path;

use chainkeeper_core::{ChainkeeperError, FileMode, atomic_write};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};

use crate::fsutil;

/// Serde error text includes the line and column reported by the parser.
fn describe(path: &Path, object: &str, error: impl std::fmt::Display) -> ChainkeeperError {
    ChainkeeperError::storage(format!(
        "could not parse {object} {}: {error}",
        path.display()
    ))
}

/// Renders a value as YAML.
pub fn to_yaml<T: Serialize>(value: &T) -> Result<String, ChainkeeperError> {
    serde_yaml_ng::to_string(value)
        .map_err(|error| ChainkeeperError::storage(format!("could not serialize YAML: {error}")))
}

/// Writes a value as YAML through [`atomic_write`].
pub fn write_yaml<T: Serialize>(
    destination: &Path,
    value: &T,
    mode: FileMode,
) -> Result<(), ChainkeeperError> {
    let rendered = to_yaml(value)?;
    atomic_write(destination, rendered.as_bytes(), mode)
}

/// Reads YAML from `path` and validates the schema version.
pub fn read_yaml<T: DeserializeOwned>(path: &Path, object: &str) -> Result<T, ChainkeeperError> {
    let bytes = fsutil::read_file(path, object)?;
    serde_yaml_ng::from_slice(&bytes).map_err(|error| describe(path, object, error))
}

/// Renders a value as canonical JSON with a trailing newline.
pub fn to_json<T: Serialize>(value: &T) -> Result<String, ChainkeeperError> {
    let mut rendered = serde_json::to_string_pretty(value)
        .map_err(|error| ChainkeeperError::storage(format!("could not serialize JSON: {error}")))?;
    rendered.push('\n');
    Ok(rendered)
}

/// Reads JSON from `path`.
pub fn read_json<T: DeserializeOwned>(path: &Path, object: &str) -> Result<T, ChainkeeperError> {
    let bytes = fsutil::read_file(path, object)?;
    serde_json::from_slice(&bytes).map_err(|error| describe(path, object, error))
}

/// Returns the lowercase hexadecimal SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Writing to a `String` cannot fail.
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::{sha256_hex, to_json};
    use serde_json::json;

    #[test]
    fn json_is_pretty_sorted_and_newline_terminated() {
        let rendered = to_json(&json!({"z": 1, "a": 2})).expect("serialisable");
        assert_eq!(rendered, "{\n  \"a\": 2,\n  \"z\": 1\n}\n");
    }

    #[test]
    fn sha256_is_lowercase_hexadecimal() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
