//! Deterministic publish manifest generation.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use chainkeeper_core::{
    ChainkeeperError, PUBLISH_MANIFEST_VERSION, PublishArtifact, PublishManifest, TenantId,
};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::MANIFEST_FILE;

/// Returns the lowercase hexadecimal SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Writing to a `String` cannot fail.
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Builds a manifest from sorted artifact bytes.
///
/// Artifacts are sorted by path and the manifest itself is never listed.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when an artifact path is unsafe.
pub fn build(
    artifacts: &BTreeMap<PathBuf, Vec<u8>>,
    generated_at: OffsetDateTime,
    source_commit: Option<String>,
    tenant_id: TenantId,
) -> Result<PublishManifest, ChainkeeperError> {
    let mut published = Vec::with_capacity(artifacts.len());
    for (path, bytes) in artifacts {
        let relative = crate::fsops::safe_relative(path)?;
        if relative == Path::new(MANIFEST_FILE) {
            return Err(ChainkeeperError::publish(
                "manifest must not list itself as an artifact",
            ));
        }
        published.push(PublishArtifact {
            path: relative,
            sha256: sha256_hex(bytes),
            bytes: u64::try_from(bytes.len()).map_err(|_| {
                ChainkeeperError::publish("artifact is too large to publish on this platform")
            })?,
        });
    }
    Ok(PublishManifest {
        version: PUBLISH_MANIFEST_VERSION,
        generated_at,
        source_commit,
        tenant_id,
        artifacts: published,
    })
}

/// Renders a manifest as pretty JSON with a trailing newline.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when serialization fails.
pub fn render(manifest: &PublishManifest) -> Result<Vec<u8>, ChainkeeperError> {
    let mut rendered = serde_json::to_string_pretty(manifest).map_err(|error| {
        ChainkeeperError::publish(format!("could not serialize manifest: {error}"))
    })?;
    rendered.push('\n');
    Ok(rendered.into_bytes())
}

/// Reads `manifest.json` from a publish directory.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when the manifest exists but cannot be
/// parsed or uses an unsupported schema version.
pub fn read(directory: &Path) -> Result<Option<PublishManifest>, ChainkeeperError> {
    let path = directory.join(MANIFEST_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ChainkeeperError::publish(format!(
                "could not read {}: {error}",
                path.display()
            )));
        }
    };
    let manifest: PublishManifest = serde_json::from_slice(&bytes).map_err(|error| {
        ChainkeeperError::publish(format!("could not parse {}: {error}", path.display()))
    })?;
    if manifest.version != PUBLISH_MANIFEST_VERSION {
        return Err(ChainkeeperError::publish(format!(
            "manifest {} uses unsupported version {}, expected {PUBLISH_MANIFEST_VERSION}",
            path.display(),
            manifest.version
        )));
    }
    Ok(Some(manifest))
}
