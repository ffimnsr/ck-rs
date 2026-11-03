//! Publish directory validation.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chainkeeper_core::{ChainkeeperError, PublishManifest};

use crate::{MANIFEST_FILE, fsops, manifest};

/// Validates a directory against its own manifest.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when the manifest is missing, the tree
/// contains symlinks, unlisted files, private keys, or hash mismatches.
pub fn validate_directory(directory: &Path) -> Result<(), ChainkeeperError> {
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ChainkeeperError::publish(format!(
                "publish directory {} is a symlink",
                directory.display()
            )));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(ChainkeeperError::publish(format!(
                "{} is not a publish directory",
                directory.display()
            )));
        }
        Ok(_) => {}
        Err(error) => {
            return Err(ChainkeeperError::publish(format!(
                "could not inspect {}: {error}",
                directory.display()
            )));
        }
    }
    let manifest = manifest::read(directory)?.ok_or_else(|| {
        ChainkeeperError::publish(format!(
            "publish directory {} has no {MANIFEST_FILE}",
            directory.display()
        ))
    })?;
    validate_tree(directory, &manifest)
}

/// Validates `directory` against `manifest`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] when any artifact is unsafe, missing,
/// unlisted, or does not match its recorded digest.
pub fn validate_tree(directory: &Path, manifest: &PublishManifest) -> Result<(), ChainkeeperError> {
    let mut expected: BTreeMap<PathBuf, String> = BTreeMap::new();
    for artifact in &manifest.artifacts {
        let relative = fsops::safe_relative(&artifact.path)?;
        if relative == Path::new(MANIFEST_FILE) {
            return Err(ChainkeeperError::publish(
                "manifest must not list itself as an artifact",
            ));
        }
        if expected
            .insert(relative.clone(), artifact.sha256.clone())
            .is_some()
        {
            return Err(ChainkeeperError::publish(format!(
                "manifest lists {} more than once",
                relative.display()
            )));
        }
    }

    let files = fsops::walk_files(directory)?;
    let mut saw_manifest = false;
    for (relative, absolute) in &files {
        if relative == Path::new(MANIFEST_FILE) {
            saw_manifest = true;
            continue;
        }
        let digest = expected.remove(relative).ok_or_else(|| {
            ChainkeeperError::publish(format!(
                "publish file {} is not listed in the manifest",
                relative.display()
            ))
        })?;
        let bytes = std::fs::read(absolute).map_err(|error| {
            ChainkeeperError::publish(format!("could not read {}: {error}", absolute.display()))
        })?;
        reject_private_key(relative, &bytes)?;
        let actual = manifest::sha256_hex(&bytes);
        if actual != digest {
            return Err(ChainkeeperError::publish(format!(
                "publish file {} digest {actual} does not match {digest}",
                relative.display()
            )));
        }
    }

    if !saw_manifest {
        return Err(ChainkeeperError::publish(format!(
            "publish directory is missing {MANIFEST_FILE}"
        )));
    }
    if let Some(missing) = expected.keys().next() {
        return Err(ChainkeeperError::publish(format!(
            "manifest artifact {} is missing from the publish directory",
            missing.display()
        )));
    }
    Ok(())
}

fn reject_private_key(relative: &Path, bytes: &[u8]) -> Result<(), ChainkeeperError> {
    let name = relative
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    if name.eq_ignore_ascii_case("key.pem") {
        return Err(ChainkeeperError::publish(format!(
            "publish file {} is a private key",
            relative.display()
        )));
    }
    let is_key_extension = relative
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|extension| extension.eq_ignore_ascii_case("key"));
    let text = String::from_utf8_lossy(bytes);
    if is_key_extension || (text.contains("-----BEGIN ") && text.contains("PRIVATE KEY-----")) {
        return Err(ChainkeeperError::publish(format!(
            "publish file {} contains private key material",
            relative.display()
        )));
    }
    Ok(())
}
