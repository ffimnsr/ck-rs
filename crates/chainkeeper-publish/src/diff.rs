//! Publish manifest diffing.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chainkeeper_core::PublishManifest;

/// Artifact paths that changed between two manifests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangedPaths {
    /// Artifacts present only in the next manifest.
    pub added: Vec<PathBuf>,
    /// Artifacts present only in the previous manifest.
    pub removed: Vec<PathBuf>,
    /// Artifacts present in both manifests with a different digest.
    pub modified: Vec<PathBuf>,
}

/// Compares two manifests by artifact path and digest.
#[must_use]
pub fn changed_paths(previous: &PublishManifest, next: &PublishManifest) -> ChangedPaths {
    let previous: BTreeMap<&PathBuf, &str> = previous
        .artifacts
        .iter()
        .map(|artifact| (&artifact.path, artifact.sha256.as_str()))
        .collect();
    let next: BTreeMap<&PathBuf, &str> = next
        .artifacts
        .iter()
        .map(|artifact| (&artifact.path, artifact.sha256.as_str()))
        .collect();

    let mut changed = ChangedPaths::default();
    for (path, digest) in &next {
        match previous.get(path) {
            None => changed.added.push((*path).clone()),
            Some(previous_digest) if previous_digest != digest => {
                changed.modified.push((*path).clone());
            }
            Some(_) => {}
        }
    }
    for path in previous.keys() {
        if !next.contains_key(path) {
            changed.removed.push((*path).clone());
        }
    }
    changed
}
