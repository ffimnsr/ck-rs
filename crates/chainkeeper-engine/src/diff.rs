//! `ck diff` between published and current state.

use std::path::PathBuf;

use chainkeeper_core::{
    ChainkeeperError, DiffReport, DiffRequest, GitChange, GitChangeKind, PublishManifest,
};

use crate::engine::Engine;
use crate::state::{ChangeCategory, categorize};

fn manifest_commit(engine: &Engine) -> Result<Option<String>, ChainkeeperError> {
    let path = engine.paths.publish_dir().join("manifest.json");
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
    Ok(manifest.source_commit)
}

const fn category_order(category: ChangeCategory) -> u8 {
    match category {
        ChangeCategory::Certificate => 0,
        ChangeCategory::Revocation => 1,
        ChangeCategory::Crl => 2,
        ChangeCategory::Policy => 3,
        ChangeCategory::Audit => 4,
        ChangeCategory::Publish => 5,
        ChangeCategory::Other => 6,
    }
}

fn ordered(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort_by(|left, right| {
        category_order(categorize(left))
            .cmp(&category_order(categorize(right)))
            .then_with(|| left.cmp(right))
    });
    paths.dedup();
    paths
}

/// Runs `ck diff`.
pub fn diff(engine: &Engine, request: &DiffRequest) -> Result<DiffReport, ChainkeeperError> {
    let from = match &request.from {
        Some(commit) => commit.clone(),
        None => manifest_commit(engine)?.ok_or_else(|| {
            ChainkeeperError::not_found("published commit", "publish/manifest.json")
        })?,
    };
    let to = match &request.to {
        Some(commit) => commit.clone(),
        None => engine.git.head_commit()?,
    };

    let changes: Vec<GitChange> = engine.git.diff(&from, &to)?;
    let mut added = Vec::new();
    let mut modified = Vec::new();
    let mut removed = Vec::new();
    for change in changes {
        match change.kind {
            GitChangeKind::Added | GitChangeKind::Renamed => added.push(change.path),
            GitChangeKind::Deleted => removed.push(change.path),
            GitChangeKind::Modified => modified.push(change.path),
            _ => {}
        }
    }

    Ok(DiffReport {
        from: Some(from),
        to: Some(to),
        added: ordered(added),
        modified: ordered(modified),
        removed: ordered(removed),
    })
}
