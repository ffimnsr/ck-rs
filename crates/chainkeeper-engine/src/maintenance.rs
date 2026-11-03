//! Publishing and index rebuild orchestration.

use std::path::PathBuf;

use chainkeeper_core::{
    AuditAction, CertificateStatus, ChainkeeperError, IndexReport, PublishManifest, PublishOptions,
};

use crate::engine::Engine;
use crate::messages;

/// Runs `ck publish`.
pub fn publish(
    engine: &Engine,
    options: &PublishOptions,
) -> Result<PublishManifest, ChainkeeperError> {
    let _guard = engine.acquire_lock()?;
    let temporary = if options.dry_run {
        let cache = engine.paths.cache_dir();
        std::fs::create_dir_all(&cache).map_err(|error| {
            ChainkeeperError::publish(format!("could not create dry-run directory: {error}"))
        })?;
        Some(
            tempfile::Builder::new()
                .prefix("publish-dry-run-")
                .tempdir_in(&cache)
                .map_err(|error| {
                    ChainkeeperError::publish(format!(
                        "could not create dry-run directory: {error}"
                    ))
                })?,
        )
    } else {
        None
    };
    let mut build_options = options.clone();
    if let Some(directory) = &temporary {
        build_options.output_dir = directory.path().to_path_buf();
    }
    let manifest = engine.publish.build(&build_options)?;

    if options.dry_run || options.no_commit {
        return Ok(manifest);
    }

    let source_commit = manifest
        .source_commit
        .clone()
        .or_else(|| engine.git.head_commit().ok())
        .unwrap_or_else(|| "unknown".to_owned());

    let event = engine.append_audit(
        AuditAction::PublishCompleted,
        "publish",
        &source_commit,
        format!(
            "published {} artifact(s) from {source_commit}",
            manifest.artifacts.len()
        ),
        serde_json::json!({
            "output_dir": options.output_dir.display().to_string(),
            "artifacts": manifest.artifacts.len(),
        }),
    )?;

    let mut paths = vec![engine.audit_path(&event)];
    if options.output_dir.starts_with(engine.paths.root()) {
        paths.push(options.output_dir.clone());
    }
    let message = messages::publish(&source_commit);
    engine.commit(&message, &paths)?;
    Ok(manifest)
}

/// Runs `ck index rebuild --repair`.
pub fn repair_index(engine: &Engine) -> Result<IndexReport, ChainkeeperError> {
    let _guard = engine.acquire_lock()?;
    let now = engine.now();
    let mut moved = Vec::new();
    for record in engine.store.list_certificates()? {
        if record.status(now) != CertificateStatus::Expired {
            continue;
        }
        let active_path = PathBuf::from(format!("certificates/active/{}.pem", record.serial));
        if record.path == active_path {
            engine
                .store
                .move_certificate(&record.serial, CertificateStatus::Expired)?;
            moved.push(record.serial);
        }
    }
    moved.sort();

    let mut report = engine.rebuild_index_from_disk()?;
    report.moved = moved;

    let event = engine.append_audit(
        AuditAction::IndexRebuilt,
        "index",
        "cache/index.sqlite",
        format!(
            "repaired index and moved {} certificate(s)",
            report.moved.len()
        ),
        serde_json::json!({
            "moved": report.moved.iter().map(chainkeeper_core::Serial::as_str).collect::<Vec<_>>(),
        }),
    )?;

    let paths: Vec<PathBuf> = vec![engine.audit_path(&event)];
    engine.commit(&messages::rebuild_index(), &paths)?;
    Ok(report)
}

/// Runs `ck index rebuild`.
pub fn rebuild_index(engine: &Engine) -> Result<IndexReport, ChainkeeperError> {
    let _guard = engine.acquire_lock()?;
    let report = engine.rebuild_index_from_disk()?;

    let event = engine.append_audit(
        AuditAction::IndexRebuilt,
        "index",
        "cache/index.sqlite",
        format!(
            "rebuilt index with {} certificate(s) and {} authority(ies)",
            report.stats.certificates, report.stats.authorities
        ),
        serde_json::json!({
            "certificates": report.stats.certificates,
            "revocations": report.stats.revocations,
            "authorities": report.stats.authorities,
            "audit_events": report.stats.audit_events,
        }),
    )?;

    let paths: Vec<PathBuf> = vec![engine.audit_path(&event)];
    engine.commit(&messages::rebuild_index(), &paths)?;
    Ok(report)
}
