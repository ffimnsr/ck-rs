//! Certificate revocation.

use std::path::PathBuf;

use chainkeeper_core::{
    AuditAction, CONFIG_VERSION, CertificateRecord, CertificateStatus, ChainkeeperError, CrlRecord,
    PublishOptions, RevocationReason, RevocationRecord, RevokeReport, Serial,
};

use crate::engine::Engine;
use crate::messages;
use crate::rollback::Rollback;

/// Result of the reusable revocation core.
pub struct RevocationOutcome {
    /// Stored revocation metadata.
    pub record: RevocationRecord,
    /// Regenerated CRL, when the manager produced one.
    pub crl: Option<CrlRecord>,
    /// Paths that must be committed.
    pub paths: Vec<PathBuf>,
}

/// Runs `ck revoke`.
pub fn revoke(
    engine: &Engine,
    request: &chainkeeper_core::RevokeRequest,
) -> Result<RevokeReport, ChainkeeperError> {
    let _guard = engine.acquire_lock()?;
    let mut rollback = Rollback::default();
    let prepared = revoke_internal(
        engine,
        &request.serial,
        request.reason,
        request.comment.clone(),
        &mut rollback,
    );
    let outcome = match prepared {
        Ok(outcome) => outcome,
        Err(error) => {
            engine.recover(&mut rollback);
            return Err(error);
        }
    };

    let event = match engine.append_audit(
        AuditAction::CertRevoked,
        "certificate",
        request.serial.as_str(),
        format!(
            "revoked certificate {} reason {}",
            request.serial, request.reason
        ),
        serde_json::json!({
            "authority": outcome.record.authority.as_str(),
            "reason": outcome.record.reason.as_str(),
            "comment": outcome.record.comment,
        }),
    ) {
        Ok(event) => event,
        Err(error) => {
            engine.recover(&mut rollback);
            return Err(error);
        }
    };

    let mut paths = outcome.paths;
    paths.push(engine.audit_path(&event));
    let message = messages::revoke(&request.serial, request.reason);
    let commit = engine.commit(&message, &paths)?;

    Ok(RevokeReport {
        revocation: outcome.record,
        crl: outcome.crl,
        commit: Some(commit),
    })
}

/// Revokes a certificate without committing or auditing.
pub fn revoke_internal(
    engine: &Engine,
    serial: &Serial,
    reason: RevocationReason,
    comment: Option<String>,
    rollback: &mut Rollback,
) -> Result<RevocationOutcome, ChainkeeperError> {
    let record = engine
        .store
        .get_certificate(serial)?
        .ok_or_else(|| ChainkeeperError::not_found("certificate", serial.as_str()))?;
    if record.revoked_at.is_some() || record.status(engine.now()) == CertificateStatus::Revoked {
        return Err(ChainkeeperError::Conflict(
            chainkeeper_core::ErrorDetail::new(format!("certificate {serial} is already revoked"))
                .with_object_id(serial.as_str()),
        ));
    }

    let crl_number = next_crl_number(engine, &record.authority)?;
    let revocation = RevocationRecord {
        version: CONFIG_VERSION,
        serial: record.serial.clone(),
        authority: record.authority.clone(),
        reason,
        comment,
        revoked_at: engine.now(),
        crl_number,
    };
    let revocation_path = engine.write_revocation(rollback, &revocation)?;

    let mut paths = vec![revocation_path];
    for extension in ["pem", "yaml"] {
        let from = engine.paths.certificate_path_in(
            CertificateStatus::Active,
            &record.serial,
            extension,
        )?;
        let to = engine.paths.certificate_path_in(
            CertificateStatus::Revoked,
            &record.serial,
            extension,
        )?;
        if from.exists() {
            rollback.moved(&from, &to);
            paths.push(from);
            paths.push(to);
        }
    }
    engine
        .store
        .move_certificate(&record.serial, CertificateStatus::Revoked)?;
    rollback.certificate_moved(record.serial.clone());

    let mut updated: CertificateRecord = record;
    updated.path =
        engine
            .paths
            .certificate_path_in(CertificateStatus::Revoked, &updated.serial, "pem")?;
    updated.revoked_at = Some(revocation.revoked_at);
    updated.revocation_reason = Some(reason);
    engine.write_certificate_metadata(&updated)?;
    engine.index.upsert_certificate(&updated)?;
    engine.index.upsert_revocation(&revocation)?;
    rollback.mark_index_dirty();

    let bundle = engine.crl.update_for_authority(&updated.authority)?;
    if let Ok(path) = engine.paths.crl_path(&updated.authority, "crl.der") {
        paths.push(path);
    }
    if let Ok(path) = engine.paths.crl_path(&updated.authority, "crl.pem") {
        paths.push(path);
    }
    if let Ok(path) = engine.paths.crl_path(&updated.authority, "yaml") {
        paths.push(path);
    }
    paths.push(engine.paths.crl_number_path(&updated.authority));

    let publish_dir = engine.paths.publish_dir();
    if publish_dir.is_dir() {
        engine
            .publish
            .build(&PublishOptions::new(publish_dir.clone()))?;
        paths.push(publish_dir);
    }

    Ok(RevocationOutcome {
        record: revocation,
        crl: Some(bundle.record),
        paths,
    })
}

fn next_crl_number(
    engine: &Engine,
    authority: &chainkeeper_core::AuthorityName,
) -> Result<u64, ChainkeeperError> {
    let records = engine.crl.list_crls()?;
    Ok(records
        .iter()
        .filter(|record| &record.authority == authority)
        .map(|record| record.number)
        .max()
        .map_or(1, |number| number.saturating_add(1)))
}
