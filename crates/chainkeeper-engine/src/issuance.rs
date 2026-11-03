//! Certificate issuance and replacement.

use std::path::PathBuf;

use chainkeeper_core::{
    AuditAction, AuthorityKind, CertificateRecord, CertificateStatus, ChainkeeperError, ErrorKind,
    IssueReport, IssueRequest, IssuedCertificate, RevocationReason,
};

use crate::engine::Engine;
use crate::messages;
use crate::revocation::revoke_internal;
use crate::rollback::Rollback;

/// Number of serial collisions tolerated before issuance fails.
const SERIAL_ATTEMPTS: usize = 3;

fn validate_authority(
    engine: &Engine,
    record: &chainkeeper_core::AuthorityMaterial,
) -> Result<(), ChainkeeperError> {
    if record.config.kind == AuthorityKind::OcspSigner {
        return Err(ChainkeeperError::validation(format!(
            "authority {} cannot issue certificates",
            record.config.name
        )));
    }
    let expires_at =
        record.config.created_at + time::Duration::days(i64::from(record.config.validity_days));
    if expires_at <= engine.now() {
        return Err(ChainkeeperError::Conflict(
            chainkeeper_core::ErrorDetail::new(format!(
                "authority {} is expired",
                record.config.name
            ))
            .with_object_id(record.config.name.as_str()),
        ));
    }
    Ok(())
}

/// Runs `ck issue`.
pub fn issue(engine: &Engine, request: &IssueRequest) -> Result<IssueReport, ChainkeeperError> {
    let _guard = engine.acquire_lock()?;
    let mut rollback = Rollback::default();
    let prepared = prepare(engine, request, &mut rollback);
    let (report, message, paths) = match prepared {
        Ok(value) => value,
        Err(error) => {
            engine.recover(&mut rollback);
            return Err(error);
        }
    };
    engine.commit(&message, &paths)?;
    Ok(report)
}

type PreparedIssue = (IssueReport, String, Vec<PathBuf>);

fn prepare(
    engine: &Engine,
    request: &IssueRequest,
    rollback: &mut Rollback,
) -> Result<PreparedIssue, ChainkeeperError> {
    request.subject.validate()?;
    for san in &request.sans {
        san.validate()?;
    }
    for extension in &request.custom_extensions {
        extension.validate()?;
    }

    let policy = engine.load_policy()?;
    let profile = engine.load_profile(&request.profile)?;
    engine.policy.validate_profile(&policy, &profile)?;
    for extension in &request.custom_extensions {
        engine
            .policy
            .validate_custom_extension(&policy, extension)?;
    }
    engine.policy.validate_issue(&policy, &profile, request)?;

    validate_replacement(engine, request)?;

    let mut paths = Vec::new();
    let replacement_old = if let Some(serial) = &request.replaces {
        let outcome = revoke_internal(
            engine,
            serial,
            RevocationReason::Superseded,
            Some("replaced by a new certificate".to_owned()),
            rollback,
        )?;
        paths.extend(outcome.paths);
        Some(outcome.record)
    } else {
        None
    };

    let authority_name = profile.authority;
    let authority = engine
        .store
        .load_authority(&authority_name)?
        .ok_or_else(|| ChainkeeperError::not_found("authority", authority_name.as_str()))?;
    validate_authority(engine, &authority)?;
    let signer = engine.signer_for(&authority_name)?;

    let (issued, key_path) = issue_with_retry(engine, request, signer.as_ref(), rollback)?;
    engine.index.upsert_certificate(&issued.record)?;
    rollback.mark_index_dirty();

    let action = if replacement_old.is_some() {
        AuditAction::CertReplaced
    } else {
        AuditAction::CertIssued
    };
    let summary = if let Some(old) = &replacement_old {
        format!(
            "replaced certificate {} with {}",
            old.serial, issued.record.serial
        )
    } else {
        format!(
            "issued certificate {} profile {}",
            issued.record.serial, issued.record.profile
        )
    };
    let event = engine.append_audit(
        action,
        "certificate",
        issued.record.serial.as_str(),
        summary,
        serde_json::json!({
            "profile": issued.record.profile.as_str(),
            "authority": issued.record.authority.as_str(),
            "algorithm": issued.record.algorithm.as_str(),
            "subject": issued.record.subject.cn,
            "replaces": replacement_old.as_ref().map(|record| record.serial.as_str()),
        }),
    )?;
    paths.push(engine.audit_path(&event));

    paths.extend(certificate_public_paths(engine, &issued.record));

    let message = if let Some(old) = &replacement_old {
        messages::replace(&old.serial, &issued.record.serial)
    } else {
        messages::issue(&issued.record.serial, &issued.record.profile)
    };

    let cert_path = engine
        .paths
        .certificate_path(&issued.record.serial, "pem")
        .unwrap_or_default();
    let report = IssueReport {
        certificate: issued.record,
        cert_path,
        key_path,
        commit: None,
    };
    Ok((report, message, paths))
}

fn validate_replacement(engine: &Engine, request: &IssueRequest) -> Result<(), ChainkeeperError> {
    let Some(replaces) = &request.replaces else {
        return Ok(());
    };
    let previous = engine
        .store
        .get_certificate(replaces)?
        .ok_or_else(|| ChainkeeperError::not_found("certificate", replaces.as_str()))?;
    if previous.status(engine.now()) != CertificateStatus::Active {
        return Err(ChainkeeperError::Conflict(
            chainkeeper_core::ErrorDetail::new(format!("certificate {replaces} is not active"))
                .with_object_id(replaces.as_str()),
        ));
    }
    if previous.profile != request.profile {
        return Err(ChainkeeperError::validation(format!(
            "replacement target {replaces} uses profile {}, not {}",
            previous.profile, request.profile
        )));
    }
    Ok(())
}

fn certificate_public_paths(engine: &Engine, record: &CertificateRecord) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(path) =
        engine
            .paths
            .certificate_path_in(CertificateStatus::Active, &record.serial, "pem")
    {
        paths.push(path);
    }
    if let Ok(path) =
        engine
            .paths
            .certificate_path_in(CertificateStatus::Active, &record.serial, "yaml")
    {
        paths.push(path);
    }
    paths
}

fn issue_with_retry(
    engine: &Engine,
    request: &IssueRequest,
    signer: &dyn chainkeeper_core::Signer,
    rollback: &mut Rollback,
) -> Result<(IssuedCertificate, Option<PathBuf>), ChainkeeperError> {
    let mut last_error = None;
    for _ in 0..SERIAL_ATTEMPTS {
        let issued = engine.provider.issue(request, signer)?;
        let key_path = request.key_out.clone();
        let stored = if key_path.is_some() {
            IssuedCertificate::new(
                issued.record.clone(),
                issued.cert_pem.clone(),
                issued.chain_pem.clone(),
                None,
            )
        } else {
            issued.clone()
        };

        for path in engine.certificate_paths(&stored) {
            rollback.created_if_absent(&path);
        }
        match engine.store.write_certificate(&stored) {
            Ok(_) => {
                let key_path = match (&key_path, &issued.key) {
                    (Some(path), Some(key)) => {
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent).map_err(|error| {
                                ChainkeeperError::storage(format!(
                                    "could not create {}: {error}",
                                    parent.display()
                                ))
                            })?;
                        }
                        rollback.created_if_absent(path);
                        chainkeeper_core::atomic_write(
                            path,
                            key.private_key_pem().as_bytes(),
                            chainkeeper_core::FileMode::Private,
                        )?;
                        Some(path.clone())
                    }
                    _ => None,
                };
                return Ok((issued, key_path));
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        ChainkeeperError::already_exists("certificate serial could not be allocated")
    }))
}
