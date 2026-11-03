//! Root, intermediate, and OCSP signer creation.

use chainkeeper_core::{
    AuditAction, AuthorityKind, AuthorityName, AuthorityRecord, ChainkeeperError,
    CreateAuthorityRequest, CreateOcspSignerRequest,
};

use crate::engine::Engine;
use crate::messages;
use crate::rollback::Rollback;

/// Default root validity in days.
pub const ROOT_VALIDITY_DAYS: u32 = 7300;
/// Default intermediate validity in days.
pub const INTERMEDIATE_VALIDITY_DAYS: u32 = 3650;
/// Default OCSP signer validity in days.
pub const OCSP_SIGNER_VALIDITY_DAYS: u32 = 90;
/// Authority names an intermediate may use.
pub const INTERMEDIATE_NAMES: [&str; 4] = ["tls", "smime", "codesign", "ocsp"];

fn validate_algorithm(
    engine: &Engine,
    request: &CreateAuthorityRequest,
) -> Result<(), ChainkeeperError> {
    let policy = engine.load_policy()?;
    if !policy.permits_algorithm(request.algorithm) {
        return Err(ChainkeeperError::Policy(
            chainkeeper_core::ErrorDetail::new(format!(
                "algorithm {} is not allowed by policy",
                request.algorithm
            ))
            .with_object_id(request.name.as_str()),
        ));
    }
    Ok(())
}

/// Runs `ck root create`.
pub fn create_root(
    engine: &Engine,
    request: &CreateAuthorityRequest,
) -> Result<AuthorityRecord, ChainkeeperError> {
    let _guard = engine.acquire_lock()?;
    let mut rollback = Rollback::default();
    let prepared = prepare_root(engine, request, &mut rollback);
    let (record, message, paths) = match prepared {
        Ok(value) => value,
        Err(error) => {
            engine.recover(&mut rollback);
            return Err(error);
        }
    };
    engine.commit(&message, &paths)?;
    Ok(record)
}

fn prepare_root(
    engine: &Engine,
    request: &CreateAuthorityRequest,
    rollback: &mut Rollback,
) -> Result<(AuthorityRecord, String, Vec<std::path::PathBuf>), ChainkeeperError> {
    if request.kind != AuthorityKind::Root {
        return Err(ChainkeeperError::validation(
            "root creation requires kind root",
        ));
    }
    if request.name.as_str() != "root" {
        return Err(ChainkeeperError::validation(
            "root authority must be named root",
        ));
    }
    request.subject.validate()?;
    if let Some(existing) = engine
        .store
        .list_authorities()?
        .into_iter()
        .find(|authority| authority.kind == AuthorityKind::Root)
    {
        return Err(ChainkeeperError::already_exists(format!(
            "root authority {}",
            existing.name
        )));
    }
    validate_algorithm(engine, request)?;

    let mut request = request.clone();
    if request.validity_days == 0 {
        request.validity_days = ROOT_VALIDITY_DAYS;
    }
    if request.validity_days > ROOT_VALIDITY_DAYS {
        return Err(ChainkeeperError::validation(format!(
            "root validity must be {ROOT_VALIDITY_DAYS} days or less"
        )));
    }

    let bundle = engine.provider.create_root(&request)?;
    let record = engine.write_authority(rollback, &bundle)?;
    engine.index.upsert_authority(&record)?;
    rollback.mark_index_dirty();

    let event = engine.append_audit(
        AuditAction::RootCreated,
        "authority",
        record.name.as_str(),
        format!("created root authority {}", record.name),
        serde_json::json!({
            "algorithm": record.algorithm.as_str(),
            "validity_days": record.validity_days,
        }),
    )?;

    let mut paths = engine.authority_public_paths(&record.name);
    paths.push(engine.audit_path(&event));
    Ok((record.clone(), messages::root(&record.name), paths))
}

/// Runs `ck intermediate create`.
pub fn create_intermediate(
    engine: &Engine,
    request: &CreateAuthorityRequest,
) -> Result<AuthorityRecord, ChainkeeperError> {
    let _guard = engine.acquire_lock()?;
    let mut rollback = Rollback::default();
    let prepared = prepare_intermediate(engine, request, &mut rollback);
    let (record, message, paths) = match prepared {
        Ok(value) => value,
        Err(error) => {
            engine.recover(&mut rollback);
            return Err(error);
        }
    };
    engine.commit(&message, &paths)?;
    Ok(record)
}

fn prepare_intermediate(
    engine: &Engine,
    request: &CreateAuthorityRequest,
    rollback: &mut Rollback,
) -> Result<(AuthorityRecord, String, Vec<std::path::PathBuf>), ChainkeeperError> {
    if request.kind != AuthorityKind::Intermediate {
        return Err(ChainkeeperError::validation(
            "intermediate creation requires kind intermediate",
        ));
    }
    if !INTERMEDIATE_NAMES.contains(&request.name.as_str()) {
        return Err(ChainkeeperError::validation(format!(
            "authority name {} is not one of {}",
            request.name,
            INTERMEDIATE_NAMES.join(", ")
        )));
    }
    request.subject.validate()?;
    let parent_name = request
        .parent
        .clone()
        .ok_or_else(|| ChainkeeperError::validation("intermediate requires a parent"))?;
    let parent = engine
        .store
        .load_authority(&parent_name)?
        .ok_or_else(|| ChainkeeperError::not_found("authority", parent_name.as_str()))?;
    if parent.config.kind != AuthorityKind::Root {
        return Err(ChainkeeperError::validation(format!(
            "parent {parent_name} is not a root authority"
        )));
    }
    if engine
        .store
        .list_authorities()?
        .iter()
        .any(|authority| authority.name == request.name)
    {
        return Err(ChainkeeperError::already_exists(format!(
            "authority {}",
            request.name
        )));
    }
    validate_algorithm(engine, request)?;

    let mut request = request.clone();
    if request.validity_days == 0 {
        request.validity_days = INTERMEDIATE_VALIDITY_DAYS;
    }
    if request.validity_days > INTERMEDIATE_VALIDITY_DAYS {
        return Err(ChainkeeperError::validation(format!(
            "intermediate validity must be {INTERMEDIATE_VALIDITY_DAYS} days or less"
        )));
    }

    let parent_signer = engine.signer_for(&parent_name)?;
    let bundle = engine
        .provider
        .create_intermediate(&request, &parent, parent_signer.as_ref())?;
    let record = engine.write_authority(rollback, &bundle)?;
    engine.index.upsert_authority(&record)?;
    rollback.mark_index_dirty();

    let event = engine.append_audit(
        AuditAction::IntermediateCreated,
        "authority",
        record.name.as_str(),
        format!("created intermediate authority {}", record.name),
        serde_json::json!({
            "parent": record.parent.as_ref().map(AuthorityName::as_str),
            "algorithm": record.algorithm.as_str(),
        }),
    )?;

    let mut paths = engine.authority_public_paths(&record.name);
    paths.push(engine.audit_path(&event));
    Ok((record.clone(), messages::intermediate(&record.name), paths))
}

/// Runs `ck ocsp-signer create`.
pub fn create_ocsp_signer(
    engine: &Engine,
    request: &CreateOcspSignerRequest,
) -> Result<AuthorityRecord, ChainkeeperError> {
    let _guard = engine.acquire_lock()?;
    let mut rollback = Rollback::default();
    let prepared = prepare_ocsp_signer(engine, request, &mut rollback);
    let (record, message, paths) = match prepared {
        Ok(value) => value,
        Err(error) => {
            engine.recover(&mut rollback);
            return Err(error);
        }
    };
    engine.commit(&message, &paths)?;
    Ok(record)
}

fn prepare_ocsp_signer(
    engine: &Engine,
    request: &CreateOcspSignerRequest,
    rollback: &mut Rollback,
) -> Result<(AuthorityRecord, String, Vec<std::path::PathBuf>), ChainkeeperError> {
    if let Some(subject) = &request.subject {
        subject.validate()?;
    }
    let parent = engine
        .store
        .load_authority(&request.parent)?
        .ok_or_else(|| ChainkeeperError::not_found("authority", request.parent.as_str()))?;
    if parent.config.kind != AuthorityKind::Intermediate {
        return Err(ChainkeeperError::validation(format!(
            "parent {} is not an intermediate authority",
            request.parent
        )));
    }
    if engine
        .store
        .list_authorities()?
        .iter()
        .any(|authority| authority.kind == AuthorityKind::OcspSigner)
    {
        return Err(ChainkeeperError::already_exists("ocsp signer"));
    }
    let policy = engine.load_policy()?;
    if !policy.permits_algorithm(request.algorithm) {
        return Err(ChainkeeperError::Policy(
            chainkeeper_core::ErrorDetail::new(format!(
                "algorithm {} is not allowed by policy",
                request.algorithm
            ))
            .with_object_id(request.name.as_str()),
        ));
    }

    let mut request = request.clone();
    if request.validity_days == 0 {
        request.validity_days = OCSP_SIGNER_VALIDITY_DAYS;
    }
    if request.validity_days > OCSP_SIGNER_VALIDITY_DAYS {
        return Err(ChainkeeperError::validation(format!(
            "OCSP signer validity must be {OCSP_SIGNER_VALIDITY_DAYS} days or less"
        )));
    }

    let parent_signer = engine.signer_for(&request.parent)?;
    let bundle = engine
        .provider
        .create_ocsp_signer(&request, &parent, parent_signer.as_ref())?;
    let chainkeeper_core::SignerBundle {
        config,
        cert_pem,
        chain_pem,
        key,
    } = bundle;
    let bevy = chainkeeper_core::AuthorityBundle::new(
        chainkeeper_core::AuthorityMaterial::new(config, cert_pem, chain_pem),
        key,
    );
    let record = engine.write_authority(rollback, &bevy)?;
    engine.index.upsert_authority(&record)?;
    rollback.mark_index_dirty();

    let event = engine.append_audit(
        AuditAction::OcspSignerCreated,
        "authority",
        record.name.as_str(),
        format!("created ocsp signer {}", record.name),
        serde_json::json!({
            "parent": record.parent.as_ref().map(AuthorityName::as_str),
            "algorithm": record.algorithm.as_str(),
        }),
    )?;

    let mut paths = engine.authority_public_paths(&record.name);
    paths.push(engine.audit_path(&event));
    Ok((record.clone(), messages::ocsp_signer(&record.name), paths))
}

/// Returns required intermediate authority names for diagnostics.
pub fn required_intermediates() -> [AuthorityName; 4] {
    INTERMEDIATE_NAMES.map(|name| {
        AuthorityName::new(name).expect("built-in intermediate name is a valid authority name")
    })
}
