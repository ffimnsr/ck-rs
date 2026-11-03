//! `ck init` orchestration.

use std::path::Path;

use chainkeeper_core::{
    AuditAction, ChainkeeperError, FileMode, InitReport, InitRequest, Policy, TenantConfig,
    atomic_write, builtin_profiles,
};

use crate::engine::Engine;
use crate::rollback::Rollback;

/// Content written to `.gitignore`.
const GITIGNORE: &str =
    "/target/\n/cache/\n/.chainkeeper/\nauthorities/**/key.pem\ncertificates/**/*.key.pem\n*.key\n";

/// Default authority directories created at init time, without keys.
const DEFAULT_AUTHORITIES: [&str; 6] = ["root", "tls", "smime", "codesign", "ocsp", "ocsp-signer"];

/// Roots that may be initialised.
fn validate_target(root: &Path) -> Result<(), ChainkeeperError> {
    if !root.is_dir() {
        return Err(ChainkeeperError::storage(format!(
            "target {} is not a directory",
            root.display()
        )));
    }
    let entries = std::fs::read_dir(root).map_err(|error| {
        ChainkeeperError::storage(format!("could not read {}: {error}", root.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ChainkeeperError::storage(format!("could not read {}: {error}", root.display()))
        })?;
        let name = entry.file_name();
        if name != ".git" {
            return Err(ChainkeeperError::already_exists(format!(
                "target directory {} is not empty",
                root.display()
            )));
        }
        if !entry.path().is_dir() {
            return Err(ChainkeeperError::already_exists(format!(
                "target directory {} contains a non-directory .git",
                root.display()
            )));
        }
        let mut contents = std::fs::read_dir(entry.path())
            .map_err(|error| ChainkeeperError::storage(format!("could not read .git: {error}")))?;
        if contents.next().is_some() {
            return Err(ChainkeeperError::already_exists(format!(
                "target directory {} contains a non-empty .git",
                root.display()
            )));
        }
    }
    Ok(())
}

/// Runs `ck init`.
pub fn execute(engine: &Engine, request: &InitRequest) -> Result<InitReport, ChainkeeperError> {
    validate_target(engine.paths.root())?;
    let _guard = engine.acquire_lock()?;
    let mut rollback = Rollback::default();

    let result = initialize(engine, request, &mut rollback);
    match result {
        Ok(mut report) => {
            report.commit = engine.git.head_commit().ok();
            Ok(report)
        }
        Err(error) => {
            engine.recover(&mut rollback);
            Err(error)
        }
    }
}

fn initialize(
    engine: &Engine,
    request: &InitRequest,
    rollback: &mut Rollback,
) -> Result<InitReport, ChainkeeperError> {
    let mut created_paths = Vec::new();

    for directory in engine.paths.required_directories() {
        std::fs::create_dir_all(&directory).map_err(|error| {
            ChainkeeperError::storage(format!("could not create {}: {error}", directory.display()))
        })?;
        created_paths.push(directory);
    }

    for name in DEFAULT_AUTHORITIES {
        let directory = engine.paths.authorities_dir().join(name);
        std::fs::create_dir_all(&directory).map_err(|error| {
            ChainkeeperError::storage(format!("could not create {}: {error}", directory.display()))
        })?;
        created_paths.push(directory);
    }

    let tenant = TenantConfig {
        ocsp_url: request.ocsp_url.clone(),
        ca_issuers_url_template: request.ca_issuers_url_template.clone(),
        crl_url_template: request.crl_url_template.clone(),
        ..TenantConfig::new(
            request.tenant_id.clone(),
            request.display_name.clone(),
            request.default_profile.clone(),
            engine.now(),
        )
    };
    tenant.validate()?;
    let tenant_path = engine.paths.tenant_yaml();
    rollback.created_if_absent(&tenant_path);
    atomic_write(
        &tenant_path,
        serde_yaml_ng::to_string(&tenant)
            .map_err(|error| {
                ChainkeeperError::storage(format!("could not encode tenant: {error}"))
            })?
            .as_bytes(),
        FileMode::Public,
    )?;
    created_paths.push(tenant_path);

    let policy = Policy::default();
    policy.validate()?;
    let policy_path = engine.paths.policy_yaml();
    rollback.created_if_absent(&policy_path);
    atomic_write(
        &policy_path,
        serde_yaml_ng::to_string(&policy)
            .map_err(|error| {
                ChainkeeperError::storage(format!("could not encode policy: {error}"))
            })?
            .as_bytes(),
        FileMode::Public,
    )?;
    created_paths.push(policy_path);

    for profile in builtin_profiles() {
        let path = engine.paths.profile_path(&profile.name);
        rollback.created_if_absent(&path);
        atomic_write(
            &path,
            serde_yaml_ng::to_string(&profile)
                .map_err(|error| {
                    ChainkeeperError::storage(format!("could not encode profile: {error}"))
                })?
                .as_bytes(),
            FileMode::Public,
        )?;
        created_paths.push(path);
    }

    let gitignore = engine.paths.root().join(".gitignore");
    rollback.created_if_absent(&gitignore);
    atomic_write(&gitignore, GITIGNORE.as_bytes(), FileMode::Public)?;
    created_paths.push(gitignore);

    let event = engine.append_audit(
        AuditAction::RepoInitialized,
        "repository",
        request.tenant_id.as_str(),
        format!("initialized tenant {}", request.tenant_id),
        serde_json::json!({
            "display_name": request.display_name,
            "default_profile": request.default_profile.as_str(),
        }),
    )?;
    created_paths.push(engine.audit_path(&event));

    engine.rebuild_index_from_disk()?;

    engine.git.init(engine.paths.root())?;
    let commit = engine.git.head_commit().ok();

    Ok(InitReport {
        tenant_id: request.tenant_id.clone(),
        root: engine.paths.root().to_path_buf(),
        created_paths,
        commit,
    })
}
