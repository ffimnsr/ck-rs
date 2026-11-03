//! `ck doctor` diagnostics.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chainkeeper_core::{
    AuditQuery, AuthorityKind, AuthorityName, AuthorityRecord, ChainkeeperError, DoctorFinding,
    DoctorReport, ExtendedKeyUsage, PublishManifest, Severity,
};
use time::OffsetDateTime;
use x509_parser::extensions::ParsedExtension;
use x509_parser::pem::parse_x509_pem;

use crate::authorities::required_intermediates;
use crate::engine::Engine;

const ROOT_EXPIRY_WARNING_DAYS: i64 = 365;
const INTERMEDIATE_EXPIRY_WARNING_DAYS: i64 = 90;
const CRL_NEXT_UPDATE_WARNING_HOURS: i64 = 24;
const PRIVATE_KEY_MARKER: &[u8] = b"PRIVATE KEY";

fn finding(
    code: &str,
    severity: Severity,
    message: impl Into<String>,
    object_id: Option<String>,
) -> DoctorFinding {
    DoctorFinding {
        code: code.to_owned(),
        severity,
        message: message.into(),
        object_id,
    }
}

fn sort(findings: &mut [DoctorFinding]) {
    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.object_id.cmp(&right.object_id))
            .then_with(|| left.code.cmp(&right.code))
    });
}

/// Runs `ck doctor`.
pub fn doctor(engine: &Engine) -> Result<DoctorReport, ChainkeeperError> {
    let now = engine.now();
    let mut findings = Vec::new();

    let authorities = engine.store.list_authorities()?;
    let by_name: BTreeMap<AuthorityName, AuthorityRecord> = authorities
        .iter()
        .cloned()
        .map(|record| (record.name.clone(), record))
        .collect();

    check_root(now, &authorities, &mut findings);
    check_intermediates(now, &by_name, &mut findings);
    check_crls(engine, now, &mut findings);
    check_ocsp_signer(engine, now, &authorities, &mut findings);
    check_git(engine, &mut findings);
    check_configuration(engine, &mut findings);
    check_publish(engine, &mut findings);
    check_index(engine, &authorities, &mut findings);
    check_audit(engine, &mut findings);
    check_ca_keys(engine, &authorities, &mut findings);

    sort(&mut findings);
    Ok(DoctorReport {
        healthy: !findings
            .iter()
            .any(|finding| finding.severity == Severity::Error),
        checked_at: now,
        findings,
    })
}

fn check_root(
    now: OffsetDateTime,
    authorities: &[AuthorityRecord],
    findings: &mut Vec<DoctorFinding>,
) {
    let roots: Vec<&AuthorityRecord> = authorities
        .iter()
        .filter(|record| record.kind == AuthorityKind::Root)
        .collect();
    if roots.is_empty() {
        findings.push(finding(
            "ROOT_MISSING",
            Severity::Error,
            "repository has no root authority",
            Some("root".to_owned()),
        ));
        return;
    }
    for root in roots {
        let expires_at = Engine::authority_expiry(root);
        if expires_at <= now {
            findings.push(finding(
                "ROOT_EXPIRED",
                Severity::Error,
                format!("root authority {} has expired", root.name),
                Some(root.name.to_string()),
            ));
        } else if expires_at - now < time::Duration::days(ROOT_EXPIRY_WARNING_DAYS) {
            findings.push(finding(
                "ROOT_EXPIRING_SOON",
                Severity::Warning,
                format!(
                    "root authority {} expires in {} day(s)",
                    root.name,
                    (expires_at - now).whole_days()
                ),
                Some(root.name.to_string()),
            ));
        }
    }
}

fn check_intermediates(
    now: OffsetDateTime,
    by_name: &BTreeMap<AuthorityName, AuthorityRecord>,
    findings: &mut Vec<DoctorFinding>,
) {
    for name in required_intermediates() {
        let Some(record) = by_name.get(&name) else {
            findings.push(finding(
                "INTERMEDIATE_MISSING",
                Severity::Error,
                format!("required intermediate authority {name} is missing"),
                Some(name.to_string()),
            ));
            continue;
        };
        if record.kind != AuthorityKind::Intermediate {
            findings.push(finding(
                "INTERMEDIATE_CHAIN_INVALID",
                Severity::Error,
                format!("authority {name} is not an intermediate"),
                Some(name.to_string()),
            ));
        }
        let expires_at = Engine::authority_expiry(record);
        if expires_at <= now {
            findings.push(finding(
                "INTERMEDIATE_EXPIRED",
                Severity::Error,
                format!("intermediate authority {name} has expired"),
                Some(name.to_string()),
            ));
        } else if expires_at - now < time::Duration::days(INTERMEDIATE_EXPIRY_WARNING_DAYS) {
            findings.push(finding(
                "INTERMEDIATE_EXPIRING_SOON",
                Severity::Warning,
                format!(
                    "intermediate authority {name} expires in {} day(s)",
                    (expires_at - now).whole_days()
                ),
                Some(name.to_string()),
            ));
        }
        match &record.parent {
            None => findings.push(finding(
                "INTERMEDIATE_CHAIN_INVALID",
                Severity::Error,
                format!("intermediate authority {name} has no parent"),
                Some(name.to_string()),
            )),
            Some(parent) => match by_name.get(parent) {
                None => findings.push(finding(
                    "INTERMEDIATE_CHAIN_INVALID",
                    Severity::Error,
                    format!("intermediate authority {name} references missing parent {parent}"),
                    Some(name.to_string()),
                )),
                Some(parent) if parent.kind != AuthorityKind::Root => findings.push(finding(
                    "INTERMEDIATE_CHAIN_INVALID",
                    Severity::Error,
                    format!(
                        "parent {} of intermediate {name} is not a root",
                        parent.name
                    ),
                    Some(name.to_string()),
                )),
                Some(_) => {}
            },
        }
    }
}

fn check_crls(engine: &Engine, now: OffsetDateTime, findings: &mut Vec<DoctorFinding>) {
    let records = match engine.crl.list_crls() {
        Ok(records) => records,
        Err(error) => {
            findings.push(finding(
                "CRL_MISSING",
                Severity::Error,
                format!("could not list CRLs: {error}"),
                None,
            ));
            return;
        }
    };
    for name in required_intermediates() {
        let record = records.iter().find(|record| record.authority == name);
        let Some(record) = record else {
            findings.push(finding(
                "CRL_MISSING",
                Severity::Error,
                format!("no CRL for authority {name}"),
                Some(name.to_string()),
            ));
            continue;
        };
        if record.next_update <= now {
            findings.push(finding(
                "CRL_EXPIRED",
                Severity::Error,
                format!("CRL {name} number {} has expired", record.number),
                Some(name.to_string()),
            ));
        } else if record.next_update - now < time::Duration::hours(CRL_NEXT_UPDATE_WARNING_HOURS) {
            findings.push(finding(
                "CRL_NEXT_UPDATE_SOON",
                Severity::Warning,
                format!(
                    "CRL {name} needs regeneration within {} hour(s)",
                    (record.next_update - now).whole_hours()
                ),
                Some(name.to_string()),
            ));
        }
    }
}

fn check_ocsp_signer(
    engine: &Engine,
    now: OffsetDateTime,
    authorities: &[AuthorityRecord],
    findings: &mut Vec<DoctorFinding>,
) {
    let signer = authorities
        .iter()
        .find(|record| record.kind == AuthorityKind::OcspSigner);
    let Some(signer) = signer else {
        findings.push(finding(
            "OCSP_SIGNER_MISSING",
            Severity::Warning,
            "no dedicated OCSP signer is configured",
            Some("ocsp-signer".to_owned()),
        ));
        return;
    };
    let expires_at = Engine::authority_expiry(signer);
    if expires_at <= now {
        findings.push(finding(
            "OCSP_SIGNER_EXPIRED",
            Severity::Error,
            format!("OCSP signer {} has expired", signer.name),
            Some(signer.name.to_string()),
        ));
    }
    let Ok(Some(material)) = engine.store.load_authority(&signer.name) else {
        return;
    };
    let ekus = extended_key_usages(&material.cert_pem).unwrap_or_default();
    if !ekus.contains(&ExtendedKeyUsage::OcspSigning) {
        findings.push(finding(
            "OCSP_SIGNER_EKU_INVALID",
            Severity::Error,
            format!("OCSP signer {} is missing the ocspSigning EKU", signer.name),
            Some(signer.name.to_string()),
        ));
    }
}

fn extended_key_usages(pem: &str) -> Option<Vec<ExtendedKeyUsage>> {
    let (_, block) = parse_x509_pem(pem.as_bytes()).ok()?;
    let certificate = block.parse_x509().ok()?;
    let extension = certificate.extensions().iter().find_map(|extension| {
        match extension.parsed_extension() {
            ParsedExtension::ExtendedKeyUsage(usage) => Some(usage),
            _ => None,
        }
    })?;
    let flags = [
        (extension.server_auth, ExtendedKeyUsage::ServerAuth),
        (extension.client_auth, ExtendedKeyUsage::ClientAuth),
        (extension.code_signing, ExtendedKeyUsage::CodeSigning),
        (
            extension.email_protection,
            ExtendedKeyUsage::EmailProtection,
        ),
        (extension.ocsp_signing, ExtendedKeyUsage::OcspSigning),
        (extension.time_stamping, ExtendedKeyUsage::TimeStamping),
    ];
    Some(
        flags
            .into_iter()
            .filter_map(|(present, usage)| present.then_some(usage))
            .collect(),
    )
}

fn check_git(engine: &Engine, findings: &mut Vec<DoctorFinding>) {
    match engine.git.head_commit() {
        Err(error) if error.kind() == chainkeeper_core::ErrorKind::NotFound => {
            findings.push(finding(
                "GIT_NOT_INITIALIZED",
                Severity::Error,
                "repository is not a Git repository",
                None,
            ));
            return;
        }
        Err(error) => {
            findings.push(finding(
                "GIT_NOT_INITIALIZED",
                Severity::Error,
                format!("could not read HEAD: {error}"),
                None,
            ));
            return;
        }
        Ok(_) => {}
    }
    if let Ok(status) = engine.git.status()
        && !status.clean
    {
        findings.push(finding(
            "GIT_DIRTY",
            Severity::Warning,
            "working tree has uncommitted changes",
            None,
        ));
    }
    let config = engine.paths.root().join(".git").join("config");
    if let Ok(contents) = std::fs::read_to_string(&config)
        && !contents.contains("[remote")
    {
        findings.push(finding(
            "GIT_REMOTE_MISSING",
            Severity::Warning,
            "repository has no Git remote",
            None,
        ));
    }
}

fn check_configuration(engine: &Engine, findings: &mut Vec<DoctorFinding>) {
    match engine.store.load_policy() {
        Ok(policy) => {
            if let Err(error) = policy.validate() {
                findings.push(finding(
                    "POLICY_INVALID",
                    Severity::Error,
                    format!("policy is invalid: {error}"),
                    Some("policy/policy.yaml".to_owned()),
                ));
            }
        }
        Err(error) => findings.push(finding(
            "POLICY_INVALID",
            Severity::Error,
            format!("policy could not be loaded: {error}"),
            Some("policy/policy.yaml".to_owned()),
        )),
    }

    match engine.store.load_profiles() {
        Ok(profiles) => {
            for profile in profiles {
                if let Err(error) = engine.profiles.validate(&profile) {
                    findings.push(finding(
                        "PROFILE_INVALID",
                        Severity::Error,
                        format!("profile {} is invalid: {error}", profile.name),
                        Some(profile.name.to_string()),
                    ));
                }
            }
        }
        Err(error) => findings.push(finding(
            "PROFILE_INVALID",
            Severity::Error,
            format!("profiles could not be loaded: {error}"),
            None,
        )),
    }
}

fn check_publish(engine: &Engine, findings: &mut Vec<DoctorFinding>) {
    let directory = engine.paths.publish_dir();
    let manifest_path = directory.join("manifest.json");
    let Ok(bytes) = std::fs::read(&manifest_path) else {
        findings.push(finding(
            "PUBLISH_MISSING",
            Severity::Warning,
            "publish directory has no manifest",
            Some("publish/manifest.json".to_owned()),
        ));
        return;
    };
    if let Ok(manifest) = serde_json::from_slice::<PublishManifest>(&bytes) {
        for artifact in &manifest.artifacts {
            let path = directory.join(&artifact.path);
            match engine.file_sha256(&path) {
                Some(hash) if hash == artifact.sha256 => {}
                _ => findings.push(finding(
                    "PUBLISH_HASH_MISMATCH",
                    Severity::Error,
                    format!(
                        "published artifact {} does not match the manifest",
                        artifact.path.display()
                    ),
                    Some(artifact.path.display().to_string()),
                )),
            }
        }
    } else {
        findings.push(finding(
            "PUBLISH_HASH_MISMATCH",
            Severity::Error,
            "publish manifest is not readable",
            Some("publish/manifest.json".to_owned()),
        ));
    }

    for path in find_files_with_marker(&directory, PRIVATE_KEY_MARKER) {
        findings.push(finding(
            "PUBLISH_PRIVATE_KEY_FOUND",
            Severity::Error,
            format!(
                "publish directory contains a private key at {}",
                path.display()
            ),
            Some(path.display().to_string()),
        ));
    }
}

fn find_files_with_marker(root: &Path, marker: &[u8]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            found.extend(find_files_with_marker(&path, marker));
        } else if let Ok(bytes) = std::fs::read(&path)
            && bytes.windows(marker.len()).any(|window| window == marker)
        {
            found.push(path);
        }
    }
    found.sort();
    found
}

fn check_index(
    engine: &Engine,
    authorities: &[AuthorityRecord],
    findings: &mut Vec<DoctorFinding>,
) {
    let Ok(stats) = engine.index.stats() else {
        findings.push(finding(
            "INDEX_DRIFT",
            Severity::Warning,
            "index statistics could not be read",
            None,
        ));
        return;
    };
    let certificates = engine
        .store
        .list_certificates()
        .map(|records| records.len() as u64)
        .unwrap_or_default();
    let revocations = engine
        .store
        .list_revocations()
        .map(|records| records.len() as u64)
        .unwrap_or_default();
    let audit_events = engine
        .audit
        .list(&AuditQuery::default())
        .map(|events| events.len() as u64)
        .unwrap_or_default();
    if stats.certificates != certificates
        || stats.revocations != revocations
        || stats.authorities != authorities.len() as u64
        || stats.audit_events != audit_events
    {
        findings.push(finding(
            "INDEX_DRIFT",
            Severity::Warning,
            "index row counts do not match canonical records",
            Some("cache/index.sqlite".to_owned()),
        ));
    }
}

fn check_audit(engine: &Engine, findings: &mut Vec<DoctorFinding>) {
    let events = match engine.audit.list(&AuditQuery::default()) {
        Ok(events) => events,
        Err(error) => {
            findings.push(finding(
                "AUDIT_INVALID",
                Severity::Error,
                format!("audit log could not be read: {error}"),
                None,
            ));
            return;
        }
    };
    let mut ids = std::collections::BTreeSet::new();
    let mut sequences = std::collections::BTreeSet::new();
    let mut invalid = false;
    for event in &events {
        if !ids.insert(&event.id) || !sequences.insert(event.seq) || event.seq == 0 {
            invalid = true;
        }
    }
    if invalid {
        findings.push(finding(
            "AUDIT_INVALID",
            Severity::Error,
            "audit log contains duplicate identifiers or sequence numbers",
            None,
        ));
    }
}

fn check_ca_keys(
    engine: &Engine,
    authorities: &[AuthorityRecord],
    findings: &mut Vec<DoctorFinding>,
) {
    for authority in authorities {
        let path = engine.paths.authority_dir(&authority.name).join("key.pem");
        let Ok(contents) = std::fs::read(&path) else {
            continue;
        };
        if contents
            .windows(b"ENCRYPTED PRIVATE KEY".len())
            .any(|window| window == b"ENCRYPTED PRIVATE KEY")
        {
            continue;
        }
        if contents
            .windows(PRIVATE_KEY_MARKER.len())
            .any(|window| window == PRIVATE_KEY_MARKER)
        {
            findings.push(finding(
                "UNENCRYPTED_CA_KEY",
                Severity::Warning,
                format!(
                    "authority {} key is not passphrase protected",
                    authority.name
                ),
                Some(authority.name.to_string()),
            ));
        }
    }
}
