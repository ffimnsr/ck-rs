//! `ck doctor` diagnostics tests.

mod common;

use std::sync::Arc;

use chainkeeper_core::{
    AuthorityKind, CertificateStore, ChainkeeperService, DoctorReport, GitStatus, IndexStore,
    Policy, ProfileName, Severity,
};
use common::Overrides;

fn codes(report: &DoctorReport) -> Vec<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect()
}

fn healthy_harness() -> common::Harness {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    common::seed_crls(&harness.crl);
    common::write_manifest(&harness.root, None, Vec::new());
    common::write_git_config(&harness.root, true);
    common::remove_authority_keys(&harness.root);
    harness
}

#[test]
fn clean_repository_has_no_findings() {
    let harness = healthy_harness();
    let report = harness.engine.doctor().expect("doctor");
    assert!(report.healthy, "{:?}", report.findings);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn empty_repository_reports_missing_components() {
    let harness = common::harness();
    let report = harness.engine.doctor().expect("doctor");
    let codes = codes(&report);
    for expected in [
        "ROOT_MISSING",
        "INTERMEDIATE_MISSING",
        "CRL_MISSING",
        "OCSP_SIGNER_MISSING",
        "GIT_NOT_INITIALIZED",
        "PUBLISH_MISSING",
    ] {
        assert!(codes.contains(&expected), "{expected} missing in {codes:?}");
    }
    assert!(!report.healthy);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.severity == Severity::Warning)
    );
}

#[test]
fn root_expiry_states_are_reported() {
    let harness = common::harness();
    harness.store.insert_authority(common::authority_config(
        "root",
        AuthorityKind::Root,
        None,
        10,
        common::NOW - time::Duration::days(100),
    ));
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"ROOT_EXPIRED"));

    let harness = common::harness();
    harness.store.insert_authority(common::authority_config(
        "root",
        AuthorityKind::Root,
        None,
        300,
        common::NOW,
    ));
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"ROOT_EXPIRING_SOON"));
}

#[test]
fn intermediate_expiry_and_chain_errors_are_reported() {
    let harness = common::harness();
    harness.store.insert_authority(common::authority_config(
        "root",
        AuthorityKind::Root,
        None,
        7300,
        common::NOW,
    ));
    harness.store.insert_authority(common::authority_config(
        "tls",
        AuthorityKind::Intermediate,
        Some("root"),
        10,
        common::NOW - time::Duration::days(100),
    ));
    harness.store.insert_authority(common::authority_config(
        "smime",
        AuthorityKind::Intermediate,
        Some("root"),
        30,
        common::NOW,
    ));
    harness.store.insert_authority(common::authority_config(
        "codesign",
        AuthorityKind::Intermediate,
        Some("missing"),
        3650,
        common::NOW,
    ));
    let report = harness.engine.doctor().expect("doctor");
    let codes = codes(&report);
    assert!(codes.contains(&"INTERMEDIATE_EXPIRED"));
    assert!(codes.contains(&"INTERMEDIATE_EXPIRING_SOON"));
    assert!(codes.contains(&"INTERMEDIATE_CHAIN_INVALID"));
    assert!(codes.contains(&"INTERMEDIATE_MISSING"));
}

#[test]
fn crl_expiry_states_are_reported() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    for name in ["tls", "smime", "codesign", "ocsp"] {
        harness.crl.seed(chainkeeper_core::CrlRecord {
            version: chainkeeper_core::CONFIG_VERSION,
            authority: chainkeeper_core::AuthorityName::new(name).expect("name"),
            number: 1,
            this_update: common::NOW - time::Duration::days(30),
            next_update: common::NOW - time::Duration::days(1),
            revoked_serials: Vec::new(),
            der_path: format!("crls/{name}.crl.der").into(),
            pem_path: format!("crls/{name}.crl.pem").into(),
        });
    }
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"CRL_EXPIRED"));

    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    for name in ["tls", "smime", "codesign", "ocsp"] {
        harness.crl.seed(chainkeeper_core::CrlRecord {
            version: chainkeeper_core::CONFIG_VERSION,
            authority: chainkeeper_core::AuthorityName::new(name).expect("name"),
            number: 1,
            this_update: common::NOW,
            next_update: common::NOW + time::Duration::hours(1),
            revoked_serials: Vec::new(),
            der_path: format!("crls/{name}.crl.der").into(),
            pem_path: format!("crls/{name}.crl.pem").into(),
        });
    }
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"CRL_NEXT_UPDATE_SOON"));
}

#[test]
fn ocsp_signer_errors_are_reported() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    harness.store.insert_authority(common::authority_config(
        "ocsp-signer",
        AuthorityKind::OcspSigner,
        Some("ocsp"),
        10,
        common::NOW - time::Duration::days(100),
    ));
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"OCSP_SIGNER_EXPIRED"));
}

#[test]
fn ocsp_signer_eku_is_validated() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    let root = harness
        .store
        .load_authority(&common::authority("root"))
        .expect("load")
        .expect("root");
    harness
        .store
        .set_authority_material(chainkeeper_core::AuthorityMaterial::new(
            common::authority_config(
                "ocsp-signer",
                AuthorityKind::OcspSigner,
                Some("ocsp"),
                90,
                common::NOW,
            ),
            root.cert_pem,
            root.chain_pem,
        ));
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"OCSP_SIGNER_EKU_INVALID"));
}

#[test]
fn git_remote_and_dirty_state_are_reported() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    common::write_git_config(&harness.root, false);
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"GIT_REMOTE_MISSING"));

    let git = Arc::new(common::FailingGit::new());
    let harness = common::harness_with(Overrides {
        git: Some(git.clone() as Arc<dyn chainkeeper_core::GitRepository>),
        ..Overrides::default()
    });
    common::create_hierarchy(&harness.engine);
    git.set_status(GitStatus {
        branch: Some("main".to_owned()),
        head: None,
        clean: false,
        changes: Vec::new(),
        untracked: Vec::new(),
    });
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"GIT_DIRTY"));
}

#[test]
fn publish_problems_are_reported() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    common::write_manifest(
        &harness.root,
        None,
        vec![chainkeeper_core::PublishArtifact {
            path: "root.pem".into(),
            sha256: "0".repeat(64),
            bytes: 1,
        }],
    );
    std::fs::write(
        harness.root.join("publish/leak.pem"),
        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
    )
    .expect("leak");
    let report = harness.engine.doctor().expect("doctor");
    let codes = codes(&report);
    assert!(codes.contains(&"PUBLISH_HASH_MISMATCH"));
    assert!(codes.contains(&"PUBLISH_PRIVATE_KEY_FOUND"));
}

#[test]
fn configuration_problems_are_reported() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    harness.store.set_policy(Policy {
        max_validity_days: 0,
        ..Policy::default()
    });
    let mut profile =
        chainkeeper_core::builtin_profile(&ProfileName::new("tls-server").expect("profile"))
            .expect("profile");
    profile.version = 99;
    harness.store.set_profile(profile);

    let report = harness.engine.doctor().expect("doctor");
    let codes = codes(&report);
    assert!(codes.contains(&"POLICY_INVALID"));
    assert!(codes.contains(&"PROFILE_INVALID"));
}

#[test]
fn index_drift_and_audit_corruption_are_reported() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    harness
        .index
        .rebuild(&chainkeeper_core::IndexRecords::default())
        .expect("clear");
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"INDEX_DRIFT"));

    let harness = common::harness_with(Overrides {
        audit: Some(Arc::new(common::DuplicateAudit)),
        ..Overrides::default()
    });
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"AUDIT_INVALID"));
}

#[test]
fn unencrypted_authority_keys_are_reported() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    let report = harness.engine.doctor().expect("doctor");
    assert!(codes(&report).contains(&"UNENCRYPTED_CA_KEY"));
}
