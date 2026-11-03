//! Lifecycle orchestration tests.

mod common;

use std::sync::Arc;

use chainkeeper_core::{
    AuditAction, AuthorityKind, CertificateStatus, CertificateStore, ChainkeeperError,
    ChainkeeperService, ErrorKind, ProfileName, RevocationReason, SearchQuery,
};
use common::{Overrides, RejectingPolicy, empty_harness, harness, harness_with};

fn init_request() -> chainkeeper_core::InitRequest {
    chainkeeper_core::InitRequest::new(
        chainkeeper_core::TenantId::new("acme").expect("tenant"),
        "Acme",
        ProfileName::new("tls-server").expect("profile"),
    )
}

#[test]
fn init_creates_the_exact_layout_and_one_commit() {
    let harness = empty_harness();
    let report = harness.engine.init(&init_request()).expect("init");

    assert!(harness.root.join("tenant.yaml").is_file());
    assert!(harness.root.join("policy/policy.yaml").is_file());
    assert!(harness.root.join(".gitignore").is_file());
    for name in [
        "tls-server",
        "tls-client",
        "mtls",
        "smime",
        "codesign",
        "ocsp",
    ] {
        assert!(harness.root.join(format!("profiles/{name}.yaml")).is_file());
    }
    for directory in [
        "certificates/active",
        "certificates/revoked",
        "certificates/expired",
        "revocations",
        "crls",
        "audit/events",
        "publish",
        "cache",
        "authorities/root",
        "authorities/tls",
    ] {
        assert!(harness.root.join(directory).is_dir(), "{directory}");
    }

    let gitignore = std::fs::read_to_string(harness.root.join(".gitignore")).expect("gitignore");
    assert!(gitignore.contains("authorities/**/key.pem"));
    assert!(gitignore.contains("certificates/**/*.key.pem"));

    assert_eq!(harness.git.commits().expect("commits").len(), 1);
    assert!(report.commit.is_some());
    assert!(
        report
            .created_paths
            .iter()
            .any(|path| path.ends_with("tenant.yaml"))
    );
}

#[test]
fn init_rejects_a_non_empty_directory() {
    let harness = harness();
    let error = harness.engine.init(&init_request()).expect_err("rejected");
    assert_eq!(error.kind(), ErrorKind::AlreadyExists);
}

#[test]
fn init_is_reproducible_with_a_fixed_clock_and_ids() {
    let first = empty_harness();
    first.engine.init(&init_request()).expect("first init");
    let second = empty_harness();
    second.engine.init(&init_request()).expect("second init");

    for relative in [
        "tenant.yaml",
        "policy/policy.yaml",
        "profiles/tls-server.yaml",
        ".gitignore",
    ] {
        let left = std::fs::read(first.root.join(relative)).expect("left");
        let right = std::fs::read(second.root.join(relative)).expect("right");
        assert_eq!(left, right, "{relative}");
    }
}

#[test]
fn init_leaves_no_private_keys() {
    let harness = empty_harness();
    harness.engine.init(&init_request()).expect("init");
    let mut keys = Vec::new();
    collect_keys(&harness.root, &mut keys);
    assert!(keys.is_empty(), "{keys:?}");
}

fn collect_keys(path: &std::path::Path, keys: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_keys(&path, keys);
        } else if path.file_name().is_some_and(|name| name == "key.pem") {
            keys.push(path);
        }
    }
}

#[test]
fn root_creation_twice_fails() {
    let harness = harness();
    harness
        .engine
        .create_root(&common::root_request())
        .expect("root");
    let error = harness
        .engine
        .create_root(&common::root_request())
        .expect_err("duplicate root");
    assert_eq!(error.kind(), ErrorKind::AlreadyExists);
}

#[test]
fn intermediate_requires_an_existing_root() {
    let harness = harness();
    let error = harness
        .engine
        .create_intermediate(&common::intermediate_request("tls"))
        .expect_err("missing root");
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[test]
fn intermediate_name_must_be_known() {
    let harness = harness();
    harness
        .engine
        .create_root(&common::root_request())
        .expect("root");
    let error = harness
        .engine
        .create_intermediate(&common::intermediate_request("bogus"))
        .expect_err("bad name");
    assert_eq!(error.kind(), ErrorKind::Validation);
}

#[test]
fn ocsp_signer_requires_the_ocsp_intermediate() {
    let harness = harness();
    harness
        .engine
        .create_root(&common::root_request())
        .expect("root");
    let error = harness
        .engine
        .create_ocsp_signer(&common::ocsp_signer_request())
        .expect_err("missing ocsp");
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[test]
fn every_mutating_success_creates_one_commit_and_one_audit_event() {
    let harness = harness();
    let mut commits = harness.git.commits().expect("commits").len();
    let mut events = harness.audit.events().expect("events").len();

    harness
        .engine
        .create_root(&common::root_request())
        .expect("root");
    assert_eq!(harness.git.commits().expect("commits").len(), commits + 1);
    assert_eq!(harness.audit.events().expect("events").len(), events + 1);
    commits += 1;
    events += 1;

    harness
        .engine
        .create_intermediate(&common::intermediate_request("tls"))
        .expect("tls");
    assert_eq!(harness.git.commits().expect("commits").len(), commits + 1);
    assert_eq!(harness.audit.events().expect("events").len(), events + 1);
}

#[test]
fn issuance_supports_every_builtin_profile() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);

    for profile in [
        "tls-server",
        "tls-client",
        "mtls",
        "smime",
        "codesign",
        "ocsp",
    ] {
        let report = harness
            .engine
            .issue(&common::issue_request(profile))
            .expect("issue");
        assert_eq!(report.certificate.profile.as_str(), profile);
        assert_eq!(
            report.certificate.status(common::NOW),
            CertificateStatus::Active
        );
    }
    assert_eq!(harness.store.list_certificates().expect("certs").len(), 6);
}

#[test]
fn policy_failure_creates_no_files_and_no_commit() {
    let harness = harness_with(Overrides {
        policy: Some(Arc::new(RejectingPolicy)),
        ..Overrides::default()
    });
    common::create_hierarchy(&harness.engine);
    let commits = harness.git.head_commit().expect("head");
    let audit_before = harness.store.list_certificates().expect("certs").len();

    let error = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect_err("policy rejection");
    assert_eq!(error.kind(), ErrorKind::Policy);
    assert_eq!(harness.git.head_commit().expect("head"), commits);
    assert_eq!(
        harness.store.list_certificates().expect("certs").len(),
        audit_before
    );
    let active = std::fs::read_dir(harness.root.join("certificates/active")).expect("active");
    assert_eq!(active.count(), 0);
}

#[test]
fn replacement_revokes_the_old_certificate_and_links_the_new_one() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);

    let first = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("first");
    let mut request = common::issue_request("tls-server");
    request.replaces = Some(first.certificate.serial.clone());
    let second = harness.engine.issue(&request).expect("replacement");

    assert_eq!(
        second.certificate.replaces,
        Some(first.certificate.serial.clone())
    );
    let old = harness
        .store
        .get_certificate(&first.certificate.serial)
        .expect("store")
        .expect("old");
    assert_eq!(old.status(common::NOW), CertificateStatus::Revoked);
    assert_eq!(old.revocation_reason, Some(RevocationReason::Superseded));
    assert!(
        harness
            .audit
            .events()
            .expect("events")
            .iter()
            .any(|event| event.action == AuditAction::CertReplaced)
    );
}

#[test]
fn issuance_with_a_csr_writes_no_private_key() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);
    let mut request = common::issue_request("tls-server");
    request.csr_pem = Some(
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n".to_owned(),
    );

    harness.engine.issue(&request).expect("issue");
    let key = harness.root.join("certificates/active/0001.key.pem");
    assert!(!key.exists());
}

#[test]
fn key_out_places_the_key_only_at_the_requested_path() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);
    let directory = tempfile::tempdir().expect("temp");
    let key_path = directory.path().join("leaf.key");
    let mut request = common::issue_request("tls-server");
    request.key_out = Some(key_path.clone());

    let report = harness.engine.issue(&request).expect("issue");
    assert_eq!(report.key_path.as_deref(), Some(key_path.as_path()));
    assert!(key_path.is_file());
    assert!(
        !harness
            .root
            .join("certificates/active/0001.key.pem")
            .exists()
    );
}

#[test]
fn revocation_marks_the_certificate_and_regenerates_the_crl() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);
    let issued = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("issue");

    let report = harness
        .engine
        .revoke(&chainkeeper_core::RevokeRequest {
            serial: issued.certificate.serial.clone(),
            reason: RevocationReason::KeyCompromise,
            comment: Some("lost".to_owned()),
        })
        .expect("revoke");
    assert_eq!(report.revocation.reason, RevocationReason::KeyCompromise);
    assert!(report.crl.is_some());
    assert_eq!(harness.crl.update_count(), 1);
    assert!(
        harness
            .root
            .join(format!(
                "certificates/revoked/{}.pem",
                issued.certificate.serial
            ))
            .is_file()
    );
    assert!(
        !harness
            .root
            .join(format!(
                "certificates/active/{}.pem",
                issued.certificate.serial
            ))
            .exists()
    );

    let error = harness
        .engine
        .revoke(&chainkeeper_core::RevokeRequest::new(
            issued.certificate.serial,
        ))
        .expect_err("already revoked");
    assert_eq!(error.kind(), ErrorKind::Conflict);
}

#[test]
fn revocation_skips_publish_when_the_directory_is_missing() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);
    let issued = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("issue");
    std::fs::remove_dir_all(harness.root.join("publish")).expect("remove publish");

    harness
        .engine
        .revoke(&chainkeeper_core::RevokeRequest::new(
            issued.certificate.serial,
        ))
        .expect("revoke");
    assert_eq!(harness.publish.build_count(), 0);
}

#[test]
fn revocation_accepts_every_reason() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);
    for reason in RevocationReason::ALL {
        let issued = harness
            .engine
            .issue(&common::issue_request("tls-server"))
            .expect("issue");
        harness
            .engine
            .revoke(&chainkeeper_core::RevokeRequest {
                serial: issued.certificate.serial,
                reason,
                comment: None,
            })
            .expect("revoke");
    }
}

#[test]
fn missing_certificate_revocation_fails() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);
    let error = harness
        .engine
        .revoke(&chainkeeper_core::RevokeRequest::new(
            chainkeeper_core::Serial::new("FFFF").expect("serial"),
        ))
        .expect_err("missing");
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[test]
fn inspect_and_search_return_issued_certificates() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);
    let issued = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("issue");

    let report = harness
        .engine
        .inspect(&issued.certificate.serial)
        .expect("inspect");
    assert_eq!(report.certificate.serial, issued.certificate.serial);
    assert_eq!(report.status, CertificateStatus::Active);
    assert!(report.cert_pem.is_some());

    let found = harness
        .engine
        .search(&SearchQuery {
            text: Some("leaf.example.test".to_owned()),
            ..SearchQuery::default()
        })
        .expect("search");
    assert_eq!(found.len(), 1);

    let missing = harness
        .engine
        .inspect(&chainkeeper_core::Serial::new("FFFF").expect("serial"))
        .expect_err("missing");
    assert_eq!(missing.kind(), ErrorKind::NotFound);
}

#[test]
fn tree_reports_the_hierarchy() {
    let harness = harness();
    common::create_hierarchy(&harness.engine);
    let report = harness.engine.tree().expect("tree");
    assert_eq!(report.roots.len(), 1);
    let root = &report.roots[0];
    assert_eq!(root.kind, AuthorityKind::Root);
    assert_eq!(root.children.len(), 4);
}

#[test]
fn tree_rejects_a_cycle() {
    let harness = harness();
    harness
        .engine
        .create_root(&common::root_request())
        .expect("root");
    harness
        .store
        .insert_authority(chainkeeper_core::AuthorityConfig::new(
            chainkeeper_core::AuthorityName::new("tls").expect("name"),
            AuthorityKind::Intermediate,
            Some(chainkeeper_core::AuthorityName::new("smime").expect("name")),
            chainkeeper_core::KeyAlgorithm::EcdsaP256,
            3650,
            0,
            Vec::new(),
            common::NOW,
        ));
    harness
        .store
        .insert_authority(chainkeeper_core::AuthorityConfig::new(
            chainkeeper_core::AuthorityName::new("smime").expect("name"),
            AuthorityKind::Intermediate,
            Some(chainkeeper_core::AuthorityName::new("tls").expect("name")),
            chainkeeper_core::KeyAlgorithm::EcdsaP256,
            3650,
            0,
            Vec::new(),
            common::NOW,
        ));
    let error = harness.engine.tree().expect_err("cycle");
    assert_eq!(error.kind(), ErrorKind::Validation);
}

#[test]
fn tree_rejects_orphan_intermediates() {
    let harness = harness();
    harness
        .engine
        .create_root(&common::root_request())
        .expect("root");
    harness
        .store
        .insert_authority(chainkeeper_core::AuthorityConfig::new(
            chainkeeper_core::AuthorityName::new("tls").expect("name"),
            AuthorityKind::Intermediate,
            Some(chainkeeper_core::AuthorityName::new("missing").expect("name")),
            chainkeeper_core::KeyAlgorithm::EcdsaP256,
            3650,
            0,
            Vec::new(),
            common::NOW,
        ));
    let error = harness.engine.tree().expect_err("orphan");
    assert_eq!(error.kind(), ErrorKind::Validation);
}

#[test]
fn audit_query_validates_bounds() {
    let harness = harness();
    let error = harness
        .engine
        .audit(&chainkeeper_core::AuditQuery {
            limit: Some(0),
            ..chainkeeper_core::AuditQuery::default()
        })
        .expect_err("zero limit");
    assert_eq!(error.kind(), ErrorKind::Validation);

    let events = harness
        .engine
        .audit(&chainkeeper_core::AuditQuery::default())
        .expect("audit");
    assert_eq!(events.len(), 0);
}

#[test]
fn failed_commit_reports_uncommitted_files() {
    let harness = harness_with(Overrides {
        git: Some(Arc::new({
            let git = common::FailingGit::new();
            git.fail_commits();
            git
        })),
        ..Overrides::default()
    });
    // The root commit itself fails, so root creation surfaces the Git error.
    let error: ChainkeeperError = harness
        .engine
        .create_root(&common::root_request())
        .expect_err("commit failure");
    assert_eq!(error.kind(), ErrorKind::Git);
    assert!(error.message().contains("uncommitted files"));
}
