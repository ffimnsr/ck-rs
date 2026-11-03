//! Failure-injection tests for orchestration rollback.

mod common;

use std::sync::Arc;

use chainkeeper_core::{
    CertificateStore, ChainkeeperError, ChainkeeperService, ErrorKind, GitRepository,
};
use chainkeeper_testkit::{FakeOperation, InMemoryIndexStore};
use common::{FailingAfterAudit, FailingAudit, FailingCrl, FailingGit, FailingIndex, Overrides};

fn hierarchy_with(overrides: Overrides) -> common::SimpleHarness {
    let harness = common::harness_with(overrides);
    common::create_hierarchy(&harness.engine);
    harness
}

#[test]
fn provider_failure_after_key_generation_leaves_no_files() {
    let harness = hierarchy_with(Overrides::default());
    let commit = harness.git.head_commit().expect("head");
    harness
        .provider
        .inject_failure(FakeOperation::IssueAfterKey);

    let error = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect_err("provider failure");
    assert_eq!(error.kind(), ErrorKind::Crypto);
    assert_eq!(harness.git.head_commit().expect("head"), commit);
    assert_eq!(harness.store.list_certificates().expect("certs").len(), 0);
    let active = std::fs::read_dir(harness.root.join("certificates/active")).expect("active");
    assert_eq!(active.count(), 0);
}

#[test]
fn index_failure_after_certificate_write_deletes_the_files() {
    let harness = hierarchy_with(Overrides {
        index: Some(Arc::new(FailingIndex::new())),
        ..Overrides::default()
    });

    let error = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect_err("index failure");
    assert_eq!(error.kind(), ErrorKind::Index);
    assert_eq!(harness.store.list_certificates().expect("certs").len(), 0);
    let active = std::fs::read_dir(harness.root.join("certificates/active")).expect("active");
    assert_eq!(active.count(), 0);
}

#[test]
fn audit_failure_after_index_write_rolls_back_files_and_rows() {
    let harness = hierarchy_with(Overrides {
        audit: Some(Arc::new(FailingAfterAudit::new(6))),
        index: Some(Arc::new(InMemoryIndexStore::new())),
        ..Overrides::default()
    });

    let error = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect_err("audit failure");
    assert_eq!(error.kind(), ErrorKind::Audit);
    assert_eq!(harness.store.list_certificates().expect("certs").len(), 0);
    assert_eq!(
        harness.index.stats().expect("stats").certificates,
        0,
        "index rows must be rebuilt after the aborted operation"
    );
    let active = std::fs::read_dir(harness.root.join("certificates/active")).expect("active");
    assert_eq!(active.count(), 0);
}

#[test]
fn audit_failure_on_the_first_append_aborts_authority_creation() {
    let harness = common::harness_with(Overrides {
        audit: Some(Arc::new(FailingAudit::default())),
        ..Overrides::default()
    });
    let error = harness
        .engine
        .create_root(&common::root_request())
        .expect_err("audit failure");
    assert_eq!(error.kind(), ErrorKind::Audit);
    assert_eq!(
        harness.store.list_authorities().expect("authorities").len(),
        0
    );
}

#[test]
fn git_failure_after_audit_reports_uncommitted_files() {
    let git = Arc::new(FailingGit::new());
    let harness = hierarchy_with(Overrides {
        git: Some(git.clone() as Arc<dyn GitRepository>),
        ..Overrides::default()
    });
    git.fail_commits();

    let error = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect_err("commit failure");
    assert_eq!(error.kind(), ErrorKind::Git);
    assert!(error.message().contains("uncommitted files"));
    // The certificate and audit event were already written; they are reported,
    // not silently discarded.
    assert_eq!(harness.store.list_certificates().expect("certs").len(), 1);
}

#[test]
fn crl_failure_rolls_back_the_revocation() {
    let harness = hierarchy_with(Overrides {
        crl: Some(Arc::new(FailingCrl)),
        ..Overrides::default()
    });
    let issued = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("issue");

    let error: ChainkeeperError = harness
        .engine
        .revoke(&chainkeeper_core::RevokeRequest::new(
            issued.certificate.serial.clone(),
        ))
        .expect_err("crl failure");
    assert_eq!(error.kind(), ErrorKind::Storage);
    assert!(
        harness
            .root
            .join(format!(
                "certificates/active/{}.pem",
                issued.certificate.serial
            ))
            .is_file()
    );
    assert!(
        !harness
            .root
            .join(format!(
                "certificates/revoked/{}.pem",
                issued.certificate.serial
            ))
            .exists()
    );
    assert!(
        !harness
            .root
            .join(format!("revocations/{}.yaml", issued.certificate.serial))
            .exists()
    );
    assert_eq!(
        harness.store.list_revocations().expect("revocations").len(),
        0
    );
}

#[test]
fn serial_collisions_retry_before_failing() {
    let harness = common::harness_with(Overrides::default());
    common::create_hierarchy(&harness.engine);

    // Occupy the serial the fake provider will hand out next.
    let record = chainkeeper_core::CertificateRecord {
        serial: chainkeeper_core::Serial::new("0001").expect("serial"),
        subject: chainkeeper_core::SubjectName::new("seed.example.test"),
        issuer: "CN=Root".to_owned(),
        profile: chainkeeper_core::ProfileName::new("tls-server").expect("profile"),
        authority: chainkeeper_core::AuthorityName::new("tls").expect("authority"),
        algorithm: chainkeeper_core::KeyAlgorithm::EcdsaP256,
        sans: Vec::new(),
        ekus: Vec::new(),
        key_usages: Vec::new(),
        issued_at: common::NOW,
        expires_at: common::NOW + time::Duration::days(397),
        path: "certificates/active/0001.pem".into(),
        revoked_at: None,
        revocation_reason: None,
        replaces: None,
    };
    harness
        .store
        .write_certificate(&chainkeeper_core::IssuedCertificate::new(
            record,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            String::new(),
            None,
        ))
        .expect("seed certificate");

    let report = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("retry succeeds");
    assert_eq!(report.certificate.serial.as_str(), "0002");
}
