//! Analysis, audit, diff, publish, and rebuild tests.

mod common;

use std::path::PathBuf;

use chainkeeper_core::{
    AnalyzeKind, AuditAction, AuditQuery, CertificateStatus, ChainkeeperService, ErrorKind,
    GitRepository, KeyAlgorithm, Policy, PublishOptions, SearchQuery, Severity,
};
use chainkeeper_engine::ChangeCategory;

#[test]
fn analyze_expirations_buckets_certificates() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("issue");

    common::insert_certificate(
        &harness.store,
        common::certificate_record(
            "0100",
            "tls-server",
            "tls",
            common::NOW - time::Duration::days(400),
            common::NOW - time::Duration::days(1),
            KeyAlgorithm::EcdsaP256,
            Vec::new(),
        ),
    );
    common::insert_certificate(
        &harness.store,
        common::certificate_record(
            "0101",
            "tls-server",
            "tls",
            common::NOW,
            common::NOW + time::Duration::days(10),
            KeyAlgorithm::EcdsaP256,
            Vec::new(),
        ),
    );

    let report = harness
        .engine
        .analyze(AnalyzeKind::Expirations)
        .expect("analyze");
    let codes: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    assert!(codes.contains(&"EXPIRATIONS_EXPIRED"));
    assert!(codes.contains(&"EXPIRATIONS_0_30"));
    assert!(codes.contains(&"EXPIRATIONS_91_PLUS"));
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.severity == Severity::Error)
    );
}

#[test]
fn analyze_revocations_counts_reasons_and_months() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    let issued = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("issue");
    harness
        .engine
        .revoke(&chainkeeper_core::RevokeRequest {
            serial: issued.certificate.serial,
            reason: chainkeeper_core::RevocationReason::KeyCompromise,
            comment: None,
        })
        .expect("revoke");

    let report = harness
        .engine
        .analyze(AnalyzeKind::Revocations)
        .expect("analyze");
    let codes: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    assert!(codes.contains(&"REVOCATIONS_BY_REASON"));
    assert!(codes.contains(&"REVOCATIONS_BY_MONTH"));
}

#[test]
fn analyze_intermediates_flags_upcoming_expiry() {
    let harness = common::harness();
    harness
        .engine
        .create_root(&common::root_request())
        .expect("root");
    harness.store.insert_authority(common::authority_config(
        "tls",
        chainkeeper_core::AuthorityKind::Intermediate,
        Some("root"),
        30,
        common::NOW,
    ));

    let report = harness
        .engine
        .analyze(AnalyzeKind::Intermediates)
        .expect("analyze");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].code, "INTERMEDIATE_EXPIRING");
}

#[test]
fn analyze_algorithms_counts_and_flags_policy_violations() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("issue");

    let report = harness
        .engine
        .analyze(AnalyzeKind::Algorithms)
        .expect("analyze");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "ALGORITHM_COUNT")
    );

    let policy = Policy {
        allowed_algorithms: vec![KeyAlgorithm::Rsa3072],
        ..Policy::default()
    };
    harness.store.set_policy(policy);
    let report = harness
        .engine
        .analyze(AnalyzeKind::Policy)
        .expect("analyze");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "POLICY_ALGORITHM_DISALLOWED")
    );
}

#[test]
fn analyze_policy_flags_validity_and_wildcards() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    harness.store.set_policy(Policy {
        max_validity_days: 30,
        allow_wildcards: false,
        ..Policy::default()
    });
    common::insert_certificate(
        &harness.store,
        common::certificate_record(
            "0200",
            "tls-server",
            "tls",
            common::NOW,
            common::NOW + time::Duration::days(397),
            KeyAlgorithm::EcdsaP256,
            vec![chainkeeper_core::San::Dns("*.example.test".to_owned())],
        ),
    );

    let report = harness
        .engine
        .analyze(AnalyzeKind::Policy)
        .expect("analyze");
    let codes: Vec<&str> = report
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    assert!(codes.contains(&"POLICY_VALIDITY_EXCEEDED"));
    assert!(codes.contains(&"POLICY_WILDCARD_DISALLOWED"));
}

#[test]
fn search_validation_rejects_oversized_limits() {
    let harness = common::harness();
    let error = harness
        .engine
        .search(&SearchQuery {
            limit: Some(10_001),
            ..SearchQuery::default()
        })
        .expect_err("limit");
    assert_eq!(error.kind(), ErrorKind::Validation);
}

#[test]
fn audit_filters_and_orders_events() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);

    let events = harness
        .engine
        .audit(&AuditQuery {
            action: Some(AuditAction::RootCreated),
            ..AuditQuery::default()
        })
        .expect("audit");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, AuditAction::RootCreated);

    let all = harness.engine.audit(&AuditQuery::default()).expect("audit");
    assert_eq!(all.len(), 6);
    assert!(all.windows(2).all(|pair| pair[0].seq < pair[1].seq));
}

#[test]
fn diff_requires_a_manifest_or_explicit_revision() {
    let harness = common::harness();
    let error = harness
        .engine
        .diff(&chainkeeper_core::DiffRequest::default())
        .expect_err("no manifest");
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[test]
fn diff_categorizes_every_change_type() {
    let harness = common::harness();
    let first = harness
        .git
        .commit("seed", &[PathBuf::from("policy/policy.yaml")])
        .expect("seed commit");
    common::write_manifest(&harness.root, Some(&first), Vec::new());

    let paths = vec![
        PathBuf::from("certificates/active/0001.pem"),
        PathBuf::from("revocations/0001.yaml"),
        PathBuf::from("crls/tls.crl.der"),
        PathBuf::from("profiles/tls-server.yaml"),
        PathBuf::from("audit/events/01J00000000000000000000001.json"),
        PathBuf::from("publish/root.pem"),
    ];
    let second = harness.git.commit("changes", &paths).expect("commit");

    let report = harness
        .engine
        .diff(&chainkeeper_core::DiffRequest::default())
        .expect("diff");
    assert_eq!(report.from.as_deref(), Some(first.as_str()));
    assert_eq!(report.to.as_deref(), Some(second.as_str()));
    assert_eq!(report.added.len(), paths.len());

    let categories: Vec<ChangeCategory> = report
        .added
        .iter()
        .map(|path| chainkeeper_engine::categorize_path(path))
        .collect();
    for expected in [
        ChangeCategory::Certificate,
        ChangeCategory::Revocation,
        ChangeCategory::Crl,
        ChangeCategory::Policy,
        ChangeCategory::Audit,
        ChangeCategory::Publish,
    ] {
        assert!(categories.contains(&expected), "{expected:?}");
    }
}

#[test]
fn diff_supports_since_and_reports_no_changes() {
    let harness = common::harness();
    let first = harness
        .git
        .commit("seed", &[PathBuf::from("policy/policy.yaml")])
        .expect("seed commit");

    let report = harness
        .engine
        .diff(&chainkeeper_core::DiffRequest {
            from: Some(first.clone()),
            to: Some(first),
        })
        .expect("diff");
    assert_eq!(report.added.len(), 0);
    assert_eq!(report.modified.len(), 0);
    assert_eq!(report.removed.len(), 0);
}

#[test]
fn publish_delegates_and_commits_an_audit_event() {
    let harness = common::harness();
    let commits = harness.git.commits().expect("commits").len();
    let manifest = harness
        .engine
        .publish(&PublishOptions::new(harness.root.join("publish")))
        .expect("publish");
    assert_eq!(harness.publish.build_count(), 1);
    assert_eq!(manifest.tenant_id.as_str(), "test-tenant");
    assert_eq!(harness.git.commits().expect("commits").len(), commits + 1);
    assert!(
        harness
            .audit
            .events()
            .expect("events")
            .iter()
            .any(|event| event.action == AuditAction::PublishCompleted)
    );
}

#[test]
fn rebuild_index_reports_rows_and_audits() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("issue");

    let report = harness.engine.rebuild_index().expect("rebuild");
    assert_eq!(report.stats.certificates, 1);
    assert_eq!(report.stats.authorities, 6);
    assert!(
        harness
            .audit
            .events()
            .expect("events")
            .iter()
            .any(|event| event.action == AuditAction::IndexRebuilt)
    );
}

#[test]
fn audit_limit_validation_rejects_oversized_limits() {
    let harness = common::harness();
    let error = harness
        .engine
        .audit(&AuditQuery {
            limit: Some(10_001),
            ..AuditQuery::default()
        })
        .expect_err("limit");
    assert_eq!(error.kind(), ErrorKind::Validation);
}

#[test]
fn inspect_reports_active_status_and_pem() {
    let harness = common::harness();
    common::create_hierarchy(&harness.engine);
    let issued = harness
        .engine
        .issue(&common::issue_request("tls-server"))
        .expect("issue");
    let report = harness
        .engine
        .inspect(&issued.certificate.serial)
        .expect("inspect");
    assert_eq!(report.status, CertificateStatus::Active);
    assert!(report.cert_pem.is_some());
}
