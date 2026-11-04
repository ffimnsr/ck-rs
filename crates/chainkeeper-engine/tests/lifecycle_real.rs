//! End-to-end lifecycle against the real service composition root.

mod real;

use std::path::PathBuf;

use chainkeeper_core::{
    AnalyzeKind, AuditQuery, CertificateStatus, ChainkeeperService, DiffRequest, IssueRequest,
    PublishOptions, RevocationReason, RevokeRequest, SearchQuery, Serial, Severity, SubjectName,
};
use chainkeeper_engine::open_service;
use real::{
    all_certificates, commit_count, files, generate_crls, init_tenant, intermediate_request, issue,
    issue_every_profile, key_files, ocsp_signer_request, root_request,
};

const INTERMEDIATES: [&str; 4] = ["tls", "smime", "codesign", "ocsp"];

#[test]
fn two_tenants_have_independent_configuration_and_indexes() {
    let alpha = init_tenant("alpha");
    let beta = init_tenant("beta");

    let alpha_tenant =
        std::fs::read_to_string(alpha.root().join("tenant.yaml")).expect("alpha tenant");
    let beta_tenant =
        std::fs::read_to_string(beta.root().join("tenant.yaml")).expect("beta tenant");
    assert!(alpha_tenant.contains("alpha"));
    assert!(!alpha_tenant.contains("beta"));
    assert!(beta_tenant.contains("beta"));
    assert!(!beta_tenant.contains("alpha"));

    assert!(alpha.root().join("cache/index.sqlite").is_file());
    assert!(beta.root().join("cache/index.sqlite").is_file());
    assert_ne!(alpha.root(), beta.root());

    alpha
        .engine
        .create_root(&root_request())
        .expect("alpha root");
    beta.engine.create_root(&root_request()).expect("beta root");

    assert_eq!(
        alpha.engine.store.list_authorities().expect("alpha").len(),
        1
    );
    assert_eq!(beta.engine.store.list_authorities().expect("beta").len(), 1);
    assert_eq!(commit_count(alpha.root()), 2);
    assert_eq!(commit_count(beta.root()), 2);
}

#[test]
#[allow(clippy::too_many_lines)]
fn full_lifecycle_creates_artifacts_and_commits() {
    let tenant = init_tenant("acme");
    let engine = &tenant.engine;
    let root = tenant.root();

    assert_eq!(commit_count(root), 1, "init produces one commit");

    engine.create_root(&root_request()).expect("root");
    assert_eq!(commit_count(root), 2);

    for name in INTERMEDIATES {
        engine
            .create_intermediate(&intermediate_request(name))
            .expect("intermediate");
    }
    assert_eq!(commit_count(root), 2 + INTERMEDIATES.len());

    engine
        .create_ocsp_signer(&ocsp_signer_request())
        .expect("ocsp signer");
    assert_eq!(commit_count(root), 7);

    let issued = issue_every_profile(engine);
    assert_eq!(issued.len(), 6);
    assert_eq!(commit_count(root), 13);
    let mut profiles: Vec<String> = issued
        .iter()
        .map(|report| report.certificate.profile.to_string())
        .collect();
    profiles.sort();
    assert_eq!(
        profiles,
        vec![
            "codesign",
            "mtls",
            "ocsp",
            "smime",
            "tls-client",
            "tls-server"
        ]
    );

    let tls_serial = issued[0].certificate.serial.clone();
    let revoke = engine
        .revoke(&RevokeRequest {
            reason: RevocationReason::KeyCompromise,
            ..RevokeRequest::new(tls_serial)
        })
        .expect("revoke tls certificate");
    assert!(revoke.crl.is_some(), "revocation regenerates the CRL");
    assert_eq!(commit_count(root), 14);
    generate_crls(engine, false);

    let replacement = engine
        .issue(&IssueRequest {
            replaces: Some(issued[1].certificate.serial.clone()),
            ..IssueRequest {
                profile: issued[1].certificate.profile.clone(),
                subject: SubjectName::new("replacement.example.test"),
                sans: vec![chainkeeper_core::San::Dns(
                    "replacement.example.test".to_owned(),
                )],
                custom_extensions: Vec::new(),
                algorithm: None,
                validity_days: None,
                csr_pem: None,
                key_out: None,
                replaces: None,
            }
        })
        .expect("replace certificate");
    assert_eq!(
        replacement.certificate.replaces.as_ref(),
        Some(&issued[1].certificate.serial)
    );
    assert_eq!(commit_count(root), 15);

    let publish_dir = PathBuf::from(".chainkeeper/publish");
    let manifest = engine
        .publish(&PublishOptions {
            output_dir: root.join(&publish_dir),
            clean: true,
            dry_run: false,
            no_commit: false,
        })
        .expect("publish artifacts");
    assert!(
        manifest
            .artifacts
            .iter()
            .any(|artifact| artifact.path.ends_with("root.pem"))
    );
    assert!(root.join(&publish_dir).join("manifest.json").is_file());
    assert_eq!(commit_count(root), 16);

    let published = files(&root.join(&publish_dir));
    assert_ne!(published.len(), 0);
    for path in &published {
        let bytes = std::fs::read(path).expect("read artifact");
        assert!(
            !real::contains_private_key(&bytes),
            "published artifact {} contains a private key",
            path.display()
        );
    }

    for record in all_certificates(engine) {
        let inspected = engine.inspect(&record.serial).expect("inspect");
        assert!(inspected.cert_pem.is_some());
    }
    assert_eq!(
        engine
            .search(&SearchQuery::default())
            .expect("search")
            .len(),
        7,
        "six issued plus one replacement"
    );
    assert_ne!(engine.tree().expect("tree").roots.len(), 0);
    assert_ne!(
        engine.audit(&AuditQuery::default()).expect("audit").len(),
        0
    );
    for kind in [
        AnalyzeKind::Expirations,
        AnalyzeKind::Revocations,
        AnalyzeKind::Intermediates,
        AnalyzeKind::Algorithms,
        AnalyzeKind::Policy,
    ] {
        engine.analyze(kind).expect("analyze");
    }
    engine.diff(&DiffRequest::default()).expect("diff");

    let report = engine.doctor().expect("doctor");
    assert!(
        report.healthy,
        "doctor reported errors: {:?}",
        report
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::Error)
            .collect::<Vec<_>>()
    );

    // Every canonical step is tracked, and no private key is tracked.
    let tracked = real::tracked_files(root);
    assert_ne!(tracked.len(), 0);
    for path in tracked {
        let bytes = std::fs::read(&path).expect("read tracked file");
        assert!(
            !real::contains_private_key(&bytes),
            "tracked file {} contains a private key",
            path.display()
        );
    }
    for (path, bytes) in real::committed_files(root) {
        assert!(
            !real::contains_private_key(&bytes),
            "committed file {} contains a private key",
            path.display()
        );
    }
}

#[test]
fn index_rebuild_after_deleting_the_database_is_identical() {
    let tenant = init_tenant("rebuild");
    let engine = &tenant.engine;
    engine.create_root(&root_request()).expect("root");
    for name in INTERMEDIATES {
        engine
            .create_intermediate(&intermediate_request(name))
            .expect("intermediate");
    }
    engine
        .create_ocsp_signer(&ocsp_signer_request())
        .expect("ocsp signer");
    let _ = issue_every_profile(engine);

    let before = all_certificates(engine);
    let mut before_inspections = Vec::new();
    for record in &before {
        before_inspections.push(engine.inspect(&record.serial).expect("inspect"));
    }

    let index_path = tenant.root().join("cache/index.sqlite");
    std::fs::remove_file(&index_path).expect("delete index");
    assert!(!index_path.exists());

    let rebuilt = open_service(tenant.root()).expect("reopen without index");
    let after = rebuilt.search(&SearchQuery::default()).expect("search");
    assert_eq!(before, after);
    for (record, expected) in before.iter().zip(before_inspections) {
        let actual = rebuilt.inspect(&record.serial).expect("inspect");
        assert_eq!(actual, expected);
    }
}

#[test]
fn clone_without_private_keys_passes_doctor() {
    let tenant = init_tenant("clone");
    let engine = &tenant.engine;
    engine.create_root(&root_request()).expect("root");
    for name in INTERMEDIATES {
        engine
            .create_intermediate(&intermediate_request(name))
            .expect("intermediate");
    }
    let _ = issue(engine, "tls-server", "clone.example.test");
    generate_crls(engine, true);

    let destination = tempfile::tempdir().expect("clone destination");
    let clone_path = destination.path().join("clone");
    git2::Repository::clone(&tenant.root().to_string_lossy(), &clone_path).expect("clone");

    assert!(
        key_files(&clone_path).is_empty(),
        "a clone must not contain private keys"
    );

    let service = open_service(&clone_path).expect("open cloned repository");
    let report = service.doctor().expect("doctor on clone");
    assert!(report.healthy, "clone doctor: {:?}", report.findings);
    for finding in &report.findings {
        assert_ne!(finding.severity, Severity::Error, "{finding:?}");
        assert!(
            !finding.message.to_lowercase().contains("private key"),
            "{finding:?}"
        );
    }
}

#[test]
fn mutating_operations_reject_unknown_serials() {
    let tenant = init_tenant("errors");
    tenant.engine.create_root(&root_request()).expect("root");

    let unknown = Serial::new("DEAD").expect("serial");
    let error = tenant
        .engine
        .revoke(&RevokeRequest::new(unknown.clone()))
        .expect_err("unknown serial");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::NotFound);

    let error = tenant.engine.inspect(&unknown).expect_err("unknown serial");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::NotFound);

    let records = all_certificates(&tenant.engine);
    assert_eq!(records.len(), 0);
    assert_eq!(
        tenant
            .engine
            .search(&SearchQuery {
                status: Some(CertificateStatus::Active),
                ..SearchQuery::default()
            })
            .expect("search")
            .len(),
        0
    );
}
