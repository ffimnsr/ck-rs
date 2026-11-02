//! Filesystem layout, permissions, and canonical record tests.

mod common;

use std::path::PathBuf;

use chainkeeper_core::{
    AuditAction, AuditEvent, CertificateStatus, CertificateStore as _, CrlBundle, CrlRecord,
    ErrorKind, EventId, FileMode, Policy, RevocationReason, RevocationRecord, Serial, atomic_write,
    builtin_profiles,
};
use chainkeeper_store::init_layout;
use serde_json::json;
use time::Duration;

use common::{CertSpec, TestRepo, files_below, issued, now};

fn serial(spec: &CertSpec) -> Serial {
    spec.serial()
}

#[test]
fn init_layout_creates_every_directory() {
    let directory = tempfile::tempdir().expect("temp dir");
    let paths = chainkeeper_core::RepositoryPaths::new(directory.path()).expect("paths");
    let created = init_layout(&paths).expect("layout");
    assert_eq!(created.len(), paths.required_directories().len());
    for required in paths.required_directories() {
        assert!(required.is_dir(), "{}", required.display());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mode = std::fs::metadata(paths.state_dir())
            .expect("state dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}

#[test]
fn tenant_policy_and_profiles_round_trip() {
    let repo = TestRepo::new();
    let tenant = chainkeeper_core::TenantConfig::new(
        chainkeeper_core::TenantId::new("corp-a").expect("tenant"),
        "Corp A",
        chainkeeper_core::ProfileName::new("tls-server").expect("profile"),
        now(),
    );
    repo.store.write_tenant(&tenant).expect("tenant");
    repo.store.write_policy(&Policy::default()).expect("policy");
    for profile in builtin_profiles() {
        repo.store.write_profile(&profile).expect("profile");
    }

    assert_eq!(repo.store.load_tenant().expect("load tenant"), tenant);
    assert_eq!(
        repo.store.load_policy().expect("load policy"),
        Policy::default()
    );
    let mut expected = builtin_profiles();
    expected.sort_by(|left, right| left.name.cmp(&right.name));
    assert_eq!(repo.store.load_profiles().expect("profiles"), expected);
}

#[test]
fn invalid_configuration_is_rejected_on_write_and_load() {
    let repo = TestRepo::new();
    let mut tenant = chainkeeper_core::TenantConfig::new(
        chainkeeper_core::TenantId::new("corp-a").expect("tenant"),
        "Corp A",
        chainkeeper_core::ProfileName::new("tls-server").expect("profile"),
        now(),
    );
    tenant.version = 2;
    assert_eq!(
        repo.store
            .write_tenant(&tenant)
            .expect_err("invalid")
            .kind(),
        ErrorKind::Config
    );

    let mut valid = tenant;
    valid.version = 1;
    let rendered = serde_yaml_ng::to_string(&valid).expect("yaml");
    std::fs::write(repo.tenant.paths().tenant_yaml(), &rendered).expect("raw tenant");
    let mut wrong = valid;
    wrong.version = 2;
    std::fs::write(
        repo.tenant.paths().tenant_yaml(),
        serde_yaml_ng::to_string(&wrong).expect("yaml"),
    )
    .expect("raw tenant");
    assert_eq!(
        repo.store.load_tenant().expect_err("invalid").kind(),
        ErrorKind::Config
    );

    let mut profile = builtin_profiles().remove(0);
    profile.name = chainkeeper_core::ProfileName::new("other").expect("profile");
    repo.store.write_profile(&profile).expect("valid profile");
    std::fs::write(
        repo.tenant.paths().profiles_dir().join("mismatched.yaml"),
        serde_yaml_ng::to_string(&profile).expect("yaml"),
    )
    .expect("raw profile");
    assert_eq!(
        repo.store.load_profiles().expect_err("mismatch").kind(),
        ErrorKind::Storage
    );
}

#[test]
fn authority_round_trip_and_conflict_detection() {
    let repo = TestRepo::new();
    repo.store
        .write_authority(&repo.fixtures.root)
        .expect("write authority");
    let material = repo
        .store
        .load_authority(&repo.fixtures.root.material.config.name)
        .expect("load")
        .expect("exists");
    assert_eq!(material.cert_pem, repo.fixtures.root.material.cert_pem);

    let records = repo.store.list_authorities().expect("list");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].cert_path,
        PathBuf::from("authorities/root/cert.pem")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let key = repo
            .tenant
            .paths()
            .authority_path(&repo.fixtures.root.material.config.name, "key.pem")
            .expect("key path");
        let mode = std::fs::metadata(key).expect("key").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let conflicting = chainkeeper_core::AuthorityMaterial::new(
        repo.fixtures.root.material.config.clone(),
        repo.fixtures.tls.material.cert_pem.clone(),
        repo.fixtures.tls.material.chain_pem.clone(),
    );
    assert_eq!(
        repo.store
            .write_authority_material(&conflicting)
            .expect_err("conflict")
            .kind(),
        ErrorKind::AlreadyExists
    );
}

#[test]
fn certificate_lifecycle_writes_lists_and_moves() {
    let repo = TestRepo::new();
    let spec = CertSpec::new(10, "leaf.example.test");
    let issued = issued(&spec);
    let written = repo.store.write_certificate(&issued).expect("write");
    assert_eq!(
        written,
        repo.tenant
            .paths()
            .certificate_path(&serial(&spec), "pem")
            .expect("path")
    );

    let loaded = repo
        .store
        .get_certificate(&serial(&spec))
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.subject.cn, "leaf.example.test");
    assert_eq!(loaded.path, PathBuf::from("certificates/active/000A.pem"));

    let listed = repo.store.list_certificates().expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].serial, serial(&spec));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let key = repo
            .tenant
            .paths()
            .certificate_path(&serial(&spec), "key.pem")
            .expect("key path");
        let mode = std::fs::metadata(key).expect("key").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    assert_eq!(
        repo.store
            .write_certificate(&issued)
            .expect_err("duplicate")
            .kind(),
        ErrorKind::AlreadyExists
    );

    repo.store
        .move_certificate(&serial(&spec), CertificateStatus::Revoked)
        .expect("move to revoked");
    assert!(
        !repo
            .tenant
            .paths()
            .certificate_path(&serial(&spec), "pem")
            .expect("path")
            .is_file()
    );
    let moved = repo
        .store
        .get_certificate(&serial(&spec))
        .expect("get")
        .expect("exists");
    assert_eq!(moved.path, PathBuf::from("certificates/revoked/000A.pem"));

    repo.store
        .move_certificate(&serial(&spec), CertificateStatus::Expired)
        .expect("move to expired");
    assert_eq!(
        repo.store
            .get_certificate(&serial(&spec))
            .expect("get")
            .expect("exists")
            .path,
        PathBuf::from("certificates/expired/000A.pem")
    );
}

#[test]
fn certificate_rejects_pem_serial_mismatch() {
    let repo = TestRepo::new();
    let spec = CertSpec::new(10, "leaf.example.test");
    let mut issued = issued(&spec);
    issued.record.serial = Serial::new("00FF").expect("serial");
    assert_eq!(
        repo.store
            .write_certificate(&issued)
            .expect_err("mismatch")
            .kind(),
        ErrorKind::Storage
    );
}

#[test]
fn revocations_use_create_new_semantics() {
    let repo = TestRepo::new();
    let spec = CertSpec::new(10, "leaf.example.test");
    repo.store.write_certificate(&issued(&spec)).expect("write");
    let record = RevocationRecord {
        version: 1,
        serial: serial(&spec),
        authority: chainkeeper_core::AuthorityName::new("tls").expect("authority"),
        reason: RevocationReason::KeyCompromise,
        comment: Some("key lost".to_owned()),
        revoked_at: now(),
        crl_number: 1,
    };
    let path = repo.store.write_revocation(&record).expect("revoke");
    assert!(path.is_file());
    assert_eq!(
        repo.store
            .write_revocation(&record)
            .expect_err("duplicate")
            .kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(repo.store.list_revocations().expect("list"), vec![record]);
}

#[test]
fn crls_write_all_parts_and_increment_numbers() {
    let repo = TestRepo::new();
    let authority = chainkeeper_core::AuthorityName::new("tls").expect("authority");
    let record = CrlRecord {
        version: 1,
        authority: authority.clone(),
        number: 1,
        this_update: now(),
        next_update: now() + Duration::days(7),
        revoked_serials: vec![Serial::new("000A").expect("serial")],
        der_path: PathBuf::from("crls/tls.crl.der"),
        pem_path: PathBuf::from("crls/tls.crl.pem"),
    };
    let bundle = CrlBundle {
        record: record.clone(),
        der: b"der-bytes".to_vec(),
        pem: "PEM".to_owned(),
    };
    repo.store.write_crl(&bundle).expect("write crl");
    for extension in ["crl.der", "crl.pem", "yaml", "number"] {
        assert!(
            repo.tenant
                .paths()
                .crl_path(&authority, extension)
                .expect("path")
                .is_file()
        );
    }
    assert_eq!(repo.store.next_crl_number(&authority).expect("next"), 2);
    assert_eq!(repo.store.read_crl(&authority).expect("read"), Some(record));
}

#[test]
fn audit_events_use_create_new_semantics_and_list_in_order() {
    let repo = TestRepo::new();
    let first = AuditEvent {
        id: EventId::new("01J00000000000000000000001").expect("id"),
        seq: 1,
        timestamp: now(),
        action: AuditAction::CertIssued,
        object_type: "certificate".to_owned(),
        object_id: "000A".to_owned(),
        summary: "issued".to_owned(),
        actor: "tester".to_owned(),
        details: json!({"serial": "000A"}),
    };
    let second = AuditEvent {
        id: EventId::new("01J00000000000000000000002").expect("id"),
        seq: 2,
        timestamp: now(),
        action: AuditAction::CertRevoked,
        object_type: "certificate".to_owned(),
        object_id: "000A".to_owned(),
        summary: "revoked".to_owned(),
        actor: "tester".to_owned(),
        details: json!({}),
    };
    repo.store.write_audit_event(&second).expect("second");
    repo.store.write_audit_event(&first).expect("first");
    assert_eq!(
        repo.store
            .write_audit_event(&first)
            .expect_err("duplicate")
            .kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        repo.store.list_audit_events().expect("list"),
        vec![first, second]
    );
}

#[test]
fn listings_are_lexical() {
    let repo = TestRepo::new();
    for number in [0x10, 0x02, 0x0A] {
        let spec = CertSpec::new(number, &format!("leaf-{number}.example.test"));
        repo.store.write_certificate(&issued(&spec)).expect("write");
    }
    let serials: Vec<String> = repo
        .store
        .list_certificates()
        .expect("list")
        .into_iter()
        .map(|record| record.serial.to_string())
        .collect();
    assert_eq!(serials, vec!["0002", "000A", "0010"]);
}

#[test]
fn atomic_write_failure_keeps_the_old_file() {
    let repo = TestRepo::new();
    let directory = repo.tenant.paths().profiles_dir();
    let destination = directory.join("artifact.yaml");
    atomic_write(&destination, b"first", FileMode::Public).expect("first write");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
            .expect("read only");
        let result = atomic_write(&destination, b"second", FileMode::Public);
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("restore");
        if result.is_ok() {
            // Running as a privileged user ignores directory permissions.
            return;
        }
        assert_eq!(result.expect_err("write fails").kind(), ErrorKind::Storage);
    }

    assert_eq!(std::fs::read(&destination).expect("read"), b"first");
}

#[test]
fn every_write_stays_inside_the_repository() {
    let repo = TestRepo::new();
    let spec = CertSpec::new(10, "leaf.example.test");
    let mut issued = issued(&spec);
    issued.record.path = PathBuf::from("../../escape.pem");
    let written = repo.store.write_certificate(&issued).expect("write");
    assert!(written.starts_with(repo.tenant.root()));
    for record in repo.store.list_certificates().expect("list") {
        assert!(!record.path.is_absolute());
        assert!(
            !record
                .path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        );
    }
    for path in files_below(repo.tenant.root()) {
        assert!(
            path.starts_with(repo.tenant.root()),
            "{} escaped",
            path.display()
        );
    }
}
