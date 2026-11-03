//! Audit log verification.

mod common;

use chainkeeper_audit::{AUDIT_DUPLICATE, AUDIT_INVALID, AUDIT_SEQ_GAP, FileAuditLog};
use chainkeeper_core::{AuditAction, AuditLog};
use std::path::PathBuf;

fn seed() -> (chainkeeper_testkit::TempTenant, FileAuditLog) {
    let tenant = common::tenant();
    let log = common::log(&tenant);
    for index in 1..=4 {
        log.append(common::event(AuditAction::CertIssued, &format!("S{index}")))
            .expect("append");
    }
    (tenant, log)
}

fn event_files(tenant: &chainkeeper_testkit::TempTenant) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(tenant.paths().audit_events_dir())
        .expect("audit dir")
        .map(|entry| entry.expect("entry").path())
        .collect();
    paths.sort();
    paths
}

#[test]
fn clean_log_has_no_findings() {
    let (_tenant, log) = seed();
    assert_eq!(log.verify().expect("verify"), Vec::new());
}

#[test]
fn edited_sequence_is_detected() {
    let (tenant, log) = seed();
    let second = event_files(&tenant)[1].clone();
    let bytes = std::fs::read(&second).expect("readable");
    let text = String::from_utf8(bytes).expect("utf8");
    let tampered = text.replace("\"seq\": 2,", "\"seq\": 4,");
    assert_ne!(text, tampered);
    std::fs::write(&second, tampered).expect("writable");

    let findings = log.verify().expect("verify");
    let codes: Vec<&str> = findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    assert!(codes.contains(&AUDIT_DUPLICATE), "{findings:?}");
    assert!(codes.contains(&AUDIT_SEQ_GAP), "{findings:?}");
}

#[test]
fn deleted_event_is_detected() {
    let (tenant, log) = seed();
    std::fs::remove_file(&event_files(&tenant)[1]).expect("remove");

    let findings = log.verify().expect("verify");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].code, AUDIT_SEQ_GAP);
    assert_eq!(findings[0].object_id.as_deref(), Some("2"));
}

#[test]
fn unparseable_file_is_detected() {
    let tenant = common::tenant();
    let log = common::log(&tenant);
    std::fs::create_dir_all(tenant.paths().audit_events_dir()).expect("audit dir");
    let path = tenant
        .paths()
        .audit_events_dir()
        .join("01J00000000000000000000009.json");
    std::fs::write(&path, b"not json").expect("write");

    let findings = log.verify().expect("verify");
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].code, AUDIT_INVALID);
}

#[test]
fn mismatched_file_name_is_detected() {
    let (tenant, log) = seed();
    let first = event_files(&tenant)[0].clone();
    let copy = first.with_file_name("01J00000000000000000000099.json");
    std::fs::copy(&first, &copy).expect("copy");

    let findings = log.verify().expect("verify");
    let codes: Vec<&str> = findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    assert!(codes.contains(&AUDIT_INVALID), "{findings:?}");
    assert!(codes.contains(&AUDIT_DUPLICATE), "{findings:?}");
}

#[test]
fn non_ulid_file_name_is_detected() {
    let tenant = common::tenant();
    let log = common::log(&tenant);
    std::fs::create_dir_all(tenant.paths().audit_events_dir()).expect("audit dir");
    std::fs::write(tenant.paths().audit_events_dir().join("notes.json"), b"{}").expect("write");

    let findings = log.verify().expect("verify");
    assert!(
        findings.iter().any(|finding| finding.code == AUDIT_INVALID),
        "{findings:?}"
    );
}
