mod common;

use std::sync::Arc;

use chainkeeper_core::{AuditAction, AuditLog as _, AuditQuery, ChainkeeperError, CrlManager as _};
use chainkeeper_testkit::FakeOperation;
use common::{Harness, MissingSigners, TestSigners, leaf_serial, other_serial, smime, tls};

fn manager(h: &Harness) -> chainkeeper_publish::FileCrlManager {
    h.crl_manager(Arc::new(TestSigners))
}

#[test]
fn first_generation_starts_at_one() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    let bundle = manager(&h)
        .update_for_authority(&authority)
        .expect("crl generated");

    assert_eq!(bundle.record.number, 1);
    assert_eq!(bundle.record.authority, authority);
    assert_eq!(bundle.record.revoked_serials.len(), 0);
    assert!(bundle.der.starts_with(b"FAKE-CRL:"));
    assert!(bundle.pem.contains("BEGIN X509 CRL"));

    let number = std::fs::read_to_string(h.paths().crl_number_path(&authority)).expect("number");
    assert_eq!(number, "1\n");
    assert!(
        h.paths()
            .crl_path(&authority, "crl.der")
            .expect("path")
            .is_file()
    );
    assert!(
        h.paths()
            .crl_path(&authority, "crl.pem")
            .expect("path")
            .is_file()
    );
    assert!(
        h.paths()
            .crl_path(&authority, "yaml")
            .expect("path")
            .is_file()
    );

    let events = h.audit.events().expect("audit events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, AuditAction::CrlGenerated);
    assert_eq!(events[0].object_id, "tls");
    assert_eq!(h.index.crl_count(), 1);
}

#[test]
fn one_revocation_appears_in_the_crl() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    let serial = leaf_serial().expect("serial");
    h.revoke(&serial, &authority).expect("revocation written");

    let bundle = manager(&h)
        .update_for_authority(&authority)
        .expect("crl generated");
    assert_eq!(bundle.record.revoked_serials, vec![serial]);
}

#[test]
fn revocations_from_another_authority_are_excluded() {
    let h = Harness::new().expect("harness");
    let tls = tls().expect("authority");
    let smime = smime().expect("authority");
    let tls_serial = leaf_serial().expect("serial");
    let smime_serial = other_serial().expect("serial");
    h.revoke(&tls_serial, &tls).expect("tls revocation");
    h.revoke(&smime_serial, &smime).expect("smime revocation");

    let bundle = manager(&h).update_for_authority(&tls).expect("crl");
    assert_eq!(bundle.record.revoked_serials, vec![tls_serial]);
}

#[test]
fn crl_number_increments_on_second_generation() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    let manager = manager(&h);

    let first = manager.update_for_authority(&authority).expect("first");
    let second = manager.update_for_authority(&authority).expect("second");

    assert_eq!(first.record.number, 1);
    assert_eq!(second.record.number, 2);
    let number = std::fs::read_to_string(h.paths().crl_number_path(&authority)).expect("number");
    assert_eq!(number, "2\n");
}

#[test]
fn corrupted_number_files_are_rejected() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    let manager = manager(&h);
    let path = h.paths().crl_number_path(&authority);

    for contents in ["0\n", "not-a-number\n", "\n"] {
        std::fs::write(&path, contents).expect("number written");
        let error = manager
            .update_for_authority(&authority)
            .expect_err("invalid number rejected");
        assert!(
            matches!(error, ChainkeeperError::Storage(_)),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn missing_signing_key_fails_without_writing_a_number() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    let manager = h.crl_manager(Arc::new(MissingSigners));

    let error = manager
        .update_for_authority(&authority)
        .expect_err("missing key rejected");
    assert!(matches!(error, ChainkeeperError::NotFound(_)));
    assert!(!h.paths().crl_number_path(&authority).exists());
    assert!(
        !h.paths()
            .crl_path(&authority, "crl.der")
            .expect("path")
            .exists()
    );
}

#[test]
fn provider_failure_fails_without_writing_a_number() {
    let h = Harness::new().expect("harness");
    let authority = tls().expect("authority");
    h.provider.inject_failure(FakeOperation::GenerateCrl);

    let error = manager(&h)
        .update_for_authority(&authority)
        .expect_err("provider failure rejected");
    assert!(matches!(error, ChainkeeperError::Crypto(_)));
    assert!(!h.paths().crl_number_path(&authority).exists());
}

#[test]
fn list_crls_reads_written_metadata() {
    let h = Harness::new().expect("harness");
    let tls = tls().expect("authority");
    let smime = smime().expect("authority");
    let manager = manager(&h);
    manager.update_for_authority(&tls).expect("tls crl");
    manager.update_for_authority(&smime).expect("smime crl");

    let records = manager.list_crls().expect("listed");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].authority, smime);
    assert_eq!(records[1].authority, tls);
    assert_eq!(records[0].number, 1);
    assert_eq!(records[1].number, 1);
}

#[test]
fn audit_query_selects_crl_events() {
    let h = Harness::new().expect("harness");
    h.seed_crl(&tls().expect("authority")).expect("crl");
    let query = AuditQuery {
        action: Some(AuditAction::CrlGenerated),
        ..AuditQuery::default()
    };
    let events = h.audit.list(&query).expect("audit");
    assert_eq!(events.len(), 1);
}
