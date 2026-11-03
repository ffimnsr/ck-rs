//! File audit log behaviour.

mod common;

use std::sync::Arc;
use std::time::Duration;

use chainkeeper_audit::FileAuditLog;
use chainkeeper_core::{AuditAction, AuditLog, AuditQuery, NewAuditEvent, RepositoryLock};
use chainkeeper_store::FileRepositoryLock;
use chainkeeper_testkit::FakeIdGenerator;
use time::macros::datetime;

#[test]
fn append_assigns_contiguous_sequence_numbers() {
    let tenant = common::tenant();
    let log = common::log(&tenant);

    let first = log
        .append(common::event(AuditAction::CertIssued, "A"))
        .expect("first append");
    let second = log
        .append(common::event(AuditAction::CertRevoked, "B"))
        .expect("second append");

    assert_eq!(first.seq, 1);
    assert_eq!(second.seq, 2);
    assert_eq!(log.next_seq().expect("next seq"), 3);
    assert!(tenant.paths().audit_event_path(&first.id).is_file());
    assert!(tenant.paths().audit_event_path(&second.id).is_file());
}

#[test]
fn details_default_to_an_empty_object() {
    let tenant = common::tenant();
    let log = common::log(&tenant);
    let stored = log
        .append(common::event(AuditAction::CertIssued, "A"))
        .expect("append");

    let path = tenant.paths().audit_event_path(&stored.id);
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).expect("readable")).expect("valid json");
    assert_eq!(value["details"], serde_json::json!({}));
}

#[test]
fn duplicate_event_ids_are_rejected() {
    let tenant = common::tenant();
    let paths = common::paths(&tenant);
    let ids = Arc::new(common::FixedIdGenerator::new("01J00000000000000000000001"));
    let log = FileAuditLog::new(
        paths,
        Arc::new(chainkeeper_testkit::FakeRepositoryLock::new()),
        ids,
    );

    log.append(common::event(AuditAction::CertIssued, "A"))
        .expect("first append");
    let error = log
        .append(common::event(AuditAction::CertIssued, "B"))
        .expect_err("duplicate id rejected");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Audit);
}

#[test]
fn concurrent_appends_stay_contiguous() {
    const WRITERS: usize = 8;

    let tenant = common::tenant();
    let paths = common::paths(&tenant);
    let lock = Arc::new(FileRepositoryLock::new(paths.clone()));
    let log = Arc::new(
        FileAuditLog::new(paths, lock, Arc::new(FakeIdGenerator::new()))
            .with_lock_timeout(Duration::from_secs(10)),
    );

    std::thread::scope(|scope| {
        for writer in 0..WRITERS {
            let log = Arc::clone(&log);
            scope.spawn(move || {
                log.append(common::event(
                    AuditAction::CertIssued,
                    &format!("S{writer}"),
                ))
                .expect("append");
            });
        }
    });

    let events = log.list(&AuditQuery::default()).expect("list");
    assert_eq!(events.len(), WRITERS);
    let sequences: Vec<u64> = events.iter().map(|event| event.seq).collect();
    assert_eq!(sequences, (1..=WRITERS as u64).collect::<Vec<_>>());
    assert_eq!(log.next_seq().expect("next seq"), WRITERS as u64 + 1);
}

#[test]
fn list_filters_and_sorts() {
    let tenant = common::tenant();
    let log = common::log(&tenant);

    let entries = [
        (
            datetime!(2024-05-01 10:00:00 UTC),
            AuditAction::CertIssued,
            "A",
        ),
        (
            datetime!(2024-05-01 11:00:00 UTC),
            AuditAction::CertIssued,
            "B",
        ),
        (
            datetime!(2024-05-01 12:00:00 UTC),
            AuditAction::CertRevoked,
            "A",
        ),
        (
            datetime!(2024-05-01 13:00:00 UTC),
            AuditAction::CrlGenerated,
            "C",
        ),
    ];
    for (timestamp, action, object_id) in entries {
        let event = NewAuditEvent::new(
            timestamp,
            action,
            "certificate",
            object_id,
            "summary",
            "tester",
        );
        log.append(event).expect("append");
    }

    let all = log.list(&AuditQuery::default()).expect("list all");
    assert_eq!(
        all.iter().map(|event| event.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );

    let by_action = log
        .list(&AuditQuery {
            action: Some(AuditAction::CertIssued),
            ..AuditQuery::default()
        })
        .expect("filter by action");
    assert_eq!(by_action.len(), 2);

    let by_object = log
        .list(&AuditQuery {
            object_id: Some("A".to_owned()),
            ..AuditQuery::default()
        })
        .expect("filter by object");
    assert_eq!(by_object.len(), 2);

    let by_type = log
        .list(&AuditQuery {
            object_type: Some("certificate".to_owned()),
            ..AuditQuery::default()
        })
        .expect("filter by type");
    assert_eq!(by_type.len(), 4);

    let by_time = log
        .list(&AuditQuery {
            since: Some(datetime!(2024-05-01 11:00:00 UTC)),
            until: Some(datetime!(2024-05-01 12:00:00 UTC)),
            ..AuditQuery::default()
        })
        .expect("filter by time");
    assert_eq!(
        by_time.iter().map(|event| event.seq).collect::<Vec<_>>(),
        vec![2, 3]
    );

    let limited = log
        .list(&AuditQuery {
            limit: Some(2),
            ..AuditQuery::default()
        })
        .expect("limit");
    assert_eq!(
        limited.iter().map(|event| event.seq).collect::<Vec<_>>(),
        vec![1, 2]
    );
}

#[test]
fn lock_timeout_is_enforced() {
    let tenant = common::tenant();
    let paths = common::paths(&tenant);
    let lock = Arc::new(FileRepositoryLock::new(paths.clone()));
    let held = lock
        .acquire_exclusive(Duration::from_millis(10))
        .expect("held");

    let log = FileAuditLog::new(paths, lock, Arc::new(FakeIdGenerator::new()))
        .with_lock_timeout(Duration::from_millis(50));
    let error = log
        .append(common::event(AuditAction::CertIssued, "A"))
        .expect_err("lock is held");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Lock);

    held.release();
}
