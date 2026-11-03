//! Canonical audit JSON contract.

mod common;

use chainkeeper_audit::{from_canonical_json, to_canonical_json};
use chainkeeper_core::{AuditAction, AuditEvent, NewAuditEvent};
use serde_json::json;

const ACTIONS: [AuditAction; 12] = [
    AuditAction::RepoInitialized,
    AuditAction::RootCreated,
    AuditAction::IntermediateCreated,
    AuditAction::OcspSignerCreated,
    AuditAction::CertIssued,
    AuditAction::CertRevoked,
    AuditAction::CertReplaced,
    AuditAction::CrlGenerated,
    AuditAction::PublishCompleted,
    AuditAction::PolicyUpdated,
    AuditAction::ProfileUpdated,
    AuditAction::IndexRebuilt,
];

fn event(action: AuditAction, seq: u64) -> AuditEvent {
    let pending = NewAuditEvent::new(
        common::NOW,
        action,
        "certificate",
        "SERIAL",
        "summary",
        "tester",
    )
    .with_details(json!({"z": 1, "a": true}));
    let id = chainkeeper_core::EventId::new(format!("01J{seq:023}")).expect("valid ulid");
    AuditEvent::from_new(pending, id, seq)
}

#[test]
fn every_action_round_trips() {
    for (index, action) in ACTIONS.into_iter().enumerate() {
        let seq = u64::try_from(index).expect("fits") + 1;
        let original = event(action, seq);
        let rendered = to_canonical_json(&original).expect("serialisable");
        let parsed = from_canonical_json(rendered.as_bytes()).expect("parseable");
        assert_eq!(parsed, original);
        assert_eq!(parsed.action, action);
        assert!(rendered.ends_with('\n'));
    }
}

#[test]
fn output_has_sorted_keys_and_object_details() {
    let rendered = to_canonical_json(&event(AuditAction::CertIssued, 1)).expect("serialisable");
    let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    assert!(value["details"].is_object());

    let keys: Vec<&str> = value
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted, "{rendered}");
    assert_eq!(
        keys,
        vec![
            "action",
            "actor",
            "details",
            "id",
            "object_id",
            "object_type",
            "seq",
            "summary",
            "timestamp",
        ]
    );
}

#[test]
fn details_must_be_an_object() {
    let mut stored = event(AuditAction::CertIssued, 1);
    stored.details = json!("raw string");
    assert!(to_canonical_json(&stored).is_err());

    stored.details = json!([1, 2, 3]);
    assert!(to_canonical_json(&stored).is_err());
}

#[test]
fn unknown_fields_are_rejected() {
    let rendered = to_canonical_json(&event(AuditAction::CertIssued, 1)).expect("serialisable");
    let tampered = rendered.replacen(
        "\"summary\": \"summary\",",
        "\"summary\": \"summary\",\n  \"unexpected\": 1,",
        1,
    );
    assert!(from_canonical_json(tampered.as_bytes()).is_err());
}

#[test]
fn timestamps_must_be_utc_with_second_precision() {
    let stored = event(AuditAction::CertIssued, 1);
    let rendered = to_canonical_json(&stored).expect("serialisable");
    let offset = rendered.replace("2024-05-01T12:00:00Z", "2024-05-01T14:00:00+02:00");
    assert!(from_canonical_json(offset.as_bytes()).is_err());

    let subsecond = rendered.replace("2024-05-01T12:00:00Z", "2024-05-01T12:00:00.5Z");
    assert!(from_canonical_json(subsecond.as_bytes()).is_err());
}
