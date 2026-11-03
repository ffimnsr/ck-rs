//! Canonical JSON for immutable audit event files.
//!
//! A stored event is pretty-printed JSON with alphabetically sorted object
//! keys and a trailing newline. Timestamps must be UTC at second precision, and
//! `details` must be a JSON object so downstream consumers never have to handle
//! ad-hoc scalar payloads.

use chainkeeper_core::time_util;
use chainkeeper_core::{AuditEvent, ChainkeeperError, EventId};
use serde::Deserialize;
use time::OffsetDateTime;
use time::UtcOffset;
use time::format_description::well_known::Rfc3339;

use chainkeeper_core::AuditAction;

/// Wire shape used for reads. `deny_unknown_fields` keeps the on-disk schema
/// closed: a new field can only be added together with a contract change.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    id: EventId,
    seq: u64,
    timestamp: String,
    action: AuditAction,
    object_type: String,
    object_id: String,
    summary: String,
    actor: String,
    details: serde_json::Value,
}

fn audit(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::audit(message)
}

fn require_utc(timestamp: OffsetDateTime) -> Result<OffsetDateTime, ChainkeeperError> {
    if timestamp.offset() != UtcOffset::UTC {
        return Err(audit(format!(
            "audit timestamp must be UTC, found {timestamp}"
        )));
    }
    if timestamp.nanosecond() != 0 {
        return Err(audit(format!(
            "audit timestamp must have second precision, found {timestamp}"
        )));
    }
    Ok(time_util::truncate(timestamp))
}

fn require_object_details(details: &serde_json::Value) -> Result<(), ChainkeeperError> {
    if details.is_object() {
        Ok(())
    } else {
        Err(audit(
            "audit event details must be a JSON object, not a scalar or array",
        ))
    }
}

/// Renders an event as canonical JSON with sorted keys and a trailing newline.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Audit`] when the timestamp is not UTC at second
/// precision, when `details` is not a JSON object, or when serialization fails.
pub fn to_canonical_json(event: &AuditEvent) -> Result<String, ChainkeeperError> {
    require_utc(event.timestamp)?;
    require_object_details(&event.details)?;

    // `serde_json::Map` uses a sorted map by default, so converting the struct
    // to a `Value` reorders keys alphabetically at every nesting level.
    let value = serde_json::to_value(event).map_err(|error| {
        audit(format!(
            "could not serialize audit event {}: {error}",
            event.id
        ))
    })?;
    let mut rendered = serde_json::to_string_pretty(&value).map_err(|error| {
        audit(format!(
            "could not render audit event {}: {error}",
            event.id
        ))
    })?;
    rendered.push('\n');
    Ok(rendered)
}

/// Parses a canonical event file.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Audit`] when the bytes are not valid JSON, carry
/// unknown fields, use a non-UTC or sub-second timestamp, or store `details` as
/// something other than a JSON object.
pub fn from_canonical_json(bytes: &[u8]) -> Result<AuditEvent, ChainkeeperError> {
    let wire: WireEvent = serde_json::from_slice(bytes)
        .map_err(|error| audit(format!("could not parse audit event: {error}")))?;
    let timestamp = OffsetDateTime::parse(&wire.timestamp, &Rfc3339).map_err(|error| {
        audit(format!(
            "invalid audit timestamp {:?}: {error}",
            wire.timestamp
        ))
    })?;
    let timestamp = require_utc(timestamp)?;
    require_object_details(&wire.details)?;

    Ok(AuditEvent {
        id: wire.id,
        seq: wire.seq,
        timestamp,
        action: wire.action,
        object_type: wire.object_type,
        object_id: wire.object_id,
        summary: wire.summary,
        actor: wire.actor,
        details: wire.details,
    })
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::ids::EventId;
    use chainkeeper_core::{AuditAction, AuditEvent, NewAuditEvent};
    use serde_json::json;
    use time::macros::datetime;

    use super::{from_canonical_json, to_canonical_json};

    fn event() -> AuditEvent {
        let id = EventId::new("01J00000000000000000000001").expect("valid ulid");
        AuditEvent::from_new(
            NewAuditEvent::new(
                datetime!(2024-05-01 12:00:00 UTC),
                AuditAction::RepoInitialized,
                "tenant",
                "acme",
                "initialised",
                "cli",
            )
            .with_details(json!({"b": 1, "a": 2})),
            id,
            1,
        )
    }

    #[test]
    fn keys_are_sorted_and_newline_terminated() {
        let rendered = to_canonical_json(&event()).expect("serialisable");
        assert!(rendered.ends_with("}\n"));
        let action = rendered.find("\"action\"").expect("action key");
        let actor = rendered.find("\"actor\"").expect("actor key");
        let id = rendered.find("\"id\"").expect("id key");
        assert!(action < actor && actor < id, "{rendered}");
        // Nested details objects are sorted too.
        assert!(rendered.contains("\"a\": 2,\n    \"b\": 1"), "{rendered}");
    }

    #[test]
    fn round_trips() {
        let original = event();
        let rendered = to_canonical_json(&original).expect("serialisable");
        assert_eq!(
            from_canonical_json(rendered.as_bytes()).expect("parsed"),
            original
        );
    }

    #[test]
    fn non_utc_timestamps_are_rejected() {
        let mut event = event();
        event.timestamp = datetime!(2024-05-01 14:00:00 +02:00);
        let error = to_canonical_json(&event).expect_err("non-utc rejected");
        assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Audit);
    }

    #[test]
    fn scalar_details_are_rejected() {
        let mut event = event();
        event.details = json!("raw string");
        assert!(to_canonical_json(&event).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let rendered = to_canonical_json(&event()).expect("serialisable");
        let tampered = rendered.replacen("\"seq\": 1,", "\"seq\": 1,\n  \"extra\": true,", 1);
        let error = from_canonical_json(tampered.as_bytes()).expect_err("unknown field rejected");
        assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Audit);
    }

    #[test]
    fn non_utc_timestamps_are_rejected_on_read() {
        let rendered = to_canonical_json(&event()).expect("serialisable");
        let tampered = rendered.replace("2024-05-01T12:00:00Z", "2024-05-01T14:00:00+02:00");
        assert!(from_canonical_json(tampered.as_bytes()).is_err());
    }
}
