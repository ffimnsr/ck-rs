//! Read-only JSON API.

use std::path::PathBuf;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use chainkeeper_core::{
    AuditAction, AuditEvent, AuthorityKind, AuthorityName, AuthorityRecord, CertificateRecord,
    CertificateStatus, ProfileName, Serial,
};
use time::{Duration, OffsetDateTime};

use crate::error::ApiError;
use crate::routes::{artifacts, query};
use crate::state::AppState;
use crate::views::{CertificateView, CrlView, IntermediateView, Page, RevocationView};

/// `GET /api/v1/certificates`.
///
/// # Errors
///
/// Returns a validation error for malformed filters.
pub async fn certificates(
    State(state): State<AppState>,
    Query(mut params): Query<query::Params>,
) -> Result<Json<Page<CertificateView>>, ApiError> {
    let status = query::status(&mut params)?;
    let profile = query::profile(&mut params)?;
    let authority = query::authority(&mut params)?;
    let within = query::expires_within(&mut params)?;
    let limit = query::limit(&mut params)?;
    let cursor = query::serial_cursor(&mut params)?;

    let index = state.index();
    let now = index.snapshot().generated_at;
    let deadline = within.map(|days| now + Duration::days(i64::from(days)));

    let mut items = Vec::new();
    let mut next_cursor = None;
    for record in index.certificates() {
        if !matches(
            record,
            now,
            status,
            profile.as_ref(),
            authority.as_ref(),
            deadline,
        ) {
            continue;
        }
        if cursor
            .as_ref()
            .is_some_and(|cursor| record.serial <= *cursor)
        {
            continue;
        }
        if items.len() == limit {
            next_cursor = items
                .last()
                .map(|view: &CertificateView| view.serial.to_string());
            break;
        }
        items.push(CertificateView::new(record, now));
    }
    Ok(Json(Page::new(items, next_cursor)))
}

fn matches(
    record: &CertificateRecord,
    now: OffsetDateTime,
    status: Option<CertificateStatus>,
    profile: Option<&ProfileName>,
    authority: Option<&AuthorityName>,
    deadline: Option<OffsetDateTime>,
) -> bool {
    if status.is_some_and(|status| record.status(now) != status) {
        return false;
    }
    if profile.is_some_and(|profile| record.profile != *profile) {
        return false;
    }
    if authority.is_some_and(|authority| record.authority != *authority) {
        return false;
    }
    if deadline.is_some_and(|deadline| record.expires_at > deadline) {
        return false;
    }
    true
}

/// `GET /api/v1/certificates/{serial}`.
///
/// # Errors
///
/// Returns a 400 for an invalid serial and 404 when it is unknown.
pub async fn certificate(
    State(state): State<AppState>,
    Path(serial): Path<String>,
) -> Result<Json<CertificateView>, ApiError> {
    let serial = Serial::new(serial).map_err(|error| ApiError::validation(error.to_string()))?;
    let index = state.index();
    let now = index.snapshot().generated_at;
    let record = index
        .certificate(&serial)
        .ok_or_else(|| ApiError::not_found("certificate not found"))?;
    Ok(Json(CertificateView::new(record, now)))
}

/// `GET /api/v1/root`.
///
/// # Errors
///
/// Returns a 404 when the root certificate is not published.
pub async fn root(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    artifacts::serve(&state, std::path::Path::new("root.pem"), &headers)
}

/// `GET /api/v1/intermediates`.
///
/// # Errors
///
/// Never fails; certificate parsing falls back to configured validity.
pub async fn intermediates(State(state): State<AppState>) -> Json<Vec<IntermediateView>> {
    let index = state.index();
    let snapshot = index.snapshot();
    let mut views = Vec::new();
    for record in snapshot
        .authorities
        .iter()
        .filter(|record| record.kind == AuthorityKind::Intermediate)
    {
        let (not_before, not_after) = authority_validity(&state, record);
        views.push(IntermediateView::new(record, not_before, not_after));
    }
    views.sort_by(|left, right| left.name.cmp(&right.name));
    Json(views)
}

fn authority_validity(
    state: &AppState,
    record: &AuthorityRecord,
) -> (OffsetDateTime, OffsetDateTime) {
    let relative = PathBuf::from(format!("aia/{}.pem", record.name.as_str()));
    let path = state.publish_dir().join(&relative);
    if let Ok(pem) = std::fs::read_to_string(&path)
        && let Ok(parsed) = chainkeeper_store::parse_certificate_pem(&pem, &path)
    {
        return (parsed.not_before, parsed.not_after);
    }
    let not_after = record.created_at + Duration::days(i64::from(record.validity_days));
    (record.created_at, not_after)
}

/// `GET /api/v1/revocations`.
///
/// # Errors
///
/// Never fails.
pub async fn revocations(State(state): State<AppState>) -> Json<Vec<RevocationView>> {
    let index = state.index();
    let mut views: Vec<RevocationView> = index
        .snapshot()
        .revocations
        .iter()
        .map(RevocationView::from)
        .collect();
    views.sort_by(|left, right| left.serial.cmp(&right.serial));
    Json(views)
}

/// `GET /api/v1/crls`.
///
/// # Errors
///
/// Never fails.
pub async fn crls(State(state): State<AppState>) -> Json<Vec<CrlView>> {
    let index = state.index();
    let mut views: Vec<CrlView> = index.snapshot().crls.iter().map(CrlView::from).collect();
    views.sort_by(|left, right| left.authority.cmp(&right.authority));
    Json(views)
}

/// `GET /api/v1/audit`.
///
/// # Errors
///
/// Returns a validation error for malformed filters.
pub async fn audit(
    State(state): State<AppState>,
    Query(mut params): Query<query::Params>,
) -> Result<Json<Page<AuditEvent>>, ApiError> {
    let action = params
        .remove("action")
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_action(value.trim()))
        .transpose()?;
    let object_type = query::text(&mut params, "object_type");
    let object_id = query::text(&mut params, "object_id");
    let since = query::timestamp(&mut params, "since")?;
    let until = query::timestamp(&mut params, "until")?;
    let limit = query::limit(&mut params)?;
    let cursor = query::event_cursor(&mut params)?;

    let mut items = Vec::new();
    let mut next_cursor = None;
    for event in &state.index().snapshot().audit_events {
        if !audit_matches(
            event,
            action,
            object_type.as_deref(),
            object_id.as_deref(),
            since,
            until,
        ) {
            continue;
        }
        if cursor.as_ref().is_some_and(|cursor| event.id <= *cursor) {
            continue;
        }
        if items.len() == limit {
            next_cursor = items.last().map(|event: &AuditEvent| event.id.to_string());
            break;
        }
        items.push(event.clone());
    }
    Ok(Json(Page::new(items, next_cursor)))
}

fn audit_matches(
    event: &AuditEvent,
    action: Option<AuditAction>,
    object_type: Option<&str>,
    object_id: Option<&str>,
    since: Option<OffsetDateTime>,
    until: Option<OffsetDateTime>,
) -> bool {
    if action.is_some_and(|action| event.action != action) {
        return false;
    }
    if object_type.is_some_and(|object_type| event.object_type != object_type) {
        return false;
    }
    if object_id.is_some_and(|object_id| event.object_id != object_id) {
        return false;
    }
    if since.is_some_and(|since| event.timestamp < since) {
        return false;
    }
    if until.is_some_and(|until| event.timestamp > until) {
        return false;
    }
    true
}

fn parse_action(value: &str) -> Result<AuditAction, ApiError> {
    let action = match value {
        "REPO_INITIALIZED" => AuditAction::RepoInitialized,
        "ROOT_CREATED" => AuditAction::RootCreated,
        "INTERMEDIATE_CREATED" => AuditAction::IntermediateCreated,
        "OCSP_SIGNER_CREATED" => AuditAction::OcspSignerCreated,
        "CERT_ISSUED" => AuditAction::CertIssued,
        "CERT_REVOKED" => AuditAction::CertRevoked,
        "CERT_REPLACED" => AuditAction::CertReplaced,
        "CRL_GENERATED" => AuditAction::CrlGenerated,
        "PUBLISH_COMPLETED" => AuditAction::PublishCompleted,
        "POLICY_UPDATED" => AuditAction::PolicyUpdated,
        "PROFILE_UPDATED" => AuditAction::ProfileUpdated,
        "INDEX_REBUILT" => AuditAction::IndexRebuilt,
        _ => return Err(ApiError::validation("unknown audit action")),
    };
    Ok(action)
}

/// `GET /api/v1/health`.
///
/// # Errors
///
/// Never fails.
pub async fn health(State(state): State<AppState>) -> Json<chainkeeper_core::ServerHealth> {
    Json(state.health())
}

#[cfg(test)]
mod tests {
    use super::{audit_matches, parse_action};
    use chainkeeper_core::{AuditAction, AuditEvent, EventId};
    use time::macros::datetime;

    #[test]
    fn audit_actions_parse() {
        assert_eq!(
            parse_action("CERT_ISSUED").expect("action"),
            AuditAction::CertIssued
        );
        assert!(parse_action("cert-issued").is_err());
    }

    #[test]
    fn audit_filters_apply() {
        let event = AuditEvent {
            id: EventId::new("01J00000000000000000000000").expect("id"),
            seq: 1,
            timestamp: datetime!(2024-05-01 12:00:00 UTC),
            action: AuditAction::CertIssued,
            object_type: "certificate".to_owned(),
            object_id: "AA".to_owned(),
            summary: "issued".to_owned(),
            actor: "ck".to_owned(),
            details: serde_json::Value::Null,
        };
        assert!(audit_matches(
            &event,
            Some(AuditAction::CertIssued),
            Some("certificate"),
            Some("AA"),
            None,
            None
        ));
        assert!(!audit_matches(
            &event,
            Some(AuditAction::CertRevoked),
            None,
            None,
            None,
            None
        ));
        assert!(!audit_matches(
            &event,
            None,
            Some("authority"),
            None,
            None,
            None
        ));
    }

    #[test]
    fn event_ids_order_lexically() {
        let first = EventId::new("01J00000000000000000000000").expect("id");
        let second = EventId::new("01J00000000000000000000001").expect("id");
        assert!(first < second);
    }
}
