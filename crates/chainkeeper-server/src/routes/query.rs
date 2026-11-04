//! Query string parsing shared by API routes.

use std::collections::BTreeMap;

use chainkeeper_core::{
    AuthorityName, CertificateStatus, EventId, ProfileName, Serial, time_util::parse_timestamp,
};
use time::OffsetDateTime;

use crate::error::ApiError;

/// Raw query parameters.
pub type Params = BTreeMap<String, String>;

/// Default page size.
pub const DEFAULT_LIMIT: usize = 50;
/// Largest accepted page size.
pub const MAX_LIMIT: usize = 500;

fn take(params: &mut Params, key: &str) -> Option<String> {
    params
        .remove(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// Removes and parses `limit`.
///
/// # Errors
///
/// Returns a validation error when the value is not a positive integer or
/// exceeds [`MAX_LIMIT`].
pub fn limit(params: &mut Params) -> Result<usize, ApiError> {
    let Some(value) = take(params, "limit") else {
        return Ok(DEFAULT_LIMIT);
    };
    let parsed = value
        .parse::<usize>()
        .map_err(|_| ApiError::validation("limit must be a positive integer"))?;
    if parsed == 0 || parsed > MAX_LIMIT {
        return Err(ApiError::validation(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    Ok(parsed)
}

/// Removes and parses `status`.
///
/// # Errors
///
/// Returns a validation error for an unknown status.
pub fn status(params: &mut Params) -> Result<Option<CertificateStatus>, ApiError> {
    let Some(value) = take(params, "status") else {
        return Ok(None);
    };
    match value.as_str() {
        "active" => Ok(Some(CertificateStatus::Active)),
        "revoked" => Ok(Some(CertificateStatus::Revoked)),
        "expired" => Ok(Some(CertificateStatus::Expired)),
        _ => Err(ApiError::validation(
            "status must be active, revoked, or expired",
        )),
    }
}

/// Removes and parses `profile`.
///
/// # Errors
///
/// Returns a validation error for an invalid profile name.
pub fn profile(params: &mut Params) -> Result<Option<ProfileName>, ApiError> {
    take(params, "profile")
        .map(|value| {
            ProfileName::new(value).map_err(|error| ApiError::validation(error.to_string()))
        })
        .transpose()
}

/// Removes and parses `authority`.
///
/// # Errors
///
/// Returns a validation error for an invalid authority name.
pub fn authority(params: &mut Params) -> Result<Option<AuthorityName>, ApiError> {
    take(params, "authority")
        .map(|value| {
            AuthorityName::new(value).map_err(|error| ApiError::validation(error.to_string()))
        })
        .transpose()
}

/// Removes and parses `expires_within` in days.
///
/// # Errors
///
/// Returns a validation error when the value is not an unsigned integer.
pub fn expires_within(params: &mut Params) -> Result<Option<u32>, ApiError> {
    take(params, "expires_within")
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| ApiError::validation("expires_within must be a number of days"))
        })
        .transpose()
}

/// Removes and parses `cursor` as a certificate serial.
///
/// # Errors
///
/// Returns a validation error for an invalid serial.
pub fn serial_cursor(params: &mut Params) -> Result<Option<Serial>, ApiError> {
    take(params, "cursor")
        .map(|value| Serial::new(value).map_err(|error| ApiError::validation(error.to_string())))
        .transpose()
}

/// Removes and parses `cursor` as an audit event id.
///
/// # Errors
///
/// Returns a validation error for an invalid event id.
pub fn event_cursor(params: &mut Params) -> Result<Option<EventId>, ApiError> {
    take(params, "cursor")
        .map(|value| EventId::new(value).map_err(|error| ApiError::validation(error.to_string())))
        .transpose()
}

/// Removes and parses an RFC 3339 timestamp parameter.
///
/// # Errors
///
/// Returns a validation error for an invalid timestamp.
pub fn timestamp(params: &mut Params, key: &str) -> Result<Option<OffsetDateTime>, ApiError> {
    take(params, key)
        .map(|value| {
            parse_timestamp(&value).map_err(|error| ApiError::validation(error.to_string()))
        })
        .transpose()
}

/// Removes a free-form parameter.
pub fn text(params: &mut Params, key: &str) -> Option<String> {
    take(params, key)
}

#[cfg(test)]
mod tests {
    use super::{Params, limit, status};
    use chainkeeper_core::CertificateStatus;

    fn params(pairs: &[(&str, &str)]) -> Params {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn limit_defaults_and_rejects_invalid_values() {
        assert_eq!(limit(&mut params(&[])).expect("default"), 50);
        assert_eq!(limit(&mut params(&[("limit", "10")])).expect("limit"), 10);
        assert!(limit(&mut params(&[("limit", "0")])).is_err());
        assert!(limit(&mut params(&[("limit", "many")])).is_err());
        assert!(limit(&mut params(&[("limit", "1000")])).is_err());
    }

    #[test]
    fn status_accepts_known_values() {
        assert_eq!(
            status(&mut params(&[("status", "revoked")])).expect("status"),
            Some(CertificateStatus::Revoked)
        );
        let error = status(&mut params(&[("status", "lost")])).expect_err("invalid");
        assert_eq!(error.status().as_u16(), 400);
    }
}
