//! Shared rendering helpers.

use chainkeeper_core::{CertificateStatus, ChainkeeperError};
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::CliError;

/// Serialises a report for [`crate::ui::Ui::json`].
///
/// # Errors
///
/// Returns [`CliError::Operation`] when the report is not serialisable.
pub fn json_value<T: Serialize>(value: &T) -> Result<Value, CliError> {
    serde_json::to_value(value)
        .map_err(|error| CliError::Operation(ChainkeeperError::io_error(error.to_string())))
}

/// RFC 3339 rendering used in human output.
#[must_use]
pub fn time_text(value: OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .unwrap_or_else(|_| value.unix_timestamp().to_string())
}

/// Stable string form of a serialisable enum.
#[must_use]
pub fn enum_text<T: Serialize + std::fmt::Debug>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{value:?}"))
}

/// Certificate status label.
#[must_use]
pub const fn status_label(status: CertificateStatus) -> &'static str {
    status.as_str()
}

/// Calculates a SHA-256 certificate fingerprint.
#[must_use]
pub fn fingerprint(pem: &str) -> Option<String> {
    use std::fmt::Write as _;

    let certificate = X509::from_pem(pem.as_bytes()).ok()?;
    let digest = certificate.digest(MessageDigest::sha256()).ok()?;
    let mut rendered = String::with_capacity(digest.len() * 3);
    for (index, byte) in digest.iter().enumerate() {
        if index > 0 {
            rendered.push(':');
        }
        let _ = write!(rendered, "{byte:02X}");
    }
    Some(rendered)
}

#[cfg(test)]
mod tests {
    use super::time_text;
    use time::macros::datetime;

    #[test]
    fn timestamps_render_as_rfc3339() {
        assert_eq!(
            time_text(datetime!(2024-05-01 12:00:00 UTC)),
            "2024-05-01T12:00:00Z"
        );
    }
}
