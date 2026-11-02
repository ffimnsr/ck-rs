//! Timestamp helpers.
//!
//! Every persisted timestamp is RFC 3339 UTC truncated to second precision.

use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use crate::error::ChainkeeperError;

/// Truncates a timestamp to whole seconds.
#[must_use]
pub fn truncate(value: OffsetDateTime) -> OffsetDateTime {
    value.replace_nanosecond(0).unwrap_or(value)
}

/// Renders a timestamp as RFC 3339 UTC with second precision.
#[must_use]
pub fn format_timestamp(value: OffsetDateTime) -> String {
    truncate(value)
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Parses an RFC 3339 timestamp and normalises it to UTC.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the value is not a valid
/// RFC 3339 timestamp.
pub fn parse_timestamp(value: &str) -> Result<OffsetDateTime, ChainkeeperError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|parsed| truncate(parsed).to_offset(UtcOffset::UTC))
        .map_err(|error| {
            ChainkeeperError::validation(format!("invalid RFC 3339 timestamp: {error}"))
        })
}

/// Serde adapter for required timestamps.
pub mod seconds {
    use super::{OffsetDateTime, format_timestamp};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes a timestamp as RFC 3339 UTC with second precision.
    ///
    /// # Errors
    ///
    /// Returns a serializer error when the target cannot accept a string.
    pub fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format_timestamp(*value))
    }

    /// Deserializes an RFC 3339 timestamp.
    ///
    /// # Errors
    ///
    /// Returns a deserializer error when the value is not a valid timestamp.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        super::parse_timestamp(&raw).map_err(serde::de::Error::custom)
    }
}

/// Serde adapter for optional timestamps.
pub mod seconds_option {
    use super::{OffsetDateTime, format_timestamp};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serializes an optional timestamp as RFC 3339 UTC with second precision.
    ///
    /// # Errors
    ///
    /// Returns a serializer error when the target cannot accept a string.
    pub fn serialize<S>(value: &Option<OffsetDateTime>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(timestamp) => serializer.serialize_some(&format_timestamp(*timestamp)),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes an optional RFC 3339 timestamp.
    ///
    /// # Errors
    ///
    /// Returns a deserializer error when the value is present but invalid.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = Option::<String>::deserialize(deserializer)?;
        raw.map(|value| super::parse_timestamp(&value))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{format_timestamp, parse_timestamp};

    #[test]
    fn formatting_truncates_subseconds() {
        let value = datetime!(2024-05-01 12:00:00.123456789 UTC);
        assert_eq!(format_timestamp(value), "2024-05-01T12:00:00Z");
    }

    #[test]
    fn parsing_normalises_to_utc() {
        let value = parse_timestamp("2024-05-01T14:00:00+02:00").expect("valid timestamp");
        assert_eq!(format_timestamp(value), "2024-05-01T12:00:00Z");
    }

    #[test]
    fn parsing_rejects_garbage() {
        assert!(parse_timestamp("yesterday").is_err());
    }
}
