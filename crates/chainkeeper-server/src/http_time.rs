//! HTTP date formatting and parsing for conditional requests.

use time::OffsetDateTime;
use time::UtcOffset;
use time::macros::format_description;

const HTTP_DATE: &[time::format_description::FormatItem<'static>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

/// Formats a timestamp as an IMF-fixdate value.
#[must_use]
pub fn format(value: OffsetDateTime) -> String {
    value
        .to_offset(UtcOffset::UTC)
        .format(HTTP_DATE)
        .unwrap_or_default()
}

/// Parses an IMF-fixdate value, returning `None` when it is malformed.
#[must_use]
pub fn parse(value: &str) -> Option<OffsetDateTime> {
    let parsed = time::PrimitiveDateTime::parse(value.trim(), HTTP_DATE).ok()?;
    Some(parsed.assume_utc())
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{format, parse};

    #[test]
    fn formats_imf_fixdate() {
        assert_eq!(
            format(datetime!(2024-05-01 12:00:00 UTC)),
            "Wed, 01 May 2024 12:00:00 GMT"
        );
    }

    #[test]
    fn parses_imf_fixdate() {
        let value = parse("Wed, 01 May 2024 12:00:00 GMT").expect("valid date");
        assert_eq!(value, datetime!(2024-05-01 12:00:00 UTC));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("yesterday").is_none());
    }
}
