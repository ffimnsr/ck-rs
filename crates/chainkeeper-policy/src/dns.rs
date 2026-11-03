//! Subject alternative name value validation.

use std::net::IpAddr;

use chainkeeper_core::ChainkeeperError;

/// Longest accepted DNS name, matching the RFC 1035 presentation limit.
const MAX_DNS_NAME_LEN: usize = 253;

/// Longest accepted DNS label.
const MAX_DNS_LABEL_LEN: usize = 63;

fn invalid(field: &str, value: &str, reason: impl std::fmt::Display) -> ChainkeeperError {
    ChainkeeperError::invalid(field, value, reason)
}

/// Validates a DNS subject alternative name.
///
/// Names must use lowercase ASCII letters, digits, hyphens, and dots. Wildcards
/// are only accepted as the leftmost `*.` label, and only when `allow_wildcard`
/// is true.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] for malformed names and
/// [`ChainkeeperError::Policy`] when a wildcard is disabled.
pub fn validate_dns_name(value: &str, allow_wildcard: bool) -> Result<(), ChainkeeperError> {
    const FIELD: &str = "DNS subject alternative name";

    if value.is_empty() {
        return Err(invalid(FIELD, value, "must not be empty"));
    }
    if value.len() > MAX_DNS_NAME_LEN {
        return Err(invalid(
            FIELD,
            value,
            format!("must be at most {MAX_DNS_NAME_LEN} characters"),
        ));
    }

    let (wildcard, name) = if let Some(rest) = value.strip_prefix("*.") {
        (true, rest)
    } else {
        if value.contains('*') {
            return Err(invalid(
                FIELD,
                value,
                "wildcard is only allowed as the leftmost '*.' label",
            ));
        }
        (false, value)
    };

    if wildcard && !allow_wildcard {
        return Err(ChainkeeperError::policy(format!(
            "{FIELD} {value:?} is a wildcard but policy allow_wildcards is false"
        )));
    }
    if name.is_empty() {
        return Err(invalid(FIELD, value, "must contain a label after '*.'"));
    }

    for label in name.split('.') {
        if label.is_empty() {
            return Err(invalid(FIELD, value, "must not contain empty labels"));
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(invalid(
                FIELD,
                value,
                format!("label {label:?} exceeds {MAX_DNS_LABEL_LEN} characters"),
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(invalid(
                FIELD,
                value,
                format!("label {label:?} must use lowercase letters, digits, and hyphens"),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid(
                FIELD,
                value,
                format!("label {label:?} must not start or end with a hyphen"),
            ));
        }
    }
    Ok(())
}

/// Returns true when a DNS name is a wildcard.
#[must_use]
pub fn is_wildcard_dns(value: &str) -> bool {
    value.starts_with("*.")
}

/// Validates an email subject alternative name.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the address does not contain
/// exactly one `@` with a non-empty local part and domain.
pub fn validate_email(value: &str) -> Result<(), ChainkeeperError> {
    validate_email_field("email subject alternative name", value)
}

/// Validates an email value using an explicit field name in error messages.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the address is malformed.
pub fn validate_email_field(field: &str, value: &str) -> Result<(), ChainkeeperError> {
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(invalid(
            field,
            value,
            "must not contain whitespace or controls",
        ));
    }
    let Some((local, domain)) = value.split_once('@') else {
        return Err(invalid(field, value, "must contain exactly one '@'"));
    };
    if domain.contains('@') {
        return Err(invalid(field, value, "must contain exactly one '@'"));
    }
    if local.is_empty() {
        return Err(invalid(field, value, "must have a non-empty local part"));
    }
    if domain.is_empty() {
        return Err(invalid(field, value, "must have a non-empty domain"));
    }
    if domain.len() > MAX_DNS_NAME_LEN {
        return Err(invalid(
            field,
            value,
            format!("domain must be at most {MAX_DNS_NAME_LEN} characters"),
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(invalid(
                field,
                value,
                "domain must not contain empty labels",
            ));
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(invalid(
                field,
                value,
                format!("domain label {label:?} exceeds {MAX_DNS_LABEL_LEN} characters"),
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid(
                field,
                value,
                format!("domain label {label:?} must use letters, digits, and hyphens"),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid(
                field,
                value,
                format!("domain label {label:?} must not start or end with a hyphen"),
            ));
        }
    }
    Ok(())
}

/// Validates an IP subject alternative name.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the value is not a valid IPv4
/// or IPv6 address.
pub fn validate_ip(value: &str) -> Result<(), ChainkeeperError> {
    value.parse::<IpAddr>().map(|_| ()).map_err(|_| {
        invalid(
            "IP subject alternative name",
            value,
            "must be a valid IPv4 or IPv6 address",
        )
    })
}

/// Validates a URI subject alternative name.
///
/// Only `https`, `spiffe`, and `urn` schemes are accepted.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the URI has a disallowed
/// scheme, is missing its scheme-specific body, or contains whitespace or
/// control characters.
pub fn validate_uri(value: &str) -> Result<(), ChainkeeperError> {
    const FIELD: &str = "URI subject alternative name";

    if value
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(invalid(
            FIELD,
            value,
            "must not contain whitespace or controls",
        ));
    }
    let Some((scheme, rest)) = value.split_once(':') else {
        return Err(invalid(FIELD, value, "must contain a scheme"));
    };
    match scheme.to_ascii_lowercase().as_str() {
        "https" | "spiffe" => {
            let Some(authority) = rest.strip_prefix("//") else {
                return Err(invalid(
                    FIELD,
                    value,
                    format!("{scheme} URIs must use '//' after the scheme"),
                ));
            };
            let host = authority.split('/').next().unwrap_or_default();
            if host.is_empty() {
                return Err(invalid(FIELD, value, "must contain a host"));
            }
        }
        "urn" => {
            if rest.is_empty() {
                return Err(invalid(FIELD, value, "urn URIs must contain a name"));
            }
        }
        _ => {
            return Err(invalid(
                FIELD,
                value,
                "scheme must be one of https, spiffe, or urn",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_wildcard_dns, validate_dns_name, validate_email, validate_ip, validate_uri};

    #[test]
    fn accepts_regular_dns_names() {
        for name in ["example.com", "a.b.c", "xn--bcher-kva.example", "localhost"] {
            assert!(validate_dns_name(name, false).is_ok(), "{name}");
        }
    }

    #[test]
    fn accepts_leftmost_wildcards_only() {
        assert!(validate_dns_name("*.example.com", true).is_ok());
        assert!(validate_dns_name("*.example.com", false).is_err());
        assert!(validate_dns_name("a.*.example.com", true).is_err());
        assert!(validate_dns_name("*", true).is_err());
        assert!(is_wildcard_dns("*.example.com"));
    }

    #[test]
    fn rejects_malformed_dns_names() {
        for name in [
            "",
            "Example.com",
            "exa mple.com",
            "example..com",
            ".example.com",
            "example.com.",
            "-example.com",
            "example-.com",
            "under_score.example",
        ] {
            assert!(validate_dns_name(name, true).is_err(), "{name:?}");
        }
        let long_label = "a".repeat(64);
        assert!(validate_dns_name(&format!("{long_label}.com"), false).is_err());
        let long_name = format!("{}.com", "a".repeat(250));
        assert!(validate_dns_name(&long_name, false).is_err());
    }

    #[test]
    fn rejects_dns_boundary_overflow() {
        let label = "a".repeat(63);
        assert!(validate_dns_name(&format!("{label}.com"), false).is_ok());
        let name = std::iter::repeat_n(label, 3).collect::<Vec<_>>().join(".");
        assert!(name.len() <= 253);
        assert!(validate_dns_name(&name, false).is_ok());
    }

    #[test]
    fn validates_email_addresses() {
        for value in ["user@example.com", "a.b+c@example.co.uk", "user@localhost"] {
            assert!(validate_email(value).is_ok(), "{value}");
        }
        for value in [
            "",
            "user",
            "@example.com",
            "user@",
            "a@b@c",
            "user name@example.com",
            "user@exa mple.com",
            "user@-example.com",
        ] {
            assert!(validate_email(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn validates_ip_addresses() {
        for value in ["192.0.2.1", "2001:db8::1", "::1"] {
            assert!(validate_ip(value).is_ok(), "{value}");
        }
        for value in ["", "192.0.2", "192.0.2.1/24", "example.com"] {
            assert!(validate_ip(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn validates_uri_schemes() {
        for value in [
            "https://example.com/path",
            "spiffe://example.org/service",
            "urn:example:service",
        ] {
            assert!(validate_uri(value).is_ok(), "{value}");
        }
        for value in [
            "",
            "example.com",
            "http://example.com",
            "https://",
            "spiffe:example.org",
            "urn:",
            "https://exa mple.com",
        ] {
            assert!(validate_uri(value).is_err(), "{value:?}");
        }
    }
}
