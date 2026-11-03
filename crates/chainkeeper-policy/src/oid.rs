//! Dotted numeric object identifier validation.

use std::fmt;

use chainkeeper_core::ChainkeeperError;

/// Object identifiers reserved for extensions Chainkeeper manages itself.
///
/// Custom extensions may not override these; the issuer decides their content.
pub const RESERVED_OIDS: [&str; 8] = [
    "2.5.29.17",         // subjectAltName
    "2.5.29.19",         // basicConstraints
    "2.5.29.15",         // keyUsage
    "2.5.29.37",         // extKeyUsage
    "2.5.29.14",         // subjectKeyIdentifier
    "2.5.29.35",         // authorityKeyIdentifier
    "2.5.29.31",         // cRLDistributionPoints
    "1.3.6.1.5.5.7.1.1", // authorityInfoAccess
];

fn invalid_oid(value: &str, reason: impl fmt::Display) -> ChainkeeperError {
    ChainkeeperError::invalid("custom extension OID", value, reason)
}

/// Validated dotted numeric object identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid {
    value: String,
}

impl Oid {
    /// Parses and validates a dotted numeric OID.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Validation`] when the value has fewer than
    /// two arcs, contains non-digit characters, has a leading zero, or breaks
    /// the first/second arc constraints.
    pub fn parse(value: &str) -> Result<Self, ChainkeeperError> {
        validate_syntax(value)?;
        Ok(Self {
            value: value.to_owned(),
        })
    }

    /// Borrowed dotted numeric value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Iterator over the arcs of the OID.
    pub fn arcs(&self) -> impl Iterator<Item = &str> {
        self.value.split('.')
    }

    /// Returns true when the OID is reserved for an issuer-managed extension.
    #[must_use]
    pub fn is_reserved(&self) -> bool {
        RESERVED_OIDS.contains(&self.value.as_str())
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

fn validate_syntax(value: &str) -> Result<(), ChainkeeperError> {
    let arcs: Vec<&str> = value.split('.').collect();
    if arcs.len() < 2 {
        return Err(invalid_oid(value, "must contain at least two arcs"));
    }
    for arc in &arcs {
        if arc.is_empty() {
            return Err(invalid_oid(value, "arcs must not be empty"));
        }
        if !arc.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid_oid(value, "arcs must contain digits only"));
        }
        if arc.len() > 1 && arc.starts_with('0') {
            return Err(invalid_oid(
                value,
                format!("arc {arc} must not have a leading zero"),
            ));
        }
    }
    let first: u64 = arcs[0]
        .parse()
        .map_err(|_| invalid_oid(value, format!("arc {} is too large", arcs[0])))?;
    let second: u64 = arcs[1]
        .parse()
        .map_err(|_| invalid_oid(value, format!("arc {} is too large", arcs[1])))?;
    if first > 2 {
        return Err(invalid_oid(
            value,
            format!("first arc {first} must be 0, 1, or 2"),
        ));
    }
    if first < 2 && second > 39 {
        return Err(invalid_oid(
            value,
            format!("second arc {second} must be at most 39 when the first arc is {first}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Oid, RESERVED_OIDS};

    #[test]
    fn accepts_valid_oids() {
        for oid in ["1.2.3.4", "0.0", "2.999.1", "1.3.6.1.5.5.7.1.24"] {
            assert!(Oid::parse(oid).is_ok(), "{oid}");
        }
    }

    #[test]
    fn rejects_invalid_oids() {
        for oid in [
            "", "1", "1.", ".1.2", "1..2", "1.2.a", "01.2", "1.02", "3.1", "1.40",
        ] {
            assert!(Oid::parse(oid).is_err(), "{oid}");
        }
    }

    #[test]
    fn detects_reserved_oids() {
        for oid in RESERVED_OIDS {
            let parsed = Oid::parse(oid).expect("reserved OID is syntactically valid");
            assert!(parsed.is_reserved(), "{oid}");
        }
        assert!(!Oid::parse("1.2.3.4").expect("valid").is_reserved());
    }

    #[test]
    fn rendering_round_trips() {
        let oid = Oid::parse("1.3.6.1.4.1.311.21.10").expect("valid");
        assert_eq!(oid.to_string(), "1.3.6.1.4.1.311.21.10");
        assert_eq!(oid.arcs().count(), 9);
    }
}
