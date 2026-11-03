//! Certificate status lookup for OCSP responses.

use std::collections::HashMap;

use chainkeeper_core::{AuthorityName, CertificateRecord, CertificateStatus, RevocationReason};
use time::OffsetDateTime;

use crate::util::serial_value;

/// Status reported for one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusValue {
    /// Active and not revoked.
    Good,
    /// Revoked with its latest revocation metadata.
    Revoked {
        at: OffsetDateTime,
        reason: Option<RevocationReason>,
    },
    /// Expired, unknown, or issued by another authority.
    Unknown,
}

/// Serial-to-status map keyed by issuer and numeric serial.
#[derive(Debug, Default)]
pub struct StatusMap {
    entries: HashMap<(AuthorityName, u128), StatusValue>,
}

impl StatusMap {
    pub fn build(now: OffsetDateTime, records: Vec<CertificateRecord>) -> Self {
        let mut entries = HashMap::with_capacity(records.len());
        for record in records {
            let Some(serial) = serial_value(&record.serial) else {
                continue;
            };
            let status = match record.status(now) {
                CertificateStatus::Active => StatusValue::Good,
                CertificateStatus::Revoked => StatusValue::Revoked {
                    at: record.revoked_at.unwrap_or(now),
                    reason: record.revocation_reason,
                },
                _ => StatusValue::Unknown,
            };
            entries.insert((record.authority.clone(), serial), status);
        }
        Self { entries }
    }

    pub fn get(&self, authority: &AuthorityName, serial: u128) -> StatusValue {
        self.entries
            .get(&(authority.clone(), serial))
            .cloned()
            .unwrap_or(StatusValue::Unknown)
    }
}
