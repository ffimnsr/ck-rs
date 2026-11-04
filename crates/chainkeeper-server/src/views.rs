//! JSON response shapes.

use chainkeeper_core::{
    AuthorityKind, AuthorityName, AuthorityRecord, CertificateRecord, CertificateStatus, CrlRecord,
    KeyAlgorithm, ProfileName, RevocationReason, RevocationRecord, Serial, SubjectName,
};
use serde::Serialize;
use time::OffsetDateTime;

/// Paginated list responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Page<T> {
    /// Page items.
    pub items: Vec<T>,
    /// Cursor for the next page, absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// Builds a page.
    #[must_use]
    pub const fn new(items: Vec<T>, next_cursor: Option<String>) -> Self {
        Self { items, next_cursor }
    }
}

/// One certificate returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertificateView {
    /// Certificate serial.
    pub serial: Serial,
    /// Subject distinguished name.
    pub subject: SubjectName,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Profile used for issuance.
    pub profile: ProfileName,
    /// Issuing authority.
    pub authority: AuthorityName,
    /// Leaf key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Lifecycle status.
    pub status: CertificateStatus,
    /// Subject alternative names.
    pub sans: Vec<chainkeeper_core::San>,
    /// Extended key usages.
    pub ekus: Vec<chainkeeper_core::ExtendedKeyUsage>,
    /// Key usages.
    pub key_usages: Vec<chainkeeper_core::KeyUsage>,
    /// Issuance time.
    #[serde(with = "chainkeeper_core::time_util::seconds")]
    pub issued_at: OffsetDateTime,
    /// Expiry time.
    #[serde(with = "chainkeeper_core::time_util::seconds")]
    pub expires_at: OffsetDateTime,
    /// Revocation time, if revoked.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "chainkeeper_core::time_util::seconds_option"
    )]
    pub revoked_at: Option<OffsetDateTime>,
    /// Revocation reason, if revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<RevocationReason>,
    /// Serial this certificate replaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<Serial>,
    /// URL of the published certificate chain.
    pub pem_url: String,
}

impl CertificateView {
    /// Builds a view from a stored record.
    #[must_use]
    pub fn new(record: &CertificateRecord, now: OffsetDateTime) -> Self {
        Self {
            serial: record.serial.clone(),
            subject: record.subject.clone(),
            issuer: record.issuer.clone(),
            profile: record.profile.clone(),
            authority: record.authority.clone(),
            algorithm: record.algorithm,
            status: record.status(now),
            sans: record.sans.clone(),
            ekus: record.ekus.clone(),
            key_usages: record.key_usages.clone(),
            issued_at: record.issued_at,
            expires_at: record.expires_at,
            revoked_at: record.revoked_at,
            revocation_reason: record.revocation_reason,
            replaces: record.replaces.clone(),
            pem_url: format!(
                "/chains/{}/{}.pem",
                record.profile.as_str(),
                record.serial.as_str()
            ),
        }
    }
}

/// One intermediate returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntermediateView {
    /// Authority name.
    pub name: AuthorityName,
    /// Authority kind.
    pub kind: AuthorityKind,
    /// Parent authority name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<AuthorityName>,
    /// Authority key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Certificate `notBefore`.
    #[serde(with = "chainkeeper_core::time_util::seconds")]
    pub not_before: OffsetDateTime,
    /// Certificate `notAfter`.
    #[serde(with = "chainkeeper_core::time_util::seconds")]
    pub not_after: OffsetDateTime,
    /// URL of the published certificate.
    pub pem_url: String,
}

impl IntermediateView {
    /// Builds a view from a stored authority record.
    #[must_use]
    pub fn new(
        record: &AuthorityRecord,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> Self {
        Self {
            name: record.name.clone(),
            kind: record.kind,
            parent: record.parent.clone(),
            algorithm: record.algorithm,
            not_before,
            not_after,
            pem_url: format!("/aia/{}.pem", record.name.as_str()),
        }
    }
}

/// One revocation returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevocationView {
    /// Revoked serial.
    pub serial: Serial,
    /// Issuing authority.
    pub authority: AuthorityName,
    /// Revocation reason.
    pub reason: RevocationReason,
    /// Operator comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Revocation time.
    #[serde(with = "chainkeeper_core::time_util::seconds")]
    pub revoked_at: OffsetDateTime,
    /// CRL number that first contained the revocation.
    pub crl_number: u64,
}

impl From<&RevocationRecord> for RevocationView {
    fn from(record: &RevocationRecord) -> Self {
        Self {
            serial: record.serial.clone(),
            authority: record.authority.clone(),
            reason: record.reason,
            comment: record.comment.clone(),
            revoked_at: record.revoked_at,
            crl_number: record.crl_number,
        }
    }
}

/// One CRL returned by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrlView {
    /// Authority that signed the CRL.
    pub authority: AuthorityName,
    /// Monotonic CRL number.
    pub number: u64,
    /// This update time.
    #[serde(with = "chainkeeper_core::time_util::seconds")]
    pub this_update: OffsetDateTime,
    /// Next update time.
    #[serde(with = "chainkeeper_core::time_util::seconds")]
    pub next_update: OffsetDateTime,
    /// Number of revoked serials.
    pub revoked_count: usize,
    /// URL of the DER encoded CRL.
    pub url: String,
}

impl From<&CrlRecord> for CrlView {
    fn from(record: &CrlRecord) -> Self {
        Self {
            authority: record.authority.clone(),
            number: record.number,
            this_update: record.this_update,
            next_update: record.next_update,
            revoked_count: record.revoked_serials.len(),
            url: format!("/crl/{}.crl", record.authority.as_str()),
        }
    }
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::{
        AuthorityName, CertificateStatus, KeyAlgorithm, ProfileName, Serial, SubjectName,
    };
    use time::macros::datetime;

    use super::CertificateView;

    #[test]
    fn certificate_view_exposes_status_and_urls() {
        let now = datetime!(2024-05-01 12:00:00 UTC);
        let record = chainkeeper_core::CertificateRecord {
            serial: Serial::new("AA").expect("serial"),
            subject: SubjectName::new("example.test"),
            issuer: "CN=Example Root".to_owned(),
            profile: ProfileName::new("tls-server").expect("profile"),
            authority: AuthorityName::new("tls").expect("authority"),
            algorithm: KeyAlgorithm::EcdsaP256,
            sans: Vec::new(),
            ekus: Vec::new(),
            key_usages: Vec::new(),
            issued_at: now,
            expires_at: now + time::Duration::days(5),
            path: std::path::PathBuf::from("certificates/active/AA.pem"),
            revoked_at: None,
            revocation_reason: None,
            replaces: None,
        };
        let view = CertificateView::new(&record, now);
        assert_eq!(view.status, CertificateStatus::Active);
        assert_eq!(view.pem_url, "/chains/tls-server/AA.pem");
    }
}
