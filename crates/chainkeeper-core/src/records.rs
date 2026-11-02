//! Persisted records and cryptographic material bundles.

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::config::{AuthorityConfig, AuthorityKind};
use crate::crypto::KeyAlgorithm;
use crate::error::ChainkeeperError;
use crate::ids::{AuthorityName, EventId, ProfileName, Serial};
use crate::profile::{ExtendedKeyUsage, KeyUsage};
use crate::request::{San, SubjectName};

/// RFC 5280 CRL reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RevocationReason {
    /// Reason not specified.
    #[serde(rename = "unspecified")]
    Unspecified,
    /// The certificate key was compromised.
    #[serde(rename = "keyCompromise")]
    KeyCompromise,
    /// The CA key was compromised.
    #[serde(rename = "caCompromise")]
    CaCompromise,
    /// Subject affiliation changed.
    #[serde(rename = "affiliationChanged")]
    AffiliationChanged,
    /// Certificate superseded.
    #[serde(rename = "superseded")]
    Superseded,
    /// Operation ceased.
    #[serde(rename = "cessationOfOperation")]
    CessationOfOperation,
    /// Certificate is on hold.
    #[serde(rename = "certificateHold")]
    CertificateHold,
    /// Privileges withdrawn.
    #[serde(rename = "privilegeWithdrawn")]
    PrivilegeWithdrawn,
    /// Attribute authority compromise.
    #[serde(rename = "aaCompromise")]
    AaCompromise,
}

impl RevocationReason {
    /// Every reason supported by V1.
    pub const ALL: [Self; 9] = [
        Self::Unspecified,
        Self::KeyCompromise,
        Self::CaCompromise,
        Self::AffiliationChanged,
        Self::Superseded,
        Self::CessationOfOperation,
        Self::CertificateHold,
        Self::PrivilegeWithdrawn,
        Self::AaCompromise,
    ];

    /// RFC 5280 reason code, which matches the code used by OpenSSL.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Unspecified => 0,
            Self::KeyCompromise => 1,
            Self::CaCompromise => 2,
            Self::AffiliationChanged => 3,
            Self::Superseded => 4,
            Self::CessationOfOperation => 5,
            Self::CertificateHold => 6,
            Self::PrivilegeWithdrawn => 9,
            Self::AaCompromise => 10,
        }
    }

    /// Maps an RFC 5280 reason code.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Validation`] for unknown codes and for
    /// `removeFromCrl` (code 8), which V1 does not support because
    /// unrevocation is out of scope.
    pub fn from_code(code: u8) -> Result<Self, ChainkeeperError> {
        match code {
            0 => Ok(Self::Unspecified),
            1 => Ok(Self::KeyCompromise),
            2 => Ok(Self::CaCompromise),
            3 => Ok(Self::AffiliationChanged),
            4 => Ok(Self::Superseded),
            5 => Ok(Self::CessationOfOperation),
            6 => Ok(Self::CertificateHold),
            8 => Err(ChainkeeperError::Validation(
                crate::error::ErrorDetail::new("removeFromCrl is not supported in V1"),
            )),
            9 => Ok(Self::PrivilegeWithdrawn),
            10 => Ok(Self::AaCompromise),
            _ => Err(ChainkeeperError::Validation(
                crate::error::ErrorDetail::new("unknown revocation reason code"),
            )),
        }
    }

    /// Stable configuration string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::KeyCompromise => "keyCompromise",
            Self::CaCompromise => "caCompromise",
            Self::AffiliationChanged => "affiliationChanged",
            Self::Superseded => "superseded",
            Self::CessationOfOperation => "cessationOfOperation",
            Self::CertificateHold => "certificateHold",
            Self::PrivilegeWithdrawn => "privilegeWithdrawn",
            Self::AaCompromise => "aaCompromise",
        }
    }
}

impl fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle status of an issued certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CertificateStatus {
    /// Issued and within its validity period.
    #[serde(rename = "active")]
    Active,
    /// Revoked by an administrator.
    #[serde(rename = "revoked")]
    Revoked,
    /// Past its `notAfter` time and not revoked.
    #[serde(rename = "expired")]
    Expired,
}

impl CertificateStatus {
    /// Derives the status of a record, with precedence revoked, expired, active.
    #[must_use]
    pub fn derive(now: OffsetDateTime, record: &CertificateRecord) -> Self {
        if record.revoked_at.is_some() {
            Self::Revoked
        } else if record.expires_at <= now {
            Self::Expired
        } else {
            Self::Active
        }
    }

    /// Stable directory name for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for CertificateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata stored next to an issued certificate as `<SERIAL>.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRecord {
    /// Certificate serial number.
    pub serial: Serial,
    /// Subject distinguished name.
    pub subject: SubjectName,
    /// Issuer distinguished name rendered as a string.
    pub issuer: String,
    /// Profile used for issuance.
    pub profile: ProfileName,
    /// Authority that signed the certificate.
    pub authority: AuthorityName,
    /// Leaf key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Subject alternative names.
    pub sans: Vec<San>,
    /// Extended key usages.
    pub ekus: Vec<ExtendedKeyUsage>,
    /// Key usages.
    pub key_usages: Vec<KeyUsage>,
    /// Issuance time.
    #[serde(with = "crate::time_util::seconds")]
    pub issued_at: OffsetDateTime,
    /// Expiry time.
    #[serde(with = "crate::time_util::seconds")]
    pub expires_at: OffsetDateTime,
    /// Repository-relative path of the PEM certificate.
    pub path: PathBuf,
    /// Revocation time, if revoked.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::time_util::seconds_option"
    )]
    pub revoked_at: Option<OffsetDateTime>,
    /// Revocation reason, if revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<RevocationReason>,
    /// Serial of the certificate this one replaces, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<Serial>,
}

impl CertificateRecord {
    /// Current lifecycle status of this record.
    #[must_use]
    pub fn status(&self, now: OffsetDateTime) -> CertificateStatus {
        CertificateStatus::derive(now, self)
    }
}

/// Revocation metadata stored at `revocations/<SERIAL>.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationRecord {
    /// Configuration schema version.
    pub version: u32,
    /// Revoked certificate serial.
    pub serial: Serial,
    /// Authority that issued the certificate.
    pub authority: AuthorityName,
    /// Revocation reason.
    pub reason: RevocationReason,
    /// Free-form operator comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Revocation time.
    #[serde(with = "crate::time_util::seconds")]
    pub revoked_at: OffsetDateTime,
    /// CRL number that first contained this revocation.
    pub crl_number: u64,
}

/// Action recorded in the append-only audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum AuditAction {
    /// Repository initialised.
    RepoInitialized,
    /// Root authority created.
    RootCreated,
    /// Intermediate authority created.
    IntermediateCreated,
    /// OCSP signer created.
    OcspSignerCreated,
    /// Certificate issued.
    CertIssued,
    /// Certificate revoked.
    CertRevoked,
    /// Certificate replaced.
    CertReplaced,
    /// CRL generated.
    CrlGenerated,
    /// Publication completed.
    PublishCompleted,
    /// Policy updated.
    PolicyUpdated,
    /// Profile updated.
    ProfileUpdated,
    /// Index rebuilt.
    IndexRebuilt,
}

impl AuditAction {
    /// Stable string stored in audit files.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RepoInitialized => "REPO_INITIALIZED",
            Self::RootCreated => "ROOT_CREATED",
            Self::IntermediateCreated => "INTERMEDIATE_CREATED",
            Self::OcspSignerCreated => "OCSP_SIGNER_CREATED",
            Self::CertIssued => "CERT_ISSUED",
            Self::CertRevoked => "CERT_REVOKED",
            Self::CertReplaced => "CERT_REPLACED",
            Self::CrlGenerated => "CRL_GENERATED",
            Self::PublishCompleted => "PUBLISH_COMPLETED",
            Self::PolicyUpdated => "POLICY_UPDATED",
            Self::ProfileUpdated => "PROFILE_UPDATED",
            Self::IndexRebuilt => "INDEX_REBUILT",
        }
    }
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Immutable audit event stored at `audit/events/<ULID>.json`.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ULID event identifier.
    pub id: EventId,
    /// Monotonic sequence number.
    pub seq: u64,
    /// Event time.
    #[serde(with = "crate::time_util::seconds")]
    pub timestamp: OffsetDateTime,
    /// Action performed.
    pub action: AuditAction,
    /// Type of the affected object.
    pub object_type: String,
    /// Identifier of the affected object.
    pub object_id: String,
    /// Human readable summary.
    pub summary: String,
    /// Actor that performed the action.
    pub actor: String,
    /// Structured details.
    #[serde(default)]
    pub details: serde_json::Value,
}

impl AuditEvent {
    /// Builds a stored event from a pending event plus assigned id and sequence.
    #[must_use]
    pub fn from_new(event: NewAuditEvent, id: EventId, seq: u64) -> Self {
        Self {
            id,
            seq,
            timestamp: event.timestamp,
            action: event.action,
            object_type: event.object_type,
            object_id: event.object_id,
            summary: event.summary,
            actor: event.actor,
            details: event.details,
        }
    }
}

/// Pending audit event. The audit log assigns `id` and `seq` on append.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Clone, PartialEq)]
pub struct NewAuditEvent {
    /// Event time.
    pub timestamp: OffsetDateTime,
    /// Action performed.
    pub action: AuditAction,
    /// Type of the affected object.
    pub object_type: String,
    /// Identifier of the affected object.
    pub object_id: String,
    /// Human readable summary.
    pub summary: String,
    /// Actor that performed the action.
    pub actor: String,
    /// Structured details.
    pub details: serde_json::Value,
}

impl NewAuditEvent {
    /// Builds a pending event without structured details.
    #[must_use]
    pub fn new(
        timestamp: OffsetDateTime,
        action: AuditAction,
        object_type: impl Into<String>,
        object_id: impl Into<String>,
        summary: impl Into<String>,
        actor: impl Into<String>,
    ) -> Self {
        Self {
            timestamp,
            action,
            object_type: object_type.into(),
            object_id: object_id.into(),
            summary: summary.into(),
            actor: actor.into(),
            details: serde_json::Value::Null,
        }
    }

    /// Attaches structured details.
    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }
}

/// Summary of an authority stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityRecord {
    /// Authority name.
    pub name: AuthorityName,
    /// Authority kind.
    pub kind: AuthorityKind,
    /// Parent authority name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<AuthorityName>,
    /// Authority key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Validity in days.
    pub validity_days: u32,
    /// Path length constraint.
    pub path_len: u32,
    /// Creation time.
    #[serde(with = "crate::time_util::seconds")]
    pub created_at: OffsetDateTime,
    /// Repository-relative path of the PEM certificate.
    pub cert_path: PathBuf,
    /// Repository-relative path of the PEM chain.
    pub chain_path: PathBuf,
}

impl AuthorityRecord {
    /// Builds an authority record from its configuration and repository paths.
    #[must_use]
    pub fn from_config(config: &AuthorityConfig, cert_path: PathBuf, chain_path: PathBuf) -> Self {
        Self {
            name: config.name.clone(),
            kind: config.kind,
            parent: config.parent.clone(),
            algorithm: config.algorithm,
            validity_days: config.validity_days,
            path_len: config.path_len,
            created_at: config.created_at,
            cert_path,
            chain_path,
        }
    }
}

/// Metadata for a generated CRL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrlRecord {
    /// Configuration schema version.
    pub version: u32,
    /// Authority that signed the CRL.
    pub authority: AuthorityName,
    /// Monotonic CRL number.
    pub number: u64,
    /// This update time.
    #[serde(with = "crate::time_util::seconds")]
    pub this_update: OffsetDateTime,
    /// Next update time.
    #[serde(with = "crate::time_util::seconds")]
    pub next_update: OffsetDateTime,
    /// Serials included in the CRL.
    pub revoked_serials: Vec<Serial>,
    /// Repository-relative path of the DER CRL.
    pub der_path: PathBuf,
    /// Repository-relative path of the PEM CRL.
    pub pem_path: PathBuf,
}

/// Kind of change reported by a Git diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GitChangeKind {
    /// File added.
    #[serde(rename = "added")]
    Added,
    /// File modified.
    #[serde(rename = "modified")]
    Modified,
    /// File deleted.
    #[serde(rename = "deleted")]
    Deleted,
    /// File renamed.
    #[serde(rename = "renamed")]
    Renamed,
}

/// Single change reported by a Git diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitChange {
    /// Repository-relative path.
    pub path: PathBuf,
    /// Kind of change.
    pub kind: GitChangeKind,
}

/// Working tree status of the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitStatus {
    /// Current branch name, if any.
    pub branch: Option<String>,
    /// Current HEAD commit, if any.
    pub head: Option<String>,
    /// Whether the working tree has no changes.
    pub clean: bool,
    /// Tracked changes.
    pub changes: Vec<GitChange>,
    /// Untracked paths.
    pub untracked: Vec<PathBuf>,
}

/// Generated private key plus its public key.
///
/// The private key PEM is redacted from `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct KeyMaterial {
    algorithm: KeyAlgorithm,
    private_key_pem: String,
    public_key_der: Vec<u8>,
}

impl KeyMaterial {
    /// Builds key material.
    #[must_use]
    pub fn new(
        algorithm: KeyAlgorithm,
        private_key_pem: impl Into<String>,
        public_key_der: Vec<u8>,
    ) -> Self {
        Self {
            algorithm,
            private_key_pem: private_key_pem.into(),
            public_key_der,
        }
    }

    /// Key algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// PEM encoded private key.
    #[must_use]
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    /// DER encoded public key.
    #[must_use]
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("algorithm", &self.algorithm)
            .field("private_key_pem", &"<redacted>")
            .field("public_key_der_bytes", &self.public_key_der.len())
            .finish()
    }
}

/// Public authority material: configuration, certificate, and chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityMaterial {
    /// Authority configuration.
    pub config: AuthorityConfig,
    /// PEM encoded authority certificate.
    pub cert_pem: String,
    /// PEM encoded chain including the authority certificate.
    pub chain_pem: String,
}

impl AuthorityMaterial {
    /// Builds authority material.
    #[must_use]
    pub fn new(
        config: AuthorityConfig,
        cert_pem: impl Into<String>,
        chain_pem: impl Into<String>,
    ) -> Self {
        Self {
            config,
            cert_pem: cert_pem.into(),
            chain_pem: chain_pem.into(),
        }
    }
}

/// Newly created authority, including its private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityBundle {
    /// Public material.
    pub material: AuthorityMaterial,
    /// Private key material.
    pub key: KeyMaterial,
}

impl AuthorityBundle {
    /// Builds an authority bundle.
    #[must_use]
    pub const fn new(material: AuthorityMaterial, key: KeyMaterial) -> Self {
        Self { material, key }
    }
}

/// Dedicated OCSP signer, including its private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerBundle {
    /// Signer configuration.
    pub config: AuthorityConfig,
    /// PEM encoded signer certificate.
    pub cert_pem: String,
    /// PEM encoded chain.
    pub chain_pem: String,
    /// Private key material.
    pub key: KeyMaterial,
}

/// Newly issued certificate and its optional private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    /// Certificate metadata.
    pub record: CertificateRecord,
    /// PEM encoded certificate.
    pub cert_pem: String,
    /// PEM encoded issuing chain.
    pub chain_pem: String,
    /// Private key material when the provider generated the key pair.
    pub key: Option<KeyMaterial>,
}

impl IssuedCertificate {
    /// Builds an issued certificate.
    #[must_use]
    pub fn new(
        record: CertificateRecord,
        cert_pem: impl Into<String>,
        chain_pem: impl Into<String>,
        key: Option<KeyMaterial>,
    ) -> Self {
        Self {
            record,
            cert_pem: cert_pem.into(),
            chain_pem: chain_pem.into(),
            key,
        }
    }
}

/// Input for CRL generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlRequest {
    /// Authority whose CRL is regenerated.
    pub authority: AuthorityName,
    /// Next CRL number.
    pub number: u64,
    /// This update time.
    pub this_update: OffsetDateTime,
    /// Next update time.
    pub next_update: OffsetDateTime,
    /// Revocations to include.
    pub revocations: Vec<RevocationRecord>,
}

/// Generated CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlBundle {
    /// CRL metadata.
    pub record: CrlRecord,
    /// DER encoded CRL.
    pub der: Vec<u8>,
    /// PEM encoded CRL.
    pub pem: String,
}

/// Everything the index needs to rebuild from the filesystem.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct IndexRecords {
    /// Certificates discovered on disk.
    pub certificates: Vec<CertificateRecord>,
    /// Revocations discovered on disk.
    pub revocations: Vec<RevocationRecord>,
    /// Authorities discovered on disk.
    pub authorities: Vec<AuthorityRecord>,
    /// Audit events discovered on disk.
    pub audit_events: Vec<AuditEvent>,
}

/// Row counts held by the index.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexStats {
    /// Number of indexed certificates.
    pub certificates: u64,
    /// Number of indexed revocations.
    pub revocations: u64,
    /// Number of indexed authorities.
    pub authorities: u64,
    /// Number of indexed audit events.
    pub audit_events: u64,
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::CertificateRecord;
    use super::{CertificateStatus, RevocationReason};
    use crate::crypto::KeyAlgorithm;
    use crate::ids::{AuthorityName, ProfileName, Serial};
    use crate::request::SubjectName;

    fn record(
        expires_at: time::OffsetDateTime,
        revoked_at: Option<time::OffsetDateTime>,
    ) -> CertificateRecord {
        CertificateRecord {
            serial: Serial::new("AB").expect("valid"),
            subject: SubjectName::new("example.test"),
            issuer: "CN=Root".to_owned(),
            profile: ProfileName::new("tls-server").expect("valid"),
            authority: AuthorityName::new("tls").expect("valid"),
            algorithm: KeyAlgorithm::EcdsaP256,
            sans: Vec::new(),
            ekus: Vec::new(),
            key_usages: Vec::new(),
            issued_at: datetime!(2024-01-01 00:00:00 UTC),
            expires_at,
            path: "certificates/active/AB.pem".into(),
            revoked_at,
            revocation_reason: revoked_at.map(|_| RevocationReason::Unspecified),
            replaces: None,
        }
    }

    #[test]
    fn status_precedence_is_revoked_expired_active() {
        let now = datetime!(2024-06-01 00:00:00 UTC);
        let future = datetime!(2025-01-01 00:00:00 UTC);
        let past = datetime!(2024-01-02 00:00:00 UTC);
        assert_eq!(
            CertificateStatus::derive(now, &record(future, None)),
            CertificateStatus::Active
        );
        assert_eq!(
            CertificateStatus::derive(now, &record(past, None)),
            CertificateStatus::Expired
        );
        assert_eq!(
            CertificateStatus::derive(now, &record(past, Some(now))),
            CertificateStatus::Revoked
        );
    }

    #[test]
    fn reason_codes_round_trip() {
        for reason in RevocationReason::ALL {
            assert_eq!(
                RevocationReason::from_code(reason.code()).expect("known code"),
                reason
            );
        }
        assert!(RevocationReason::from_code(7).is_err());
        assert!(RevocationReason::from_code(8).is_err());
        assert!(RevocationReason::from_code(11).is_err());
    }
}
