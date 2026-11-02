//! Command and API request types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::crypto::KeyAlgorithm;
use crate::error::ChainkeeperError;
use crate::ids::{AuthorityName, ProfileName, Serial, TenantId};
use crate::profile::SanType;
use crate::records::{AuditAction, CertificateStatus, RevocationReason};

/// Distinguished name of a certificate subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubjectName {
    /// Common name.
    pub cn: String,
    /// Organisation name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// Organisational unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organizational_unit: Option<String>,
    /// Two letter country code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// State or province.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Locality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// Email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl SubjectName {
    /// Builds a subject with only a common name.
    #[must_use]
    pub fn new(cn: impl Into<String>) -> Self {
        Self {
            cn: cn.into(),
            organization: None,
            organizational_unit: None,
            country: None,
            state: None,
            locality: None,
            email: None,
        }
    }

    /// Sets the organisation.
    #[must_use]
    pub fn with_organization(mut self, organization: impl Into<String>) -> Self {
        self.organization = Some(organization.into());
        self
    }

    /// Sets the email address.
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Validates the distinguished name.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Validation`] when the common name is empty,
    /// the country code is not two ASCII letters, or the email is malformed.
    pub fn validate(&self) -> Result<(), ChainkeeperError> {
        if self.cn.trim().is_empty() {
            return Err(ChainkeeperError::validation(
                "subject common name must not be empty",
            ));
        }
        if let Some(country) = &self.country
            && (country.len() != 2 || !country.chars().all(|c| c.is_ascii_alphabetic()))
        {
            return Err(ChainkeeperError::validation(
                "subject country must be a two letter code",
            ));
        }
        if let Some(email) = &self.email
            && !email.contains('@')
        {
            return Err(ChainkeeperError::validation(
                "subject email must contain an @ sign",
            ));
        }
        Ok(())
    }
}

/// Subject alternative name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "lowercase")]
pub enum San {
    /// DNS name.
    Dns(String),
    /// IP address.
    Ip(String),
    /// Email address.
    Email(String),
    /// URI.
    Uri(String),
}

impl San {
    /// Borrowed value of the SAN.
    #[must_use]
    pub fn value(&self) -> &str {
        match self {
            Self::Dns(value) | Self::Ip(value) | Self::Email(value) | Self::Uri(value) => value,
        }
    }

    /// Kind of the SAN.
    #[must_use]
    pub const fn kind(&self) -> SanType {
        match self {
            Self::Dns(_) => SanType::Dns,
            Self::Ip(_) => SanType::Ip,
            Self::Email(_) => SanType::Email,
            Self::Uri(_) => SanType::Uri,
        }
    }

    /// Validates the SAN value.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Validation`] when the value is empty or an
    /// IP SAN is not a valid IP address.
    pub fn validate(&self) -> Result<(), ChainkeeperError> {
        let value = self.value();
        if value.trim().is_empty() {
            return Err(ChainkeeperError::validation(
                "subject alternative name must not be empty",
            ));
        }
        if matches!(self, Self::Ip(_)) && value.parse::<std::net::IpAddr>().is_err() {
            return Err(ChainkeeperError::validation(
                "IP subject alternative name is not a valid address",
            ));
        }
        Ok(())
    }
}

/// Custom certificate extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomExtension {
    /// Dotted numeric object identifier.
    pub oid: String,
    /// Criticality flag.
    #[serde(default)]
    pub critical: bool,
    /// UTF-8 value. Exactly one of `value_utf8` and `value_hex` must be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_utf8: Option<String>,
    /// Hexadecimal value. Exactly one of `value_utf8` and `value_hex` must be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_hex: Option<String>,
}

impl CustomExtension {
    /// Builds a UTF-8 valued custom extension.
    #[must_use]
    pub fn utf8(oid: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            oid: oid.into(),
            critical: false,
            value_utf8: Some(value.into()),
            value_hex: None,
        }
    }

    /// Validates the OID and value encoding.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Validation`] when the OID is malformed, when
    /// both or neither value field is set, or when the hex value is invalid.
    pub fn validate(&self) -> Result<(), ChainkeeperError> {
        if !is_valid_oid(&self.oid) {
            return Err(ChainkeeperError::Validation(
                crate::error::ErrorDetail::new("custom extension OID is not a dotted numeric OID")
                    .with_object_id(self.oid.clone()),
            ));
        }
        match (&self.value_utf8, &self.value_hex) {
            (Some(_), Some(_)) | (None, None) => Err(ChainkeeperError::validation(
                "custom extension must set exactly one of value_utf8 and value_hex",
            )),
            (None, Some(hex)) => {
                let is_hex = hex.len() % 2 == 0 && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
                if !is_hex {
                    return Err(ChainkeeperError::validation(
                        "custom extension value_hex must be even-length hexadecimal",
                    ));
                }
                Ok(())
            }
            (Some(_), None) => Ok(()),
        }
    }
}

fn is_valid_oid(oid: &str) -> bool {
    let parts: Vec<&str> = oid.split('.').collect();
    if parts.len() < 2 || oid.len() > 128 {
        return false;
    }
    if parts
        .iter()
        .any(|part| part.is_empty() || part.len() > 10 || !part.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let Ok(first) = parts[0].parse::<u32>() else {
        return false;
    };
    let Ok(second) = parts[1].parse::<u32>() else {
        return false;
    };
    if first > 2 {
        return false;
    }
    if first < 2 && second > 39 {
        return false;
    }
    true
}

/// Request for `ck init`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitRequest {
    /// Tenant identifier.
    pub tenant_id: TenantId,
    /// Human readable tenant name.
    pub display_name: String,
    /// Default profile for the repository.
    pub default_profile: ProfileName,
    /// OCSP responder URL.
    pub ocsp_url: Option<String>,
    /// AIA CA Issuers URL template.
    pub ca_issuers_url_template: Option<String>,
    /// CRL distribution point URL template.
    pub crl_url_template: Option<String>,
}

impl InitRequest {
    /// Builds an init request with template defaults.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        display_name: impl Into<String>,
        default_profile: ProfileName,
    ) -> Self {
        Self {
            tenant_id,
            display_name: display_name.into(),
            default_profile,
            ocsp_url: None,
            ca_issuers_url_template: None,
            crl_url_template: None,
        }
    }
}

/// Request to create a root or intermediate authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateAuthorityRequest {
    /// Authority name.
    pub name: AuthorityName,
    /// Authority kind.
    pub kind: crate::config::AuthorityKind,
    /// Parent authority. Required for non-root authorities.
    pub parent: Option<AuthorityName>,
    /// Subject of the authority certificate.
    pub subject: SubjectName,
    /// Key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Validity in days.
    pub validity_days: u32,
    /// Path length constraint.
    pub path_len: u32,
}

/// Request to create a dedicated OCSP signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOcspSignerRequest {
    /// Authority name of the signer.
    pub name: AuthorityName,
    /// Authority that signs the OCSP signer certificate.
    pub parent: AuthorityName,
    /// Override subject. Defaults to the parent organisation with the signer name.
    pub subject: Option<SubjectName>,
    /// Key algorithm.
    pub algorithm: KeyAlgorithm,
    /// Validity in days.
    pub validity_days: u32,
}

/// Request for `ck issue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueRequest {
    /// Profile to issue from.
    pub profile: ProfileName,
    /// Subject of the leaf certificate.
    pub subject: SubjectName,
    /// Subject alternative names.
    pub sans: Vec<San>,
    /// Custom OID extensions.
    pub custom_extensions: Vec<CustomExtension>,
    /// Key algorithm override. Falls back to the profile default.
    pub algorithm: Option<KeyAlgorithm>,
    /// Validity override in days. Falls back to the profile default.
    pub validity_days: Option<u32>,
    /// PEM encoded CSR. When set the provider must not generate a key pair.
    pub csr_pem: Option<String>,
    /// Destination for the generated private key.
    pub key_out: Option<PathBuf>,
    /// Serial of the certificate this request replaces.
    pub replaces: Option<Serial>,
}

impl IssueRequest {
    /// Builds an issuance request with only the required fields.
    #[must_use]
    pub const fn new(profile: ProfileName, subject: SubjectName) -> Self {
        Self {
            profile,
            subject,
            sans: Vec::new(),
            custom_extensions: Vec::new(),
            algorithm: None,
            validity_days: None,
            csr_pem: None,
            key_out: None,
            replaces: None,
        }
    }
}

/// Request for `ck revoke`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeRequest {
    /// Serial of the certificate to revoke.
    pub serial: Serial,
    /// Revocation reason.
    pub reason: RevocationReason,
    /// Operator comment.
    pub comment: Option<String>,
}

impl RevokeRequest {
    /// Builds a revocation request with the `unspecified` reason.
    #[must_use]
    pub const fn new(serial: Serial) -> Self {
        Self {
            serial,
            reason: RevocationReason::Unspecified,
            comment: None,
        }
    }
}

/// Filter used by `ck search` and the read-only API.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchQuery {
    /// Free text matched against subject, SANs, and serial.
    pub text: Option<String>,
    /// Restrict to a lifecycle status.
    pub status: Option<CertificateStatus>,
    /// Restrict to a profile.
    pub profile: Option<ProfileName>,
    /// Restrict to an issuing authority.
    pub authority: Option<AuthorityName>,
    /// Restrict to certificates expiring within this many days.
    pub expires_within_days: Option<u32>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

/// Filter used by `ck audit`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQuery {
    /// Restrict to an action.
    pub action: Option<AuditAction>,
    /// Restrict to an object type.
    pub object_type: Option<String>,
    /// Restrict to an object identifier.
    pub object_id: Option<String>,
    /// Lower bound on the event timestamp.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::time_util::seconds_option"
    )]
    pub since: Option<OffsetDateTime>,
    /// Upper bound on the event timestamp.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::time_util::seconds_option"
    )]
    pub until: Option<OffsetDateTime>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

/// Options for `ck publish`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOptions {
    /// Destination directory for published artifacts.
    pub output_dir: PathBuf,
    /// Remove stale artifacts from the destination before publishing.
    pub clean: bool,
}

impl PublishOptions {
    /// Builds publish options.
    #[must_use]
    pub fn new(output_dir: impl Into<PathBuf>) -> Self {
        Self {
            output_dir: output_dir.into(),
            clean: false,
        }
    }
}

/// Request for `ck diff`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiffRequest {
    /// Start commit. Defaults to the last published commit.
    pub from: Option<String>,
    /// End commit. Defaults to `HEAD`.
    pub to: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{CustomExtension, San, SubjectName};

    #[test]
    fn custom_extension_requires_exactly_one_value() {
        let mut extension = CustomExtension::utf8("1.2.3.4", "value");
        assert!(extension.validate().is_ok());
        extension.value_hex = Some("00ff".to_owned());
        assert!(extension.validate().is_err());
        extension.value_utf8 = None;
        assert!(extension.validate().is_ok());
    }

    #[test]
    fn custom_extension_rejects_bad_oids() {
        for oid in ["", "1", "abc", "3.1", "1.40", "1..2"] {
            let extension = CustomExtension::utf8(oid, "value");
            assert!(extension.validate().is_err(), "{oid}");
        }
    }

    #[test]
    fn san_validation_checks_ips() {
        assert!(San::Ip("192.0.2.1".to_owned()).validate().is_ok());
        assert!(San::Ip("not-an-ip".to_owned()).validate().is_err());
        assert!(San::Dns(String::new()).validate().is_err());
    }

    #[test]
    fn subject_validation_checks_country() {
        let mut subject = SubjectName::new("example.test");
        subject.country = Some("USA".to_owned());
        assert!(subject.validate().is_err());
        subject.country = Some("US".to_owned());
        assert!(subject.validate().is_ok());
    }
}
