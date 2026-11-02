//! Tenant, policy, and authority configuration types.
//!
//! Every YAML configuration carries `version: 1` and rejects unknown fields.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::crypto::KeyAlgorithm;
use crate::error::ChainkeeperError;
use crate::ids::{AuthorityName, ProfileName, TenantId};
use crate::profile::{KeyUsage, builtin_profile_names};

/// Configuration schema version accepted by V1.
pub const CONFIG_VERSION: u32 = 1;

fn check_version(version: u32, object: &str) -> Result<(), ChainkeeperError> {
    if version == CONFIG_VERSION {
        Ok(())
    } else {
        Err(ChainkeeperError::config(format!(
            "{object} uses unsupported version {version}, expected {CONFIG_VERSION}"
        )))
    }
}

fn check_template(template: Option<&str>, field: &str) -> Result<(), ChainkeeperError> {
    if let Some(value) = template {
        if !value.contains("{authority}") {
            return Err(ChainkeeperError::config(format!(
                "{field} must contain the {{authority}} placeholder"
            )));
        }
        if !(value.starts_with("http://") || value.starts_with("https://")) {
            return Err(ChainkeeperError::config(format!(
                "{field} must be an absolute http or https URL"
            )));
        }
    }
    Ok(())
}

/// Top level repository configuration stored in `tenant.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    /// Configuration schema version, always [`CONFIG_VERSION`].
    pub version: u32,
    /// Tenant identifier.
    pub tenant_id: TenantId,
    /// Human readable tenant name.
    pub display_name: String,
    /// Repository creation time.
    #[serde(with = "crate::time_util::seconds")]
    pub created_at: OffsetDateTime,
    /// Profile used when a command does not specify one.
    pub default_profile: ProfileName,
    /// OCSP responder URL embedded in issued certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ocsp_url: Option<String>,
    /// AIA CA Issuers URL template. Must contain `{authority}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_issuers_url_template: Option<String>,
    /// CRL distribution point URL template. Must contain `{authority}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_url_template: Option<String>,
}

impl TenantConfig {
    /// Builds a tenant configuration with the current schema version.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        display_name: impl Into<String>,
        default_profile: ProfileName,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            version: CONFIG_VERSION,
            tenant_id,
            display_name: display_name.into(),
            created_at,
            default_profile,
            ocsp_url: None,
            ca_issuers_url_template: None,
            crl_url_template: None,
        }
    }

    /// Validates schema version, naming, and URL templates.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when a field is invalid or the
    /// schema version is unsupported.
    pub fn validate(&self) -> Result<(), ChainkeeperError> {
        check_version(self.version, "tenant configuration")?;
        if self.display_name.trim().is_empty() {
            return Err(ChainkeeperError::config("display_name must not be empty"));
        }
        check_template(
            self.ca_issuers_url_template.as_deref(),
            "ca_issuers_url_template",
        )?;
        check_template(self.crl_url_template.as_deref(), "crl_url_template")?;
        Ok(())
    }
}

/// Repository-wide issuance policy stored in `policy/policy.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Configuration schema version, always [`CONFIG_VERSION`].
    pub version: u32,
    /// Maximum validity in days for leaf certificates.
    pub max_validity_days: u32,
    /// Algorithms an issuance request may use.
    pub allowed_algorithms: Vec<KeyAlgorithm>,
    /// Profiles an issuance request may use.
    pub allowed_profiles: Vec<ProfileName>,
    /// Whether custom OID extensions are accepted.
    pub allow_custom_oid: bool,
    /// Whether wildcard DNS SANs are accepted.
    pub allow_wildcards: bool,
    /// Maximum number of subject alternative names.
    pub max_sans: usize,
    /// Allowed DNS SAN suffixes. An empty list allows any suffix.
    #[serde(default)]
    pub allowed_san_suffixes: Vec<String>,
    /// Whether the common name must match a SAN entry.
    pub cn_must_match_san: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            max_validity_days: 397,
            allowed_algorithms: KeyAlgorithm::ALL.to_vec(),
            allowed_profiles: builtin_profile_names(),
            allow_custom_oid: true,
            allow_wildcards: false,
            max_sans: 100,
            allowed_san_suffixes: Vec::new(),
            cn_must_match_san: true,
        }
    }
}

impl Policy {
    /// Validates policy self-consistency.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when a required list is empty, a
    /// limit is zero, or the schema version is unsupported.
    pub fn validate(&self) -> Result<(), ChainkeeperError> {
        check_version(self.version, "policy")?;
        if self.max_validity_days == 0 {
            return Err(ChainkeeperError::config(
                "max_validity_days must be positive",
            ));
        }
        if self.allowed_algorithms.is_empty() {
            return Err(ChainkeeperError::config(
                "allowed_algorithms must not be empty",
            ));
        }
        if self.allowed_profiles.is_empty() {
            return Err(ChainkeeperError::config(
                "allowed_profiles must not be empty",
            ));
        }
        if self.max_sans == 0 {
            return Err(ChainkeeperError::config("max_sans must be positive"));
        }
        for suffix in &self.allowed_san_suffixes {
            if suffix.is_empty()
                || suffix.starts_with('.')
                || suffix
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
            {
                return Err(ChainkeeperError::config(format!(
                    "invalid allowed_san_suffix {suffix:?}"
                )));
            }
        }
        Ok(())
    }

    /// Returns true when the algorithm is allowed by this policy.
    #[must_use]
    pub fn permits_algorithm(&self, algorithm: KeyAlgorithm) -> bool {
        self.allowed_algorithms.contains(&algorithm)
    }

    /// Returns true when the profile is allowed by this policy.
    #[must_use]
    pub fn permits_profile(&self, profile: &ProfileName) -> bool {
        self.allowed_profiles.contains(profile)
    }
}

/// Kind of authority stored under `authorities/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuthorityKind {
    /// Self-signed trust anchor.
    #[serde(rename = "root")]
    Root,
    /// Intermediate CA signed by the root.
    #[serde(rename = "intermediate")]
    Intermediate,
    /// Dedicated OCSP response signer.
    #[serde(rename = "ocsp-signer")]
    OcspSigner,
}

impl AuthorityKind {
    /// Stable configuration string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Intermediate => "intermediate",
            Self::OcspSigner => "ocsp-signer",
        }
    }
}

/// Authority metadata stored in `authorities/<name>/authority.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    /// Directory name and certificate common name source.
    pub name: AuthorityName,
    /// Kind of authority.
    pub kind: AuthorityKind,
    /// Parent authority name. Absent for the root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<AuthorityName>,
    /// Key algorithm of the authority key pair.
    pub algorithm: KeyAlgorithm,
    /// Validity in days.
    pub validity_days: u32,
    /// Maximum number of intermediate CA certificates below this authority.
    pub path_len: u32,
    /// Key usages asserted by the authority certificate.
    pub key_usage: Vec<KeyUsage>,
    /// Creation time.
    #[serde(with = "crate::time_util::seconds")]
    pub created_at: OffsetDateTime,
}

impl AuthorityConfig {
    /// Builds an authority configuration.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        name: AuthorityName,
        kind: AuthorityKind,
        parent: Option<AuthorityName>,
        algorithm: KeyAlgorithm,
        validity_days: u32,
        path_len: u32,
        key_usage: Vec<KeyUsage>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            name,
            kind,
            parent,
            algorithm,
            validity_days,
            path_len,
            key_usage,
            created_at,
        }
    }

    /// Validates authority self-consistency.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when the parent/kind combination is
    /// invalid, validity is zero, or the path length is unreasonable.
    pub fn validate(&self) -> Result<(), ChainkeeperError> {
        match (self.kind, &self.parent) {
            (AuthorityKind::Root, Some(_)) => {
                return Err(ChainkeeperError::config(
                    "root authority must not have a parent",
                ));
            }
            (AuthorityKind::Intermediate | AuthorityKind::OcspSigner, None) => {
                return Err(ChainkeeperError::config(
                    "non-root authority must declare a parent",
                ));
            }
            _ => {}
        }
        if self.parent.as_ref() == Some(&self.name) {
            return Err(ChainkeeperError::config(
                "authority must not be its own parent",
            ));
        }
        if self.validity_days == 0 {
            return Err(ChainkeeperError::config("validity_days must be positive"));
        }
        if self.path_len > 32 {
            return Err(ChainkeeperError::config("path_len must be 32 or less"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::{AuthorityConfig, AuthorityKind, Policy};
    use crate::crypto::KeyAlgorithm;
    use crate::ids::AuthorityName;
    use crate::profile::{KeyUsage, builtin_profile_names};

    #[test]
    fn policy_defaults_match_the_decision_matrix() {
        let policy = Policy::default();
        assert_eq!(policy.max_validity_days, 397);
        assert_eq!(policy.allowed_algorithms, KeyAlgorithm::ALL.to_vec());
        assert_eq!(policy.allowed_profiles, builtin_profile_names());
        assert!(policy.allow_custom_oid);
        assert!(!policy.allow_wildcards);
        assert_eq!(policy.max_sans, 100);
        assert_eq!(policy.allowed_san_suffixes.len(), 0);
        assert!(policy.cn_must_match_san);
    }

    #[test]
    fn root_must_not_have_parent() {
        let config = AuthorityConfig::new(
            AuthorityName::new("root").expect("valid"),
            AuthorityKind::Root,
            Some(AuthorityName::new("other").expect("valid")),
            KeyAlgorithm::EcdsaP256,
            7300,
            1,
            vec![KeyUsage::KeyCertSign],
            datetime!(2024-01-01 00:00:00 UTC),
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn intermediate_requires_parent() {
        let config = AuthorityConfig::new(
            AuthorityName::new("tls").expect("valid"),
            AuthorityKind::Intermediate,
            None,
            KeyAlgorithm::EcdsaP256,
            3650,
            0,
            vec![KeyUsage::KeyCertSign],
            datetime!(2024-01-01 00:00:00 UTC),
        );
        assert!(config.validate().is_err());
    }
}
