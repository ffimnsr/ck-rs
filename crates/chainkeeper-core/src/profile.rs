//! Certificate profiles and their X.509 extension vocabularies.

use serde::{Deserialize, Serialize};

use crate::config::CONFIG_VERSION;
use crate::crypto::KeyAlgorithm;
use crate::error::ChainkeeperError;
use crate::ids::{AuthorityName, ProfileName};

/// X.509 key usage bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyUsage {
    /// Digital signature.
    #[serde(rename = "digitalSignature")]
    DigitalSignature,
    /// Non-repudiation / content commitment.
    #[serde(rename = "contentCommitment")]
    ContentCommitment,
    /// Key encipherment.
    #[serde(rename = "keyEncipherment")]
    KeyEncipherment,
    /// Data encipherment.
    #[serde(rename = "dataEncipherment")]
    DataEncipherment,
    /// Key agreement.
    #[serde(rename = "keyAgreement")]
    KeyAgreement,
    /// Certificate signing.
    #[serde(rename = "keyCertSign")]
    KeyCertSign,
    /// CRL signing.
    #[serde(rename = "cRLSign")]
    CrlSign,
    /// Encipher only.
    #[serde(rename = "encipherOnly")]
    EncipherOnly,
    /// Decipher only.
    #[serde(rename = "decipherOnly")]
    DecipherOnly,
}

/// X.509 extended key usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ExtendedKeyUsage {
    /// TLS server authentication.
    #[serde(rename = "serverAuth")]
    ServerAuth,
    /// TLS client authentication.
    #[serde(rename = "clientAuth")]
    ClientAuth,
    /// Code signing.
    #[serde(rename = "codeSigning")]
    CodeSigning,
    /// S/MIME email protection.
    #[serde(rename = "emailProtection")]
    EmailProtection,
    /// OCSP response signing.
    #[serde(rename = "ocspSigning")]
    OcspSigning,
    /// Trusted timestamping.
    #[serde(rename = "timeStamping")]
    TimeStamping,
}

/// Kind of subject alternative name accepted by a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SanType {
    /// DNS name.
    #[serde(rename = "dns")]
    Dns,
    /// IP address.
    #[serde(rename = "ip")]
    Ip,
    /// Email address (RFC 822 name).
    #[serde(rename = "email")]
    Email,
    /// URI.
    #[serde(rename = "uri")]
    Uri,
}

/// Certificate profile stored in `profiles/<name>.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Configuration schema version, always [`CONFIG_VERSION`].
    pub version: u32,
    /// Profile name, matching the file stem.
    pub name: ProfileName,
    /// Authority that signs certificates issued from this profile.
    pub authority: AuthorityName,
    /// Key algorithm used when the request does not override it.
    pub algorithm: KeyAlgorithm,
    /// Default validity in days.
    pub validity_days: u32,
    /// Key usages asserted by the certificate.
    pub key_usage: Vec<KeyUsage>,
    /// Extended key usages asserted by the certificate.
    pub eku: Vec<ExtendedKeyUsage>,
    /// Whether at least one subject alternative name is required.
    pub san_required: bool,
    /// SAN kinds accepted by the profile. An empty list accepts every kind.
    pub san_types: Vec<SanType>,
    /// Whether custom OID extensions are accepted for this profile.
    pub allow_custom_oid: bool,
}

impl Profile {
    /// Validates profile self-consistency.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Profile`] when the schema version, validity,
    /// or SAN configuration is inconsistent.
    pub fn validate(&self) -> Result<(), ChainkeeperError> {
        if self.version != CONFIG_VERSION {
            return Err(ChainkeeperError::profile(format!(
                "profile {} uses unsupported version {}, expected {CONFIG_VERSION}",
                self.name, self.version
            )));
        }
        if self.validity_days == 0 {
            return Err(ChainkeeperError::profile(format!(
                "profile {} must declare a positive validity_days",
                self.name
            )));
        }
        if self.san_required && self.san_types.is_empty() {
            return Err(ChainkeeperError::profile(format!(
                "profile {} requires SANs but declares no san_types",
                self.name
            )));
        }
        Ok(())
    }

    /// Returns true when the profile accepts the given SAN kind.
    #[must_use]
    pub fn accepts_san_type(&self, san_type: SanType) -> bool {
        self.san_types.is_empty() || self.san_types.contains(&san_type)
    }
}

fn profile_name(value: &str) -> ProfileName {
    ProfileName::new(value).expect("built-in profile names are valid")
}

fn authority_name(value: &str) -> AuthorityName {
    AuthorityName::new(value).expect("built-in authority names are valid")
}

/// Names of every built-in profile, in canonical order.
#[must_use]
pub fn builtin_profile_names() -> Vec<ProfileName> {
    [
        "tls-server",
        "tls-client",
        "mtls",
        "smime",
        "codesign",
        "ocsp",
    ]
    .into_iter()
    .map(profile_name)
    .collect()
}

/// Every built-in profile, in canonical order.
#[must_use]
pub fn builtin_profiles() -> Vec<Profile> {
    vec![
        Profile {
            version: CONFIG_VERSION,
            name: profile_name("tls-server"),
            authority: authority_name("tls"),
            algorithm: KeyAlgorithm::EcdsaP256,
            validity_days: 397,
            key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            eku: vec![ExtendedKeyUsage::ServerAuth],
            san_required: true,
            san_types: vec![SanType::Dns, SanType::Ip],
            allow_custom_oid: false,
        },
        Profile {
            version: CONFIG_VERSION,
            name: profile_name("tls-client"),
            authority: authority_name("tls"),
            algorithm: KeyAlgorithm::EcdsaP256,
            validity_days: 397,
            key_usage: vec![KeyUsage::DigitalSignature],
            eku: vec![ExtendedKeyUsage::ClientAuth],
            san_required: false,
            san_types: vec![SanType::Dns, SanType::Email],
            allow_custom_oid: false,
        },
        Profile {
            version: CONFIG_VERSION,
            name: profile_name("mtls"),
            authority: authority_name("tls"),
            algorithm: KeyAlgorithm::EcdsaP256,
            validity_days: 397,
            key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            eku: vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth],
            san_required: true,
            san_types: vec![SanType::Dns, SanType::Ip],
            allow_custom_oid: false,
        },
        Profile {
            version: CONFIG_VERSION,
            name: profile_name("smime"),
            authority: authority_name("smime"),
            algorithm: KeyAlgorithm::Rsa3072,
            validity_days: 397,
            key_usage: vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment],
            eku: vec![ExtendedKeyUsage::EmailProtection],
            san_required: true,
            san_types: vec![SanType::Email],
            allow_custom_oid: false,
        },
        Profile {
            version: CONFIG_VERSION,
            name: profile_name("codesign"),
            authority: authority_name("codesign"),
            algorithm: KeyAlgorithm::Rsa3072,
            validity_days: 397,
            key_usage: vec![KeyUsage::DigitalSignature],
            eku: vec![ExtendedKeyUsage::CodeSigning],
            san_required: false,
            san_types: Vec::new(),
            allow_custom_oid: false,
        },
        Profile {
            version: CONFIG_VERSION,
            name: profile_name("ocsp"),
            authority: authority_name("ocsp-signer"),
            algorithm: KeyAlgorithm::EcdsaP256,
            validity_days: 90,
            key_usage: vec![KeyUsage::DigitalSignature],
            eku: vec![ExtendedKeyUsage::OcspSigning],
            san_required: false,
            san_types: Vec::new(),
            allow_custom_oid: false,
        },
    ]
}

/// Looks up a built-in profile by name.
#[must_use]
pub fn builtin_profile(name: &ProfileName) -> Option<Profile> {
    builtin_profiles()
        .into_iter()
        .find(|profile| &profile.name == name)
}

#[cfg(test)]
mod tests {
    use super::{ExtendedKeyUsage, KeyUsage, Profile, SanType, builtin_profile, builtin_profiles};
    use crate::crypto::KeyAlgorithm;
    use crate::ids::ProfileName;

    #[test]
    fn every_builtin_profile_is_valid() {
        let profiles = builtin_profiles();
        assert_eq!(profiles.len(), 6);
        for profile in &profiles {
            profile.validate().expect("builtin profile is valid");
        }
    }

    #[test]
    fn defaults_match_the_decision_matrix() {
        let smime = builtin_profile(&ProfileName::new("smime").expect("valid")).expect("exists");
        assert_eq!(smime.algorithm, KeyAlgorithm::Rsa3072);
        assert_eq!(smime.eku, vec![ExtendedKeyUsage::EmailProtection]);

        let ocsp = builtin_profile(&ProfileName::new("ocsp").expect("valid")).expect("exists");
        assert_eq!(ocsp.algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(ocsp.validity_days, 90);
        assert_eq!(ocsp.eku, vec![ExtendedKeyUsage::OcspSigning]);

        let tls = builtin_profile(&ProfileName::new("tls-server").expect("valid")).expect("exists");
        assert_eq!(tls.algorithm, KeyAlgorithm::EcdsaP256);
        assert!(tls.san_required);
        assert!(tls.accepts_san_type(SanType::Dns));
        assert_eq!(tls.key_usage[0], KeyUsage::DigitalSignature);
    }

    #[test]
    fn profile_validation_rejects_empty_validity() {
        let mut profile = builtin_profiles().remove(0);
        profile.validity_days = 0;
        assert!(profile.validate().is_err());
    }

    #[test]
    fn san_type_matching_respects_the_allow_list() {
        let profile = Profile {
            san_types: vec![SanType::Email],
            ..builtin_profiles().remove(3)
        };
        assert!(profile.accepts_san_type(SanType::Email));
        assert!(!profile.accepts_san_type(SanType::Dns));
    }
}
