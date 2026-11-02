//! Algorithm identifiers shared by the crypto, policy, and engine crates.

use serde::{Deserialize, Serialize};

/// Key algorithm used to generate a key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyAlgorithm {
    /// RSA with a 3072 bit modulus.
    #[serde(rename = "rsa3072")]
    Rsa3072,
    /// ECDSA over the NIST P-256 curve.
    #[serde(rename = "ecdsa-p256")]
    EcdsaP256,
    /// Ed25519.
    #[serde(rename = "ed25519")]
    Ed25519,
}

impl KeyAlgorithm {
    /// Every algorithm supported by V1.
    pub const ALL: [Self; 3] = [Self::Rsa3072, Self::EcdsaP256, Self::Ed25519];

    /// Stable configuration string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rsa3072 => "rsa3072",
            Self::EcdsaP256 => "ecdsa-p256",
            Self::Ed25519 => "ed25519",
        }
    }

    /// Recommended algorithm for a profile name.
    ///
    /// TLS, mTLS, and OCSP default to ECDSA P-256, while S/MIME and code
    /// signing default to RSA-3072 for ecosystem compatibility. Unknown
    /// profiles fall back to the TLS default.
    #[must_use]
    pub const fn default_for_profile(profile: &str) -> Self {
        match profile.as_bytes() {
            b"smime" | b"codesign" => Self::Rsa3072,
            _ => Self::EcdsaP256,
        }
    }
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Signature scheme used when a signer produces a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SignatureScheme {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    #[serde(rename = "rsa-pkcs1-sha256")]
    RsaPkcs1Sha256,
    /// ECDSA with SHA-256.
    #[serde(rename = "ecdsa-sha256")]
    EcdsaSha256,
    /// Ed25519 (pure `EdDSA`, the message is not prehashed).
    #[serde(rename = "ed25519")]
    Ed25519,
}

impl SignatureScheme {
    /// Total mapping from key algorithm to signature scheme.
    #[must_use]
    pub const fn from_key_algorithm(algorithm: KeyAlgorithm) -> Self {
        match algorithm {
            KeyAlgorithm::Rsa3072 => Self::RsaPkcs1Sha256,
            KeyAlgorithm::EcdsaP256 => Self::EcdsaSha256,
            KeyAlgorithm::Ed25519 => Self::Ed25519,
        }
    }

    /// Stable configuration string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RsaPkcs1Sha256 => "rsa-pkcs1-sha256",
            Self::EcdsaSha256 => "ecdsa-sha256",
            Self::Ed25519 => "ed25519",
        }
    }
}

impl std::fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyAlgorithm, SignatureScheme};

    #[test]
    fn profile_defaults_match_the_decision_matrix() {
        assert_eq!(
            KeyAlgorithm::default_for_profile("tls-server"),
            KeyAlgorithm::EcdsaP256
        );
        assert_eq!(
            KeyAlgorithm::default_for_profile("mtls"),
            KeyAlgorithm::EcdsaP256
        );
        assert_eq!(
            KeyAlgorithm::default_for_profile("ocsp"),
            KeyAlgorithm::EcdsaP256
        );
        assert_eq!(
            KeyAlgorithm::default_for_profile("smime"),
            KeyAlgorithm::Rsa3072
        );
        assert_eq!(
            KeyAlgorithm::default_for_profile("codesign"),
            KeyAlgorithm::Rsa3072
        );
        assert_eq!(
            KeyAlgorithm::default_for_profile("unknown"),
            KeyAlgorithm::EcdsaP256
        );
    }

    #[test]
    fn every_algorithm_has_a_scheme() {
        assert_eq!(
            SignatureScheme::from_key_algorithm(KeyAlgorithm::Rsa3072),
            SignatureScheme::RsaPkcs1Sha256
        );
        assert_eq!(
            SignatureScheme::from_key_algorithm(KeyAlgorithm::EcdsaP256),
            SignatureScheme::EcdsaSha256
        );
        assert_eq!(
            SignatureScheme::from_key_algorithm(KeyAlgorithm::Ed25519),
            SignatureScheme::Ed25519
        );
    }
}
