//! File-backed signer implementation.

use std::fmt;
use std::path::Path;

use chainkeeper_core::{ChainkeeperError, KeyAlgorithm, KeyMaterial, SignatureScheme, Signer};
use openssl::pkey::{PKey, Private};

use crate::keygen;
use crate::secret::SecretString;

/// Signer backed by a PEM private key held in memory.
///
/// The key is loaded once and reused for every signature. `Debug` never
/// renders the key bytes.
pub struct FileSigner {
    key: PKey<Private>,
    algorithm: KeyAlgorithm,
    material: KeyMaterial,
}

impl fmt::Debug for FileSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSigner")
            .field("algorithm", &self.algorithm)
            .field("key", &"<redacted>")
            .field("material", &"<redacted>")
            .finish()
    }
}

impl FileSigner {
    /// Loads a signer from a PEM file.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when the file cannot be read, the
    /// passphrase is missing or wrong, or the key algorithm is unsupported.
    pub fn from_path(
        path: impl AsRef<Path>,
        passphrase: Option<&SecretString>,
    ) -> Result<Self, ChainkeeperError> {
        let bytes = std::fs::read(path.as_ref()).map_err(|error| {
            ChainkeeperError::crypto(format!("cannot read private key: {error}"))
        })?;
        Self::from_pem(&bytes, passphrase)
    }

    /// Loads a signer from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when the passphrase is missing or
    /// wrong, the PEM is malformed, or the key algorithm is unsupported.
    pub fn from_pem(
        pem: &[u8],
        passphrase: Option<&SecretString>,
    ) -> Result<Self, ChainkeeperError> {
        let key = keygen::load_pem(pem, passphrase)?;
        let algorithm = keygen::algorithm_of(&key)?;
        let text = std::str::from_utf8(pem)
            .map_err(|_| ChainkeeperError::crypto("private key PEM is not UTF-8"))?;
        let material = KeyMaterial::new(
            algorithm,
            text,
            key.public_key_to_der()
                .map_err(|error| ChainkeeperError::crypto(error.to_string()))?,
        );
        Ok(Self {
            key,
            algorithm,
            material,
        })
    }

    /// Builds a signer from an in-memory key, encoding fresh key material.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when the key cannot be encoded.
    pub fn from_key(
        key: PKey<Private>,
        algorithm: KeyAlgorithm,
        passphrase: Option<&SecretString>,
    ) -> Result<Self, ChainkeeperError> {
        let material = keygen::key_material(&key, algorithm, passphrase)?;
        Ok(Self {
            key,
            algorithm,
            material,
        })
    }

    /// Builds a signer from an already serialized key pair.
    ///
    /// Used internally so a freshly generated key is encoded once.
    #[must_use]
    pub(crate) const fn from_key_and_material(key: PKey<Private>, material: KeyMaterial) -> Self {
        Self {
            key,
            algorithm: material.algorithm(),
            material,
        }
    }

    /// Private key material backing this signer.
    ///
    /// File-backed signers own an exportable key, so callers that need to write
    /// the key to the repository can reuse it instead of re-reading the file.
    #[must_use]
    pub const fn key_material(&self) -> &KeyMaterial {
        &self.material
    }
}

impl Signer for FileSigner {
    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn public_key_der(&self) -> Result<Vec<u8>, ChainkeeperError> {
        Ok(self.material.public_key_der().to_vec())
    }

    fn sign(&self, message: &[u8], scheme: SignatureScheme) -> Result<Vec<u8>, ChainkeeperError> {
        if scheme != SignatureScheme::from_key_algorithm(self.algorithm) {
            return Err(ChainkeeperError::crypto(format!(
                "signature scheme {} does not match {} key",
                scheme.as_str(),
                self.algorithm.as_str()
            )));
        }
        keygen::sign(&self.key, message, scheme)
    }
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::{KeyAlgorithm, SignatureScheme, Signer};
    use openssl::hash::MessageDigest;
    use openssl::sign::Verifier;

    use super::FileSigner;
    use crate::keygen::generate;

    #[test]
    fn signs_and_verifies_with_every_algorithm() {
        for algorithm in KeyAlgorithm::ALL {
            let generated = generate(algorithm, None).expect("key generation");
            let signer = FileSigner::from_key(generated.key, algorithm, None).expect("signer");
            let scheme = SignatureScheme::from_key_algorithm(algorithm);
            let signature = signer.sign(b"chainkeeper", scheme).expect("signature");
            let public =
                openssl::pkey::PKey::public_key_from_der(&signer.public_key_der().expect("der"))
                    .expect("public key");
            let mut verifier = match scheme {
                SignatureScheme::Ed25519 => {
                    Verifier::new_without_digest(&public).expect("verifier")
                }
                _ => Verifier::new(MessageDigest::sha256(), &public).expect("verifier"),
            };
            if scheme == SignatureScheme::Ed25519 {
                assert!(
                    verifier
                        .verify_oneshot(&signature, b"chainkeeper")
                        .expect("verify")
                );
            } else {
                verifier.update(b"chainkeeper").expect("update");
                assert!(verifier.verify(&signature).expect("verify"));
            }
        }
    }

    #[test]
    fn rejects_mismatched_schemes() {
        let generated = generate(KeyAlgorithm::EcdsaP256, None).expect("key generation");
        let signer =
            FileSigner::from_key(generated.key, KeyAlgorithm::EcdsaP256, None).expect("signer");
        let error = signer
            .sign(b"message", SignatureScheme::RsaPkcs1Sha256)
            .expect_err("mismatch");
        assert!(error.to_string().contains("does not match"));
    }
}
