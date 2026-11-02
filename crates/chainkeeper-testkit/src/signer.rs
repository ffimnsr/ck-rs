//! Deterministic signer.

use std::sync::atomic::{AtomicBool, Ordering};

use chainkeeper_core::{ChainkeeperError, KeyAlgorithm, SignatureScheme, Signer};
use sha2::{Digest, Sha256};

/// Signer that returns the SHA-256 digest of the message.
#[derive(Debug)]
pub struct FakeSigner {
    algorithm: KeyAlgorithm,
    public_key_der: Vec<u8>,
    fail: AtomicBool,
}

impl FakeSigner {
    /// Creates a signer for the given algorithm.
    #[must_use]
    pub fn new(algorithm: KeyAlgorithm) -> Self {
        let public_key_der = format!("fake-public-key:{}", algorithm.as_str()).into_bytes();
        Self {
            algorithm,
            public_key_der,
            fail: AtomicBool::new(false),
        }
    }

    /// Creates a signer that always fails.
    #[must_use]
    pub fn failing(algorithm: KeyAlgorithm) -> Self {
        let signer = Self::new(algorithm);
        signer.fail.store(true, Ordering::SeqCst);
        signer
    }

    /// Enables or disables failure injection.
    pub fn set_failing(&self, failing: bool) {
        self.fail.store(failing, Ordering::SeqCst);
    }
}

impl Signer for FakeSigner {
    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn public_key_der(&self) -> Result<Vec<u8>, ChainkeeperError> {
        Ok(self.public_key_der.clone())
    }

    fn sign(&self, message: &[u8], scheme: SignatureScheme) -> Result<Vec<u8>, ChainkeeperError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ChainkeeperError::crypto("fake signer failure"));
        }
        if scheme != SignatureScheme::from_key_algorithm(self.algorithm) {
            return Err(ChainkeeperError::crypto(
                "signature scheme does not match signer algorithm",
            ));
        }
        Ok(Sha256::digest(message).to_vec())
    }
}
