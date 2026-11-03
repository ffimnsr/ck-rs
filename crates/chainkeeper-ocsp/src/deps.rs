//! OCSP responder dependency bundle.

use std::sync::Arc;

use chainkeeper_core::{
    AuthorityName, CertificateStore, ChainkeeperError, Clock, RepositoryPaths, Signer,
};

/// Resolves the private key of the dedicated OCSP signer.
///
/// The canonical store never exposes private keys, so the responder needs an
/// injected resolver. Production wires a file-backed resolver; tests wire a
/// deterministic double.
pub trait AuthoritySigners: Send + Sync {
    /// Returns the signer for `authority`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when the authority has no key, or
    /// [`ChainkeeperError::Crypto`] when the key cannot be loaded.
    fn signer_for(&self, authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError>;
}

impl<F> AuthoritySigners for F
where
    F: Fn(&AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> + Send + Sync,
{
    fn signer_for(&self, authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        self(authority)
    }
}

/// Every collaborator a [`crate::FileOcspResponder`] needs.
#[derive(Clone)]
pub struct OcspDependencies {
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Canonical store.
    pub store: Arc<dyn CertificateStore>,
    /// OCSP signer private key.
    pub signers: Arc<dyn AuthoritySigners>,
    /// Repository layout.
    pub paths: RepositoryPaths,
    /// Authority name of the dedicated OCSP signer.
    pub ocsp_signer: AuthorityName,
}

impl OcspDependencies {
    /// Builds a dependency bundle.
    #[must_use]
    pub const fn new(
        clock: Arc<dyn Clock>,
        store: Arc<dyn CertificateStore>,
        signers: Arc<dyn AuthoritySigners>,
        paths: RepositoryPaths,
        ocsp_signer: AuthorityName,
    ) -> Self {
        Self {
            clock,
            store,
            signers,
            paths,
            ocsp_signer,
        }
    }
}

impl std::fmt::Debug for OcspDependencies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OcspDependencies")
            .field("root", &self.paths.root())
            .field("ocsp_signer", &self.ocsp_signer)
            .finish_non_exhaustive()
    }
}
