//! Engine dependency bundle.

use std::sync::Arc;

use chainkeeper_core::{
    AuditLog, AuthorityName, CertificateProvider, CertificateStore, ChainkeeperError, Clock,
    CrlManager, GitRepository, IdGenerator, IndexStore, PolicyEngine, ProfileRegistry,
    PublishBuilder, RepositoryLock, RepositoryPaths, Signer,
};

/// Resolves the signing key for an authority.
///
/// Authority keys are intentionally not exposed through [`CertificateStore`], so
/// the engine needs an injected resolver. Production wires a file-backed
/// resolver; tests wire a deterministic double.
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

/// Every collaborator an [`super::Engine`] needs.
#[derive(Clone)]
pub struct EngineDependencies {
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// ULID and serial generator.
    pub ids: Arc<dyn IdGenerator>,
    /// X.509 provider.
    pub provider: Arc<dyn CertificateProvider>,
    /// Canonical store.
    pub store: Arc<dyn CertificateStore>,
    /// Disposable index.
    pub index: Arc<dyn IndexStore>,
    /// Profile registry.
    pub profiles: Arc<dyn ProfileRegistry>,
    /// Policy engine.
    pub policy: Arc<dyn PolicyEngine>,
    /// Append-only audit log.
    pub audit: Arc<dyn AuditLog>,
    /// Git repository.
    pub git: Arc<dyn GitRepository>,
    /// Repository lock.
    pub lock: Arc<dyn RepositoryLock>,
    /// CRL manager.
    pub crl: Arc<dyn CrlManager>,
    /// Publication builder.
    pub publish: Arc<dyn PublishBuilder>,
    /// Authority signing keys.
    pub signers: Arc<dyn AuthoritySigners>,
    /// Repository layout.
    pub paths: RepositoryPaths,
}

impl std::fmt::Debug for EngineDependencies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EngineDependencies")
            .field("root", &self.paths.root())
            .finish_non_exhaustive()
    }
}
