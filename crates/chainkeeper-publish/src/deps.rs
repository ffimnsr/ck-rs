//! Dependency bundles for the CRL manager and publish builder.

use std::path::PathBuf;
use std::sync::Arc;

use chainkeeper_core::{
    AuditLog, AuthorityName, CertificateProvider, CertificateStore, ChainkeeperError, Clock,
    GitRepository, IndexStore, RepositoryPaths, Signer,
};

/// Resolves the signing key for an authority.
///
/// The canonical store never exposes private keys, so CRL generation needs an
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

/// Resolves the certificate provider configured for an authority.
///
/// [`CertificateProvider::generate_crl`] signs with issuer material supplied by
/// the provider, so a multi-authority repository needs one provider per
/// authority.
pub trait AuthorityProviders: Send + Sync {
    /// Returns the provider for `authority`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when no provider is configured.
    fn provider_for(
        &self,
        authority: &AuthorityName,
    ) -> Result<Arc<dyn CertificateProvider>, ChainkeeperError>;
}

impl<F> AuthorityProviders for F
where
    F: Fn(&AuthorityName) -> Result<Arc<dyn CertificateProvider>, ChainkeeperError> + Send + Sync,
{
    fn provider_for(
        &self,
        authority: &AuthorityName,
    ) -> Result<Arc<dyn CertificateProvider>, ChainkeeperError> {
        self(authority)
    }
}

/// Every collaborator a [`super::FileCrlManager`] needs.
#[derive(Clone)]
pub struct CrlDependencies {
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Canonical store.
    pub store: Arc<dyn CertificateStore>,
    /// Authority signing keys.
    pub signers: Arc<dyn AuthoritySigners>,
    /// Per-authority certificate providers.
    pub providers: Arc<dyn AuthorityProviders>,
    /// Append-only audit log.
    pub audit: Arc<dyn AuditLog>,
    /// Disposable index.
    pub index: Arc<dyn IndexStore>,
    /// Repository layout.
    pub paths: RepositoryPaths,
}

impl std::fmt::Debug for CrlDependencies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CrlDependencies")
            .field("root", &self.paths.root())
            .finish_non_exhaustive()
    }
}

/// Every collaborator a [`super::FilePublishBuilder`] needs.
#[derive(Clone)]
pub struct PublishDependencies {
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Canonical store.
    pub store: Arc<dyn CertificateStore>,
    /// Git repository used to record the source commit.
    pub git: Arc<dyn GitRepository>,
    /// Repository layout.
    pub paths: RepositoryPaths,
    /// Directory a publish destination must stay inside.
    pub allowed_root: PathBuf,
}

impl PublishDependencies {
    /// Builds dependencies whose destination is restricted to the repository.
    #[must_use]
    pub fn new(
        clock: Arc<dyn Clock>,
        store: Arc<dyn CertificateStore>,
        git: Arc<dyn GitRepository>,
        paths: RepositoryPaths,
    ) -> Self {
        let allowed_root = paths.root().to_path_buf();
        Self {
            clock,
            store,
            git,
            paths,
            allowed_root,
        }
    }

    /// Overrides the directory a publish destination must stay inside.
    #[must_use]
    pub fn with_allowed_root(mut self, allowed_root: impl Into<PathBuf>) -> Self {
        self.allowed_root = allowed_root.into();
        self
    }
}

impl std::fmt::Debug for PublishDependencies {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublishDependencies")
            .field("root", &self.paths.root())
            .field("allowed_root", &self.allowed_root)
            .finish_non_exhaustive()
    }
}
