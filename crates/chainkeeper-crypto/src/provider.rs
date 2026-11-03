//! OpenSSL-backed [`CertificateProvider`] implementation.

use std::fmt;
use std::sync::Arc;

use chainkeeper_core::{
    AuthorityBundle, AuthorityMaterial, CertificateProvider, ChainkeeperError, Clock,
    CreateAuthorityRequest, CreateOcspSignerRequest, CrlBundle, CrlRequest, IdGenerator,
    IssueRequest, IssuedCertificate, KeyAlgorithm, KeyMaterial, ProductionIdGenerator, Profile,
    Signer, SignerBundle, SystemClock, TenantConfig,
};

use crate::authority;
use crate::crl;
use crate::keygen;
use crate::leaf::{self, IssueContext};
use crate::secret::SecretString;

/// In-process X.509 provider backed by the `openssl` crate.
///
/// The provider never shells out to the `openssl` binary. Authority creation
/// always generates a fresh key pair; leaf issuance uses the configured issuer
/// material and signing key.
pub struct OpenSslProvider {
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    passphrase: Option<SecretString>,
    issuer: Option<AuthorityMaterial>,
    tenant: Option<TenantConfig>,
    profile: Option<Profile>,
}

impl fmt::Debug for OpenSslProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenSslProvider")
            .field(
                "issuer",
                &self.issuer.as_ref().map(|material| &material.config.name),
            )
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl OpenSslProvider {
    /// Creates a provider with explicit clock and identifier sources.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, ids: Arc<dyn IdGenerator>) -> Self {
        Self {
            clock,
            ids,
            passphrase: None,
            issuer: None,
            tenant: None,
            profile: None,
        }
    }

    /// Sets the passphrase used to encrypt generated private keys.
    #[must_use]
    pub fn with_passphrase(mut self, passphrase: SecretString) -> Self {
        self.passphrase = Some(passphrase);
        self
    }

    /// Sets the issuing authority used by [`CertificateProvider::issue`] and
    /// [`CertificateProvider::generate_crl`].
    #[must_use]
    pub fn with_issuer(mut self, issuer: AuthorityMaterial) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Sets the repository configuration used for AIA and CRL URLs.
    #[must_use]
    pub fn with_tenant(mut self, tenant: TenantConfig) -> Self {
        self.tenant = Some(tenant);
        self
    }

    /// Sets the profile used by [`CertificateProvider::issue`].
    ///
    /// When unset the provider falls back to the built-in profile registry.
    #[must_use]
    pub fn with_profile(mut self, profile: Profile) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Issuing authority currently configured, if any.
    #[must_use]
    pub const fn issuer(&self) -> Option<&AuthorityMaterial> {
        self.issuer.as_ref()
    }

    fn require_issuer(&self) -> Result<&AuthorityMaterial, ChainkeeperError> {
        self.issuer.as_ref().ok_or_else(|| {
            ChainkeeperError::crypto("issuing authority context is required for this operation")
        })
    }
}

impl Default for OpenSslProvider {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock), Arc::new(ProductionIdGenerator))
    }
}

impl CertificateProvider for OpenSslProvider {
    fn generate_key(&self, algorithm: KeyAlgorithm) -> Result<KeyMaterial, ChainkeeperError> {
        Ok(keygen::generate(algorithm, self.passphrase.as_ref())?.material)
    }

    fn create_root(
        &self,
        request: &CreateAuthorityRequest,
    ) -> Result<AuthorityBundle, ChainkeeperError> {
        authority::create_root(
            request,
            self.clock.as_ref(),
            self.ids.as_ref(),
            self.passphrase.as_ref(),
        )
    }

    fn create_intermediate(
        &self,
        request: &CreateAuthorityRequest,
        parent: &AuthorityMaterial,
        parent_signer: &dyn Signer,
    ) -> Result<AuthorityBundle, ChainkeeperError> {
        authority::create_intermediate(
            request,
            parent,
            parent_signer,
            self.clock.as_ref(),
            self.ids.as_ref(),
            self.passphrase.as_ref(),
        )
    }

    fn create_ocsp_signer(
        &self,
        request: &CreateOcspSignerRequest,
        parent: &AuthorityMaterial,
        parent_signer: &dyn Signer,
    ) -> Result<SignerBundle, ChainkeeperError> {
        authority::create_ocsp_signer(
            request,
            parent,
            parent_signer,
            self.clock.as_ref(),
            self.ids.as_ref(),
            self.passphrase.as_ref(),
        )
    }

    fn issue(
        &self,
        request: &IssueRequest,
        signer: &dyn Signer,
    ) -> Result<IssuedCertificate, ChainkeeperError> {
        let issuer = self.require_issuer()?;
        let context = IssueContext {
            issuer,
            tenant: self.tenant.as_ref(),
            profile: self.profile.as_ref(),
            clock: self.clock.as_ref(),
            ids: self.ids.as_ref(),
            passphrase: self.passphrase.as_ref(),
        };
        leaf::issue(request, signer, &context)
    }

    fn generate_crl(
        &self,
        request: &CrlRequest,
        signer: &dyn Signer,
    ) -> Result<CrlBundle, ChainkeeperError> {
        let issuer = self.require_issuer()?;
        crl::generate(request, issuer, signer)
    }
}
