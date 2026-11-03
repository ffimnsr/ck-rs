#![allow(dead_code)]

//! Shared publish test harness.

use std::sync::Arc;

use chainkeeper_core::{
    AuthorityName, CertificateStore as _, ChainkeeperError, CrlManager as _, GitRepository as _,
    KeyAlgorithm, ProfileName, RevocationReason, RevocationRecord, Serial, Signer, TenantConfig,
    TenantId,
};
use chainkeeper_publish::{
    AuthorityProviders, AuthoritySigners, CrlDependencies, FileCrlManager, FilePublishBuilder,
    PublishDependencies,
};
use chainkeeper_store::FileStore;
use chainkeeper_testkit::{
    CertificateFixtures, FakeCertificateProvider, FakeClock, FakeSigner, InMemoryAuditLog,
    InMemoryGitRepository, InMemoryIndexStore, TempTenant,
};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

/// Fixed test time shared by every double.
pub const NOW: OffsetDateTime = datetime!(2024-06-01 00:00:00 UTC);

/// Signer resolver that returns a deterministic signer for every authority.
#[derive(Debug, Clone, Copy, Default)]
pub struct TestSigners;

impl AuthoritySigners for TestSigners {
    fn signer_for(&self, _authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        Ok(Arc::new(FakeSigner::new(KeyAlgorithm::EcdsaP256)))
    }
}

/// Signer resolver that always fails.
#[derive(Debug, Clone, Copy, Default)]
pub struct MissingSigners;

impl AuthoritySigners for MissingSigners {
    fn signer_for(&self, authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        Err(ChainkeeperError::not_found(
            "authority key",
            authority.as_str(),
        ))
    }
}

/// Repository fixture with public authorities, one leaf, and an empty index.
pub struct Harness {
    tenant: TempTenant,
    pub clock: Arc<FakeClock>,
    pub store: Arc<FileStore>,
    pub audit: Arc<InMemoryAuditLog>,
    pub index: Arc<InMemoryIndexStore>,
    pub git: Arc<InMemoryGitRepository>,
    pub provider: Arc<FakeCertificateProvider>,
    pub fixtures: CertificateFixtures,
}

impl Harness {
    /// Builds a repository and writes the default fixture hierarchy.
    ///
    /// # Errors
    ///
    /// Returns the first fixture, store, or Git error.
    pub fn new() -> Result<Self, ChainkeeperError> {
        let tenant = TempTenant::new()?;
        let clock = Arc::new(FakeClock::new(NOW));
        let store = Arc::new(FileStore::with_clock(
            tenant.paths().clone(),
            Arc::clone(&clock) as Arc<dyn chainkeeper_core::Clock>,
        ));
        store.write_tenant(&TenantConfig::new(
            TenantId::new("acme")?,
            "Acme",
            ProfileName::new("tls-server")?,
            NOW,
        ))?;

        let provider = Arc::new(FakeCertificateProvider::with_time(NOW)?);
        let fixtures = provider.fixtures().clone();
        store.write_authority(&fixtures.root)?;
        store.write_authority(&fixtures.tls)?;
        store.write_authority(&fixtures.smime)?;
        store.write_certificate(&fixtures.leaf)?;

        let git = Arc::new(InMemoryGitRepository::new());
        git.init(tenant.paths().root())?;

        Ok(Self {
            tenant,
            clock,
            store,
            audit: Arc::new(InMemoryAuditLog::new()),
            index: Arc::new(InMemoryIndexStore::new()),
            git,
            provider,
            fixtures,
        })
    }

    /// Repository paths.
    #[must_use]
    pub const fn paths(&self) -> &chainkeeper_core::RepositoryPaths {
        self.tenant.paths()
    }

    /// Absolute path of `relative` inside the repository.
    #[must_use]
    pub fn absolute(&self, relative: &str) -> std::path::PathBuf {
        self.paths().root().join(relative)
    }

    /// Writes a revocation for `serial` at the fixed clock.
    ///
    /// # Errors
    ///
    /// Returns a store error when the record cannot be written.
    pub fn revoke(
        &self,
        serial: &Serial,
        authority: &AuthorityName,
    ) -> Result<RevocationRecord, ChainkeeperError> {
        let record = RevocationRecord {
            version: chainkeeper_core::CONFIG_VERSION,
            serial: serial.clone(),
            authority: authority.clone(),
            reason: RevocationReason::KeyCompromise,
            comment: None,
            revoked_at: NOW,
            crl_number: 0,
        };
        self.store.write_revocation(&record)?;
        Ok(record)
    }

    /// Builds a CRL manager with the given signer resolver.
    #[must_use]
    pub fn crl_manager(&self, signers: Arc<dyn AuthoritySigners>) -> FileCrlManager {
        let provider = Arc::clone(&self.provider);
        let providers: Arc<dyn AuthorityProviders> = Arc::new(move |_: &AuthorityName| {
            Ok(Arc::clone(&provider) as Arc<dyn chainkeeper_core::CertificateProvider>)
        });
        FileCrlManager::new(CrlDependencies {
            clock: Arc::clone(&self.clock) as Arc<dyn chainkeeper_core::Clock>,
            store: Arc::clone(&self.store) as Arc<dyn chainkeeper_core::CertificateStore>,
            signers,
            providers,
            audit: Arc::clone(&self.audit) as Arc<dyn chainkeeper_core::AuditLog>,
            index: Arc::clone(&self.index) as Arc<dyn chainkeeper_core::IndexStore>,
            paths: self.paths().clone(),
        })
    }

    /// Builds a publish builder restricted to the repository root.
    #[must_use]
    pub fn publisher(&self) -> FilePublishBuilder {
        FilePublishBuilder::new(PublishDependencies::new(
            Arc::clone(&self.clock) as Arc<dyn chainkeeper_core::Clock>,
            Arc::clone(&self.store) as Arc<dyn chainkeeper_core::CertificateStore>,
            Arc::clone(&self.git) as Arc<dyn chainkeeper_core::GitRepository>,
            self.paths().clone(),
        ))
    }

    /// Seeds a CRL through the manager so publish tests have CRL artifacts.
    ///
    /// # Errors
    ///
    /// Returns a CRL generation error.
    pub fn seed_crl(&self, authority: &AuthorityName) -> Result<(), ChainkeeperError> {
        self.crl_manager(Arc::new(TestSigners))
            .update_for_authority(authority)?;
        Ok(())
    }
}

/// Returns the leaf serial used by the fixtures.
///
/// # Errors
///
/// Returns a validation error for an invalid serial literal.
pub fn leaf_serial() -> Result<Serial, ChainkeeperError> {
    Serial::new("000A")
}

/// Returns a serial that is not issued by the fixtures.
///
/// # Errors
///
/// Returns a validation error for an invalid serial literal.
pub fn other_serial() -> Result<Serial, ChainkeeperError> {
    Serial::new("000B")
}

/// Returns the fixed `tls` authority name.
///
/// # Errors
///
/// Returns a validation error for an invalid authority literal.
pub fn tls() -> Result<AuthorityName, ChainkeeperError> {
    AuthorityName::new("tls")
}

/// Returns the fixed `smime` authority name.
///
/// # Errors
///
/// Returns a validation error for an invalid authority literal.
pub fn smime() -> Result<AuthorityName, ChainkeeperError> {
    AuthorityName::new("smime")
}

/// Returns a revocation record for `serial`.
#[must_use]
pub fn revocation(serial: &Serial, authority: &AuthorityName) -> RevocationRecord {
    RevocationRecord {
        version: chainkeeper_core::CONFIG_VERSION,
        serial: serial.clone(),
        authority: authority.clone(),
        reason: RevocationReason::Superseded,
        comment: Some("test".to_owned()),
        revoked_at: NOW,
        crl_number: 1,
    }
}

/// Returns a time offset from the fixed test time.
#[must_use]
pub fn later(days: i64) -> OffsetDateTime {
    NOW + Duration::days(days)
}
