//! Verifies that every frozen trait can be stored as an `Arc<dyn Trait>`.

use std::sync::Arc;
use std::time::Duration;

use chainkeeper_core::{
    AuditLog, CertificateProvider, CertificateStore, ChainkeeperService, Clock, CrlManager,
    GitRepository, IdGenerator, IndexStore, OcspResponder, PolicyEngine, ProfileRegistry,
    PublishBuilder, RepositoryLock, ServerStateProvider, Signer,
};
use chainkeeper_testkit::{
    FakeCertificateProvider, FakeChainkeeperService, FakeClock, FakeCrlManager, FakeIdGenerator,
    FakeOcspResponder, FakePublishBuilder, FakeRepositoryLock, FakeServerStateProvider, FakeSigner,
    InMemoryAuditLog, InMemoryCertificateStore, InMemoryGitRepository, InMemoryIndexStore,
    InMemoryProfileRegistry, NoopPolicyEngine,
};

#[test]
fn every_trait_is_object_safe() {
    let clock: Arc<dyn Clock> = Arc::new(FakeClock::default());
    let ids: Arc<dyn IdGenerator> = Arc::new(FakeIdGenerator::new());
    let signer: Arc<dyn Signer> =
        Arc::new(FakeSigner::new(chainkeeper_core::KeyAlgorithm::EcdsaP256));
    let provider: Arc<dyn CertificateProvider> =
        Arc::new(FakeCertificateProvider::new().expect("fixtures"));
    let store: Arc<dyn CertificateStore> = Arc::new(InMemoryCertificateStore::new());
    let index: Arc<dyn IndexStore> = Arc::new(InMemoryIndexStore::new());
    let profiles: Arc<dyn ProfileRegistry> = Arc::new(InMemoryProfileRegistry::new());
    let policy: Arc<dyn PolicyEngine> = Arc::new(NoopPolicyEngine);
    let audit: Arc<dyn AuditLog> = Arc::new(InMemoryAuditLog::new());
    let git: Arc<dyn GitRepository> = Arc::new(InMemoryGitRepository::new());
    let lock: Arc<dyn RepositoryLock> = Arc::new(FakeRepositoryLock::new());
    let crls: Arc<dyn CrlManager> = Arc::new(FakeCrlManager::new());
    let publish: Arc<dyn PublishBuilder> = Arc::new(FakePublishBuilder::new());
    let ocsp: Arc<dyn OcspResponder> = Arc::new(FakeOcspResponder::new());
    let service: Arc<dyn ChainkeeperService> = Arc::new(FakeChainkeeperService::new());
    let state: Arc<dyn ServerStateProvider> = Arc::new(FakeServerStateProvider::new());

    assert_eq!(clock.now(), FakeClock::default().now());
    assert!(ids.serial().as_str().len() >= 2);
    assert_eq!(
        signer.algorithm(),
        chainkeeper_core::KeyAlgorithm::EcdsaP256
    );
    assert!(
        provider
            .generate_key(chainkeeper_core::KeyAlgorithm::EcdsaP256)
            .is_ok()
    );
    assert!(store.load_tenant().is_err());
    assert!(index.stats().is_ok());
    assert_eq!(profiles.list().len(), 6);
    assert!(
        policy
            .validate_profile(
                &chainkeeper_core::Policy::default(),
                &chainkeeper_core::builtin_profiles()[0]
            )
            .is_ok()
    );
    assert_eq!(audit.next_seq().expect("sequence"), 1);
    assert!(git.is_clean().expect("status"));
    assert!(
        lock.acquire_exclusive(Duration::from_millis(10))
            .expect("lock acquired")
            .path()
            .is_some()
    );
    assert_eq!(crls.list_crls().expect("crls").len(), 0);
    assert!(
        publish
            .validate_publish_dir(std::path::Path::new("/nonexistent"))
            .is_err()
    );
    assert!(ocsp.ready());
    assert_eq!(service.tree().expect("tree").roots.len(), 0);
    assert_ne!(state.snapshot().repo_commit.len(), 0);
}
