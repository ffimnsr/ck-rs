//! Snapshot construction tests.

mod support;

use std::sync::Arc;

use chainkeeper_core::{CertificateStore, RevocationReason, RevocationRecord, ServerStateProvider};
use chainkeeper_server::snapshot::{RepositoryDeps, RepositoryStateProvider};
use chainkeeper_testkit::{
    CertificateFixtures, InMemoryAuditLog, InMemoryCertificateStore, InMemoryGitRepository,
};
use time::Duration;

fn deps(store: Arc<InMemoryCertificateStore>, publish_dir: &std::path::Path) -> RepositoryDeps {
    let git = Arc::new(InMemoryGitRepository::new());
    chainkeeper_core::GitRepository::init(git.as_ref(), std::path::Path::new("."))
        .expect("initial commit");
    RepositoryDeps {
        clock: Arc::new(chainkeeper_core::SystemClock),
        store,
        audit: Arc::new(InMemoryAuditLog::new()),
        git,
        publish_dir: publish_dir.to_path_buf(),
    }
}

fn seeded_store() -> (Arc<InMemoryCertificateStore>, CertificateFixtures) {
    let fixtures = CertificateFixtures::generate(support::now()).expect("fixtures");
    let store = Arc::new(InMemoryCertificateStore::new());
    store.write_authority(&fixtures.root).expect("root");
    store.write_authority(&fixtures.tls).expect("tls");
    store
        .write_certificate(&fixtures.leaf)
        .expect("leaf certificate");
    (store, fixtures)
}

#[test]
fn snapshot_is_built_from_the_store_and_manifest() {
    let fixture = support::fixture();
    let (store, fixtures) = seeded_store();
    let provider =
        RepositoryStateProvider::open(deps(store, fixture.directory.path())).expect("snapshot");

    let snapshot = provider.snapshot();
    assert_ne!(snapshot.repo_commit.len(), 0);
    assert_eq!(snapshot.certificates.len(), 1);
    assert_eq!(snapshot.certificates[0].serial, fixtures.leaf.record.serial);
    assert_eq!(snapshot.authorities.len(), 2);
    assert!(snapshot.manifest.is_some());
    assert_eq!(snapshot.audit_events.len(), 0);

    let health = provider.health();
    assert_eq!(health.status, chainkeeper_core::HealthStatus::Ok);
    assert_eq!(
        health.repo_commit.as_deref(),
        Some(snapshot.repo_commit.as_str())
    );
}

#[test]
fn successful_reload_replaces_the_snapshot() {
    let fixture = support::fixture();
    let (store, fixtures) = seeded_store();
    let provider =
        RepositoryStateProvider::open(deps(Arc::clone(&store), fixture.directory.path()))
            .expect("snapshot");
    let before = provider.snapshot();
    assert_eq!(before.revocations.len(), 0);

    store
        .write_revocation(&RevocationRecord {
            version: chainkeeper_core::CONFIG_VERSION,
            serial: fixtures.leaf.record.serial.clone(),
            authority: fixtures.leaf.record.authority,
            reason: RevocationReason::KeyCompromise,
            comment: None,
            revoked_at: support::now() + Duration::days(1),
            crl_number: 1,
        })
        .expect("revocation");

    let after = provider.reload().expect("reload");
    assert!(!Arc::ptr_eq(&before, &after));
    assert_eq!(after.revocations.len(), 1);
    assert_eq!(provider.snapshot().revocations.len(), 1);
    assert_eq!(provider.health().status, chainkeeper_core::HealthStatus::Ok);
}

#[test]
fn corrupt_repository_fails_at_startup() {
    let fixture = support::fixture();
    let (store, _fixtures) = seeded_store();
    let mut deps = deps(store, fixture.directory.path());
    deps.git = Arc::new(InMemoryGitRepository::new());
    let error = RepositoryStateProvider::open(deps).expect_err("no commits");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::NotFound);
}

#[test]
fn missing_manifest_is_allowed_but_empty_summary() {
    let directory = tempfile::tempdir().expect("publish dir");
    let (store, _fixtures) = seeded_store();
    let provider = RepositoryStateProvider::open(deps(store, directory.path())).expect("snapshot");
    let snapshot = provider.snapshot();
    assert!(snapshot.manifest.is_none());
    assert_eq!(snapshot.certificates.len(), 1);
}

/// Store wrapper that records whether authority material was loaded.
struct SpyStore {
    inner: Arc<InMemoryCertificateStore>,
    loaded: Arc<std::sync::atomic::AtomicBool>,
}

impl chainkeeper_core::CertificateStore for SpyStore {
    fn load_tenant(
        &self,
    ) -> Result<chainkeeper_core::TenantConfig, chainkeeper_core::ChainkeeperError> {
        self.inner.load_tenant()
    }

    fn load_policy(&self) -> Result<chainkeeper_core::Policy, chainkeeper_core::ChainkeeperError> {
        self.inner.load_policy()
    }

    fn load_profiles(
        &self,
    ) -> Result<Vec<chainkeeper_core::Profile>, chainkeeper_core::ChainkeeperError> {
        self.inner.load_profiles()
    }

    fn write_certificate(
        &self,
        certificate: &chainkeeper_core::IssuedCertificate,
    ) -> Result<std::path::PathBuf, chainkeeper_core::ChainkeeperError> {
        self.inner.write_certificate(certificate)
    }

    fn get_certificate(
        &self,
        serial: &chainkeeper_core::Serial,
    ) -> Result<Option<chainkeeper_core::CertificateRecord>, chainkeeper_core::ChainkeeperError>
    {
        self.inner.get_certificate(serial)
    }

    fn list_certificates(
        &self,
    ) -> Result<Vec<chainkeeper_core::CertificateRecord>, chainkeeper_core::ChainkeeperError> {
        self.inner.list_certificates()
    }

    fn move_certificate(
        &self,
        serial: &chainkeeper_core::Serial,
        to: chainkeeper_core::CertificateStatus,
    ) -> Result<(), chainkeeper_core::ChainkeeperError> {
        self.inner.move_certificate(serial, to)
    }

    fn write_revocation(
        &self,
        record: &chainkeeper_core::RevocationRecord,
    ) -> Result<std::path::PathBuf, chainkeeper_core::ChainkeeperError> {
        self.inner.write_revocation(record)
    }

    fn list_revocations(
        &self,
    ) -> Result<Vec<chainkeeper_core::RevocationRecord>, chainkeeper_core::ChainkeeperError> {
        self.inner.list_revocations()
    }

    fn write_authority(
        &self,
        bundle: &chainkeeper_core::AuthorityBundle,
    ) -> Result<(), chainkeeper_core::ChainkeeperError> {
        self.inner.write_authority(bundle)
    }

    fn load_authority(
        &self,
        name: &chainkeeper_core::AuthorityName,
    ) -> Result<Option<chainkeeper_core::AuthorityMaterial>, chainkeeper_core::ChainkeeperError>
    {
        self.loaded.store(true, std::sync::atomic::Ordering::SeqCst);
        self.inner.load_authority(name)
    }

    fn list_authorities(
        &self,
    ) -> Result<Vec<chainkeeper_core::AuthorityRecord>, chainkeeper_core::ChainkeeperError> {
        self.inner.list_authorities()
    }
}

#[test]
fn snapshot_build_does_not_load_authority_material() {
    let fixture = support::fixture();
    let (inner, _fixtures) = seeded_store();
    let loaded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let store = Arc::new(SpyStore {
        inner,
        loaded: Arc::clone(&loaded),
    });
    let git = Arc::new(InMemoryGitRepository::new());
    chainkeeper_core::GitRepository::init(git.as_ref(), std::path::Path::new("."))
        .expect("initial commit");
    let provider = RepositoryStateProvider::open(RepositoryDeps {
        clock: Arc::new(chainkeeper_core::SystemClock),
        store,
        audit: Arc::new(InMemoryAuditLog::new()),
        git,
        publish_dir: fixture.directory.path().to_path_buf(),
    })
    .expect("snapshot");

    assert!(!loaded.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(provider.snapshot().certificates.len(), 1);
}
