//! Shared engine test fixture.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use chainkeeper_core::{
    AuditEvent, AuditLog, AuditQuery, AuthorityBundle, AuthorityConfig, AuthorityKind,
    AuthorityMaterial, AuthorityName, AuthorityRecord, CertificateRecord, CertificateStatus,
    CertificateStore, ChainkeeperError, ChainkeeperService, FileMode, GitChange, GitRepository,
    GitStatus, IndexRecords, IndexReport, IssuedCertificate, KeyAlgorithm, KeyMaterial,
    NewAuditEvent, Policy, Profile, ProfileName, RepositoryPaths, RevocationRecord, Serial, Signer,
    TenantConfig, atomic_write,
};
use chainkeeper_engine::{AuthoritySigners, Engine, EngineDependencies};
use chainkeeper_testkit::{
    FakeCertificateProvider, FakeClock, FakeCrlManager, FakeIdGenerator, FakePublishBuilder,
    FakeRepositoryLock, FakeSigner, InMemoryAuditLog, InMemoryCertificateStore,
    InMemoryGitRepository, InMemoryIndexStore, InMemoryProfileRegistry,
};
use tempfile::TempDir;
use time::OffsetDateTime;
use time::macros::datetime;

/// Fixed engine clock.
pub const NOW: OffsetDateTime = datetime!(2024-06-01 00:00:00 UTC);

fn tenant_config() -> TenantConfig {
    TenantConfig::new(
        chainkeeper_core::TenantId::new("acme").expect("tenant"),
        "Acme",
        ProfileName::new("tls-server").expect("profile"),
        datetime!(2024-01-01 00:00:00 UTC),
    )
}

/// Certificate store that mirrors writes into the temporary repository.
pub struct MirroringStore {
    inner: InMemoryCertificateStore,
    root: PathBuf,
}

impl MirroringStore {
    /// Creates a store rooted at `root`.
    #[must_use]
    pub fn new(root: &Path) -> Self {
        Self {
            inner: InMemoryCertificateStore::with_config(tenant_config(), Policy::default()),
            root: root.to_path_buf(),
        }
    }

    /// Replaces the policy.
    pub fn set_policy(&self, policy: Policy) {
        self.inner.set_policy(policy);
    }

    /// Replaces a profile.
    pub fn set_profile(&self, profile: Profile) {
        self.inner.set_profile(profile);
    }

    /// Replaces stored authority material.
    pub fn set_authority_material(&self, material: AuthorityMaterial) {
        let bundle = AuthorityBundle::new(material, key_material());
        self.inner
            .write_authority(&bundle)
            .expect("inner authority write");
        self.mirror_authority(&bundle);
    }

    /// Inserts an authority record with an arbitrary configuration.
    pub fn insert_authority(&self, config: AuthorityConfig) {
        let material = AuthorityMaterial::new(
            config,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        );
        let bundle = AuthorityBundle::new(material, key_material());
        self.inner
            .write_authority(&bundle)
            .expect("inner authority write");
        self.mirror_authority(&bundle);
    }

    fn mirror_authority(&self, bundle: &AuthorityBundle) {
        let directory = self
            .root
            .join("authorities")
            .join(bundle.material.config.name.as_str());
        std::fs::create_dir_all(&directory).expect("authority dir");
        let _ = atomic_write(
            &directory.join("cert.pem"),
            bundle.material.cert_pem.as_bytes(),
            FileMode::Public,
        );
        let _ = atomic_write(
            &directory.join("chain.pem"),
            bundle.material.chain_pem.as_bytes(),
            FileMode::Public,
        );
        let _ = atomic_write(
            &directory.join("authority.yaml"),
            serde_yaml_ng::to_string(&bundle.material.config)
                .expect("config yaml")
                .as_bytes(),
            FileMode::Public,
        );
        let _ = atomic_write(
            &directory.join("key.pem"),
            bundle.key.private_key_pem().as_bytes(),
            FileMode::Private,
        );
    }

    fn mirror_certificate(&self, certificate: &IssuedCertificate) {
        let record = &certificate.record;
        let path = self.root.join(&record.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("certificate dir");
        }
        let _ = atomic_write(&path, certificate.cert_pem.as_bytes(), FileMode::Public);
        let _ = atomic_write(
            &path.with_extension("yaml"),
            serde_yaml_ng::to_string(record)
                .expect("record yaml")
                .as_bytes(),
            FileMode::Public,
        );
        if let Some(key) = &certificate.key {
            let _ = atomic_write(
                &path.with_extension("key.pem"),
                key.private_key_pem().as_bytes(),
                FileMode::Private,
            );
        }
    }
}

impl CertificateStore for MirroringStore {
    fn load_tenant(&self) -> Result<TenantConfig, ChainkeeperError> {
        self.inner.load_tenant()
    }

    fn load_policy(&self) -> Result<Policy, ChainkeeperError> {
        self.inner.load_policy()
    }

    fn load_profiles(&self) -> Result<Vec<Profile>, ChainkeeperError> {
        self.inner.load_profiles()
    }

    fn write_certificate(
        &self,
        certificate: &IssuedCertificate,
    ) -> Result<PathBuf, ChainkeeperError> {
        let path = self.inner.write_certificate(certificate)?;
        self.mirror_certificate(certificate);
        Ok(path)
    }

    fn get_certificate(
        &self,
        serial: &Serial,
    ) -> Result<Option<CertificateRecord>, ChainkeeperError> {
        for status in [
            CertificateStatus::Active,
            CertificateStatus::Revoked,
            CertificateStatus::Expired,
        ] {
            let path = self
                .root
                .join("certificates")
                .join(status.as_str())
                .join(format!("{serial}.yaml"));
            match std::fs::read_to_string(&path) {
                Ok(yaml) => {
                    return serde_yaml_ng::from_str(&yaml).map(Some).map_err(|error| {
                        ChainkeeperError::storage(format!(
                            "could not parse {}: {error}",
                            path.display()
                        ))
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(ChainkeeperError::storage(format!(
                        "could not read {}: {error}",
                        path.display()
                    )));
                }
            }
        }
        Ok(None)
    }

    fn list_certificates(&self) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        let mut records: Vec<CertificateRecord> = Vec::new();
        for status in [
            CertificateStatus::Active,
            CertificateStatus::Revoked,
            CertificateStatus::Expired,
        ] {
            let directory = self.root.join("certificates").join(status.as_str());
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_none_or(|extension| extension != "yaml") {
                    continue;
                }
                let yaml = std::fs::read_to_string(&path).map_err(|error| {
                    ChainkeeperError::storage(format!("could not read {}: {error}", path.display()))
                })?;
                records.push(serde_yaml_ng::from_str(&yaml).map_err(|error| {
                    ChainkeeperError::storage(format!(
                        "could not parse {}: {error}",
                        path.display()
                    ))
                })?);
            }
        }
        records.sort_by(|left, right| left.serial.cmp(&right.serial));
        Ok(records)
    }

    fn move_certificate(
        &self,
        serial: &Serial,
        to: CertificateStatus,
    ) -> Result<(), ChainkeeperError> {
        let before = self
            .inner
            .get_certificate(serial)?
            .map(|record| record.path);
        self.inner.move_certificate(serial, to)?;
        if let Some(before) = before
            && let Some(directory) = before.parent()
        {
            let target = self.root.join("certificates").join(to.as_str());
            std::fs::create_dir_all(&target).expect("target status dir");
            for extension in ["pem", "yaml", "key.pem"] {
                let source = self
                    .root
                    .join(directory)
                    .join(format!("{serial}.{extension}"));
                let destination = target.join(format!("{serial}.{extension}"));
                if source.exists() {
                    let _ = std::fs::rename(source, destination);
                }
            }
        }
        Ok(())
    }

    fn write_revocation(&self, record: &RevocationRecord) -> Result<PathBuf, ChainkeeperError> {
        let path = self.inner.write_revocation(record)?;
        let _ = atomic_write(
            &self.root.join(&path),
            serde_yaml_ng::to_string(record)
                .expect("revocation yaml")
                .as_bytes(),
            FileMode::Public,
        );
        Ok(path)
    }

    fn list_revocations(&self) -> Result<Vec<RevocationRecord>, ChainkeeperError> {
        Ok(self
            .inner
            .list_revocations()?
            .into_iter()
            .filter(|record| {
                self.root
                    .join("revocations")
                    .join(format!("{}.yaml", record.serial))
                    .exists()
            })
            .collect())
    }

    fn write_authority(&self, bundle: &AuthorityBundle) -> Result<(), ChainkeeperError> {
        self.inner.write_authority(bundle)?;
        self.mirror_authority(bundle);
        Ok(())
    }

    fn load_authority(
        &self,
        name: &AuthorityName,
    ) -> Result<Option<AuthorityMaterial>, ChainkeeperError> {
        self.inner.load_authority(name)
    }

    fn list_authorities(&self) -> Result<Vec<AuthorityRecord>, ChainkeeperError> {
        Ok(self
            .inner
            .list_authorities()?
            .into_iter()
            .filter(|record| self.root.join(&record.cert_path).exists())
            .collect())
    }
}

fn key_material() -> KeyMaterial {
    KeyMaterial::new(
        KeyAlgorithm::EcdsaP256,
        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
        b"public".to_vec(),
    )
}

/// Git repository whose commit behaviour can be disabled.
pub struct FailingGit {
    inner: InMemoryGitRepository,
    fail: AtomicBool,
    status: RwLock<Option<GitStatus>>,
}

impl FailingGit {
    /// Wraps a fresh repository.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: InMemoryGitRepository::new(),
            fail: AtomicBool::new(false),
            status: RwLock::new(None),
        }
    }

    /// Makes every commit fail.
    pub fn fail_commits(&self) {
        self.fail.store(true, Ordering::SeqCst);
    }

    /// Overrides the reported status.
    pub fn set_status(&self, status: GitStatus) {
        *self
            .status
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(status);
    }
}

impl Default for FailingGit {
    fn default() -> Self {
        Self::new()
    }
}

impl GitRepository for FailingGit {
    fn init(&self, path: &Path) -> Result<(), ChainkeeperError> {
        self.inner.init(path)
    }

    fn head_commit(&self) -> Result<String, ChainkeeperError> {
        self.inner.head_commit()
    }

    fn commit(&self, message: &str, paths: &[PathBuf]) -> Result<String, ChainkeeperError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ChainkeeperError::git("injected commit failure"));
        }
        self.inner.commit(message, paths)
    }

    fn diff(&self, from: &str, to: &str) -> Result<Vec<GitChange>, ChainkeeperError> {
        self.inner.diff(from, to)
    }

    fn status(&self) -> Result<GitStatus, ChainkeeperError> {
        let override_status = self
            .status
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(status) = override_status {
            return Ok(status);
        }
        self.inner.status()
    }

    fn is_clean(&self) -> Result<bool, ChainkeeperError> {
        Ok(self.status()?.clean)
    }
}

/// Index that can fail the next certificate upsert.
pub struct FailingIndex {
    inner: InMemoryIndexStore,
    fail: AtomicBool,
}

impl FailingIndex {
    /// Creates an index that fails the first certificate upsert.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: InMemoryIndexStore::new(),
            fail: AtomicBool::new(true),
        }
    }
}

impl Default for FailingIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl chainkeeper_core::IndexStore for FailingIndex {
    fn rebuild(&self, records: &IndexRecords) -> Result<IndexReport, ChainkeeperError> {
        self.inner.rebuild(records)
    }

    fn query(
        &self,
        query: &chainkeeper_core::SearchQuery,
    ) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        self.inner.query(query)
    }

    fn upsert_certificate(&self, record: &CertificateRecord) -> Result<(), ChainkeeperError> {
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(ChainkeeperError::index("injected index failure"));
        }
        self.inner.upsert_certificate(record)
    }

    fn upsert_revocation(&self, record: &RevocationRecord) -> Result<(), ChainkeeperError> {
        self.inner.upsert_revocation(record)
    }

    fn upsert_authority(&self, record: &AuthorityRecord) -> Result<(), ChainkeeperError> {
        self.inner.upsert_authority(record)
    }

    fn upsert_crl(&self, crl: &chainkeeper_core::IndexedCrl) -> Result<(), ChainkeeperError> {
        self.inner.upsert_crl(crl)
    }

    fn upsert_audit_event(&self, event: &AuditEvent) -> Result<(), ChainkeeperError> {
        self.inner.upsert_audit_event(event)
    }

    fn list_audit(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        self.inner.list_audit(query)
    }

    fn count(&self, query: &chainkeeper_core::SearchQuery) -> Result<u64, ChainkeeperError> {
        self.inner.count(query)
    }

    fn stats(&self) -> Result<chainkeeper_core::IndexStats, ChainkeeperError> {
        self.inner.stats()
    }

    fn schema_version(&self) -> Result<u32, ChainkeeperError> {
        self.inner.schema_version()
    }
}

/// Audit log that fails every append.
#[derive(Debug, Default)]
pub struct FailingAudit {
    inner: InMemoryAuditLog,
}

impl AuditLog for FailingAudit {
    fn append(&self, _event: NewAuditEvent) -> Result<AuditEvent, ChainkeeperError> {
        Err(ChainkeeperError::audit("injected audit failure"))
    }

    fn list(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        self.inner.list(query)
    }

    fn next_seq(&self) -> Result<u64, ChainkeeperError> {
        self.inner.next_seq()
    }
}

/// Audit log that succeeds a fixed number of times before failing.
#[derive(Debug)]
pub struct FailingAfterAudit {
    inner: InMemoryAuditLog,
    remaining: std::sync::atomic::AtomicUsize,
}

impl FailingAfterAudit {
    /// Allows `succeeding` appends before failing.
    #[must_use]
    pub fn new(succeeding: usize) -> Self {
        Self {
            inner: InMemoryAuditLog::new(),
            remaining: std::sync::atomic::AtomicUsize::new(succeeding),
        }
    }
}

impl AuditLog for FailingAfterAudit {
    fn append(&self, event: NewAuditEvent) -> Result<AuditEvent, ChainkeeperError> {
        let remaining = self.remaining.load(Ordering::SeqCst);
        if remaining == 0 {
            return Err(ChainkeeperError::audit("injected audit failure"));
        }
        self.remaining.store(remaining - 1, Ordering::SeqCst);
        self.inner.append(event)
    }

    fn list(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        self.inner.list(query)
    }

    fn next_seq(&self) -> Result<u64, ChainkeeperError> {
        self.inner.next_seq()
    }
}

/// Audit log returning duplicate event identifiers.
#[derive(Debug, Default)]
pub struct DuplicateAudit;

impl AuditLog for DuplicateAudit {
    fn append(&self, _event: NewAuditEvent) -> Result<AuditEvent, ChainkeeperError> {
        Err(ChainkeeperError::audit("duplicate audit log is read only"))
    }

    fn list(&self, _query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        let first = AuditEvent {
            id: chainkeeper_core::EventId::new("01J00000000000000000000001")?,
            seq: 1,
            timestamp: NOW,
            action: chainkeeper_core::AuditAction::RepoInitialized,
            object_type: "repository".to_owned(),
            object_id: "acme".to_owned(),
            summary: "first".to_owned(),
            actor: "test".to_owned(),
            details: serde_json::Value::Null,
        };
        Ok(vec![first.clone(), first])
    }

    fn next_seq(&self) -> Result<u64, ChainkeeperError> {
        Ok(3)
    }
}

/// CRL manager that always fails.
#[derive(Debug, Default)]
pub struct FailingCrl;

impl chainkeeper_core::CrlManager for FailingCrl {
    fn update_for_authority(
        &self,
        _authority: &AuthorityName,
    ) -> Result<chainkeeper_core::CrlBundle, ChainkeeperError> {
        Err(ChainkeeperError::storage("injected CRL failure"))
    }

    fn list_crls(&self) -> Result<Vec<chainkeeper_core::CrlRecord>, ChainkeeperError> {
        Ok(Vec::new())
    }
}

/// Policy engine that rejects issuance.
#[derive(Debug, Default)]
pub struct RejectingPolicy;

impl chainkeeper_core::PolicyEngine for RejectingPolicy {
    fn validate_issue(
        &self,
        _policy: &Policy,
        _profile: &Profile,
        _request: &chainkeeper_core::IssueRequest,
    ) -> Result<(), ChainkeeperError> {
        Err(ChainkeeperError::policy("injected policy rejection"))
    }

    fn validate_custom_extension(
        &self,
        _policy: &Policy,
        _extension: &chainkeeper_core::CustomExtension,
    ) -> Result<(), ChainkeeperError> {
        Ok(())
    }

    fn validate_profile(
        &self,
        _policy: &Policy,
        _profile: &Profile,
    ) -> Result<(), ChainkeeperError> {
        Ok(())
    }
}

/// Everything a test needs to inspect after an operation.
pub struct Harness {
    pub engine: Engine,
    pub store: Arc<MirroringStore>,
    pub index: Arc<InMemoryIndexStore>,
    pub audit: Arc<InMemoryAuditLog>,
    pub git: Arc<InMemoryGitRepository>,
    pub crl: Arc<FakeCrlManager>,
    pub publish: Arc<FakePublishBuilder>,
    pub provider: Arc<FakeCertificateProvider>,
    pub root: PathBuf,
    _temp: TempDir,
}

fn signers() -> Arc<dyn AuthoritySigners> {
    let mut map: BTreeMap<AuthorityName, Arc<dyn Signer>> = BTreeMap::new();
    for name in ["root", "tls", "smime", "codesign", "ocsp", "ocsp-signer"] {
        map.insert(
            AuthorityName::new(name).expect("name"),
            Arc::new(FakeSigner::new(KeyAlgorithm::EcdsaP256)),
        );
    }
    Arc::new(move |authority: &AuthorityName| {
        map.get(authority)
            .cloned()
            .ok_or_else(|| ChainkeeperError::not_found("signer", authority.as_str()))
    })
}

/// Builds a harness with the complete repository layout.
///
/// # Panics
///
/// Panics when the temporary repository or the fakes cannot be created.
pub fn harness() -> Harness {
    harness_with_layout(true)
}

/// Builds a harness whose root is empty, as required by `init`.
///
/// # Panics
///
/// Panics when the temporary repository or the fakes cannot be created.
pub fn empty_harness() -> Harness {
    harness_with_layout(false)
}

fn harness_with_layout(create_layout: bool) -> Harness {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path().to_path_buf();
    let paths = RepositoryPaths::new(&root).expect("paths");
    if create_layout {
        for path in paths.required_directories() {
            std::fs::create_dir_all(path).expect("layout dir");
        }
        std::fs::create_dir_all(root.join("authorities")).expect("authorities dir");
    }

    let store = Arc::new(MirroringStore::new(&root));
    let index = Arc::new(InMemoryIndexStore::new());
    let audit = Arc::new(InMemoryAuditLog::new());
    let git = Arc::new(InMemoryGitRepository::new());
    let crl = Arc::new(FakeCrlManager::new());
    let publish = Arc::new(FakePublishBuilder::new());
    let provider = Arc::new(FakeCertificateProvider::with_time(NOW).expect("provider"));

    let deps = EngineDependencies {
        clock: Arc::new(FakeClock::new(NOW)),
        ids: Arc::new(FakeIdGenerator::new()),
        provider: Arc::clone(&provider) as Arc<dyn chainkeeper_core::CertificateProvider>,
        store: Arc::clone(&store) as Arc<dyn CertificateStore>,
        index: Arc::clone(&index) as Arc<dyn chainkeeper_core::IndexStore>,
        profiles: Arc::new(InMemoryProfileRegistry::new()),
        policy: Arc::new(chainkeeper_testkit::NoopPolicyEngine),
        audit: Arc::clone(&audit) as Arc<dyn AuditLog>,
        git: Arc::clone(&git) as Arc<dyn GitRepository>,
        lock: Arc::new(FakeRepositoryLock::new()),
        crl: Arc::clone(&crl) as Arc<dyn chainkeeper_core::CrlManager>,
        publish: Arc::clone(&publish) as Arc<dyn chainkeeper_core::PublishBuilder>,
        signers: signers(),
        paths,
    };
    let engine = Engine::new(deps).expect("engine");
    Harness {
        engine,
        store,
        index,
        audit,
        git,
        crl,
        publish,
        provider,
        root,
        _temp: directory,
    }
}

/// Overrides used by failure-injection tests.
#[derive(Clone, Default)]
pub struct Overrides {
    /// Replacement policy engine.
    pub policy: Option<Arc<dyn chainkeeper_core::PolicyEngine>>,
    /// Replacement index.
    pub index: Option<Arc<dyn chainkeeper_core::IndexStore>>,
    /// Replacement audit log.
    pub audit: Option<Arc<dyn AuditLog>>,
    /// Replacement Git repository.
    pub git: Option<Arc<dyn GitRepository>>,
    /// Replacement CRL manager.
    pub crl: Option<Arc<dyn chainkeeper_core::CrlManager>>,
}

/// Harness built with explicit collaborators.
pub struct SimpleHarness {
    pub engine: Engine,
    pub store: Arc<MirroringStore>,
    pub index: Arc<dyn chainkeeper_core::IndexStore>,
    pub provider: Arc<FakeCertificateProvider>,
    pub git: Arc<dyn GitRepository>,
    pub root: PathBuf,
    _temp: TempDir,
}

/// Builds a harness with overrides applied.
///
/// # Panics
///
/// Panics when the temporary repository or the fakes cannot be created.
pub fn harness_with(overrides: Overrides) -> SimpleHarness {
    let directory = tempfile::tempdir().expect("temp dir");
    let root = directory.path().to_path_buf();
    let paths = RepositoryPaths::new(&root).expect("paths");
    for path in paths.required_directories() {
        std::fs::create_dir_all(path).expect("layout dir");
    }
    std::fs::create_dir_all(root.join("authorities")).expect("authorities dir");

    let store = Arc::new(MirroringStore::new(&root));
    let provider = Arc::new(FakeCertificateProvider::with_time(NOW).expect("provider"));
    let git = overrides
        .git
        .unwrap_or_else(|| Arc::new(InMemoryGitRepository::new()));
    let index = overrides
        .index
        .unwrap_or_else(|| Arc::new(InMemoryIndexStore::new()));
    let deps = EngineDependencies {
        clock: Arc::new(FakeClock::new(NOW)),
        ids: Arc::new(FakeIdGenerator::new()),
        provider: Arc::clone(&provider) as Arc<dyn chainkeeper_core::CertificateProvider>,
        store: Arc::clone(&store) as Arc<dyn CertificateStore>,
        index: Arc::clone(&index),
        profiles: Arc::new(InMemoryProfileRegistry::new()),
        policy: overrides
            .policy
            .unwrap_or_else(|| Arc::new(chainkeeper_testkit::NoopPolicyEngine)),
        audit: overrides
            .audit
            .unwrap_or_else(|| Arc::new(InMemoryAuditLog::new())),
        git: Arc::clone(&git),
        lock: Arc::new(FakeRepositoryLock::new()),
        crl: overrides
            .crl
            .unwrap_or_else(|| Arc::new(FakeCrlManager::new())),
        publish: Arc::new(FakePublishBuilder::new()),
        signers: signers(),
        paths,
    };
    SimpleHarness {
        engine: Engine::new(deps).expect("engine"),
        store,
        index,
        provider,
        git,
        root,
        _temp: directory,
    }
}

/// Root creation request.
#[must_use]
pub fn root_request() -> chainkeeper_core::CreateAuthorityRequest {
    chainkeeper_core::CreateAuthorityRequest {
        name: AuthorityName::new("root").expect("name"),
        kind: AuthorityKind::Root,
        parent: None,
        subject: chainkeeper_core::SubjectName::new("Chainkeeper Root"),
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 7300,
        path_len: 2,
    }
}

/// Intermediate creation request.
#[must_use]
pub fn intermediate_request(name: &str) -> chainkeeper_core::CreateAuthorityRequest {
    chainkeeper_core::CreateAuthorityRequest {
        name: AuthorityName::new(name).expect("name"),
        kind: AuthorityKind::Intermediate,
        parent: Some(AuthorityName::new("root").expect("name")),
        subject: chainkeeper_core::SubjectName::new(format!("Chainkeeper {name}")),
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 3650,
        path_len: 0,
    }
}

/// OCSP signer creation request.
#[must_use]
pub fn ocsp_signer_request() -> chainkeeper_core::CreateOcspSignerRequest {
    chainkeeper_core::CreateOcspSignerRequest {
        name: AuthorityName::new("ocsp-signer").expect("name"),
        parent: AuthorityName::new("ocsp").expect("name"),
        subject: None,
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 90,
    }
}

/// Issuance request for a profile.
#[must_use]
pub fn issue_request(profile: &str) -> chainkeeper_core::IssueRequest {
    chainkeeper_core::IssueRequest {
        profile: ProfileName::new(profile).expect("profile"),
        subject: chainkeeper_core::SubjectName::new("leaf.example.test"),
        sans: vec![chainkeeper_core::San::Dns("leaf.example.test".to_owned())],
        custom_extensions: Vec::new(),
        algorithm: None,
        validity_days: None,
        csr_pem: None,
        key_out: None,
        replaces: None,
    }
}

/// Creates root, every intermediate, and the OCSP signer.
pub fn create_hierarchy(engine: &Engine) {
    engine.create_root(&root_request()).expect("root");
    for name in ["tls", "smime", "codesign", "ocsp"] {
        engine
            .create_intermediate(&intermediate_request(name))
            .expect("intermediate");
    }
    engine
        .create_ocsp_signer(&ocsp_signer_request())
        .expect("ocsp signer");
}

/// Seeds a healthy CRL for each intermediate.
pub fn seed_crls(crl: &FakeCrlManager) {
    for name in ["tls", "smime", "codesign", "ocsp"] {
        crl.seed(chainkeeper_core::CrlRecord {
            version: chainkeeper_core::CONFIG_VERSION,
            authority: AuthorityName::new(name).expect("name"),
            number: 1,
            this_update: NOW,
            next_update: NOW + time::Duration::days(7),
            revoked_serials: Vec::new(),
            der_path: PathBuf::from(format!("crls/{name}.crl.der")),
            pem_path: PathBuf::from(format!("crls/{name}.pem")),
        });
    }
}

/// Writes a publish manifest into the repository.
///
/// # Panics
///
/// Panics when the manifest cannot be written.
pub fn write_manifest(
    root: &Path,
    source_commit: Option<&str>,
    artifacts: Vec<chainkeeper_core::PublishArtifact>,
) {
    let manifest = chainkeeper_core::PublishManifest {
        version: chainkeeper_core::PUBLISH_MANIFEST_VERSION,
        generated_at: NOW,
        source_commit: source_commit.map(str::to_owned),
        tenant_id: chainkeeper_core::TenantId::new("acme").expect("tenant"),
        artifacts,
    };
    let directory = root.join("publish");
    std::fs::create_dir_all(&directory).expect("publish dir");
    std::fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec(&manifest).expect("manifest json"),
    )
    .expect("manifest write");
}

/// Writes a `.git/config` with or without a remote.
///
/// # Panics
///
/// Panics when the file cannot be written.
pub fn write_git_config(root: &Path, with_remote: bool) {
    let directory = root.join(".git");
    std::fs::create_dir_all(&directory).expect("git dir");
    let contents = if with_remote {
        "[remote \"origin\"]\n\turl = https://example.test/repo.git\n"
    } else {
        "[core]\n\tbare = false\n"
    };
    std::fs::write(directory.join("config"), contents).expect("git config");
}

/// Removes every authority private key.
///
/// # Panics
///
/// Panics when a key exists but cannot be removed.
pub fn remove_authority_keys(root: &Path) {
    let directory = root.join("authorities");
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let key = entry.path().join("key.pem");
        if key.exists() {
            std::fs::remove_file(key).expect("remove key");
        }
    }
}

/// Builds a certificate record.
#[must_use]
pub fn certificate_record(
    serial: &str,
    profile: &str,
    authority: &str,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    algorithm: KeyAlgorithm,
    sans: Vec<chainkeeper_core::San>,
) -> CertificateRecord {
    CertificateRecord {
        serial: Serial::new(serial).expect("serial"),
        subject: chainkeeper_core::SubjectName::new("leaf.example.test"),
        issuer: "CN=Chainkeeper Test".to_owned(),
        profile: ProfileName::new(profile).expect("profile"),
        authority: AuthorityName::new(authority).expect("authority"),
        algorithm,
        sans,
        ekus: Vec::new(),
        key_usages: Vec::new(),
        issued_at,
        expires_at,
        path: PathBuf::from(format!("certificates/active/{serial}.pem")),
        revoked_at: None,
        revocation_reason: None,
        replaces: None,
    }
}

/// Writes a certificate record through the mirroring store.
///
/// # Panics
///
/// Panics when the store rejects the record.
pub fn insert_certificate(store: &MirroringStore, record: CertificateRecord) {
    store
        .write_certificate(&IssuedCertificate::new(
            record,
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            String::new(),
            None,
        ))
        .expect("certificate write");
}

/// Builds an authority name.
#[must_use]
pub fn authority(value: &str) -> AuthorityName {
    AuthorityName::new(value).expect("authority")
}

/// Builds an authority configuration.
#[must_use]
pub fn authority_config(
    name: &str,
    kind: AuthorityKind,
    parent: Option<&str>,
    validity_days: u32,
    created_at: OffsetDateTime,
) -> AuthorityConfig {
    AuthorityConfig::new(
        AuthorityName::new(name).expect("name"),
        kind,
        parent.map(|parent| AuthorityName::new(parent).expect("parent")),
        KeyAlgorithm::EcdsaP256,
        validity_days,
        0,
        Vec::new(),
        created_at,
    )
}
