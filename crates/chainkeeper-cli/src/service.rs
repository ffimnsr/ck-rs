//! Production wiring for the `ck` binary.

use std::path::Path;
use std::sync::{Arc, Mutex};

use chainkeeper_audit::FileAuditLog;
use chainkeeper_core::{
    AuditLog, CertificateProvider, CertificateStore, ChainkeeperError, Clock, CrlManager,
    ErrorDetail, GitRepository, IdGenerator, IndexStore, LockGuard, PolicyEngine,
    ProductionIdGenerator, Profile, ProfileRegistry, RepositoryLock, RepositoryPaths, Signer,
    SystemClock,
};
use chainkeeper_crypto::{FileSigner, OpenSslProvider, SecretString};
use chainkeeper_engine::{Engine, EngineDependencies};
use chainkeeper_git::GitRepo;
use chainkeeper_policy::{DefaultProfileRegistry, PolicyValidator};
use chainkeeper_publish::{
    AuthorityProviders, AuthoritySigners as PublishSigners, CrlDependencies, FileCrlManager,
    FilePublishBuilder, PublishDependencies,
};
use chainkeeper_store::{FileRepositoryLock, FileStore, SqliteIndex};

/// How the service is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// The repository may be empty; `init` creates the layout.
    Init,
    /// Every command requiring an initialised repository.
    Normal,
}

/// Opens the production service for `root`.
///
/// # Errors
///
/// Returns storage, index, Git, or configuration errors when the repository
/// cannot be opened.
pub fn open(root: &Path, mode: OpenMode) -> Result<Arc<Engine>, ChainkeeperError> {
    let paths = RepositoryPaths::new(root)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let ids: Arc<dyn IdGenerator> = Arc::new(ProductionIdGenerator);
    let store = Arc::new(FileStore::with_clock(paths.clone(), Arc::clone(&clock)));
    let lock: Arc<dyn RepositoryLock> = Arc::new(ReentrantLock::new(Arc::new(
        FileRepositoryLock::new(paths.clone()),
    )));

    let index: Arc<dyn IndexStore> = match mode {
        OpenMode::Init => Arc::new(SqliteIndex::open_in_memory_with_clock(Arc::clone(&clock))?),
        OpenMode::Normal => Arc::new(SqliteIndex::open_with_clock(
            &paths.index_path(),
            Arc::clone(&clock),
        )?),
    };

    let profiles = load_profiles(store.as_ref(), mode)?;
    let git: Arc<dyn GitRepository> = match mode {
        OpenMode::Init => Arc::new(GitRepo::new(root)),
        OpenMode::Normal => Arc::new(GitRepo::open(root)?),
    };
    let audit = Arc::new(FileAuditLog::new(
        paths.clone(),
        Arc::clone(&lock),
        Arc::clone(&ids),
    ));
    let provider = Arc::new(RepositoryProvider::new(
        Arc::clone(&clock),
        Arc::clone(&ids),
        Arc::clone(&store) as Arc<dyn CertificateStore>,
        Arc::clone(&profiles),
        passphrase(),
    ));
    let signers = Arc::new(FileSigners::new(paths.clone(), passphrase()));

    let crl = Arc::new(FileCrlManager::new(CrlDependencies {
        clock: Arc::clone(&clock),
        store: Arc::clone(&store) as Arc<dyn CertificateStore>,
        signers: Arc::clone(&signers) as Arc<dyn PublishSigners>,
        providers: Arc::clone(&provider) as Arc<dyn AuthorityProviders>,
        audit: Arc::clone(&audit) as Arc<dyn AuditLog>,
        index: Arc::clone(&index),
        paths: paths.clone(),
    }));
    let publish = Arc::new(FilePublishBuilder::new(PublishDependencies::new(
        Arc::clone(&clock),
        Arc::clone(&store) as Arc<dyn CertificateStore>,
        Arc::clone(&git),
        paths.clone(),
    )));

    let deps = EngineDependencies {
        clock: Arc::clone(&clock),
        ids: Arc::clone(&ids),
        provider: Arc::clone(&provider) as Arc<dyn CertificateProvider>,
        store: Arc::clone(&store) as Arc<dyn CertificateStore>,
        index: Arc::clone(&index),
        profiles,
        policy: Arc::new(PolicyValidator::new()) as Arc<dyn PolicyEngine>,
        audit: Arc::clone(&audit) as Arc<dyn AuditLog>,
        git,
        lock: Arc::clone(&lock),
        crl: Arc::clone(&crl) as Arc<dyn CrlManager>,
        publish,
        signers: Arc::clone(&signers) as Arc<dyn chainkeeper_engine::AuthoritySigners>,
        paths,
    };
    let engine = Engine::new(deps)?;
    if mode == OpenMode::Normal {
        rebuild_empty_index(&engine)?;
    }
    Ok(Arc::new(engine))
}

fn load_profiles(
    store: &FileStore,
    mode: OpenMode,
) -> Result<Arc<dyn ProfileRegistry>, ChainkeeperError> {
    if mode == OpenMode::Init {
        return Ok(Arc::new(DefaultProfileRegistry::defaults()));
    }
    let profiles = store.load_profiles()?;
    if profiles.is_empty() {
        Ok(Arc::new(DefaultProfileRegistry::defaults()))
    } else {
        Ok(Arc::new(DefaultProfileRegistry::with_profiles(profiles)))
    }
}

fn rebuild_empty_index(engine: &Engine) -> Result<(), ChainkeeperError> {
    let stats = engine.index.stats()?;
    if stats.certificates == 0 && stats.authorities == 0 {
        let certificates = engine.store.list_certificates()?;
        if !certificates.is_empty() {
            engine.rebuild_index_from_disk()?;
        }
    }
    Ok(())
}

/// Writes the persistent index after `init` finished with its in-memory one.
///
/// # Errors
///
/// Returns an index error when the database cannot be written.
pub fn finalize_init(engine: &Engine) -> Result<(), ChainkeeperError> {
    let index = SqliteIndex::open_with_clock(&engine.paths.index_path(), Arc::new(SystemClock))?;
    let records = engine.collect_index_records()?;
    IndexStore::rebuild(&index, &records)?;
    Ok(())
}

fn passphrase() -> Option<SecretString> {
    std::env::var("CHAINKEEPER_KEY_PASSPHRASE")
        .ok()
        .filter(|value| !value.is_empty())
        .map(SecretString::new)
}

/// Reentrant process-local wrapper around the file lock.
///
/// Mutating commands hold the engine lock while appending audit events, and the
/// audit log takes the same repository lock. Making the lock reentrant for the
/// owning thread keeps that composition atomic without deadlocking.
struct ReentrantLock {
    inner: Arc<dyn RepositoryLock>,
    state: Arc<Mutex<LockState>>,
}

#[derive(Default)]
struct LockState {
    owner: Option<std::thread::ThreadId>,
    depth: usize,
    guard: Option<LockGuard>,
}

impl ReentrantLock {
    fn new(inner: Arc<dyn RepositoryLock>) -> Self {
        Self {
            inner,
            state: Arc::new(Mutex::new(LockState::default())),
        }
    }
}

impl RepositoryLock for ReentrantLock {
    fn acquire_exclusive(
        &self,
        timeout: std::time::Duration,
    ) -> Result<LockGuard, ChainkeeperError> {
        let current = std::thread::current().id();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ChainkeeperError::Lock(ErrorDetail::new("lock state poisoned")))?;
        if state.depth > 0 {
            if state.owner != Some(current) {
                return Err(ChainkeeperError::Lock(ErrorDetail::new(
                    "repository lock is held by another thread",
                )));
            }
            state.depth += 1;
        } else {
            state.guard = Some(self.inner.acquire_exclusive(timeout)?);
            state.owner = Some(current);
            state.depth = 1;
        }
        drop(state);

        let state = Arc::clone(&self.state);
        Ok(LockGuard::new(None, move || {
            if let Ok(mut state) = state.lock() {
                state.depth = state.depth.saturating_sub(1);
                if state.depth == 0 {
                    state.owner = None;
                    state.guard = None;
                }
            }
        }))
    }
}

/// File-backed authority key resolver.
struct FileSigners {
    paths: RepositoryPaths,
    passphrase: Option<SecretString>,
}

impl FileSigners {
    const fn new(paths: RepositoryPaths, passphrase: Option<SecretString>) -> Self {
        Self { paths, passphrase }
    }

    fn load(
        &self,
        authority: &chainkeeper_core::AuthorityName,
    ) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        let path = self.paths.authority_path(authority, "key.pem")?;
        let bytes = std::fs::read(&path).map_err(|error| {
            ChainkeeperError::storage(format!(
                "could not read authority key {}: {error}",
                path.display()
            ))
        })?;
        let signer = FileSigner::from_pem(&bytes, self.passphrase.as_ref())?;
        Ok(Arc::new(signer))
    }
}

impl std::fmt::Debug for FileSigners {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileSigners")
            .field("root", &self.paths.root())
            .finish_non_exhaustive()
    }
}

impl chainkeeper_engine::AuthoritySigners for FileSigners {
    fn signer_for(
        &self,
        authority: &chainkeeper_core::AuthorityName,
    ) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        self.load(authority)
    }
}

impl PublishSigners for FileSigners {
    fn signer_for(
        &self,
        authority: &chainkeeper_core::AuthorityName,
    ) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        self.load(authority)
    }
}

/// Certificate provider that resolves issuer material per authority.
struct RepositoryProvider {
    clock: Arc<dyn Clock>,
    ids: Arc<dyn IdGenerator>,
    store: Arc<dyn CertificateStore>,
    profiles: Arc<dyn ProfileRegistry>,
    passphrase: Option<SecretString>,
}

impl RepositoryProvider {
    const fn new(
        clock: Arc<dyn Clock>,
        ids: Arc<dyn IdGenerator>,
        store: Arc<dyn CertificateStore>,
        profiles: Arc<dyn ProfileRegistry>,
        passphrase: Option<SecretString>,
    ) -> Self {
        Self {
            clock,
            ids,
            store,
            profiles,
            passphrase,
        }
    }

    fn base(&self) -> OpenSslProvider {
        let provider = OpenSslProvider::new(Arc::clone(&self.clock), Arc::clone(&self.ids));
        match &self.passphrase {
            Some(passphrase) => provider.with_passphrase(passphrase.clone()),
            None => provider,
        }
    }

    fn issuing(
        &self,
        authority: &chainkeeper_core::AuthorityName,
        profile: Option<Profile>,
    ) -> Result<OpenSslProvider, ChainkeeperError> {
        let issuer = self
            .store
            .load_authority(authority)?
            .ok_or_else(|| ChainkeeperError::not_found("authority", authority.as_str()))?;
        let mut provider = self.base().with_issuer(issuer);
        if let Ok(tenant) = self.store.load_tenant() {
            provider = provider.with_tenant(tenant);
        }
        if let Some(profile) = profile {
            provider = provider.with_profile(profile);
        }
        Ok(provider)
    }
}

impl std::fmt::Debug for RepositoryProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RepositoryProvider")
            .finish_non_exhaustive()
    }
}

impl CertificateProvider for RepositoryProvider {
    fn generate_key(
        &self,
        algorithm: chainkeeper_core::KeyAlgorithm,
    ) -> Result<chainkeeper_core::KeyMaterial, ChainkeeperError> {
        self.base().generate_key(algorithm)
    }

    fn create_root(
        &self,
        request: &chainkeeper_core::CreateAuthorityRequest,
    ) -> Result<chainkeeper_core::AuthorityBundle, ChainkeeperError> {
        self.base().create_root(request)
    }

    fn create_intermediate(
        &self,
        request: &chainkeeper_core::CreateAuthorityRequest,
        parent: &chainkeeper_core::AuthorityMaterial,
        parent_signer: &dyn Signer,
    ) -> Result<chainkeeper_core::AuthorityBundle, ChainkeeperError> {
        self.base()
            .create_intermediate(request, parent, parent_signer)
    }

    fn create_ocsp_signer(
        &self,
        request: &chainkeeper_core::CreateOcspSignerRequest,
        parent: &chainkeeper_core::AuthorityMaterial,
        parent_signer: &dyn Signer,
    ) -> Result<chainkeeper_core::SignerBundle, ChainkeeperError> {
        self.base()
            .create_ocsp_signer(request, parent, parent_signer)
    }

    fn issue(
        &self,
        request: &chainkeeper_core::IssueRequest,
        signer: &dyn Signer,
    ) -> Result<chainkeeper_core::IssuedCertificate, ChainkeeperError> {
        let profile = self.profiles.get(&request.profile)?;
        let authority = profile.authority.clone();
        self.issuing(&authority, Some(profile))?
            .issue(request, signer)
    }

    fn generate_crl(
        &self,
        request: &chainkeeper_core::CrlRequest,
        signer: &dyn Signer,
    ) -> Result<chainkeeper_core::CrlBundle, ChainkeeperError> {
        self.issuing(&request.authority, None)?
            .generate_crl(request, signer)
    }
}

impl AuthorityProviders for RepositoryProvider {
    fn provider_for(
        &self,
        authority: &chainkeeper_core::AuthorityName,
    ) -> Result<Arc<dyn CertificateProvider>, ChainkeeperError> {
        Ok(Arc::new(self.issuing(authority, None)?))
    }
}
