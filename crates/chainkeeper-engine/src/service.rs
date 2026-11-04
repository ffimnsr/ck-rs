//! Production wiring for the `ck` binary and integration tests.
//!
//! This module is the single composition root for the concrete collaborators
//! behind [`ChainkeeperService`]. Keeping it in the engine crate means the CLI
//! and integration tests exercise exactly the same object graph.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chainkeeper_audit::FileAuditLog;
use chainkeeper_core::{
    AuditLog, AuthorityName, CertificateProvider, CertificateStore, ChainkeeperError,
    ChainkeeperService, Clock, CrlManager, ErrorDetail, GitRepository, IdGenerator, IndexStore,
    LockGuard, PolicyEngine, ProductionIdGenerator, Profile, ProfileRegistry, RepositoryLock,
    RepositoryPaths, Signer, SystemClock,
};
use chainkeeper_crypto::{FileSigner, OpenSslProvider, SecretString};
use chainkeeper_git::{GitIdentity, GitRepo};
use chainkeeper_policy::{DefaultProfileRegistry, PolicyValidator};
use chainkeeper_publish::{
    AuthorityProviders, AuthoritySigners as PublishSigners, CrlDependencies, FileCrlManager,
    FilePublishBuilder, PublishDependencies,
};
use chainkeeper_store::{FileRepositoryLock, FileStore, SqliteIndex};

use crate::deps::{AuthoritySigners, EngineDependencies};
use crate::engine::Engine;

/// Environment variable holding the authority key passphrase.
pub const PASSPHRASE_ENV: &str = "CHAINKEEPER_KEY_PASSPHRASE";

/// How the service is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpenMode {
    /// The repository may be empty; `init` creates the layout.
    Init,
    /// Every command requiring an initialised repository.
    #[default]
    Normal,
}

/// Optional overrides applied while opening the service.
#[derive(Debug, Clone, Default)]
pub struct ServiceOptions {
    /// Init or normal mode.
    pub mode: OpenMode,
    /// Explicit commit identity instead of the repository configuration.
    pub git_identity: Option<GitIdentity>,
    /// Explicit commit signing flag instead of `commit.gpgsign`.
    pub commit_signing: Option<bool>,
}

impl ServiceOptions {
    /// Options for normal mode with no overrides.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Options for `mode` with no overrides.
    #[must_use]
    pub const fn with_mode(mode: OpenMode) -> Self {
        Self {
            mode,
            git_identity: None,
            commit_signing: None,
        }
    }
}

/// Opens the production service for `root`.
///
/// # Errors
///
/// Returns storage, index, Git, or configuration errors when the repository
/// cannot be opened.
pub fn open(root: &Path, mode: OpenMode) -> Result<Arc<Engine>, ChainkeeperError> {
    open_with(root, &ServiceOptions::with_mode(mode))
}

/// Opens the production service for `root` with explicit overrides.
///
/// Tests use this to pin the Git identity and commit signing instead of
/// inheriting the host configuration.
///
/// # Errors
///
/// Returns storage, index, Git, or configuration errors when the repository
/// cannot be opened.
pub fn open_with(root: &Path, options: &ServiceOptions) -> Result<Arc<Engine>, ChainkeeperError> {
    let paths = RepositoryPaths::new(root)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let ids: Arc<dyn IdGenerator> = Arc::new(ProductionIdGenerator);
    let store = Arc::new(FileStore::with_clock(paths.clone(), Arc::clone(&clock)));
    let lock: Arc<dyn RepositoryLock> = Arc::new(ReentrantLock::new(Arc::new(
        FileRepositoryLock::new(paths.clone()),
    )));

    let index: Arc<dyn IndexStore> = match options.mode {
        OpenMode::Init => Arc::new(SqliteIndex::open_in_memory_with_clock(Arc::clone(&clock))?),
        OpenMode::Normal => Arc::new(open_index(&paths.index_path(), Arc::clone(&clock))?),
    };

    let profiles = load_profiles(store.as_ref(), options.mode)?;
    let git: Arc<dyn GitRepository> = {
        let repo = match options.mode {
            OpenMode::Init => GitRepo::new(root),
            OpenMode::Normal => GitRepo::open(root)?,
        };
        let repo = match options.git_identity.clone() {
            Some(identity) => repo.with_identity(identity),
            None => repo,
        };
        let repo = match options.commit_signing {
            Some(signing) => repo.with_signing(signing),
            None => repo,
        };
        Arc::new(repo)
    };
    let audit = Arc::new(FileAuditLog::new(
        paths.clone(),
        Arc::clone(&lock),
        Arc::clone(&ids),
    ));
    let signers = Arc::new(FileSigners::from_env(paths.clone()));
    let provider = Arc::new(RepositoryProvider::new(
        Arc::clone(&clock),
        Arc::clone(&ids),
        Arc::clone(&store) as Arc<dyn CertificateStore>,
        Arc::clone(&profiles),
        signers.passphrase.clone(),
    ));

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
        signers: Arc::clone(&signers) as Arc<dyn AuthoritySigners>,
        paths,
    };
    let engine = Engine::new(deps)?;
    if options.mode == OpenMode::Normal {
        rebuild_empty_index(&engine)?;
    }
    Ok(Arc::new(engine))
}

/// Opens the production service for an initialised repository.
///
/// This is the documented entry point used by binaries and integration tests
/// that only need the [`ChainkeeperService`] surface.
///
/// # Errors
///
/// Returns storage, index, Git, or configuration errors when the repository
/// cannot be opened.
pub fn open_service(repo: &Path) -> Result<Arc<dyn ChainkeeperService>, ChainkeeperError> {
    let engine = open(repo, OpenMode::Normal)?;
    Ok(engine)
}

/// Opens the disposable index, recovering from a corrupt database.
///
/// The index is derived state; a database that cannot be opened is moved aside
/// and recreated so the engine can rebuild it from canonical records.
fn open_index(path: &Path, clock: Arc<dyn Clock>) -> Result<SqliteIndex, ChainkeeperError> {
    match SqliteIndex::open_with_clock(path, Arc::clone(&clock)) {
        Ok(index) => Ok(index),
        Err(error) if path.exists() => {
            let backup = path.with_extension("sqlite.corrupt");
            std::fs::rename(path, &backup).map_err(|rename| {
                ChainkeeperError::index(format!(
                    "index {} is corrupt ({error}) and could not be moved to {}: {rename}",
                    path.display(),
                    backup.display()
                ))
            })?;
            SqliteIndex::open_with_clock(path, clock)
        }
        Err(error) => Err(error),
    }
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

/// Reads the authority passphrase from the environment.
#[must_use]
pub fn passphrase_from_env() -> Option<SecretString> {
    std::env::var(PASSPHRASE_ENV)
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
///
/// The resolver reads one `key.pem` per authority. Callers may override the
/// path of individual authorities, which lets the server load a dedicated OCSP
/// signer key without ever touching CA key material.
pub struct FileSigners {
    paths: RepositoryPaths,
    passphrase: Option<SecretString>,
    key_overrides: BTreeMap<AuthorityName, PathBuf>,
}

impl FileSigners {
    /// Creates a resolver rooted at `paths`.
    #[must_use]
    pub const fn new(paths: RepositoryPaths, passphrase: Option<SecretString>) -> Self {
        Self {
            paths,
            passphrase,
            key_overrides: BTreeMap::new(),
        }
    }

    /// Creates a resolver configured from the process environment.
    #[must_use]
    pub fn from_env(paths: RepositoryPaths) -> Self {
        Self::new(paths, passphrase_from_env())
    }

    /// Resolves `authority` from an explicit key path instead of the layout.
    #[must_use]
    pub fn with_key_path(mut self, authority: AuthorityName, path: PathBuf) -> Self {
        self.key_overrides.insert(authority, path);
        self
    }

    fn key_path(&self, authority: &AuthorityName) -> Result<PathBuf, ChainkeeperError> {
        if let Some(path) = self.key_overrides.get(authority) {
            return Ok(path.clone());
        }
        self.paths.authority_path(authority, "key.pem")
    }

    fn load(&self, authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        let path = self.key_path(authority)?;
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

impl AuthoritySigners for FileSigners {
    fn signer_for(&self, authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        self.load(authority)
    }
}

impl PublishSigners for FileSigners {
    fn signer_for(&self, authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        self.load(authority)
    }
}

impl chainkeeper_ocsp::AuthoritySigners for FileSigners {
    fn signer_for(&self, authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
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
        authority: &AuthorityName,
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
        authority: &AuthorityName,
    ) -> Result<Arc<dyn CertificateProvider>, ChainkeeperError> {
        Ok(Arc::new(self.issuing(authority, None)?))
    }
}
