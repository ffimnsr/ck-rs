//! Engine construction and shared helpers.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chainkeeper_core::{
    AnalyzeKind, AnalyzeReport, AuditAction, AuditEvent, AuditLog, AuditQuery, AuthorityBundle,
    AuthorityMaterial, AuthorityName, AuthorityRecord, CertificateRecord, CertificateStatus,
    CertificateStore, ChainkeeperError, ChainkeeperService, CrlManager, DiffRequest, DoctorReport,
    IndexRecords, IndexReport, IndexStore, InitReport, InspectReport, IssueReport,
    IssuedCertificate, NewAuditEvent, Policy, PolicyEngine, Profile, ProfileName, PublishManifest,
    PublishOptions, RevocationRecord, RevokeReport, SearchQuery, Serial, Signer, TreeReport,
};
use time::OffsetDateTime;

use crate::deps::{AuthoritySigners, EngineDependencies};
use crate::rollback::Rollback;

/// Actor recorded on audit events produced by the engine.
pub const ACTOR: &str = "ck";

/// Orchestrates the complete PKI lifecycle through injected traits.
pub struct Engine {
    pub clock: Arc<dyn chainkeeper_core::Clock>,
    // The provider owns serial and ULID allocation in V1; the field stays so the
    // dependency bundle matches the documented engine contract.
    #[allow(dead_code)]
    pub ids: Arc<dyn chainkeeper_core::IdGenerator>,
    pub provider: Arc<dyn chainkeeper_core::CertificateProvider>,
    pub store: Arc<dyn CertificateStore>,
    pub index: Arc<dyn IndexStore>,
    pub profiles: Arc<dyn chainkeeper_core::ProfileRegistry>,
    pub policy: Arc<dyn PolicyEngine>,
    pub audit: Arc<dyn AuditLog>,
    pub git: Arc<dyn chainkeeper_core::GitRepository>,
    pub lock: Arc<dyn chainkeeper_core::RepositoryLock>,
    pub crl: Arc<dyn CrlManager>,
    pub publish: Arc<dyn chainkeeper_core::PublishBuilder>,
    pub signers: Arc<dyn AuthoritySigners>,
    pub paths: chainkeeper_core::RepositoryPaths,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("root", &self.paths.root())
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Builds an engine from its dependencies.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when the repository root is not an
    /// existing directory.
    pub fn new(deps: EngineDependencies) -> Result<Self, ChainkeeperError> {
        if !deps.paths.root().is_dir() {
            return Err(ChainkeeperError::storage(format!(
                "repository root {} is not a directory",
                deps.paths.root().display()
            )));
        }
        Ok(Self {
            clock: deps.clock,
            ids: deps.ids,
            provider: deps.provider,
            store: deps.store,
            index: deps.index,
            profiles: deps.profiles,
            policy: deps.policy,
            audit: deps.audit,
            git: deps.git,
            lock: deps.lock,
            crl: deps.crl,
            publish: deps.publish,
            signers: deps.signers,
            paths: deps.paths,
        })
    }

    /// Repository layout.
    #[must_use]
    pub const fn paths(&self) -> &chainkeeper_core::RepositoryPaths {
        &self.paths
    }

    /// Current time from the injected clock.
    pub fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// Acquires the exclusive repository lock.
    pub fn acquire_lock(&self) -> Result<chainkeeper_core::LockGuard, ChainkeeperError> {
        self.lock.acquire_exclusive(crate::DEFAULT_LOCK_TIMEOUT)
    }

    /// Resolves the signer for an authority.
    pub fn signer_for(
        &self,
        authority: &AuthorityName,
    ) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        self.signers.signer_for(authority)
    }

    /// Loads the repository policy.
    pub fn load_policy(&self) -> Result<Policy, ChainkeeperError> {
        self.store.load_policy()
    }

    /// Loads a profile from the registry after validating it.
    pub fn load_profile(&self, name: &ProfileName) -> Result<Profile, ChainkeeperError> {
        let profile = self.profiles.get(name)?;
        self.profiles.validate(&profile)?;
        Ok(profile)
    }

    /// Converts an absolute path inside the repository to a relative path.
    pub fn relative(&self, path: &Path) -> Result<PathBuf, ChainkeeperError> {
        match path.strip_prefix(self.paths.root()) {
            Ok(relative) => Ok(relative.to_path_buf()),
            Err(_) => Err(ChainkeeperError::storage(format!(
                "path {} is outside the repository",
                path.display()
            ))),
        }
    }

    /// Appends an audit event and returns it.
    pub fn append_audit(
        &self,
        action: AuditAction,
        object_type: &str,
        object_id: impl Into<String>,
        summary: impl Into<String>,
        details: serde_json::Value,
    ) -> Result<AuditEvent, ChainkeeperError> {
        let event = NewAuditEvent::new(self.now(), action, object_type, object_id, summary, ACTOR)
            .with_details(details);
        let event = self.audit.append(event)?;
        self.index.upsert_audit_event(&event)?;
        Ok(event)
    }

    /// Path of a stored audit event.
    pub fn audit_path(&self, event: &AuditEvent) -> PathBuf {
        self.paths.audit_event_path(&event.id)
    }

    /// Commits the given absolute or relative paths.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] with the uncommitted paths listed when
    /// the commit fails.
    pub fn commit(&self, message: &str, paths: &[PathBuf]) -> Result<String, ChainkeeperError> {
        let mut relative = BTreeSet::new();
        for path in paths {
            let value = if path.is_absolute() {
                self.relative(path)?
            } else {
                path.clone()
            };
            relative.insert(value);
        }
        let relative: Vec<PathBuf> = relative.into_iter().collect();
        self.git.commit(message, &relative).map_err(|error| {
            let rendered: Vec<String> = relative
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            ChainkeeperError::git(format!(
                "commit failed: {}; uncommitted files: {}",
                error.message(),
                rendered.join(", ")
            ))
        })
    }

    /// Collects every canonical record for an index rebuild.
    pub fn collect_index_records(&self) -> Result<IndexRecords, ChainkeeperError> {
        let audit = self.audit.list(&AuditQuery::default())?;
        let crls = self.crl.list_crls()?;
        let crls = crls
            .into_iter()
            .map(|record| {
                let path = self.paths.crl_path(&record.authority, "crl.der")?;
                let sha256 = self.file_sha256(&path).unwrap_or_default();
                Ok(chainkeeper_core::IndexedCrl { record, sha256 })
            })
            .collect::<Result<Vec<_>, ChainkeeperError>>()?;
        Ok(IndexRecords {
            certificates: self.store.list_certificates()?,
            revocations: self.store.list_revocations()?,
            authorities: self.store.list_authorities()?,
            profiles: self.profiles.list(),
            crls,
            audit_events: audit,
        })
    }

    /// Rebuilds the index from canonical records.
    pub fn rebuild_index_from_disk(&self) -> Result<IndexReport, ChainkeeperError> {
        let records = self.collect_index_records()?;
        self.index.rebuild(&records)
    }

    /// Lowercase hexadecimal SHA-256 of a file, when it exists.
    pub fn file_sha256(&self, path: &Path) -> Option<String> {
        use sha2::{Digest, Sha256};
        use std::fmt::Write as _;

        let bytes = std::fs::read(path).ok()?;
        let digest = Sha256::digest(&bytes);
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            let _ = write!(hex, "{byte:02x}");
        }
        Some(hex)
    }

    /// Expiry time derived from an authority record.
    pub fn authority_expiry(record: &AuthorityRecord) -> OffsetDateTime {
        record.created_at + time::Duration::days(i64::from(record.validity_days))
    }

    /// Builds the record for a stored authority bundle.
    pub fn authority_record(&self, material: &AuthorityMaterial) -> AuthorityRecord {
        AuthorityRecord::from_config(
            &material.config,
            PathBuf::from("authorities")
                .join(material.config.name.as_str())
                .join("cert.pem"),
            PathBuf::from("authorities")
                .join(material.config.name.as_str())
                .join("chain.pem"),
        )
    }

    /// Absolute paths of the public files written with an authority.
    pub fn authority_public_paths(&self, name: &AuthorityName) -> Vec<PathBuf> {
        vec![
            self.paths.authority_dir(name).join("cert.pem"),
            self.paths.authority_dir(name).join("chain.pem"),
            self.paths.authority_dir(name).join("authority.yaml"),
        ]
    }

    /// Absolute paths written by [`CertificateStore::write_certificate`].
    pub fn certificate_paths(&self, certificate: &IssuedCertificate) -> Vec<PathBuf> {
        let serial = &certificate.record.serial;
        let mut paths = vec![
            self.paths
                .certificate_path(serial, "pem")
                .unwrap_or_else(|_| PathBuf::new()),
            self.paths
                .certificate_path(serial, "yaml")
                .unwrap_or_else(|_| PathBuf::new()),
        ];
        if certificate.key.is_some()
            && let Ok(path) = self.paths.certificate_path(serial, "key.pem")
        {
            paths.push(path);
        }
        paths
    }

    /// Persists an authority bundle through the store.
    pub fn write_authority(
        &self,
        rollback: &mut Rollback,
        bundle: &AuthorityBundle,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        let name = &bundle.material.config.name;
        for path in self.authority_public_paths(name) {
            rollback.created_if_absent(&path);
        }
        let key_path = self.paths.authority_dir(name).join("key.pem");
        rollback.created_if_absent(&key_path);
        self.store.write_authority(bundle)?;
        Ok(self.authority_record(&bundle.material))
    }

    /// Writes a revocation record, returning its absolute path.
    pub fn write_revocation(
        &self,
        rollback: &mut Rollback,
        record: &RevocationRecord,
    ) -> Result<PathBuf, ChainkeeperError> {
        let path = self.paths.revocation_path(&record.serial);
        rollback.created_if_absent(&path);
        let written = self.store.write_revocation(record)?;
        Ok(if written.is_absolute() {
            written
        } else {
            self.paths.root().join(written)
        })
    }

    /// Rebuilds the index after a rollback, ignoring secondary failures.
    pub fn restore_index(&self, rollback: &Rollback) {
        if rollback.index_dirty() {
            let _ = self.rebuild_index_from_disk();
        }
    }

    /// Rewrites certificate metadata so moved or revoked records stay accurate.
    ///
    /// [`CertificateStore::move_certificate`] moves the existing YAML file, so
    /// the engine refreshes it once the lifecycle fields change.
    pub fn write_certificate_metadata(
        &self,
        record: &CertificateRecord,
    ) -> Result<(), ChainkeeperError> {
        let path = self.root_join(&record.path).with_extension("yaml");
        let yaml = serde_yaml_ng::to_string(record).map_err(|error| {
            ChainkeeperError::storage(format!("could not encode certificate metadata: {error}"))
        })?;
        chainkeeper_core::atomic_write(&path, yaml.as_bytes(), chainkeeper_core::FileMode::Public)
    }

    /// Joins a repository-relative path with the root.
    pub fn root_join(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.paths.root().join(path)
        }
    }

    /// Undoes files, restores certificate directories, and resynchronises the
    /// index after a failed operation.
    pub fn recover(&self, rollback: &mut Rollback) {
        rollback.undo();
        for serial in rollback.moved_certificates() {
            let _ = self
                .store
                .move_certificate(serial, CertificateStatus::Active);
        }
        self.restore_index(rollback);
    }
}

impl ChainkeeperService for Engine {
    fn init(
        &self,
        request: &chainkeeper_core::InitRequest,
    ) -> Result<InitReport, ChainkeeperError> {
        crate::init::execute(self, request)
    }

    fn create_root(
        &self,
        request: &chainkeeper_core::CreateAuthorityRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        crate::authorities::create_root(self, request)
    }

    fn create_intermediate(
        &self,
        request: &chainkeeper_core::CreateAuthorityRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        crate::authorities::create_intermediate(self, request)
    }

    fn create_ocsp_signer(
        &self,
        request: &chainkeeper_core::CreateOcspSignerRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        crate::authorities::create_ocsp_signer(self, request)
    }

    fn issue(
        &self,
        request: &chainkeeper_core::IssueRequest,
    ) -> Result<IssueReport, ChainkeeperError> {
        crate::issuance::issue(self, request)
    }

    fn revoke(
        &self,
        request: &chainkeeper_core::RevokeRequest,
    ) -> Result<RevokeReport, ChainkeeperError> {
        crate::revocation::revoke(self, request)
    }

    fn inspect(&self, serial: &Serial) -> Result<InspectReport, ChainkeeperError> {
        crate::query::inspect(self, serial)
    }

    fn search(&self, query: &SearchQuery) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        crate::query::search(self, query)
    }

    fn count(&self, query: &SearchQuery) -> Result<u64, ChainkeeperError> {
        self.index.count(query)
    }

    fn tree(&self) -> Result<TreeReport, ChainkeeperError> {
        crate::query::tree(self)
    }

    fn analyze(&self, kind: AnalyzeKind) -> Result<AnalyzeReport, ChainkeeperError> {
        crate::analyze::analyze(self, kind)
    }

    fn audit(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        crate::query::audit(self, query)
    }

    fn doctor(&self) -> Result<DoctorReport, ChainkeeperError> {
        crate::doctor::doctor(self)
    }

    fn diff(
        &self,
        request: &DiffRequest,
    ) -> Result<chainkeeper_core::DiffReport, ChainkeeperError> {
        crate::diff::diff(self, request)
    }

    fn publish(&self, options: &PublishOptions) -> Result<PublishManifest, ChainkeeperError> {
        crate::maintenance::publish(self, options)
    }

    fn rebuild_index(&self) -> Result<IndexReport, ChainkeeperError> {
        crate::maintenance::rebuild_index(self)
    }

    fn repair_index(&self) -> Result<IndexReport, ChainkeeperError> {
        crate::maintenance::repair_index(self)
    }
}
