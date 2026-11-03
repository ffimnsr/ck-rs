//! Frozen trait contracts consumed by the CLI, the server, and every library
//! crate.
//!
//! Every trait is object-safe so implementations can be stored as
//! `Arc<dyn Trait>` and swapped at runtime. HSM signers will implement
//! [`Signer`] without changing any caller.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;

use crate::config::Policy;
use crate::crypto::{KeyAlgorithm, SignatureScheme};
use crate::error::ChainkeeperError;
use crate::ids::{AuthorityName, ProfileName, Serial};
use crate::profile::Profile;
use crate::publish::{PublishManifest, ServerHealth, ServerSnapshot};
use crate::records::{
    AuditEvent, AuthorityBundle, AuthorityMaterial, AuthorityRecord, CertificateRecord, CrlBundle,
    CrlRecord, GitChange, GitStatus, IndexRecords, IndexStats, IssuedCertificate, KeyMaterial,
    NewAuditEvent, RevocationRecord, SignerBundle,
};
use crate::report::{
    AnalyzeKind, AnalyzeReport, DiffReport, DoctorReport, IndexReport, InitReport, InspectReport,
    IssueReport, RevokeReport, TreeReport,
};
use crate::request::{
    AuditQuery, CreateAuthorityRequest, CreateOcspSignerRequest, CustomExtension, DiffRequest,
    InitRequest, IssueRequest, PublishOptions, RevokeRequest, SearchQuery,
};

/// Source of the current time.
pub trait Clock: Send + Sync {
    /// Returns the current UTC time truncated to whole seconds.
    fn now(&self) -> OffsetDateTime;
}

/// Wall clock backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        crate::time_util::truncate(OffsetDateTime::now_utc())
    }
}

/// Generator of ULIDs and certificate serials.
pub trait IdGenerator: Send + Sync {
    /// Returns a new canonical ULID string.
    fn ulid(&self) -> String;

    /// Returns a new random 16 byte serial.
    fn serial(&self) -> Serial;
}

/// Key holder that produces signatures.
///
/// Production implementations are file based in V1. `YubiKey` and PKCS#11
/// implementations will provide the same trait in a later phase.
pub trait Signer: Send + Sync {
    /// Algorithm of the held key.
    fn algorithm(&self) -> KeyAlgorithm;

    /// DER encoded `SubjectPublicKeyInfo` of the held key.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when the public key cannot be
    /// encoded.
    fn public_key_der(&self) -> Result<Vec<u8>, ChainkeeperError>;

    /// Signs `message` with the given scheme.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when the scheme does not match the
    /// key algorithm or the signature operation fails.
    fn sign(&self, message: &[u8], scheme: SignatureScheme) -> Result<Vec<u8>, ChainkeeperError>;
}

/// X.509 generation backend.
pub trait CertificateProvider: Send + Sync {
    /// Generates a key pair for the given algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when key generation fails.
    fn generate_key(&self, algorithm: KeyAlgorithm) -> Result<KeyMaterial, ChainkeeperError>;

    /// Creates a self-signed root authority and its key pair.
    ///
    /// The provider owns root key generation because the returned
    /// [`AuthorityBundle`] carries the private key. Root key material is
    /// therefore always exportable; HSM-backed roots are a post-V1 concern.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when key generation, certificate
    /// construction, or signing fails, or [`ChainkeeperError::Validation`]
    /// when the request is inconsistent.
    fn create_root(
        &self,
        request: &CreateAuthorityRequest,
    ) -> Result<AuthorityBundle, ChainkeeperError>;

    /// Creates an intermediate authority signed by `parent`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when certificate construction or
    /// signing fails.
    fn create_intermediate(
        &self,
        request: &CreateAuthorityRequest,
        parent: &AuthorityMaterial,
        parent_signer: &dyn Signer,
    ) -> Result<AuthorityBundle, ChainkeeperError>;

    /// Creates a dedicated OCSP signer signed by `parent`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when certificate construction or
    /// signing fails.
    fn create_ocsp_signer(
        &self,
        request: &CreateOcspSignerRequest,
        parent: &AuthorityMaterial,
        parent_signer: &dyn Signer,
    ) -> Result<SignerBundle, ChainkeeperError>;

    /// Issues a leaf certificate.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when certificate construction or
    /// signing fails.
    fn issue(
        &self,
        request: &IssueRequest,
        signer: &dyn Signer,
    ) -> Result<IssuedCertificate, ChainkeeperError>;

    /// Generates a CRL for the authority.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when CRL construction or signing
    /// fails.
    fn generate_crl(
        &self,
        request: &crate::records::CrlRequest,
        signer: &dyn Signer,
    ) -> Result<CrlBundle, ChainkeeperError>;
}

/// Canonical filesystem store.
pub trait CertificateStore: Send + Sync {
    /// Loads `tenant.yaml`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when the file cannot be read or
    /// parsed.
    fn load_tenant(&self) -> Result<crate::config::TenantConfig, ChainkeeperError>;

    /// Loads `policy/policy.yaml`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when the file cannot be read or
    /// parsed.
    fn load_policy(&self) -> Result<Policy, ChainkeeperError>;

    /// Loads every profile under `profiles/`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a profile cannot be read or
    /// parsed.
    fn load_profiles(&self) -> Result<Vec<Profile>, ChainkeeperError>;

    /// Writes an issued certificate, its metadata, and its key when present.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::AlreadyExists`] when the serial exists, or
    /// [`ChainkeeperError::Storage`] on write failure.
    fn write_certificate(
        &self,
        certificate: &IssuedCertificate,
    ) -> Result<PathBuf, ChainkeeperError>;

    /// Loads certificate metadata by serial.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when the metadata exists but
    /// cannot be parsed.
    fn get_certificate(
        &self,
        serial: &Serial,
    ) -> Result<Option<CertificateRecord>, ChainkeeperError>;

    /// Lists every certificate in every status directory.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a directory cannot be read.
    fn list_certificates(&self) -> Result<Vec<CertificateRecord>, ChainkeeperError>;

    /// Moves a certificate between status directories.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when the serial is unknown.
    fn move_certificate(
        &self,
        serial: &Serial,
        to: crate::records::CertificateStatus,
    ) -> Result<(), ChainkeeperError>;

    /// Writes a revocation record.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] on write failure.
    fn write_revocation(&self, record: &RevocationRecord) -> Result<PathBuf, ChainkeeperError>;

    /// Lists every revocation record.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a record cannot be read or
    /// parsed.
    fn list_revocations(&self) -> Result<Vec<RevocationRecord>, ChainkeeperError>;

    /// Writes an authority bundle, including its private key.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] on write failure.
    fn write_authority(&self, bundle: &AuthorityBundle) -> Result<(), ChainkeeperError>;

    /// Loads public authority material by name.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when files exist but cannot be
    /// read or parsed.
    fn load_authority(
        &self,
        name: &AuthorityName,
    ) -> Result<Option<AuthorityMaterial>, ChainkeeperError>;

    /// Lists every authority.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a directory cannot be read.
    fn list_authorities(&self) -> Result<Vec<AuthorityRecord>, ChainkeeperError>;
}

/// Disposable SQLite index.
pub trait IndexStore: Send + Sync {
    /// Rebuilds the index from canonical records.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] when the rebuild fails.
    fn rebuild(&self, records: &IndexRecords) -> Result<IndexReport, ChainkeeperError>;

    /// Searches indexed certificates.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] when the query fails.
    fn query(&self, query: &SearchQuery) -> Result<Vec<CertificateRecord>, ChainkeeperError>;

    /// Inserts or updates a certificate row.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] on query failure.
    fn upsert_certificate(&self, record: &CertificateRecord) -> Result<(), ChainkeeperError>;

    /// Inserts or updates a revocation row.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] on query failure.
    fn upsert_revocation(&self, record: &RevocationRecord) -> Result<(), ChainkeeperError>;

    /// Inserts or updates an authority row.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] on query failure.
    fn upsert_authority(&self, record: &AuthorityRecord) -> Result<(), ChainkeeperError>;

    /// Inserts or updates a CRL row.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] on query failure.
    fn upsert_crl(&self, crl: &crate::records::IndexedCrl) -> Result<(), ChainkeeperError>;

    /// Inserts or updates an audit event row.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] on query failure.
    fn upsert_audit_event(&self, event: &AuditEvent) -> Result<(), ChainkeeperError>;

    /// Lists indexed audit events matching the query.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] on query failure.
    fn list_audit(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError>;

    /// Counts indexed certificates matching the query, ignoring pagination.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] on query failure.
    fn count(&self, query: &SearchQuery) -> Result<u64, ChainkeeperError>;

    /// Returns row counts.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] on query failure.
    fn stats(&self) -> Result<IndexStats, ChainkeeperError>;

    /// Returns the index schema version.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] on query failure.
    fn schema_version(&self) -> Result<u32, ChainkeeperError>;
}

/// Registry of certificate profiles.
pub trait ProfileRegistry: Send + Sync {
    /// Looks up a profile by name.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when the profile does not exist.
    fn get(&self, name: &ProfileName) -> Result<Profile, ChainkeeperError>;

    /// Returns every known profile.
    fn list(&self) -> Vec<Profile>;

    /// Validates a profile against the registry rules.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Profile`] when the profile is invalid.
    fn validate(&self, profile: &Profile) -> Result<(), ChainkeeperError>;
}

/// Policy validation engine.
pub trait PolicyEngine: Send + Sync {
    /// Validates an issuance request against the policy and profile.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Policy`] or
    /// [`ChainkeeperError::Validation`] when the request is rejected.
    fn validate_issue(
        &self,
        policy: &Policy,
        profile: &Profile,
        request: &IssueRequest,
    ) -> Result<(), ChainkeeperError>;

    /// Validates a custom extension against the policy.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Policy`] or
    /// [`ChainkeeperError::Validation`] when the extension is rejected.
    fn validate_custom_extension(
        &self,
        policy: &Policy,
        extension: &CustomExtension,
    ) -> Result<(), ChainkeeperError>;

    /// Validates a profile against the policy.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Policy`] when the profile is not allowed.
    fn validate_profile(&self, policy: &Policy, profile: &Profile) -> Result<(), ChainkeeperError>;
}

/// Append-only audit log.
pub trait AuditLog: Send + Sync {
    /// Appends an event and assigns its identifier and sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Audit`] on write failure or duplicate
    /// identifier.
    fn append(&self, event: NewAuditEvent) -> Result<AuditEvent, ChainkeeperError>;

    /// Lists events matching the query.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Audit`] when the log cannot be read.
    fn list(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError>;

    /// Returns the next sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Audit`] when the log cannot be read.
    fn next_seq(&self) -> Result<u64, ChainkeeperError>;
}

/// Git repository operations required by the engine.
pub trait GitRepository: Send + Sync {
    /// Initialises a repository at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] on failure.
    fn init(&self, path: &Path) -> Result<(), ChainkeeperError>;

    /// Returns the current `HEAD` commit.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when the repository has no
    /// commits, or [`ChainkeeperError::Git`] on failure.
    fn head_commit(&self) -> Result<String, ChainkeeperError>;

    /// Commits the given paths with the given message.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the commit fails.
    fn commit(&self, message: &str, paths: &[PathBuf]) -> Result<String, ChainkeeperError>;

    /// Lists changes between two commits.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when a commit is unknown or the diff
    /// fails.
    fn diff(&self, from: &str, to: &str) -> Result<Vec<GitChange>, ChainkeeperError>;

    /// Returns the working tree status.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] on failure.
    fn status(&self) -> Result<GitStatus, ChainkeeperError>;

    /// Returns true when the working tree has no changes.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] on failure.
    fn is_clean(&self) -> Result<bool, ChainkeeperError>;
}

/// Guard that releases an acquired repository lock when dropped.
pub struct LockGuard {
    path: Option<PathBuf>,
    release: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl LockGuard {
    /// Builds a guard that invokes `release` on drop.
    #[must_use]
    pub fn new(path: Option<PathBuf>, release: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self {
            path,
            release: Some(Box::new(release)),
        }
    }

    /// Path of the lock file, when the guard is file backed.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Releases the lock immediately. Drop after this call is a no-op.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        self.release_inner();
    }
}

impl fmt::Debug for LockGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockGuard")
            .field("path", &self.path)
            .field("held", &self.release.is_some())
            .finish()
    }
}

/// Exclusive repository lock.
pub trait RepositoryLock: Send + Sync {
    /// Acquires the exclusive lock, waiting at most `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Lock`] when the timeout elapses first.
    fn acquire_exclusive(&self, timeout: Duration) -> Result<LockGuard, ChainkeeperError>;
}

/// CRL generation and inspection.
pub trait CrlManager: Send + Sync {
    /// Regenerates the CRL for an authority and writes it to the repository.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] or [`ChainkeeperError::Crypto`]
    /// when regeneration fails.
    fn update_for_authority(
        &self,
        authority: &AuthorityName,
    ) -> Result<CrlBundle, ChainkeeperError>;

    /// Lists known CRLs.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a CRL record cannot be read.
    fn list_crls(&self) -> Result<Vec<CrlRecord>, ChainkeeperError>;
}

/// Publication artifact builder.
pub trait PublishBuilder: Send + Sync {
    /// Builds the publish directory and returns its manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Publish`] when the build fails.
    fn build(&self, options: &PublishOptions) -> Result<PublishManifest, ChainkeeperError>;

    /// Validates that a directory looks like a publish directory.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Publish`] when the directory is invalid.
    fn validate_publish_dir(&self, path: &Path) -> Result<(), ChainkeeperError>;
}

/// RFC 6960 OCSP responder.
pub trait OcspResponder: Send + Sync {
    /// Answers a DER encoded OCSP request with a DER encoded response.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Ocsp`] when the request is malformed or the
    /// responder is not ready.
    fn respond(&self, request_der: &[u8]) -> Result<Vec<u8>, ChainkeeperError>;

    /// Reloads revocation data from the repository snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Ocsp`] when reload fails.
    fn reload(&self) -> Result<(), ChainkeeperError>;

    /// Returns true when the responder can answer requests.
    fn ready(&self) -> bool;
}

/// Full PKI workflow surface consumed by the CLI.
pub trait ChainkeeperService: Send + Sync {
    /// Initialises a repository.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::AlreadyExists`] or
    /// [`ChainkeeperError::Storage`] on failure.
    fn init(&self, request: &InitRequest) -> Result<InitReport, ChainkeeperError>;

    /// Creates the root authority.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Conflict`] when a root already exists.
    fn create_root(
        &self,
        request: &CreateAuthorityRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError>;

    /// Creates an intermediate authority.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when the parent is unknown.
    fn create_intermediate(
        &self,
        request: &CreateAuthorityRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError>;

    /// Creates a dedicated OCSP signer.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when the parent is unknown.
    fn create_ocsp_signer(
        &self,
        request: &CreateOcspSignerRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError>;

    /// Issues a certificate.
    ///
    /// # Errors
    ///
    /// Returns policy, crypto, or storage errors on failure.
    fn issue(&self, request: &IssueRequest) -> Result<IssueReport, ChainkeeperError>;

    /// Revokes a certificate and regenerates the CRL.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when the serial is unknown.
    fn revoke(&self, request: &RevokeRequest) -> Result<RevokeReport, ChainkeeperError>;

    /// Inspects a certificate.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when the serial is unknown.
    fn inspect(&self, serial: &Serial) -> Result<InspectReport, ChainkeeperError>;

    /// Searches certificates.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] or
    /// [`ChainkeeperError::Storage`] on failure.
    fn search(&self, query: &SearchQuery) -> Result<Vec<CertificateRecord>, ChainkeeperError>;

    /// Counts certificates matching `query`, ignoring pagination.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] or
    /// [`ChainkeeperError::Storage`] on failure.
    fn count(&self, query: &SearchQuery) -> Result<u64, ChainkeeperError> {
        Ok(u64::try_from(self.search(query)?.len()).unwrap_or(u64::MAX))
    }

    /// Returns the trust hierarchy.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when authorities cannot be read.
    fn tree(&self) -> Result<TreeReport, ChainkeeperError>;

    /// Runs an analysis.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when records cannot be read.
    fn analyze(&self, kind: AnalyzeKind) -> Result<AnalyzeReport, ChainkeeperError>;

    /// Lists audit events.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Audit`] when the log cannot be read.
    fn audit(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError>;

    /// Runs health diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when checks cannot run.
    fn doctor(&self) -> Result<DoctorReport, ChainkeeperError>;

    /// Compares repository state between commits.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the diff fails.
    fn diff(&self, request: &DiffRequest) -> Result<DiffReport, ChainkeeperError>;

    /// Publishes artifacts and returns the manifest.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Publish`] when the build fails.
    fn publish(&self, options: &PublishOptions) -> Result<PublishManifest, ChainkeeperError>;

    /// Rebuilds the disposable index.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] when the rebuild fails.
    fn rebuild_index(&self) -> Result<IndexReport, ChainkeeperError>;

    /// Repairs misplaced canonical records and rebuilds the index.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] or
    /// [`ChainkeeperError::Storage`] when repair fails.
    fn repair_index(&self) -> Result<IndexReport, ChainkeeperError> {
        Err(ChainkeeperError::not_implemented(
            "index repair is not available",
        ))
    }
}

/// Provider of the immutable snapshot served by the HTTP server.
pub trait ServerStateProvider: Send + Sync {
    /// Returns the current snapshot without blocking on disk access.
    fn snapshot(&self) -> Arc<ServerSnapshot>;

    /// Reloads the snapshot from the repository.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when the reload fails.
    fn reload(&self) -> Result<Arc<ServerSnapshot>, ChainkeeperError>;

    /// Returns the current health response.
    fn health(&self) -> ServerHealth;
}
