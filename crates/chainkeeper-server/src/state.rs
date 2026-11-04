//! Application state shared by every route.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use chainkeeper_core::{
    AuthorityName, AuthorityRecord, CertificateRecord, CertificateStatus, CrlRecord, HealthStatus,
    OcspResponder, ProfileName, PublishArtifact, RevocationRecord, Serial, ServerHealth,
    ServerSnapshot, ServerStateProvider,
};

use crate::watcher::WatchStatus;

/// Body limit applied to every request.
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
/// Request timeout applied to every route.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Immutable snapshot plus lookup maps.
#[derive(Debug)]
pub struct SnapshotIndex {
    snapshot: Arc<ServerSnapshot>,
    certificates: Vec<CertificateRecord>,
    by_serial: BTreeMap<Serial, usize>,
    by_profile: BTreeMap<ProfileName, Vec<usize>>,
    by_authority: BTreeMap<AuthorityName, Vec<usize>>,
    by_status: BTreeMap<CertificateStatus, Vec<usize>>,
    revocations: BTreeMap<Serial, RevocationRecord>,
    authorities: BTreeMap<AuthorityName, AuthorityRecord>,
    crls: BTreeMap<AuthorityName, CrlRecord>,
    artifacts: BTreeMap<PathBuf, PublishArtifact>,
}

impl SnapshotIndex {
    /// Builds every lookup map from `snapshot`.
    #[must_use]
    pub fn new(snapshot: Arc<ServerSnapshot>) -> Self {
        let now = snapshot.generated_at;
        let certificates = snapshot.certificates.clone();
        let mut by_serial = BTreeMap::new();
        let mut by_profile: BTreeMap<ProfileName, Vec<usize>> = BTreeMap::new();
        let mut by_authority: BTreeMap<AuthorityName, Vec<usize>> = BTreeMap::new();
        let mut by_status: BTreeMap<CertificateStatus, Vec<usize>> = BTreeMap::new();
        for (position, record) in certificates.iter().enumerate() {
            by_serial.insert(record.serial.clone(), position);
            by_profile
                .entry(record.profile.clone())
                .or_default()
                .push(position);
            by_authority
                .entry(record.authority.clone())
                .or_default()
                .push(position);
            by_status
                .entry(record.status(now))
                .or_default()
                .push(position);
        }
        let revocations = snapshot
            .revocations
            .iter()
            .map(|record| (record.serial.clone(), record.clone()))
            .collect();
        let authorities = snapshot
            .authorities
            .iter()
            .map(|record| (record.name.clone(), record.clone()))
            .collect();
        let crls = snapshot
            .crls
            .iter()
            .map(|record| (record.authority.clone(), record.clone()))
            .collect();
        let artifacts = snapshot
            .manifest
            .as_ref()
            .map(|manifest| {
                manifest
                    .artifacts
                    .iter()
                    .map(|artifact| (artifact.path.clone(), artifact.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            snapshot,
            certificates,
            by_serial,
            by_profile,
            by_authority,
            by_status,
            revocations,
            authorities,
            crls,
            artifacts,
        }
    }

    /// Snapshot this index was built from.
    #[must_use]
    pub const fn snapshot(&self) -> &Arc<ServerSnapshot> {
        &self.snapshot
    }

    /// Every certificate in serial order.
    #[must_use]
    pub fn certificates(&self) -> &[CertificateRecord] {
        &self.certificates
    }

    /// Certificate by serial.
    #[must_use]
    pub fn certificate(&self, serial: &Serial) -> Option<&CertificateRecord> {
        self.by_serial
            .get(serial)
            .and_then(|position| self.certificates.get(*position))
    }

    /// Positions of certificates issued from a profile.
    #[must_use]
    pub const fn profile_index(&self) -> &BTreeMap<ProfileName, Vec<usize>> {
        &self.by_profile
    }

    /// Positions of certificates issued by an authority.
    #[must_use]
    pub const fn authority_index(&self) -> &BTreeMap<AuthorityName, Vec<usize>> {
        &self.by_authority
    }

    /// Positions of certificates in a lifecycle status.
    #[must_use]
    pub const fn status_index(&self) -> &BTreeMap<CertificateStatus, Vec<usize>> {
        &self.by_status
    }

    /// Revocation by serial.
    #[must_use]
    pub fn revocation(&self, serial: &Serial) -> Option<&RevocationRecord> {
        self.revocations.get(serial)
    }

    /// Authority by name.
    #[must_use]
    pub fn authority(&self, name: &AuthorityName) -> Option<&AuthorityRecord> {
        self.authorities.get(name)
    }

    /// CRL by authority.
    #[must_use]
    pub fn crl(&self, authority: &AuthorityName) -> Option<&CrlRecord> {
        self.crls.get(authority)
    }

    /// Manifest artifact by relative path.
    #[must_use]
    pub fn artifact(&self, path: &Path) -> Option<&PublishArtifact> {
        self.artifacts.get(path)
    }
}

/// State shared by every HTTP handler.
#[derive(Clone)]
pub struct AppState {
    provider: Arc<dyn ServerStateProvider>,
    ocsp: Arc<dyn OcspResponder>,
    publish_dir: PathBuf,
    watcher: Option<Arc<WatchStatus>>,
    cache: Arc<RwLock<Option<CachedIndex>>>,
    request_timeout: Duration,
    max_body_bytes: usize,
}

#[derive(Clone)]
struct CachedIndex {
    snapshot: Arc<ServerSnapshot>,
    index: Arc<SnapshotIndex>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AppState")
            .field("publish_dir", &self.publish_dir)
            .field("request_timeout", &self.request_timeout)
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Builds state from a snapshot provider and OCSP responder.
    #[must_use]
    pub fn new(
        provider: Arc<dyn ServerStateProvider>,
        ocsp: Arc<dyn OcspResponder>,
        publish_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            provider,
            ocsp,
            publish_dir: publish_dir.into(),
            watcher: None,
            cache: Arc::new(RwLock::new(None)),
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }

    /// Attaches watcher status to the health response.
    #[must_use]
    pub fn with_watcher(mut self, watcher: Arc<WatchStatus>) -> Self {
        self.watcher = Some(watcher);
        self
    }

    /// Overrides the request timeout and body limit.
    #[must_use]
    pub const fn with_limits(mut self, timeout: Duration, max_body_bytes: usize) -> Self {
        self.request_timeout = timeout;
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Current snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ServerSnapshot> {
        self.provider.snapshot()
    }

    /// Lookup index for the current snapshot, rebuilt when the snapshot swaps.
    #[must_use]
    pub fn index(&self) -> Arc<SnapshotIndex> {
        let snapshot = self.provider.snapshot();
        {
            let cache = self
                .cache
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(cached) = cache.as_ref()
                && Arc::ptr_eq(&cached.snapshot, &snapshot)
            {
                return Arc::clone(&cached.index);
            }
        }
        let index = Arc::new(SnapshotIndex::new(Arc::clone(&snapshot)));
        let mut cache = self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *cache = Some(CachedIndex {
            snapshot,
            index: Arc::clone(&index),
        });
        index
    }

    /// Publish directory.
    #[must_use]
    pub fn publish_dir(&self) -> &Path {
        &self.publish_dir
    }

    /// OCSP responder.
    #[must_use]
    pub fn ocsp(&self) -> &Arc<dyn OcspResponder> {
        &self.ocsp
    }

    /// Request timeout applied by the router.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Body limit applied by the router.
    #[must_use]
    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Health combining the provider, OCSP responder, and watcher.
    #[must_use]
    pub fn health(&self) -> ServerHealth {
        let mut health = self.provider.health();
        health.ocsp_ready = self.ocsp.ready();
        if !health.ocsp_ready {
            health.errors.push("ocsp responder is not ready".to_owned());
            downgrade(&mut health, HealthStatus::Degraded);
        }
        if let Some(watcher) = &self.watcher
            && let Some(error) = watcher.health().last_error
        {
            health
                .errors
                .push(format!("repository reload failed: {error}"));
            downgrade(&mut health, HealthStatus::Degraded);
        }
        health
    }
}

fn downgrade(health: &mut ServerHealth, status: HealthStatus) {
    if status > health.status {
        health.status = status;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chainkeeper_core::{
        CertificateRecord, CertificateStatus, KeyAlgorithm, ProfileName, Serial, ServerSnapshot,
        SubjectName,
    };
    use chainkeeper_testkit::{FakeOcspResponder, FakeServerStateProvider};
    use time::macros::datetime;
    use time::{Duration, OffsetDateTime};

    use super::{AppState, SnapshotIndex};

    fn record(
        serial: &str,
        profile: &str,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> CertificateRecord {
        CertificateRecord {
            serial: Serial::new(serial).expect("serial"),
            subject: SubjectName::new("example.test"),
            issuer: "CN=Example Root".to_owned(),
            profile: ProfileName::new(profile).expect("profile"),
            authority: chainkeeper_core::AuthorityName::new("tls").expect("authority"),
            algorithm: KeyAlgorithm::EcdsaP256,
            sans: Vec::new(),
            ekus: Vec::new(),
            key_usages: Vec::new(),
            issued_at,
            expires_at,
            path: std::path::PathBuf::from(format!("certificates/active/{serial}.pem")),
            revoked_at: None,
            revocation_reason: None,
            replaces: None,
        }
    }

    fn snapshot() -> ServerSnapshot {
        let now = datetime!(2024-05-01 12:00:00 UTC);
        ServerSnapshot {
            generated_at: now,
            repo_commit: "a".repeat(40),
            manifest: None,
            certificates: vec![
                record("AA", "tls-server", now, now + Duration::days(30)),
                record("BB", "tls-client", now, now - Duration::days(1)),
            ],
            revocations: Vec::new(),
            authorities: Vec::new(),
            crls: Vec::new(),
            audit_events: Vec::new(),
        }
    }

    #[test]
    fn index_maps_every_certificate() {
        let index = SnapshotIndex::new(Arc::new(snapshot()));
        assert_eq!(index.certificates().len(), 2);
        assert!(
            index
                .certificate(&Serial::new("AA").expect("serial"))
                .is_some()
        );
        assert_eq!(index.profile_index().len(), 2);
        assert_eq!(index.authority_index().len(), 1);
        assert_eq!(
            index
                .status_index()
                .get(&CertificateStatus::Active)
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            index
                .status_index()
                .get(&CertificateStatus::Expired)
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn health_reports_unready_ocsp() {
        let provider = Arc::new(FakeServerStateProvider::new());
        let state = AppState::new(
            provider,
            Arc::new(FakeOcspResponder::with_ready(false)),
            "/tmp",
        );
        let health = state.health();
        assert!(!health.ocsp_ready);
        assert!(health.status >= chainkeeper_core::HealthStatus::Degraded);
        assert_eq!(health.errors.len(), 1);
    }

    #[test]
    fn health_is_ok_when_every_component_is_ready() {
        let provider = Arc::new(FakeServerStateProvider::new());
        let state = AppState::new(provider, Arc::new(FakeOcspResponder::new()), "/tmp");
        let health = state.health();
        assert!(health.ocsp_ready);
        assert_eq!(health.status, chainkeeper_core::HealthStatus::Ok);
    }
}
