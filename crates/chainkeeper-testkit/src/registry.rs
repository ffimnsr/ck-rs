//! Remaining in-memory test doubles.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use chainkeeper_core::{
    AnalysisFinding, AnalyzeKind, AnalyzeReport, AuditEvent, AuditQuery, AuthorityName,
    AuthorityRecord, CertificateRecord, ChainkeeperError, ChainkeeperService, CrlBundle,
    CrlManager, CrlRecord, DiffReport, DoctorReport, EventId, HealthStatus, IdGenerator as _,
    IndexRecords, IndexReport, IndexStats, IndexStore, InitReport, InspectReport, IssueReport,
    KeyAlgorithm, LockGuard, Policy, PolicyEngine, Profile, ProfileName, ProfileRegistry,
    PublishManifest, PublishOptions, RepositoryLock, RevocationRecord, SearchQuery, Serial,
    ServerHealth, ServerSnapshot, ServerStateProvider, TenantId, TreeReport, builtin_profile,
    builtin_profiles,
};
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::audit::matches_query;

fn authority_name(value: &str) -> AuthorityName {
    AuthorityName::new(value).expect("built-in authority name is valid")
}

fn tenant_id() -> TenantId {
    TenantId::new("test-tenant").expect("test tenant id is valid")
}

/// Profile registry backed by a map.
#[derive(Debug)]
pub struct InMemoryProfileRegistry {
    profiles: BTreeMap<ProfileName, Profile>,
}

impl Default for InMemoryProfileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryProfileRegistry {
    /// Creates a registry containing the built-in profiles.
    #[must_use]
    pub fn new() -> Self {
        Self::with_profiles(builtin_profiles())
    }

    /// Creates a registry from an explicit profile list.
    #[must_use]
    pub fn with_profiles(profiles: Vec<Profile>) -> Self {
        Self {
            profiles: profiles
                .into_iter()
                .map(|profile| (profile.name.clone(), profile))
                .collect(),
        }
    }

    /// Inserts or replaces a profile.
    pub fn register(&mut self, profile: Profile) {
        self.profiles.insert(profile.name.clone(), profile);
    }
}

impl ProfileRegistry for InMemoryProfileRegistry {
    fn get(&self, name: &ProfileName) -> Result<Profile, ChainkeeperError> {
        self.profiles
            .get(name)
            .cloned()
            .ok_or_else(|| ChainkeeperError::not_found("profile", name.as_str()))
    }

    fn list(&self) -> Vec<Profile> {
        self.profiles.values().cloned().collect()
    }

    fn validate(&self, profile: &Profile) -> Result<(), ChainkeeperError> {
        profile.validate()
    }
}

/// Policy engine that accepts every request.
///
/// Engine tests that need rejections use the real engine from
/// `chainkeeper-policy`; this double only unblocks orchestration tests.
#[derive(Debug, Default)]
pub struct NoopPolicyEngine;

impl PolicyEngine for NoopPolicyEngine {
    fn validate_issue(
        &self,
        _policy: &Policy,
        _profile: &Profile,
        _request: &chainkeeper_core::IssueRequest,
    ) -> Result<(), ChainkeeperError> {
        Ok(())
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

/// CRL manager that returns deterministic bundles without touching disk.
#[derive(Debug)]
pub struct FakeCrlManager {
    now: OffsetDateTime,
    updates: AtomicU64,
}

impl Default for FakeCrlManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeCrlManager {
    /// Creates a manager pinned to `tls` at a fixed time.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            now: time::macros::datetime!(2024-01-01 00:00:00 UTC),
            updates: AtomicU64::new(0),
        }
    }

    /// Number of successful CRL updates.
    #[must_use]
    pub fn update_count(&self) -> u64 {
        self.updates.load(Ordering::SeqCst)
    }
}

impl CrlManager for FakeCrlManager {
    fn update_for_authority(
        &self,
        authority: &AuthorityName,
    ) -> Result<CrlBundle, ChainkeeperError> {
        let number = self.updates.fetch_add(1, Ordering::SeqCst) + 1;
        let record = CrlRecord {
            version: chainkeeper_core::CONFIG_VERSION,
            authority: authority.clone(),
            number,
            this_update: self.now,
            next_update: self.now + TimeDuration::days(7),
            revoked_serials: Vec::new(),
            der_path: PathBuf::from(format!("crls/{authority}.crl.der")),
            pem_path: PathBuf::from(format!("crls/{authority}.crl.pem")),
        };
        Ok(CrlBundle {
            record,
            der: b"FAKE-CRL".to_vec(),
            pem: "-----BEGIN X509 CRL-----\nFAKE\n-----END X509 CRL-----\n".to_owned(),
        })
    }

    fn list_crls(&self) -> Result<Vec<CrlRecord>, ChainkeeperError> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Default)]
struct LockState {
    held: Mutex<bool>,
    available: Condvar,
}

/// Repository lock that serialises callers within one process.
#[derive(Debug, Clone, Default)]
pub struct FakeRepositoryLock {
    state: Arc<LockState>,
}

impl FakeRepositoryLock {
    /// Creates a free lock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RepositoryLock for FakeRepositoryLock {
    fn acquire_exclusive(&self, timeout: Duration) -> Result<LockGuard, ChainkeeperError> {
        let deadline = Instant::now() + timeout;
        let mut held = self
            .state
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        while *held {
            let now = Instant::now();
            if now >= deadline {
                return Err(ChainkeeperError::lock(
                    "timed out acquiring repository lock",
                ));
            }
            let (guard, result) = self
                .state
                .available
                .wait_timeout(held, deadline - now)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            held = guard;
            if result.timed_out() && *held {
                return Err(ChainkeeperError::lock(
                    "timed out acquiring repository lock",
                ));
            }
        }

        *held = true;
        drop(held);

        let state = Arc::clone(&self.state);
        Ok(LockGuard::new(
            Some(PathBuf::from(".chainkeeper/lock")),
            move || {
                let mut held = state
                    .held
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *held = false;
                drop(held);
                state.available.notify_one();
            },
        ))
    }
}

/// Index that keeps rows in memory.
#[derive(Debug)]
pub struct InMemoryIndexStore {
    now: OffsetDateTime,
    certificates: RwLock<BTreeMap<Serial, CertificateRecord>>,
    revocations: RwLock<BTreeMap<Serial, RevocationRecord>>,
    authorities: RwLock<BTreeMap<AuthorityName, AuthorityRecord>>,
    audit_events: RwLock<BTreeMap<EventId, AuditEvent>>,
}

impl Default for InMemoryIndexStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryIndexStore {
    /// Creates an empty index with a fixed evaluation time.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            now: time::macros::datetime!(2024-06-01 00:00:00 UTC),
            certificates: RwLock::new(BTreeMap::new()),
            revocations: RwLock::new(BTreeMap::new()),
            authorities: RwLock::new(BTreeMap::new()),
            audit_events: RwLock::new(BTreeMap::new()),
        }
    }

    /// Returns the time used to derive certificate status.
    #[must_use]
    pub const fn now(&self) -> OffsetDateTime {
        self.now
    }
}

impl IndexStore for InMemoryIndexStore {
    fn rebuild(&self, records: &IndexRecords) -> Result<IndexReport, ChainkeeperError> {
        for certificate in &records.certificates {
            self.upsert_certificate(certificate)?;
        }
        for revocation in &records.revocations {
            self.upsert_revocation(revocation)?;
        }
        for authority in &records.authorities {
            self.upsert_authority(authority)?;
        }
        for event in &records.audit_events {
            self.upsert_audit_event(event)?;
        }
        let stats = self.stats()?;
        Ok(IndexReport {
            generated_at: self.now,
            schema_version: self.schema_version()?,
            stats,
            moved: Vec::new(),
        })
    }

    fn query(&self, query: &SearchQuery) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        let certificates = self
            .certificates
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut selected: Vec<CertificateRecord> = certificates
            .values()
            .filter(|record| {
                query
                    .status
                    .is_none_or(|status| record.status(self.now) == status)
            })
            .filter(|record| {
                query
                    .profile
                    .as_ref()
                    .is_none_or(|profile| &record.profile == profile)
            })
            .filter(|record| {
                query
                    .authority
                    .as_ref()
                    .is_none_or(|authority| &record.authority == authority)
            })
            .filter(|record| {
                query.expires_within_days.is_none_or(|days| {
                    let limit = self.now + TimeDuration::days(i64::from(days));
                    let within_window = record.expires_at <= limit;
                    let include_expired = query.include_expired
                        || query.status == Some(chainkeeper_core::CertificateStatus::Expired)
                        || record.expires_at > self.now;
                    within_window && include_expired
                })
            })
            .filter(|record| {
                query.text.as_ref().is_none_or(|text| {
                    record.subject.cn.contains(text)
                        || record.serial.as_str().contains(&text.to_uppercase())
                        || record.sans.iter().any(|san| san.value().contains(text))
                })
            })
            .cloned()
            .collect();
        drop(certificates);
        selected.sort_by(|left, right| {
            left.expires_at
                .cmp(&right.expires_at)
                .then_with(|| left.serial.cmp(&right.serial))
        });
        if query.offset > 0 {
            selected.drain(..query.offset.min(selected.len()));
        }
        if let Some(limit) = query.limit {
            selected.truncate(limit);
        }
        Ok(selected)
    }

    fn upsert_certificate(&self, record: &CertificateRecord) -> Result<(), ChainkeeperError> {
        self.certificates
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(record.serial.clone(), record.clone());
        Ok(())
    }

    fn upsert_revocation(&self, record: &RevocationRecord) -> Result<(), ChainkeeperError> {
        self.revocations
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(record.serial.clone(), record.clone());
        Ok(())
    }

    fn upsert_authority(&self, record: &AuthorityRecord) -> Result<(), ChainkeeperError> {
        self.authorities
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(record.name.clone(), record.clone());
        Ok(())
    }

    fn upsert_audit_event(&self, event: &AuditEvent) -> Result<(), ChainkeeperError> {
        self.audit_events
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(event.id.clone(), event.clone());
        Ok(())
    }

    fn list_audit(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        let events = self
            .audit_events
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut selected: Vec<AuditEvent> = events
            .values()
            .filter(|event| matches_query(event, query))
            .cloned()
            .collect();
        drop(events);
        if let Some(limit) = query.limit {
            selected.truncate(limit);
        }
        Ok(selected)
    }

    fn count(&self, query: &SearchQuery) -> Result<u64, ChainkeeperError> {
        let mut unbounded = query.clone();
        unbounded.limit = None;
        unbounded.offset = 0;
        let results = self.query(&unbounded)?;
        Ok(u64::try_from(results.len()).unwrap_or(u64::MAX))
    }

    fn stats(&self) -> Result<IndexStats, ChainkeeperError> {
        Ok(IndexStats {
            certificates: count(&self.certificates),
            revocations: count(&self.revocations),
            authorities: count(&self.authorities),
            audit_events: count(&self.audit_events),
        })
    }

    fn schema_version(&self) -> Result<u32, ChainkeeperError> {
        Ok(chainkeeper_core::CONFIG_VERSION)
    }
}

fn count<T>(map: &RwLock<BTreeMap<impl Ord, T>>) -> u64 {
    let guard = map
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    u64::try_from(guard.len()).unwrap_or(u64::MAX)
}

/// Service that returns canned reports without touching disk.
#[derive(Debug)]
pub struct FakeChainkeeperService {
    now: OffsetDateTime,
    ids: crate::ids::FakeIdGenerator,
}

impl Default for FakeChainkeeperService {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeChainkeeperService {
    /// Creates a service pinned to a fixed time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            now: time::macros::datetime!(2024-01-01 00:00:00 UTC),
            ids: crate::ids::FakeIdGenerator::new(),
        }
    }

    fn authority_record(
        &self,
        name: AuthorityName,
        kind: chainkeeper_core::AuthorityKind,
        parent: Option<AuthorityName>,
        algorithm: KeyAlgorithm,
        validity_days: u32,
        path_len: u32,
    ) -> AuthorityRecord {
        AuthorityRecord {
            cert_path: PathBuf::from(format!("authorities/{name}/cert.pem")),
            chain_path: PathBuf::from(format!("authorities/{name}/chain.pem")),
            name,
            kind,
            parent,
            algorithm,
            validity_days,
            path_len,
            created_at: self.now,
        }
    }
}

impl ChainkeeperService for FakeChainkeeperService {
    fn init(
        &self,
        request: &chainkeeper_core::InitRequest,
    ) -> Result<InitReport, ChainkeeperError> {
        Ok(InitReport {
            tenant_id: request.tenant_id.clone(),
            root: PathBuf::from("."),
            created_paths: Vec::new(),
            commit: None,
        })
    }

    fn create_root(
        &self,
        request: &chainkeeper_core::CreateAuthorityRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        Ok(self.authority_record(
            request.name.clone(),
            chainkeeper_core::AuthorityKind::Root,
            None,
            request.algorithm,
            request.validity_days,
            request.path_len,
        ))
    }

    fn create_intermediate(
        &self,
        request: &chainkeeper_core::CreateAuthorityRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        Ok(self.authority_record(
            request.name.clone(),
            chainkeeper_core::AuthorityKind::Intermediate,
            request.parent.clone(),
            request.algorithm,
            request.validity_days,
            request.path_len,
        ))
    }

    fn create_ocsp_signer(
        &self,
        request: &chainkeeper_core::CreateOcspSignerRequest,
    ) -> Result<AuthorityRecord, ChainkeeperError> {
        Ok(self.authority_record(
            request.name.clone(),
            chainkeeper_core::AuthorityKind::OcspSigner,
            Some(request.parent.clone()),
            request.algorithm,
            request.validity_days,
            0,
        ))
    }

    fn issue(
        &self,
        request: &chainkeeper_core::IssueRequest,
    ) -> Result<IssueReport, ChainkeeperError> {
        let profile = builtin_profile(&request.profile)
            .ok_or_else(|| ChainkeeperError::not_found("profile", request.profile.as_str()))?;
        let serial = self.ids.serial();
        let validity_days = request.validity_days.unwrap_or(profile.validity_days);
        let record = CertificateRecord {
            path: PathBuf::from(format!("certificates/active/{serial}.pem")),
            serial,
            subject: request.subject.clone(),
            issuer: "CN=Root, O=Test".to_owned(),
            profile: request.profile.clone(),
            authority: profile.authority.clone(),
            algorithm: request.algorithm.unwrap_or(profile.algorithm),
            sans: request.sans.clone(),
            ekus: profile.eku.clone(),
            key_usages: profile.key_usage,
            issued_at: self.now,
            expires_at: self.now + TimeDuration::days(i64::from(validity_days)),
            revoked_at: None,
            revocation_reason: None,
            replaces: request.replaces.clone(),
        };
        Ok(IssueReport {
            cert_path: record.path.clone(),
            certificate: record,
            key_path: request.key_out.clone(),
            commit: None,
        })
    }

    fn revoke(
        &self,
        request: &chainkeeper_core::RevokeRequest,
    ) -> Result<chainkeeper_core::RevokeReport, ChainkeeperError> {
        Ok(chainkeeper_core::RevokeReport {
            revocation: RevocationRecord {
                version: chainkeeper_core::CONFIG_VERSION,
                serial: request.serial.clone(),
                authority: authority_name("tls"),
                reason: request.reason,
                comment: request.comment.clone(),
                revoked_at: self.now,
                crl_number: 1,
            },
            crl: None,
            commit: None,
        })
    }

    fn inspect(&self, serial: &Serial) -> Result<InspectReport, ChainkeeperError> {
        Err(ChainkeeperError::not_found("certificate", serial.as_str()))
    }

    fn search(&self, _query: &SearchQuery) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        Ok(Vec::new())
    }

    fn tree(&self) -> Result<TreeReport, ChainkeeperError> {
        Ok(TreeReport { roots: Vec::new() })
    }

    fn analyze(&self, kind: AnalyzeKind) -> Result<AnalyzeReport, ChainkeeperError> {
        Ok(AnalyzeReport {
            kind,
            generated_at: self.now,
            findings: Vec::<AnalysisFinding>::new(),
        })
    }

    fn audit(&self, _query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        Ok(Vec::new())
    }

    fn doctor(&self) -> Result<DoctorReport, ChainkeeperError> {
        Ok(DoctorReport {
            healthy: true,
            checked_at: self.now,
            findings: Vec::new(),
        })
    }

    fn diff(
        &self,
        request: &chainkeeper_core::DiffRequest,
    ) -> Result<DiffReport, ChainkeeperError> {
        Ok(DiffReport {
            from: request.from.clone(),
            to: request.to.clone(),
            added: Vec::new(),
            modified: Vec::new(),
            removed: Vec::new(),
        })
    }

    fn publish(&self, _options: &PublishOptions) -> Result<PublishManifest, ChainkeeperError> {
        Ok(PublishManifest {
            version: chainkeeper_core::PUBLISH_MANIFEST_VERSION,
            generated_at: self.now,
            source_commit: None,
            tenant_id: tenant_id(),
            artifacts: Vec::new(),
        })
    }

    fn rebuild_index(&self) -> Result<IndexReport, ChainkeeperError> {
        Ok(IndexReport {
            generated_at: self.now,
            schema_version: chainkeeper_core::CONFIG_VERSION,
            stats: IndexStats::default(),
            moved: Vec::new(),
        })
    }
}

/// Server state provider with a swappable snapshot.
#[derive(Debug)]
pub struct FakeServerStateProvider {
    snapshot: RwLock<Arc<ServerSnapshot>>,
    health: RwLock<ServerHealth>,
}

fn empty_snapshot(now: OffsetDateTime) -> ServerSnapshot {
    ServerSnapshot {
        generated_at: now,
        repo_commit: "0".repeat(40),
        manifest: None,
        certificates: Vec::new(),
        revocations: Vec::new(),
        authorities: Vec::new(),
        crls: Vec::new(),
        audit_events: Vec::new(),
    }
}

impl Default for FakeServerStateProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeServerStateProvider {
    /// Creates a provider serving an empty snapshot.
    #[must_use]
    pub fn new() -> Self {
        let now = time::macros::datetime!(2024-01-01 00:00:00 UTC);
        Self {
            snapshot: RwLock::new(Arc::new(empty_snapshot(now))),
            health: RwLock::new(ServerHealth {
                status: HealthStatus::Ok,
                repo_commit: Some("0".repeat(40)),
                publish_commit: None,
                ocsp_ready: true,
                errors: Vec::new(),
            }),
        }
    }

    /// Replaces the served snapshot.
    pub fn set_snapshot(&self, snapshot: ServerSnapshot) {
        let mut guard = self
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Arc::new(snapshot);
    }
}

impl ServerStateProvider for FakeServerStateProvider {
    fn snapshot(&self) -> Arc<ServerSnapshot> {
        Arc::clone(
            &self
                .snapshot
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    fn reload(&self) -> Result<Arc<ServerSnapshot>, ChainkeeperError> {
        Ok(self.snapshot())
    }

    fn health(&self) -> ServerHealth {
        self.health
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}
