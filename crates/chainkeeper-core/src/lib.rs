#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Frozen domain contracts for Chainkeeper.
//!
//! This crate owns every type and trait shared across crates: identifiers,
//! configuration and record types, request and report types, the repository
//! layout helpers, and the trait contracts that later phases implement.
//!
//! Contracts are deliberately object-safe and free of I/O so the CLI and the
//! server can consume them as `Arc<dyn Trait>`.

pub mod config;
pub mod crypto;
pub mod error;
pub mod ids;
pub mod logging;
pub mod paths;
pub mod profile;
pub mod publish;
pub mod records;
pub mod report;
pub mod request;
pub mod time_util;
pub mod traits;

pub use config::{AuthorityConfig, AuthorityKind, CONFIG_VERSION, Policy, TenantConfig};
pub use crypto::{KeyAlgorithm, SignatureScheme};
pub use error::{ChainkeeperError, ErrorDetail, ErrorKind, ErrorSource};
pub use ids::{AuthorityName, EventId, ProductionIdGenerator, ProfileName, Serial, TenantId};
pub use logging::{init_tracing, init_tracing_with_default};
pub use paths::{FileMode, RepositoryPaths, atomic_write, atomic_write_new};
pub use profile::{
    ExtendedKeyUsage, KeyUsage, Profile, SanType, builtin_profile, builtin_profile_names,
    builtin_profiles,
};
pub use publish::{
    HealthStatus, PUBLISH_MANIFEST_VERSION, PublishArtifact, PublishManifest, ServerHealth,
    ServerSnapshot,
};
pub use records::{
    AuditAction, AuditEvent, AuthorityBundle, AuthorityMaterial, AuthorityRecord,
    CertificateRecord, CertificateStatus, CrlBundle, CrlRecord, CrlRequest, GitChange,
    GitChangeKind, GitStatus, IndexRecords, IndexStats, IndexedCrl, IssuedCertificate, KeyMaterial,
    NewAuditEvent, RevocationReason, RevocationRecord, SignerBundle,
};
pub use report::{
    AnalysisFinding, AnalyzeKind, AnalyzeReport, DiffReport, DoctorFinding, DoctorReport,
    IndexReport, InitReport, InspectReport, IssueReport, RevokeReport, Severity, TreeNode,
    TreeReport,
};
pub use request::{
    AuditQuery, CreateAuthorityRequest, CreateOcspSignerRequest, CustomExtension, DiffRequest,
    InitRequest, IssueRequest, PublishOptions, RevokeRequest, San, SearchQuery, SubjectName,
};
pub use traits::{
    AuditLog, CertificateProvider, CertificateStore, ChainkeeperService, Clock, CrlManager,
    GitRepository, IdGenerator, IndexStore, LockGuard, OcspResponder, PolicyEngine,
    ProfileRegistry, PublishBuilder, RepositoryLock, ServerStateProvider, Signer, SystemClock,
};

/// Version of this crate, taken from Cargo metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
