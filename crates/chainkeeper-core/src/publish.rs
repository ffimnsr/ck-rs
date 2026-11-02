//! Publication manifest and read-only server snapshot types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::ids::TenantId;
use crate::records::{AuditEvent, AuthorityRecord, CertificateRecord, CrlRecord, RevocationRecord};

/// Schema version of `publish/manifest.json`.
pub const PUBLISH_MANIFEST_VERSION: u32 = 1;

/// One published artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishArtifact {
    /// Path relative to the publish directory.
    pub path: PathBuf,
    /// Lowercase hexadecimal SHA-256 of the artifact bytes.
    pub sha256: String,
    /// Artifact size in bytes.
    pub bytes: u64,
}

/// Manifest describing a publish directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishManifest {
    /// Schema version, always [`PUBLISH_MANIFEST_VERSION`].
    pub version: u32,
    /// Manifest generation time.
    #[serde(with = "crate::time_util::seconds")]
    pub generated_at: OffsetDateTime,
    /// Commit the artifacts were built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    /// Tenant the artifacts belong to.
    pub tenant_id: TenantId,
    /// Published artifacts.
    pub artifacts: Vec<PublishArtifact>,
}

/// Immutable snapshot served by `ck-server`.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerSnapshot {
    /// Snapshot generation time.
    pub generated_at: OffsetDateTime,
    /// Commit the snapshot was built from.
    pub repo_commit: String,
    /// Manifest of the publish directory, when one exists.
    pub manifest: Option<PublishManifest>,
    /// Certificates visible to the server.
    pub certificates: Vec<CertificateRecord>,
    /// Revocations visible to the server.
    pub revocations: Vec<RevocationRecord>,
    /// Authorities visible to the server.
    pub authorities: Vec<AuthorityRecord>,
    /// CRLs visible to the server.
    pub crls: Vec<CrlRecord>,
    /// Immutable audit events.
    pub audit_events: Vec<AuditEvent>,
}

/// Overall health reported by `GET /api/v1/health`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HealthStatus {
    /// All components are ready.
    #[serde(rename = "ok")]
    Ok,
    /// Served from a stale snapshot.
    #[serde(rename = "degraded")]
    Degraded,
    /// A required component failed.
    #[serde(rename = "error")]
    Error,
}

/// Health response served by `ck-server`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHealth {
    /// Overall status.
    pub status: HealthStatus,
    /// Commit currently served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_commit: Option<String>,
    /// Commit the publish directory was built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_commit: Option<String>,
    /// Whether OCSP is ready to answer requests.
    pub ocsp_ready: bool,
    /// Accumulated error messages.
    pub errors: Vec<String>,
}

impl ServerHealth {
    /// Builds a healthy response for the given commit.
    #[must_use]
    pub fn ok(repo_commit: impl Into<String>, ocsp_ready: bool) -> Self {
        Self {
            status: HealthStatus::Ok,
            repo_commit: Some(repo_commit.into()),
            publish_commit: None,
            ocsp_ready,
            errors: Vec::new(),
        }
    }
}
