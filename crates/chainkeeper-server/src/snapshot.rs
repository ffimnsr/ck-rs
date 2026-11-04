//! Repository-backed server snapshot provider.
//!
//! The provider builds an immutable snapshot from the canonical store, the
//! audit log, the Git `HEAD`, and the publish manifest. Reload failures keep
//! the previous snapshot and mark health degraded.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use chainkeeper_core::{
    AuditLog, AuditQuery, CertificateStore, ChainkeeperError, Clock, GitRepository, HealthStatus,
    ServerHealth, ServerSnapshot, ServerStateProvider,
};

/// Files larger than this are not scanned for private keys.
const MAX_SCANNED_FILE_BYTES: u64 = 8 * 1024 * 1024;
const PRIVATE_KEY_MARKER: &[u8] = b"PRIVATE KEY";

/// Collaborators used to build a snapshot.
#[derive(Clone)]
pub struct RepositoryDeps {
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Canonical store.
    pub store: Arc<dyn CertificateStore>,
    /// Append-only audit log.
    pub audit: Arc<dyn AuditLog>,
    /// Git repository.
    pub git: Arc<dyn GitRepository>,
    /// Publish directory served by ck-server.
    pub publish_dir: PathBuf,
}

impl std::fmt::Debug for RepositoryDeps {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RepositoryDeps")
            .field("publish_dir", &self.publish_dir)
            .finish_non_exhaustive()
    }
}

/// Snapshot provider backed by the canonical repository.
pub struct RepositoryStateProvider {
    deps: RepositoryDeps,
    snapshot: ArcSwap<ServerSnapshot>,
    health: RwLock<ServerHealth>,
}

impl std::fmt::Debug for RepositoryStateProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RepositoryStateProvider")
            .field("publish_dir", &self.deps.publish_dir)
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}

impl RepositoryStateProvider {
    /// Builds the initial snapshot.
    ///
    /// # Errors
    ///
    /// Returns a storage, audit, Git, or publish error when the repository
    /// cannot be read. Returns [`ChainkeeperError::Publish`] when the publish
    /// directory contains a private key.
    pub fn open(deps: RepositoryDeps) -> Result<Self, ChainkeeperError> {
        scan_for_private_keys(&deps.publish_dir)?;
        let snapshot = build(&deps)?;
        let health = ServerHealth {
            status: HealthStatus::Ok,
            repo_commit: Some(snapshot.repo_commit.clone()),
            publish_commit: snapshot
                .manifest
                .as_ref()
                .and_then(|manifest| manifest.source_commit.clone()),
            ocsp_ready: false,
            errors: Vec::new(),
        };
        Ok(Self {
            deps,
            snapshot: ArcSwap::from_pointee(snapshot),
            health: RwLock::new(health),
        })
    }

    /// Publish directory served by this provider.
    #[must_use]
    pub fn publish_dir(&self) -> &Path {
        &self.deps.publish_dir
    }
}

fn build(deps: &RepositoryDeps) -> Result<ServerSnapshot, ChainkeeperError> {
    let manifest = chainkeeper_publish::read_manifest(&deps.publish_dir)?;
    let mut audit_events = deps.audit.list(&AuditQuery::default())?;
    audit_events.sort_by_key(|event| event.seq);
    Ok(ServerSnapshot {
        generated_at: deps.clock.now(),
        repo_commit: deps.git.head_commit()?,
        manifest,
        certificates: deps.store.list_certificates()?,
        revocations: deps.store.list_revocations()?,
        authorities: deps.store.list_authorities()?,
        crls: deps.store.list_crls()?,
        audit_events,
    })
}

impl ServerStateProvider for RepositoryStateProvider {
    fn snapshot(&self) -> Arc<ServerSnapshot> {
        self.snapshot.load_full()
    }

    fn reload(&self) -> Result<Arc<ServerSnapshot>, ChainkeeperError> {
        match build(&self.deps) {
            Ok(snapshot) => {
                let health = ServerHealth {
                    status: HealthStatus::Ok,
                    repo_commit: Some(snapshot.repo_commit.clone()),
                    publish_commit: snapshot
                        .manifest
                        .as_ref()
                        .and_then(|manifest| manifest.source_commit.clone()),
                    ocsp_ready: false,
                    errors: Vec::new(),
                };
                let arc = Arc::new(snapshot);
                self.snapshot.store(Arc::clone(&arc));
                *self.write_health() = health;
                Ok(arc)
            }
            Err(error) => {
                tracing::warn!(error = %error, "snapshot reload failed; keeping previous snapshot");
                let mut health = self.write_health();
                health.status = HealthStatus::Degraded;
                health.errors = vec![error.to_string()];
                drop(health);
                Err(error)
            }
        }
    }

    fn health(&self) -> ServerHealth {
        self.read_health().clone()
    }
}

impl RepositoryStateProvider {
    fn read_health(&self) -> std::sync::RwLockReadGuard<'_, ServerHealth> {
        self.health
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_health(&self) -> std::sync::RwLockWriteGuard<'_, ServerHealth> {
        self.health
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Returns an error when the publish directory contains a private key.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Publish`] on a private key or an unreadable
/// directory.
pub fn scan_for_private_keys(directory: &Path) -> Result<(), ChainkeeperError> {
    if !directory.exists() {
        return Ok(());
    }
    scan(directory, directory)
}

fn scan(root: &Path, directory: &Path) -> Result<(), ChainkeeperError> {
    let entries = fs::read_dir(directory).map_err(|error| {
        ChainkeeperError::publish(format!(
            "could not read publish directory {}: {error}",
            directory.display()
        ))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            ChainkeeperError::publish(format!(
                "could not read publish directory {}: {error}",
                directory.display()
            ))
        })?;
        let path = entry.path();
        let metadata = entry.metadata().map_err(|error| {
            ChainkeeperError::publish(format!("could not inspect {}: {error}", path.display()))
        })?;
        if metadata.is_dir() {
            scan(root, &path)?;
            continue;
        }
        if !metadata.is_file() || metadata.len() > MAX_SCANNED_FILE_BYTES {
            continue;
        }
        let bytes = fs::read(&path).map_err(|error| {
            ChainkeeperError::publish(format!("could not read {}: {error}", path.display()))
        })?;
        if contains_private_key(&bytes) {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            return Err(ChainkeeperError::publish(format!(
                "publish directory contains a private key at {}",
                relative.display()
            )));
        }
    }
    Ok(())
}

fn contains_private_key(bytes: &[u8]) -> bool {
    bytes
        .windows(PRIVATE_KEY_MARKER.len())
        .any(|window| window == PRIVATE_KEY_MARKER)
}

/// Returns true when `path` is a safe relative artifact path.
#[must_use]
pub(crate) fn is_safe_relative(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::{contains_private_key, is_safe_relative};
    use std::path::Path;

    #[test]
    fn private_key_marker_is_detected() {
        assert!(contains_private_key(
            b"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
        ));
        assert!(!contains_private_key(b"-----BEGIN CERTIFICATE-----\nabc\n"));
    }

    #[test]
    fn traversal_is_not_a_safe_relative_path() {
        assert!(is_safe_relative(Path::new("intermediates/tls.pem")));
        assert!(!is_safe_relative(Path::new("../secret.pem")));
        assert!(!is_safe_relative(Path::new("/etc/passwd")));
    }
}
