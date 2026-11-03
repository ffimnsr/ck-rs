//! Append-only file backed audit log.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind as IoErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chainkeeper_core::{
    AuditEvent, AuditLog, AuditQuery, ChainkeeperError, DoctorFinding, ErrorDetail, ErrorKind,
    EventId, IdGenerator, LockGuard, NewAuditEvent, RepositoryLock, RepositoryPaths,
};

use crate::canonical::{from_canonical_json, to_canonical_json};
use crate::verify::verify_events;

/// Default wait for the repository lock.
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

fn audit(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::audit(message)
}

fn audit_with_object(message: impl Into<String>, object_id: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::from_detail(
        ErrorKind::Audit,
        ErrorDetail::new(message).with_object_id(object_id),
    )
}

fn parse_event(path: &Path) -> Result<AuditEvent, ChainkeeperError> {
    let bytes = fs::read(path).map_err(|error| {
        audit(format!(
            "could not read audit event {}: {error}",
            path.display()
        ))
    })?;
    from_canonical_json(&bytes).map_err(|error| error.with_context(path.display().to_string()))
}

/// Lists `audit/events/*.json` in lexical order. A missing directory is empty.
pub fn event_paths(paths: &RepositoryPaths) -> Result<Vec<PathBuf>, ChainkeeperError> {
    let directory = paths.audit_events_dir();
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == IoErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(audit(format!(
                "could not read audit directory {}: {error}",
                directory.display()
            )));
        }
    };

    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            audit(format!(
                "could not read audit directory {}: {error}",
                directory.display()
            ))
        })?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "json")
        {
            found.push(path);
        }
    }
    found.sort();
    Ok(found)
}

fn matches_query(event: &AuditEvent, query: &AuditQuery) -> bool {
    query.action.is_none_or(|action| event.action == action)
        && query
            .object_type
            .as_ref()
            .is_none_or(|object_type| &event.object_type == object_type)
        && query
            .object_id
            .as_ref()
            .is_none_or(|object_id| &event.object_id == object_id)
        && query.since.is_none_or(|since| event.timestamp >= since)
        && query.until.is_none_or(|until| event.timestamp <= until)
}

/// Audit log storing one immutable JSON file per event.
///
/// `seq` allocation, id assignment, and the write all happen while holding the
/// injected repository lock, so concurrent appends produce contiguous sequence
/// numbers even across processes.
#[derive(Clone)]
pub struct FileAuditLog {
    paths: RepositoryPaths,
    lock: Arc<dyn RepositoryLock>,
    ids: Arc<dyn IdGenerator>,
    lock_timeout: Duration,
}

impl fmt::Debug for FileAuditLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileAuditLog")
            .field("root", &self.paths.root())
            .field("lock_timeout", &self.lock_timeout)
            .finish_non_exhaustive()
    }
}

impl FileAuditLog {
    /// Creates a log for a repository layout.
    #[must_use]
    pub fn new(
        paths: RepositoryPaths,
        lock: Arc<dyn RepositoryLock>,
        ids: Arc<dyn IdGenerator>,
    ) -> Self {
        Self {
            paths,
            lock,
            ids,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
        }
    }

    /// Overrides the lock acquisition timeout.
    #[must_use]
    pub const fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    /// Repository layout used by this log.
    #[must_use]
    pub const fn paths(&self) -> &RepositoryPaths {
        &self.paths
    }

    /// Verifies the on-disk log and returns doctor findings.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Audit`] when the directory cannot be read.
    pub fn verify(&self) -> Result<Vec<DoctorFinding>, ChainkeeperError> {
        verify_events(&self.paths)
    }

    fn next_seq_unlocked(&self) -> Result<u64, ChainkeeperError> {
        let mut seen = BTreeSet::new();
        let mut maximum = 0_u64;
        for path in event_paths(&self.paths)? {
            let event = parse_event(&path)?;
            if !seen.insert(event.seq) {
                return Err(audit_with_object(
                    format!(
                        "duplicate audit sequence number {} in {}",
                        event.seq,
                        path.display()
                    ),
                    event.seq.to_string(),
                ));
            }
            maximum = maximum.max(event.seq);
        }
        Ok(maximum + 1)
    }

    fn write_event(&self, event: &AuditEvent) -> Result<(), ChainkeeperError> {
        let directory = self.paths.audit_events_dir();
        fs::create_dir_all(&directory).map_err(|error| {
            audit(format!(
                "could not create audit directory {}: {error}",
                directory.display()
            ))
        })?;

        let bytes = to_canonical_json(event)?;
        let path = self.paths.audit_event_path(&event.id);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                if error.kind() == IoErrorKind::AlreadyExists {
                    audit_with_object(
                        format!("audit event {} already exists", event.id),
                        event.id.to_string(),
                    )
                } else {
                    audit(format!(
                        "could not create audit event {}: {error}",
                        path.display()
                    ))
                }
            })?;

        file.write_all(bytes.as_bytes()).map_err(|error| {
            audit(format!(
                "could not write audit event {}: {error}",
                path.display()
            ))
        })?;
        file.sync_all().map_err(|error| {
            audit(format!(
                "could not flush audit event {}: {error}",
                path.display()
            ))
        })?;
        drop(file);

        // Best effort directory sync so a crash cannot lose the directory entry.
        if let Ok(directory) = fs::File::open(&directory) {
            let _ = directory.sync_all();
        }
        Ok(())
    }

    fn acquire(&self) -> Result<LockGuard, ChainkeeperError> {
        self.lock.acquire_exclusive(self.lock_timeout)
    }
}

impl AuditLog for FileAuditLog {
    fn append(&self, event: NewAuditEvent) -> Result<AuditEvent, ChainkeeperError> {
        let mut event = event;
        if event.details.is_null() {
            event.details = serde_json::Value::Object(serde_json::Map::new());
        }

        let _guard = self.acquire()?;
        let seq = self.next_seq_unlocked()?;
        let id = EventId::new(self.ids.ulid())?;
        let stored = AuditEvent::from_new(event, id, seq);
        self.write_event(&stored)?;
        Ok(stored)
    }

    fn list(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        let mut events = Vec::new();
        for path in event_paths(&self.paths)? {
            let event = parse_event(&path)?;
            if matches_query(&event, query) {
                events.push(event);
            }
        }
        events.sort_by_key(|event| event.seq);
        if let Some(limit) = query.limit {
            events.truncate(limit);
        }
        Ok(events)
    }

    fn next_seq(&self) -> Result<u64, ChainkeeperError> {
        self.next_seq_unlocked()
    }
}
