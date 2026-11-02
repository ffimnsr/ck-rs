//! Disposable SQLite index.
//!
//! The index never owns canonical data: every row is derived from records that
//! live under [`chainkeeper_core::RepositoryPaths`].

mod drift;
mod query;
mod schema;
mod stats;
mod write;

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use chainkeeper_core::{
    AuditEvent, AuditQuery, AuthorityRecord, CertificateRecord, CertificateStatus,
    CertificateStore as _, ChainkeeperError, Clock, DoctorFinding, IndexRecords, IndexReport,
    IndexStats, IndexStore, RepositoryPaths, RevocationReason, RevocationRecord, SearchQuery,
    Serial, SystemClock,
};
use rusqlite::{Connection, Row};
use serde::de::DeserializeOwned;
use time::OffsetDateTime;

pub use stats::IndexBreakdown;

use crate::fsutil;
use crate::layout::FileStore;

/// Columns selected for a [`CertificateRecord`].
pub const CERTIFICATE_COLUMNS: &str = "serial, subject, issuer, profile, authority, \
     algorithm, issued_at, expires_at, path, sans_json, email, eku_json, key_usage_json, \
     revoked_at, revocation_reason, replaces";

/// Connection-backed index.
pub struct SqliteIndex {
    connection: Mutex<Connection>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for SqliteIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteIndex").finish_non_exhaustive()
    }
}

pub fn index_error(context: impl std::fmt::Display) -> ChainkeeperError {
    ChainkeeperError::index(context.to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn decode<T: DeserializeOwned>(value: String, column: &str) -> Result<T, ChainkeeperError> {
    serde_json::from_value(serde_json::Value::String(value)).map_err(|error| {
        index_error(format!(
            "column {column} does not hold a valid value: {error}"
        ))
    })
}

#[allow(clippy::needless_pass_by_value)]
fn decode_json<T: DeserializeOwned>(value: String, column: &str) -> Result<T, ChainkeeperError> {
    serde_json::from_str(&value)
        .map_err(|error| index_error(format!("column {column} is not valid JSON: {error}")))
}

#[allow(clippy::needless_pass_by_value)]
fn decode_timestamp(value: String, column: &str) -> Result<OffsetDateTime, ChainkeeperError> {
    chainkeeper_core::time_util::parse_timestamp(&value)
        .map_err(|error| index_error(format!("column {column} is not a timestamp: {error}")))
}

fn optional_timestamp(
    value: Option<String>,
    column: &str,
) -> Result<Option<OffsetDateTime>, ChainkeeperError> {
    value
        .map(|value| decode_timestamp(value, column))
        .transpose()
}

fn decode_option<T: DeserializeOwned>(
    value: Option<String>,
    column: &str,
) -> Result<Option<T>, ChainkeeperError> {
    value.map(|value| decode(value, column)).transpose()
}

fn get<T: rusqlite::types::FromSql>(
    row: &Row<'_>,
    index: usize,
    column: &str,
) -> Result<T, ChainkeeperError> {
    row.get(index)
        .map_err(|error| index_error(format!("column {column} is unreadable: {error}")))
}

/// Builds a record from a row selecting [`CERTIFICATE_COLUMNS`].
pub fn certificate_from_row(row: &Row<'_>) -> Result<CertificateRecord, ChainkeeperError> {
    let cn: String = get(row, 1, "subject")?;
    let email: Option<String> = get(row, 10, "email")?;
    let mut subject = chainkeeper_core::SubjectName::new(cn);
    subject.email = email;
    Ok(CertificateRecord {
        serial: decode(get(row, 0, "serial")?, "serial")?,
        subject,
        issuer: get(row, 2, "issuer")?,
        profile: decode(get(row, 3, "profile")?, "profile")?,
        authority: decode(get(row, 4, "authority")?, "authority")?,
        algorithm: decode(get(row, 5, "algorithm")?, "algorithm")?,
        issued_at: decode_timestamp(get(row, 6, "issued_at")?, "issued_at")?,
        expires_at: decode_timestamp(get(row, 7, "expires_at")?, "expires_at")?,
        path: PathBuf::from(get::<String>(row, 8, "path")?),
        sans: decode_json(get(row, 9, "sans_json")?, "sans_json")?,
        ekus: decode_json(get(row, 11, "eku_json")?, "eku_json")?,
        key_usages: decode_json(get(row, 12, "key_usage_json")?, "key_usage_json")?,
        revoked_at: optional_timestamp(get(row, 13, "revoked_at")?, "revoked_at")?,
        revocation_reason: decode_option::<RevocationReason>(
            get(row, 14, "revocation_reason")?,
            "revocation_reason",
        )?,
        replaces: decode_option::<Serial>(get(row, 15, "replaces")?, "replaces")?,
    })
}

/// Builds an audit event from the canonical column order.
pub fn audit_event_from_row(row: &Row<'_>) -> Result<AuditEvent, ChainkeeperError> {
    let details = get::<String>(row, 8, "details_json")?;
    Ok(AuditEvent {
        id: decode(get(row, 0, "id")?, "id")?,
        seq: get::<i64>(row, 1, "seq")?.cast_unsigned(),
        timestamp: decode_timestamp(get(row, 2, "timestamp")?, "timestamp")?,
        action: decode(get(row, 3, "action")?, "action")?,
        object_type: get(row, 4, "object_type")?,
        object_id: get(row, 5, "object_id")?,
        summary: get(row, 6, "summary")?,
        actor: get(row, 7, "actor")?,
        details: serde_json::from_str(&details)
            .map_err(|error| index_error(format!("details_json is not valid JSON: {error}")))?,
    })
}

impl SqliteIndex {
    /// Opens an index at `path`, creating the cache directory when needed.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] when the database cannot be opened
    /// or migrated.
    pub fn open(path: &Path) -> Result<Self, ChainkeeperError> {
        Self::open_with_clock(path, Arc::new(SystemClock))
    }

    /// Opens an index with an injected clock.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] when the database cannot be opened
    /// or migrated.
    pub fn open_with_clock(path: &Path, clock: Arc<dyn Clock>) -> Result<Self, ChainkeeperError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fsutil::ensure_directory(parent)?;
        }
        let mut connection = Connection::open(path)
            .map_err(|error| index_error(format!("could not open {}: {error}", path.display())))?;
        schema::configure(&connection)?;
        schema::migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            clock,
        })
    }

    /// Opens an in-memory index. Intended for tests and one-shot queries.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] when the schema cannot be created.
    pub fn open_in_memory() -> Result<Self, ChainkeeperError> {
        Self::open_in_memory_with_clock(Arc::new(SystemClock))
    }

    /// Opens an in-memory index with an injected clock.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] when the schema cannot be created.
    pub fn open_in_memory_with_clock(clock: Arc<dyn Clock>) -> Result<Self, ChainkeeperError> {
        let mut connection = Connection::open_in_memory()
            .map_err(|error| index_error(format!("could not open in-memory index: {error}")))?;
        schema::configure(&connection)?;
        schema::migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            clock,
        })
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Current time according to the injected clock.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        self.clock.now()
    }

    /// Rebuilds the index from the canonical records on disk.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a record cannot be read or
    /// [`ChainkeeperError::Index`] when a row cannot be written.
    pub fn rebuild_from_store(&self, store: &FileStore) -> Result<IndexReport, ChainkeeperError> {
        let records = store.load_index_records()?;
        self.rebuild(&records)
    }

    /// Rebuilds the index and moves expired active certificates.
    ///
    /// File contents are never modified; only the containing directory
    /// changes.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] or [`ChainkeeperError::Storage`]
    /// when the rebuild or repair fails.
    pub fn repair(&self, store: &FileStore) -> Result<IndexReport, ChainkeeperError> {
        let now = self.now();
        let records = store.load_index_records()?;
        let mut report = self.rebuild(&records)?;

        let mut moved = Vec::new();
        for record in &records.certificates {
            if record.status(now) != CertificateStatus::Expired {
                continue;
            }
            let active_path = PathBuf::from(format!("certificates/active/{}.pem", record.serial));
            if record.path != active_path {
                continue;
            }
            store.move_certificate(&record.serial, CertificateStatus::Expired)?;
            moved.push(record.serial.clone());
        }

        if !moved.is_empty() {
            moved.sort();
            let refreshed = store.load_index_records()?;
            report = self.rebuild(&refreshed)?;
        }
        report.moved = moved;
        Ok(report)
    }

    /// Compares canonical records with indexed rows.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] when the comparison fails.
    pub fn drift(&self, records: &IndexRecords) -> Result<Vec<DoctorFinding>, ChainkeeperError> {
        drift::compare(self, records)
    }

    /// Returns counts grouped by status, profile, authority, and algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Index`] when the query fails.
    pub fn breakdown(&self) -> Result<IndexBreakdown, ChainkeeperError> {
        stats::breakdown(self)
    }

    /// Repository layout of the index file.
    #[must_use]
    pub fn path_in(paths: &RepositoryPaths) -> PathBuf {
        paths.index_path()
    }
}

impl IndexStore for SqliteIndex {
    fn rebuild(&self, records: &IndexRecords) -> Result<IndexReport, ChainkeeperError> {
        write::rebuild(self, records)
    }

    fn query(&self, query: &SearchQuery) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        query::search(self, query)
    }

    fn upsert_certificate(&self, record: &CertificateRecord) -> Result<(), ChainkeeperError> {
        write::upsert_certificate(self, record)
    }

    fn upsert_revocation(&self, record: &RevocationRecord) -> Result<(), ChainkeeperError> {
        write::upsert_revocation(self, record)
    }

    fn upsert_authority(&self, record: &AuthorityRecord) -> Result<(), ChainkeeperError> {
        write::upsert_authority(self, record)
    }

    fn upsert_audit_event(&self, event: &AuditEvent) -> Result<(), ChainkeeperError> {
        write::upsert_audit_event(self, event)
    }

    fn list_audit(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        query::list_audit(self, query)
    }

    fn stats(&self) -> Result<IndexStats, ChainkeeperError> {
        stats::totals(self)
    }

    fn count(&self, query: &SearchQuery) -> Result<u64, ChainkeeperError> {
        query::count(self, query)
    }

    fn schema_version(&self) -> Result<u32, ChainkeeperError> {
        let connection = self.lock();
        schema::read_version(&connection)
    }
}

/// Loads every certificate row in lexical serial order.
pub fn all_certificates(
    connection: &Connection,
) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
    let sql = format!("SELECT {CERTIFICATE_COLUMNS} FROM certificates ORDER BY serial ASC");
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| index_error(format!("could not prepare certificate scan: {error}")))?;
    let mut rows = statement
        .query([])
        .map_err(|error| index_error(format!("could not scan certificates: {error}")))?;
    let mut records = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| index_error(format!("could not scan certificates: {error}")))?
    {
        records.push(certificate_from_row(row)?);
    }
    Ok(records)
}
