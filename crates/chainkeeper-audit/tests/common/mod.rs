#![allow(dead_code)]

//! Shared fixtures for the audit integration tests.

use std::sync::Arc;

use chainkeeper_audit::FileAuditLog;
use chainkeeper_core::{AuditAction, IdGenerator, NewAuditEvent, RepositoryPaths, Serial};
use chainkeeper_testkit::{FakeIdGenerator, FakeRepositoryLock, TempTenant};
use time::OffsetDateTime;
use time::macros::datetime;

/// Fixed timestamp used by every audit fixture.
pub const NOW: OffsetDateTime = datetime!(2024-05-01 12:00:00 UTC);

/// Creates a temporary repository.
pub fn tenant() -> TempTenant {
    TempTenant::new().expect("temporary tenant")
}

/// Creates a log backed by the temporary repository.
pub fn log(tenant: &TempTenant) -> FileAuditLog {
    FileAuditLog::new(
        tenant.paths().clone(),
        Arc::new(FakeRepositoryLock::new()),
        Arc::new(FakeIdGenerator::new()),
    )
}

/// Builds a pending event.
pub fn event(action: AuditAction, object_id: &str) -> NewAuditEvent {
    NewAuditEvent::new(NOW, action, "certificate", object_id, "summary", "tester")
}

/// Returns the parsed repository layout.
pub fn paths(tenant: &TempTenant) -> RepositoryPaths {
    RepositoryPaths::new(tenant.root()).expect("valid root")
}

/// Identifier generator that always returns the same ULID.
#[derive(Debug, Default)]
pub struct FixedIdGenerator {
    value: String,
}

impl FixedIdGenerator {
    /// Creates a generator returning `value`.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

impl IdGenerator for FixedIdGenerator {
    fn ulid(&self) -> String {
        self.value.clone()
    }

    fn serial(&self) -> Serial {
        Serial::from_bytes(&[0_u8; 16])
    }
}
