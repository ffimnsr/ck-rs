//! In-memory audit log.

use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use chainkeeper_core::{
    AuditEvent, AuditLog, AuditQuery, ChainkeeperError, EventId, NewAuditEvent,
};

/// Audit log that stores events in a vector and rejects duplicate ids.
#[derive(Debug, Default)]
pub struct InMemoryAuditLog {
    events: RwLock<Vec<AuditEvent>>,
    next_seq: AtomicU64,
}

impl InMemoryAuditLog {
    /// Creates an empty log whose next sequence number is one.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every stored event.
    ///
    /// # Errors
    ///
    /// Never fails; the signature matches the production implementation.
    pub fn events(&self) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        Ok(self
            .events
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone())
    }
}

fn event_id(seq: u64) -> Result<EventId, ChainkeeperError> {
    EventId::new(format!("01J{seq:023}"))
}

/// Returns true when `event` satisfies `query`.
#[must_use]
pub fn matches_query(event: &AuditEvent, query: &AuditQuery) -> bool {
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

impl AuditLog for InMemoryAuditLog {
    fn append(&self, event: NewAuditEvent) -> Result<AuditEvent, ChainkeeperError> {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let id = event_id(seq)?;
        let stored = AuditEvent::from_new(event, id, seq);

        let mut events = self
            .events
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if events.iter().any(|existing| existing.id == stored.id) {
            return Err(ChainkeeperError::audit("duplicate audit event id"));
        }
        events.push(stored.clone());
        drop(events);
        Ok(stored)
    }

    fn list(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        let events = self
            .events
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut selected: Vec<AuditEvent> = events
            .iter()
            .filter(|event| matches_query(event, query))
            .cloned()
            .collect();
        drop(events);
        if let Some(limit) = query.limit {
            selected.truncate(limit);
        }
        Ok(selected)
    }

    fn next_seq(&self) -> Result<u64, ChainkeeperError> {
        Ok(self.next_seq.load(Ordering::SeqCst) + 1)
    }
}
