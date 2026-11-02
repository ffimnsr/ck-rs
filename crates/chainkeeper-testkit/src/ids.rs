//! Deterministic identifier generator.

use std::sync::atomic::{AtomicU64, Ordering};

use chainkeeper_core::{IdGenerator, Serial};

/// Identifier generator that counts up from one per instance.
///
/// Serial and ULID sequences are independent so tests are not sensitive to the
/// order in which identifiers are requested.
#[derive(Debug, Default)]
pub struct FakeIdGenerator {
    next_serial: AtomicU64,
    next_ulid: AtomicU64,
}

impl FakeIdGenerator {
    /// Creates a generator starting at one.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a generator whose next identifiers are `start`.
    #[must_use]
    pub const fn starting_at(start: u64) -> Self {
        Self {
            next_serial: AtomicU64::new(start),
            next_ulid: AtomicU64::new(start),
        }
    }
}

impl IdGenerator for FakeIdGenerator {
    fn ulid(&self) -> String {
        let value = self.next_ulid.fetch_add(1, Ordering::SeqCst) + 1;
        format!("01J{value:022}")
    }

    fn serial(&self) -> Serial {
        let value = self.next_serial.fetch_add(1, Ordering::SeqCst) + 1;
        Serial::from_bytes(&value.to_be_bytes())
    }
}
