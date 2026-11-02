//! Deterministic clock.

use std::sync::RwLock;

use chainkeeper_core::Clock;
use time::{Duration, OffsetDateTime};

/// Fixed clock that only moves when a test moves it.
#[derive(Debug)]
pub struct FakeClock {
    now: RwLock<OffsetDateTime>,
}

impl FakeClock {
    /// Creates a clock pinned to `now`.
    #[must_use]
    pub const fn new(now: OffsetDateTime) -> Self {
        Self {
            now: RwLock::new(now),
        }
    }

    /// Replaces the current time.
    pub fn set(&self, now: OffsetDateTime) {
        let mut guard = self
            .now
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = now;
    }

    /// Advances the current time.
    pub fn advance(&self, duration: Duration) {
        let mut guard = self
            .now
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard += duration;
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new(time::macros::datetime!(2024-01-01 00:00:00 UTC))
    }
}

impl Clock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *self
            .now
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
