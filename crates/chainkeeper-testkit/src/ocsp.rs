//! Fake OCSP responder.

use std::sync::atomic::{AtomicBool, Ordering};

use chainkeeper_core::{ChainkeeperError, OcspResponder};

/// OCSP responder that echoes a deterministic marker.
#[derive(Debug)]
pub struct FakeOcspResponder {
    ready: AtomicBool,
    reloads: AtomicBool,
}

impl FakeOcspResponder {
    /// Creates a ready responder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ready: AtomicBool::new(true),
            reloads: AtomicBool::new(false),
        }
    }

    /// Creates a responder that reports `ready` from the start.
    #[must_use]
    pub const fn with_ready(ready: bool) -> Self {
        Self {
            ready: AtomicBool::new(ready),
            reloads: AtomicBool::new(false),
        }
    }

    /// Returns true when `reload` has been called at least once.
    #[must_use]
    pub fn was_reloaded(&self) -> bool {
        self.reloads.load(Ordering::SeqCst)
    }
}

impl Default for FakeOcspResponder {
    fn default() -> Self {
        Self::new()
    }
}

impl OcspResponder for FakeOcspResponder {
    fn respond(&self, request_der: &[u8]) -> Result<Vec<u8>, ChainkeeperError> {
        if !self.ready.load(Ordering::SeqCst) {
            return Err(ChainkeeperError::ocsp("responder is not ready"));
        }
        let mut response = b"FAKE-OCSP:".to_vec();
        response.extend_from_slice(request_der);
        Ok(response)
    }

    fn reload(&self) -> Result<(), ChainkeeperError> {
        self.reloads.store(true, Ordering::SeqCst);
        self.ready.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
}
