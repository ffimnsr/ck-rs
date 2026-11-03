//! RFC 6960 responder with atomic state reload.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use chainkeeper_core::{ChainkeeperError, OcspResponder};
use rasn_ocsp::OcspResponseStatus;

use crate::deps::OcspDependencies;
use crate::request::{MAX_REQUEST_BYTES, parse_request};
use crate::response::{error_response, status_label, success_response};
use crate::state::{OcspState, load_state};

/// OCSP responder backed by the canonical repository store.
pub struct FileOcspResponder {
    deps: OcspDependencies,
    state: ArcSwapOption<OcspState>,
}

impl std::fmt::Debug for FileOcspResponder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileOcspResponder")
            .field("deps", &self.deps)
            .field("ready", &self.ready())
            .field("state_loaded", &self.state.load().is_some())
            .finish()
    }
}

impl FileOcspResponder {
    /// Builds a responder that answers `tryLater` until [`OcspResponder::reload`]
    /// succeeds.
    #[must_use]
    pub fn new(deps: OcspDependencies) -> Self {
        Self {
            deps,
            state: ArcSwapOption::empty(),
        }
    }

    /// Builds a responder and loads its initial state.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Ocsp`] when the state cannot be loaded.
    pub fn load(deps: OcspDependencies) -> Result<Self, ChainkeeperError> {
        let responder = Self::new(deps);
        responder.reload()?;
        Ok(responder)
    }

    fn respond_inner(&self, request_der: &[u8]) -> Result<Vec<u8>, Failure> {
        if request_der.len() > MAX_REQUEST_BYTES {
            return Err(Failure::Malformed);
        }
        let request = parse_request(request_der).map_err(|_| Failure::Malformed)?;
        let Some(state) = self.state.load_full() else {
            return Err(Failure::TryLater);
        };

        let mut resolved = Vec::with_capacity(request.entries.len());
        for entry in &request.entries {
            let Some(authority) = state
                .issuers
                .find(entry.hash, &entry.issuer_name_hash, &entry.issuer_key_hash)
                .map_err(|_| Failure::Internal)?
            else {
                return Err(Failure::Unauthorized);
            };
            let status = state.status(authority, entry.serial);
            resolved.push((entry.clone(), status));
        }

        success_response(
            &state,
            &resolved,
            request.nonce.as_deref(),
            self.deps.clock.now(),
        )
        .map_err(|_| Failure::Internal)
    }
}

impl OcspResponder for FileOcspResponder {
    fn respond(&self, request_der: &[u8]) -> Result<Vec<u8>, ChainkeeperError> {
        let outcome = self.respond_inner(request_der);
        let (status, body) = match outcome {
            Ok(body) => (OcspResponseStatus::Successful, body),
            Err(failure) => {
                let status = failure.status();
                let body = error_response(status)?;
                (status, body)
            }
        };
        tracing::info!(
            request_bytes = request_der.len(),
            result = status_label(status),
            "ocsp request"
        );
        Ok(body)
    }

    fn reload(&self) -> Result<(), ChainkeeperError> {
        let state = load_state(&self.deps)
            .map_err(|error| ChainkeeperError::ocsp(format!("cannot load OCSP state: {error}")))?;
        self.state.store(Some(Arc::new(state)));
        Ok(())
    }

    fn ready(&self) -> bool {
        self.state.load().is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    Malformed,
    Unauthorized,
    Internal,
    TryLater,
}

impl Failure {
    const fn status(self) -> OcspResponseStatus {
        match self {
            Self::Malformed => OcspResponseStatus::MalformedRequest,
            Self::Unauthorized => OcspResponseStatus::Unauthorized,
            Self::Internal => OcspResponseStatus::InternalError,
            Self::TryLater => OcspResponseStatus::TryLater,
        }
    }
}
