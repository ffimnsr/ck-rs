#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! RFC 6960 OCSP responder.
//!
//! Implemented by Phase 8. Phase 1 only freezes the contract in
//! [`chainkeeper_core::OcspResponder`].
