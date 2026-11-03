#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! RFC 6960 OCSP responder.
//!
//! [`FileOcspResponder`] parses DER encoded requests, matches the issuer against
//! repository authorities, looks up certificate status, and signs a
//! `BasicOCSPResponse` with a dedicated OCSP signer. Runtime handling never
//! executes a subprocess.

mod deps;
mod issuer;
mod request;
mod responder;
mod response;
mod state;
mod status;
mod util;

pub use deps::{AuthoritySigners, OcspDependencies};
pub use request::{
    HashAlgorithm, MAX_NONCE_BYTES, MAX_REQUEST_BYTES, MAX_REQUESTS, OcspRequestEntry,
    OcspRequestMeta, parse_request,
};
pub use responder::FileOcspResponder;
