#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

//! Cryptographic provider and signer implementations.
//!
//! The crate generates keys, builds X.509 certificates and CRLs, and signs them
//! through the [`chainkeeper_core::Signer`] trait. Certificates are encoded by
//! hand so signatures never require exporting private key material, which keeps
//! the provider compatible with future HSM-backed signers. The `openssl` crate
//! performs key generation and signature primitives; the `openssl` binary is
//! never executed.

mod authority;
mod certificate;
mod crl;
mod csr;
mod der;
mod extensions;
mod keygen;
mod leaf;
mod names;
mod pem;
mod provider;
mod secret;
mod signer;

pub use certificate::CertificateInput;
pub use csr::CsrInfo;
pub use provider::OpenSslProvider;
pub use secret::SecretString;
pub use signer::FileSigner;
