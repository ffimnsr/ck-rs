//! RFC 6960 request parsing.

use chainkeeper_core::ChainkeeperError;
use rasn_ocsp::{CertId, OcspRequest};
use rasn_pkix::Extensions;

use crate::util::{OCSP_NONCE_OID, digest};

/// Largest request accepted before ASN.1 decoding.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Largest number of certificate identifiers accepted per request.
pub const MAX_REQUESTS: usize = 10;
/// Largest nonce content accepted, matching the RFC 6960 recommendation.
pub const MAX_NONCE_BYTES: usize = 32;

/// Hash algorithm used by a certificate identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
}

impl HashAlgorithm {
    /// Stable name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Digest length in bytes.
    #[must_use]
    pub const fn length(self) -> usize {
        self.digest_len()
    }

    /// Hashes `data` with this algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Ocsp`] when the digest cannot be computed.
    pub fn digest(self, data: &[u8]) -> Result<Vec<u8>, ChainkeeperError> {
        digest(self, data)
    }
}

/// One parsed certificate identifier.
#[derive(Debug, Clone)]
pub struct OcspRequestEntry {
    /// Identifier exactly as received, echoed in the response.
    pub cert_id: CertId,
    /// Hash algorithm declared by the request.
    pub hash: HashAlgorithm,
    /// Issuer distinguished name hash.
    pub issuer_name_hash: Vec<u8>,
    /// Issuer public key hash.
    pub issuer_key_hash: Vec<u8>,
    /// Serial number as a non-negative integer.
    pub serial: u128,
}

impl OcspRequestEntry {
    /// Uppercase hexadecimal rendering of the serial number.
    #[must_use]
    pub fn serial_hex(&self) -> String {
        crate::util::serial_hex(self.serial)
    }
}

/// Parsed request metadata.
#[derive(Debug, Clone)]
pub struct OcspRequestMeta {
    /// Certificate identifiers in request order.
    pub entries: Vec<OcspRequestEntry>,
    /// Raw nonce extension value, echoed byte-for-byte when present.
    pub nonce: Option<Vec<u8>>,
}

/// Parses a DER encoded OCSP request.
///
/// Trailing bytes, unsupported versions, unsupported hash algorithms, empty
/// request lists, oversized nonces, and oversized inputs are rejected.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Ocsp`] when the request is not acceptable.
pub fn parse_request(request_der: &[u8]) -> Result<OcspRequestMeta, ChainkeeperError> {
    if request_der.len() > MAX_REQUEST_BYTES {
        return Err(ChainkeeperError::ocsp(
            "OCSP request exceeds the size limit",
        ));
    }

    let request: OcspRequest = rasn::der::decode(request_der)
        .map_err(|error| ChainkeeperError::ocsp(format!("malformed OCSP request: {error}")))?;

    if request.tbs_request.version != rasn::types::Integer::ZERO {
        return Err(ChainkeeperError::ocsp("unsupported OCSP request version"));
    }
    if request.tbs_request.request_list.is_empty() {
        return Err(ChainkeeperError::ocsp("OCSP request list is empty"));
    }
    if request.tbs_request.request_list.len() > MAX_REQUESTS {
        return Err(ChainkeeperError::ocsp(
            "OCSP request has too many certificate identifiers",
        ));
    }

    let nonce = nonce_from(request.tbs_request.request_extensions.as_ref())
        .or_else(|| {
            request
                .tbs_request
                .request_list
                .iter()
                .find_map(|entry| nonce_from(entry.single_request_extensions.as_ref()))
        })
        .transpose()?;

    let mut entries = Vec::with_capacity(request.tbs_request.request_list.len());
    for item in &request.tbs_request.request_list {
        let hash = HashAlgorithm::from_oid(item.req_cert.hash_algorithm.algorithm.as_ref())
            .ok_or_else(|| ChainkeeperError::ocsp("unsupported OCSP hash algorithm"))?;
        let expected = hash.digest_len();
        if item.req_cert.issuer_name_hash.len() != expected
            || item.req_cert.issuer_key_hash.len() != expected
        {
            return Err(ChainkeeperError::ocsp(
                "OCSP certificate identifier has an invalid hash length",
            ));
        }
        let serial = u128::try_from(&item.req_cert.serial_number)
            .map_err(|_| ChainkeeperError::ocsp("OCSP serial number is out of range"))?;
        entries.push(OcspRequestEntry {
            cert_id: item.req_cert.clone(),
            hash,
            issuer_name_hash: item.req_cert.issuer_name_hash.as_ref().to_vec(),
            issuer_key_hash: item.req_cert.issuer_key_hash.as_ref().to_vec(),
            serial,
        });
    }

    Ok(OcspRequestMeta { entries, nonce })
}

fn nonce_from(extensions: Option<&Extensions>) -> Option<Result<Vec<u8>, ChainkeeperError>> {
    let extensions = extensions?;
    for extension in extensions.iter() {
        if extension.extn_id.as_ref() == OCSP_NONCE_OID {
            let raw = extension.extn_value.as_ref().to_vec();
            let length = nonce_content_len(&raw);
            if length > MAX_NONCE_BYTES {
                return Some(Err(ChainkeeperError::ocsp("OCSP nonce is too long")));
            }
            return Some(Ok(raw));
        }
    }
    None
}

/// Returns the length of the nonce after unwrapping the `OCTET STRING` that
/// RFC 6960 places inside the extension value.
fn nonce_content_len(raw: &[u8]) -> usize {
    rasn::der::decode::<rasn::types::OctetString>(raw)
        .map_or(raw.len(), |nonce| nonce.as_ref().len())
}
