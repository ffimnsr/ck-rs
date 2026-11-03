//! Small ASN.1, hashing, and certificate helpers shared by the OCSP modules.

use chainkeeper_core::{ChainkeeperError, Serial};
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use rasn::types::{GeneralizedTime, ObjectIdentifier};
use rasn_pkix::{Certificate, Name};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::request::HashAlgorithm;

/// `id-pkix-ocsp-basic` response type.
pub const OCSP_BASIC_OID: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 1];
/// `id-pkix-ocsp-nonce` extension.
pub const OCSP_NONCE_OID: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 2];
/// `sha1` digest algorithm.
pub const SHA1_OID: &[u32] = &[1, 3, 14, 3, 2, 26];
/// `sha256` digest algorithm.
pub const SHA256_OID: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
/// `sha256WithRSAEncryption`.
const SHA256_WITH_RSA_OID: &[u32] = &[1, 2, 840, 113_549, 1, 1, 11];
/// `ecdsa-with-SHA256`.
const ECDSA_WITH_SHA256_OID: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];
/// `id-Ed25519`.
const ED25519_OID: &[u32] = &[1, 3, 101, 112];

impl HashAlgorithm {
    #[must_use]
    pub fn from_oid(oid: &[u32]) -> Option<Self> {
        if oid == SHA1_OID {
            Some(Self::Sha1)
        } else if oid == SHA256_OID {
            Some(Self::Sha256)
        } else {
            None
        }
    }

    #[must_use]
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }
}

pub fn digest(algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, ChainkeeperError> {
    let digest = match algorithm {
        HashAlgorithm::Sha1 => MessageDigest::sha1(),
        HashAlgorithm::Sha256 => MessageDigest::sha256(),
    };
    openssl::hash::hash(digest, data)
        .map(|value| value.as_ref().to_vec())
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot hash issuer material: {error}")))
}

pub fn oid(arcs: &'static [u32]) -> Result<ObjectIdentifier, ChainkeeperError> {
    ObjectIdentifier::new(arcs)
        .ok_or_else(|| ChainkeeperError::ocsp("invalid OCSP object identifier"))
}

pub fn signature_algorithm(
    algorithm: chainkeeper_core::KeyAlgorithm,
) -> Result<rasn_pkix::AlgorithmIdentifier, ChainkeeperError> {
    use chainkeeper_core::KeyAlgorithm;

    let (arcs, parameters) = match algorithm {
        KeyAlgorithm::Rsa3072 => (
            SHA256_WITH_RSA_OID,
            Some(rasn::types::Any::new(vec![0x05, 0x00])),
        ),
        KeyAlgorithm::EcdsaP256 => (ECDSA_WITH_SHA256_OID, None),
        KeyAlgorithm::Ed25519 => (ED25519_OID, None),
        _ => {
            return Err(ChainkeeperError::ocsp(
                "unsupported OCSP signer key algorithm",
            ));
        }
    };
    Ok(rasn_pkix::AlgorithmIdentifier {
        algorithm: oid(arcs)?,
        parameters,
    })
}

pub fn generalized(value: OffsetDateTime) -> Result<GeneralizedTime, ChainkeeperError> {
    let text = value
        .format(&Rfc3339)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot format OCSP time: {error}")))?;
    GeneralizedTime::parse_from_rfc3339(&text)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot encode OCSP time: {error}")))
}

pub fn x509_from_pem(pem: &str) -> Result<X509, ChainkeeperError> {
    X509::from_pem(pem.as_bytes())
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot parse certificate PEM: {error}")))
}

pub fn rasn_certificate_from_pem(pem: &str) -> Result<Certificate, ChainkeeperError> {
    let x509 = x509_from_pem(pem)?;
    let der = x509
        .to_der()
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot encode certificate: {error}")))?;
    rasn::der::decode(&der)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot decode certificate: {error}")))
}

pub fn name_der(name: &Name) -> Result<Vec<u8>, ChainkeeperError> {
    rasn::der::encode(name)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot encode name: {error}")))
}

/// Returns the bytes hashed for `issuerKeyHash`.
///
/// OpenSSL and RFC 6960 hash the `subjectPublicKey` value without the
/// unused-bits octet, that is, the raw key bytes held by the BIT STRING.
pub fn issuer_key_hash_input(certificate: &Certificate) -> Vec<u8> {
    certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_raw_slice()
        .to_vec()
}

pub fn serial_value(serial: &Serial) -> Option<u128> {
    u128::from_str_radix(serial.as_str(), 16).ok()
}

pub fn serial_hex(value: u128) -> String {
    format!("{value:X}")
}
