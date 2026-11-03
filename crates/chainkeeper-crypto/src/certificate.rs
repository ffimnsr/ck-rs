//! Certificate construction and parsing.

use chainkeeper_core::{ChainkeeperError, KeyAlgorithm, Serial, SignatureScheme, Signer};
use openssl::x509::X509;
use time::OffsetDateTime;

use crate::der;
use crate::extensions::Extension;
use crate::keygen;
use crate::pem;

/// Inputs shared by every certificate the provider builds.
#[derive(Debug, Clone)]
pub struct CertificateInput {
    /// Serial number.
    pub serial: Serial,
    /// DER encoded issuer distinguished name.
    pub issuer_der: Vec<u8>,
    /// DER encoded subject distinguished name.
    pub subject_der: Vec<u8>,
    /// Validity start.
    pub not_before: OffsetDateTime,
    /// Validity end.
    pub not_after: OffsetDateTime,
    /// DER encoded `SubjectPublicKeyInfo`.
    pub public_key_der: Vec<u8>,
    /// Extensions to assert.
    pub extensions: Vec<Extension>,
}

/// Builds a v3 certificate and returns its DER and PEM encodings.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when encoding or signing fails.
pub fn build(
    input: &CertificateInput,
    signer: &dyn Signer,
) -> Result<(Vec<u8>, String), ChainkeeperError> {
    let scheme = SignatureScheme::from_key_algorithm(signer.algorithm());
    let algorithm = signature_algorithm_identifier(signer.algorithm())?;

    let mut extension_parts = Vec::with_capacity(input.extensions.len());
    for extension in &input.extensions {
        extension_parts.push(crate::extensions::encode(extension)?);
    }
    let extensions = der::context_constructed(3, &der::sequence(&extension_parts));

    let tbs = der::sequence(&[
        der::context_constructed(0, &der::integer_u64(2)),
        keygen::serial_integer(input.serial.as_str())?,
        algorithm.clone(),
        input.issuer_der.clone(),
        der::sequence(&[der::time(input.not_before), der::time(input.not_after)]),
        input.subject_der.clone(),
        input.public_key_der.clone(),
        extensions,
    ]);

    let signature = signer.sign(&tbs, scheme)?;
    let certificate = der::sequence(&[tbs, algorithm, der::bit_string(0, &signature)]);
    let pem = pem::encode("CERTIFICATE", &certificate);
    Ok((certificate, pem))
}

/// Algorithm identifier for a certificate signature.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the OID cannot be encoded.
pub fn signature_algorithm_identifier(
    algorithm: KeyAlgorithm,
) -> Result<Vec<u8>, ChainkeeperError> {
    let (oid, with_null) = match algorithm {
        KeyAlgorithm::Rsa3072 => ("1.2.840.113549.1.1.11", true),
        KeyAlgorithm::EcdsaP256 => ("1.2.840.10045.4.3.2", false),
        KeyAlgorithm::Ed25519 => ("1.3.101.112", false),
        _ => return Err(ChainkeeperError::crypto("unsupported key algorithm for V1")),
    };
    let oid = der::oid(oid)?;
    Ok(if with_null {
        der::sequence(&[oid, der::null()])
    } else {
        der::sequence(&[oid])
    })
}

/// Parses every certificate in a PEM bundle.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the bundle cannot be parsed.
pub fn parse_chain(pem_text: &str) -> Result<Vec<X509>, ChainkeeperError> {
    X509::stack_from_pem(pem_text.as_bytes()).map_err(|error| {
        ChainkeeperError::crypto(format!("cannot parse certificate chain: {error}"))
    })
}

/// Parses the first certificate in a PEM bundle.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the bundle is empty or malformed.
pub fn parse_first(pem_text: &str) -> Result<X509, ChainkeeperError> {
    parse_chain(pem_text)?
        .into_iter()
        .next()
        .ok_or_else(|| ChainkeeperError::crypto("certificate PEM is empty"))
}

/// DER encoded subject name of a certificate.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when encoding fails.
pub fn subject_der(certificate: &X509) -> Result<Vec<u8>, ChainkeeperError> {
    certificate
        .subject_name()
        .to_der()
        .map_err(|error| ChainkeeperError::crypto(error.to_string()))
}

/// Key identifier of a certificate, computing one when the extension is absent.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the public key cannot be read.
pub fn key_id(certificate: &X509) -> Result<Vec<u8>, ChainkeeperError> {
    if let Some(identifier) = certificate.subject_key_id() {
        return Ok(identifier.as_slice().to_vec());
    }
    let public_key = certificate
        .public_key()
        .map_err(|error| ChainkeeperError::crypto(error.to_string()))?;
    let spki = public_key
        .public_key_to_der()
        .map_err(|error| ChainkeeperError::crypto(error.to_string()))?;
    keygen::key_id_from_spki(&spki)
}

/// Expiry time of a certificate.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the certificate cannot be parsed.
pub fn not_after(certificate_pem: &str) -> Result<OffsetDateTime, ChainkeeperError> {
    use x509_parser::prelude::FromDer as _;

    let (_, pem) =
        x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).map_err(|error| {
            ChainkeeperError::crypto(format!("cannot parse certificate PEM: {error}"))
        })?;
    let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .map_err(|error| ChainkeeperError::crypto(format!("cannot parse certificate: {error}")))?;
    OffsetDateTime::from_unix_timestamp(certificate.validity().not_after.timestamp())
        .map_err(|error| ChainkeeperError::crypto(error.to_string()))
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::KeyAlgorithm;

    use super::signature_algorithm_identifier;

    #[test]
    fn signature_algorithms_match_rfc_identifiers() {
        let rsa = signature_algorithm_identifier(KeyAlgorithm::Rsa3072).expect("rsa");
        assert_eq!(rsa[0], 0x30);
        assert!(rsa.windows(2).any(|window| window == [0x05, 0x00]));
        let ecdsa = signature_algorithm_identifier(KeyAlgorithm::EcdsaP256).expect("ecdsa");
        assert!(!ecdsa.windows(2).any(|window| window == [0x05, 0x00]));
        let ed25519 = signature_algorithm_identifier(KeyAlgorithm::Ed25519).expect("ed25519");
        assert!(!ed25519.windows(2).any(|window| window == [0x05, 0x00]));
    }
}
