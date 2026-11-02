//! Read-side certificate and metadata parsing.
//!
//! The store never re-signs or rewrites certificates. It parses PEM only to
//! validate fixture output and to keep indexed metadata aligned with the
//! bytes on disk.

use std::net::IpAddr;
use std::path::Path;

use chainkeeper_core::{
    CertificateRecord, ChainkeeperError, ExtendedKeyUsage, KeyAlgorithm, KeyUsage, Serial,
};
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::parse_x509_pem;

use crate::canonical;
use crate::fsutil;

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_ED25519: &str = "1.3.101.112";

/// Fields extracted from a PEM certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCertificate {
    /// Serial rendered as uppercase hexadecimal.
    pub serial: Serial,
    /// Subject distinguished name rendered as a string.
    pub subject: String,
    /// Issuer distinguished name rendered as a string.
    pub issuer: String,
    /// Start of the validity period.
    pub not_before: OffsetDateTime,
    /// End of the validity period.
    pub not_after: OffsetDateTime,
    /// Subject alternative names.
    pub sans: Vec<chainkeeper_core::San>,
    /// Extended key usages.
    pub ekus: Vec<ExtendedKeyUsage>,
    /// Key usages.
    pub key_usages: Vec<KeyUsage>,
    /// Leaf public key algorithm.
    pub algorithm: KeyAlgorithm,
}

fn parse_error(path: &Path, error: impl std::fmt::Display) -> ChainkeeperError {
    ChainkeeperError::storage(format!(
        "could not parse certificate {}: {error}",
        path.display()
    ))
}

fn decode_serial(serial: &Serial) -> Result<Vec<u8>, ChainkeeperError> {
    let encoded = serial.as_str();
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    let raw = encoded.as_bytes();
    for pair in raw.as_chunks::<2>().0 {
        let text = std::str::from_utf8(pair).map_err(|_| {
            ChainkeeperError::storage(format!("serial {serial} is not valid hexadecimal"))
        })?;
        let byte = u8::from_str_radix(text, 16).map_err(|_| {
            ChainkeeperError::storage(format!("serial {serial} is not valid hexadecimal"))
        })?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn trim_leading_zeroes(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first..]
}

/// Returns true when two serial renderings identify the same integer.
#[must_use]
pub fn serials_equal(left: &Serial, right: &Serial) -> bool {
    match (decode_serial(left), decode_serial(right)) {
        (Ok(left), Ok(right)) => trim_leading_zeroes(&left) == trim_leading_zeroes(&right),
        _ => false,
    }
}

/// Returns true when the certificate serial equals `serial` numerically.
#[must_use]
pub fn serial_matches(certificate: &X509Certificate<'_>, serial: &Serial) -> bool {
    serials_equal(&Serial::from_bytes(certificate.raw_serial()), serial)
}

fn key_algorithm(certificate: &X509Certificate<'_>) -> KeyAlgorithm {
    match certificate
        .public_key()
        .algorithm
        .algorithm
        .to_id_string()
        .as_str()
    {
        OID_EC_PUBLIC_KEY => KeyAlgorithm::EcdsaP256,
        OID_ED25519 => KeyAlgorithm::Ed25519,
        OID_RSA_ENCRYPTION => KeyAlgorithm::Rsa3072,
        _ => KeyAlgorithm::default_for_profile(""),
    }
}

fn key_usages(certificate: &X509Certificate<'_>) -> Vec<KeyUsage> {
    let Some(extension) =
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::KeyUsage(usage) => Some(usage),
                _ => None,
            })
    else {
        return Vec::new();
    };

    let mut usages = Vec::new();
    let flags = [
        (extension.digital_signature(), KeyUsage::DigitalSignature),
        (extension.non_repudiation(), KeyUsage::ContentCommitment),
        (extension.key_encipherment(), KeyUsage::KeyEncipherment),
        (extension.data_encipherment(), KeyUsage::DataEncipherment),
        (extension.key_agreement(), KeyUsage::KeyAgreement),
        (extension.key_cert_sign(), KeyUsage::KeyCertSign),
        (extension.crl_sign(), KeyUsage::CrlSign),
        (extension.encipher_only(), KeyUsage::EncipherOnly),
        (extension.decipher_only(), KeyUsage::DecipherOnly),
    ];
    for (present, usage) in flags {
        if present {
            usages.push(usage);
        }
    }
    usages
}

fn extended_key_usages(certificate: &X509Certificate<'_>) -> Vec<ExtendedKeyUsage> {
    let Some(extension) =
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::ExtendedKeyUsage(usage) => Some(usage),
                _ => None,
            })
    else {
        return Vec::new();
    };

    let mut usages = Vec::new();
    let flags = [
        (extension.server_auth, ExtendedKeyUsage::ServerAuth),
        (extension.client_auth, ExtendedKeyUsage::ClientAuth),
        (extension.code_signing, ExtendedKeyUsage::CodeSigning),
        (
            extension.email_protection,
            ExtendedKeyUsage::EmailProtection,
        ),
        (extension.ocsp_signing, ExtendedKeyUsage::OcspSigning),
        (extension.time_stamping, ExtendedKeyUsage::TimeStamping),
    ];
    for (present, usage) in flags {
        if present {
            usages.push(usage);
        }
    }
    usages
}

fn subject_alternative_names(certificate: &X509Certificate<'_>) -> Vec<chainkeeper_core::San> {
    let Some(extension) =
        certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(names) => Some(names),
                _ => None,
            })
    else {
        return Vec::new();
    };

    let mut names_out = Vec::new();
    for name in &extension.general_names {
        match name {
            GeneralName::DNSName(value) => {
                names_out.push(chainkeeper_core::San::Dns((*value).to_owned()));
            }
            GeneralName::RFC822Name(value) => {
                names_out.push(chainkeeper_core::San::Email((*value).to_owned()));
            }
            GeneralName::URI(value) => {
                names_out.push(chainkeeper_core::San::Uri((*value).to_owned()));
            }
            GeneralName::IPAddress(bytes) => {
                let address = match bytes.len() {
                    4 => <[u8; 4]>::try_from(*bytes).ok().map(IpAddr::from),
                    16 => <[u8; 16]>::try_from(*bytes).ok().map(IpAddr::from),
                    _ => None,
                };
                if let Some(address) = address {
                    names_out.push(chainkeeper_core::San::Ip(address.to_string()));
                }
            }
            _ => {}
        }
    }
    names_out
}

/// Parses a PEM certificate.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Storage`] when the PEM is malformed.
pub fn parse_certificate_pem(
    pem: &str,
    path: &Path,
) -> Result<ParsedCertificate, ChainkeeperError> {
    let (_, encoded) = parse_x509_pem(pem.as_bytes()).map_err(|error| parse_error(path, error))?;
    let certificate = encoded
        .parse_x509()
        .map_err(|error| parse_error(path, error))?;
    let validity = certificate.validity();

    Ok(ParsedCertificate {
        serial: Serial::from_bytes(certificate.raw_serial()),
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        not_before: validity.not_before.to_datetime(),
        not_after: validity.not_after.to_datetime(),
        sans: subject_alternative_names(&certificate),
        ekus: extended_key_usages(&certificate),
        key_usages: key_usages(&certificate),
        algorithm: key_algorithm(&certificate),
    })
}

/// Reads a certificate metadata file and validates it against its PEM sibling.
pub fn read_certificate_record(
    metadata_path: &Path,
    pem_path: &Path,
    repository_relative_pem: &Path,
) -> Result<CertificateRecord, ChainkeeperError> {
    let mut record: CertificateRecord =
        canonical::read_yaml(metadata_path, "certificate metadata")?;
    if record.issued_at >= record.expires_at {
        return Err(ChainkeeperError::storage(format!(
            "certificate metadata {} has issued_at not before expires_at",
            metadata_path.display()
        )));
    }
    record.subject.validate().map_err(|error| {
        ChainkeeperError::storage(format!(
            "certificate metadata {} has an invalid subject: {error}",
            metadata_path.display()
        ))
    })?;

    let pem_bytes = fsutil::read_file(pem_path, "certificate")?;
    let pem = std::str::from_utf8(&pem_bytes).map_err(|error| {
        ChainkeeperError::storage(format!(
            "certificate {} is not valid UTF-8: {error}",
            pem_path.display()
        ))
    })?;
    let (_, encoded) =
        parse_x509_pem(pem.as_bytes()).map_err(|error| parse_error(pem_path, error))?;
    let certificate = encoded
        .parse_x509()
        .map_err(|error| parse_error(pem_path, error))?;
    if !serial_matches(&certificate, &record.serial) {
        return Err(ChainkeeperError::storage(format!(
            "certificate {} serial does not match metadata serial {}",
            pem_path.display(),
            record.serial
        )));
    }

    record.path = repository_relative_pem.to_path_buf();
    Ok(record)
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::Serial;

    use super::trim_leading_zeroes;

    #[test]
    fn serial_comparison_ignores_leading_zeroes() {
        assert_eq!(trim_leading_zeroes(&[0x00, 0x0A]), &[0x0A]);
        assert_eq!(trim_leading_zeroes(&[0x00, 0x00]), &[] as &[u8]);
        assert_eq!(trim_leading_zeroes(&[0x01, 0x02]), &[0x01, 0x02]);
        assert!(Serial::new("000A").is_ok());
    }
}
