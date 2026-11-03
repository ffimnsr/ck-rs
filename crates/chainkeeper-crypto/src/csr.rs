//! Certificate signing request parsing.

use std::net::{Ipv4Addr, Ipv6Addr};

use chainkeeper_core::{ChainkeeperError, KeyAlgorithm, San, SubjectName};
use openssl::x509::X509Req;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer as _;
use x509_parser::x509::{AttributeTypeAndValue, X509Name};

use crate::keygen;

/// Fields extracted from a PEM certificate signing request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrInfo {
    /// Subject distinguished name.
    pub subject: SubjectName,
    /// Requested subject alternative names.
    pub sans: Vec<San>,
    /// DER encoded `SubjectPublicKeyInfo`.
    pub public_key_der: Vec<u8>,
    /// Algorithm of the requested public key.
    pub algorithm: KeyAlgorithm,
}

/// Parses and verifies a PEM certificate signing request.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the signature is invalid and
/// [`ChainkeeperError::Crypto`] when the request cannot be decoded.
pub fn parse(pem_text: &str) -> Result<CsrInfo, ChainkeeperError> {
    let request = X509Req::from_pem(pem_text.as_bytes())
        .map_err(|error| ChainkeeperError::crypto(format!("cannot parse CSR: {error}")))?;
    let public_key = request
        .public_key()
        .map_err(|error| ChainkeeperError::crypto(format!("cannot read CSR key: {error}")))?;
    let valid = request
        .verify(&public_key)
        .map_err(|error| ChainkeeperError::crypto(format!("cannot verify CSR: {error}")))?;
    if !valid {
        return Err(ChainkeeperError::validation("CSR signature is invalid"));
    }
    let public_key_der = public_key
        .public_key_to_der()
        .map_err(|error| ChainkeeperError::crypto(error.to_string()))?;
    let algorithm = keygen::algorithm_of(&public_key)?;

    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes())
        .map_err(|error| ChainkeeperError::crypto(format!("cannot parse CSR PEM: {error}")))?;
    let (_, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
            .map_err(|error| ChainkeeperError::crypto(format!("cannot parse CSR: {error}")))?;

    let subject = subject_from_name(&request.certification_request_info.subject)?;
    let mut sans = Vec::new();
    if let Some(extensions) = request.requested_extensions() {
        for extension in extensions {
            if let ParsedExtension::SubjectAlternativeName(names) = extension {
                for name in &names.general_names {
                    if let Some(san) = san_from_general_name(name)? {
                        sans.push(san);
                    }
                }
            }
        }
    }
    Ok(CsrInfo {
        subject,
        sans,
        public_key_der,
        algorithm,
    })
}

fn subject_from_name(name: &X509Name<'_>) -> Result<SubjectName, ChainkeeperError> {
    let cn = attribute_value(name.iter_common_name().next())
        .ok_or_else(|| ChainkeeperError::validation("CSR subject has no common name"))?;
    Ok(SubjectName {
        cn,
        organization: attribute_value(name.iter_organization().next()),
        organizational_unit: attribute_value(name.iter_organizational_unit().next()),
        country: attribute_value(name.iter_country().next()),
        state: attribute_value(name.iter_state_or_province().next()),
        locality: attribute_value(name.iter_locality().next()),
        email: attribute_value(name.iter_email().next()),
    })
}

fn attribute_value(attribute: Option<&AttributeTypeAndValue<'_>>) -> Option<String> {
    attribute
        .and_then(|entry| entry.as_str().ok())
        .map(str::to_owned)
}

fn san_from_general_name(name: &GeneralName<'_>) -> Result<Option<San>, ChainkeeperError> {
    let san = match name {
        GeneralName::DNSName(value) => San::Dns((*value).to_owned()),
        GeneralName::RFC822Name(value) => San::Email((*value).to_owned()),
        GeneralName::URI(value) => San::Uri((*value).to_owned()),
        GeneralName::IPAddress(bytes) => San::Ip(ip_address(bytes)?),
        _ => return Ok(None),
    };
    san.validate()?;
    Ok(Some(san))
}

fn ip_address(bytes: &[u8]) -> Result<String, ChainkeeperError> {
    match bytes.len() {
        4 => <[u8; 4]>::try_from(bytes)
            .map(Ipv4Addr::from)
            .map(|address| address.to_string())
            .map_err(|_| ChainkeeperError::validation("invalid CSR IP address")),
        16 => <[u8; 16]>::try_from(bytes)
            .map(Ipv6Addr::from)
            .map(|address| address.to_string())
            .map_err(|_| ChainkeeperError::validation("invalid CSR IP address")),
        _ => Err(ChainkeeperError::validation("invalid CSR IP address")),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use chainkeeper_core::San;

    use super::ip_address;

    #[test]
    fn ip_addresses_decode_from_both_families() {
        assert_eq!(ip_address(&[192, 0, 2, 1]).expect("v4"), "192.0.2.1");
        let v6 = "2001:db8::1".parse::<IpAddr>().expect("v6").to_string();
        let bytes = match "2001:db8::1".parse::<IpAddr>().expect("v6") {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        };
        assert_eq!(ip_address(&bytes).expect("v6"), v6);
        assert_eq!(San::Ip(v6), San::Ip(ip_address(&bytes).expect("v6")));
    }
}
