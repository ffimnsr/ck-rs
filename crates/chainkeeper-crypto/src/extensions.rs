//! X.509 extension encoders.

use std::net::IpAddr;

use chainkeeper_core::{ChainkeeperError, CustomExtension, ExtendedKeyUsage, KeyUsage, San};

use crate::der;

/// Object identifier of `basicConstraints`.
pub const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
/// Object identifier of `keyUsage`.
pub const OID_KEY_USAGE: &str = "2.5.29.15";
/// Object identifier of `extendedKeyUsage`.
pub const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
/// Object identifier of `subjectAltName`.
pub const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";
/// Object identifier of `subjectKeyIdentifier`.
pub const OID_SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
/// Object identifier of `authorityKeyIdentifier`.
pub const OID_AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
/// Object identifier of `authorityInfoAccess`.
pub const OID_AUTHORITY_INFO_ACCESS: &str = "1.3.6.1.5.5.7.1.1";
/// Object identifier of `cRLDistributionPoints`.
pub const OID_CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
/// Object identifier of `id-ad-caIssuers`.
pub const OID_CA_ISSUERS: &str = "1.3.6.1.5.5.7.48.2";
/// Object identifier of `cRLNumber`.
pub const OID_CRL_NUMBER: &str = "2.5.29.20";
/// Object identifier of `reasonCode`.
pub const OID_REASON_CODE: &str = "2.5.29.21";

/// One encoded extension ready to be placed in a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Dotted numeric object identifier.
    pub oid: String,
    /// Criticality flag.
    pub critical: bool,
    /// DER encoded extension value.
    pub value: Vec<u8>,
}

impl Extension {
    /// Builds an extension.
    #[must_use]
    pub fn new(oid: impl Into<String>, critical: bool, value: Vec<u8>) -> Self {
        Self {
            oid: oid.into(),
            critical,
            value,
        }
    }
}

/// Encodes an extension as `SEQUENCE { OID, [critical], OCTET STRING }`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the OID is malformed.
pub fn encode(extension: &Extension) -> Result<Vec<u8>, ChainkeeperError> {
    let mut parts = vec![der::oid(&extension.oid)?];
    if extension.critical {
        parts.push(der::boolean(true));
    }
    parts.push(der::octet_string(&extension.value));
    Ok(der::sequence(&parts))
}

/// `basicConstraints` value.
#[must_use]
pub fn basic_constraints(ca: bool, path_len: Option<u32>) -> Vec<u8> {
    let mut parts = vec![der::boolean(ca)];
    if let Some(path_len) = path_len {
        parts.push(der::integer_u64(u64::from(path_len)));
    }
    der::sequence(&parts)
}

/// `keyUsage` value.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when an unknown usage is supplied.
pub fn key_usage(usages: &[KeyUsage]) -> Result<Vec<u8>, ChainkeeperError> {
    let mut positions = Vec::with_capacity(usages.len());
    for usage in usages {
        positions.push(
            key_usage_bit(*usage)
                .ok_or_else(|| ChainkeeperError::validation("unsupported key usage"))?,
        );
    }
    Ok(der::bit_string_from_positions(&positions))
}

const fn key_usage_bit(usage: KeyUsage) -> Option<usize> {
    Some(match usage {
        KeyUsage::DigitalSignature => 0,
        KeyUsage::ContentCommitment => 1,
        KeyUsage::KeyEncipherment => 2,
        KeyUsage::DataEncipherment => 3,
        KeyUsage::KeyAgreement => 4,
        KeyUsage::KeyCertSign => 5,
        KeyUsage::CrlSign => 6,
        KeyUsage::EncipherOnly => 7,
        KeyUsage::DecipherOnly => 8,
        _ => return None,
    })
}

/// `extendedKeyUsage` value.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when an OID cannot be encoded.
pub fn extended_key_usage(usages: &[ExtendedKeyUsage]) -> Result<Vec<u8>, ChainkeeperError> {
    let mut parts = Vec::with_capacity(usages.len());
    for usage in usages {
        let oid = extended_key_usage_oid(*usage)
            .ok_or_else(|| ChainkeeperError::validation("unsupported extended key usage"))?;
        parts.push(der::oid(oid)?);
    }
    Ok(der::sequence(&parts))
}

const fn extended_key_usage_oid(usage: ExtendedKeyUsage) -> Option<&'static str> {
    Some(match usage {
        ExtendedKeyUsage::ServerAuth => "1.3.6.1.5.5.7.3.1",
        ExtendedKeyUsage::ClientAuth => "1.3.6.1.5.5.7.3.2",
        ExtendedKeyUsage::CodeSigning => "1.3.6.1.5.5.7.3.3",
        ExtendedKeyUsage::EmailProtection => "1.3.6.1.5.5.7.3.4",
        ExtendedKeyUsage::TimeStamping => "1.3.6.1.5.5.7.3.8",
        ExtendedKeyUsage::OcspSigning => "1.3.6.1.5.5.7.3.9",
        _ => return None,
    })
}

/// `subjectAltName` value.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when a SAN value is invalid.
pub fn subject_alt_name(sans: &[San]) -> Result<Vec<u8>, ChainkeeperError> {
    let parts = sans
        .iter()
        .map(general_name)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(der::sequence(&parts))
}

fn general_name(san: &San) -> Result<Vec<u8>, ChainkeeperError> {
    san.validate()?;
    Ok(match san {
        San::Dns(value) => der::tlv(0x82, value.as_bytes()),
        San::Email(value) => der::tlv(0x81, value.as_bytes()),
        San::Uri(value) => der::tlv(0x86, value.as_bytes()),
        San::Ip(value) => {
            let address: IpAddr = value
                .parse()
                .map_err(|_| ChainkeeperError::validation("invalid IP subject alternative name"))?;
            let bytes = match address {
                IpAddr::V4(address) => address.octets().to_vec(),
                IpAddr::V6(address) => address.octets().to_vec(),
            };
            der::tlv(0x87, &bytes)
        }
    })
}

/// `subjectKeyIdentifier` value.
#[must_use]
pub fn subject_key_identifier(key_id: &[u8]) -> Vec<u8> {
    der::octet_string(key_id)
}

/// `authorityKeyIdentifier` value.
#[must_use]
pub fn authority_key_identifier(key_id: &[u8]) -> Vec<u8> {
    der::sequence(&[der::context_primitive(0, key_id)])
}

/// `authorityInfoAccess` value with a single `caIssuers` URI.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the OID cannot be encoded.
pub fn authority_info_access(ca_issuers_url: &str) -> Result<Vec<u8>, ChainkeeperError> {
    let access = der::sequence(&[
        der::oid(OID_CA_ISSUERS)?,
        der::tlv(0x86, ca_issuers_url.as_bytes()),
    ]);
    Ok(der::sequence(&[access]))
}

/// `cRLDistributionPoints` value with a single URI distribution point.
#[must_use]
pub fn crl_distribution_points(url: &str) -> Vec<u8> {
    let full_name = der::context_constructed(0, &der::tlv(0x86, url.as_bytes()));
    let distribution_point = der::sequence(&[der::context_constructed(0, &full_name)]);
    der::sequence(&[distribution_point])
}

/// Custom extension value.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the extension is invalid.
pub fn custom(extension: &CustomExtension) -> Result<Vec<u8>, ChainkeeperError> {
    extension.validate()?;
    match (&extension.value_utf8, &extension.value_hex) {
        (Some(value), None) => Ok(der::utf8_string(value)),
        (None, Some(hex)) => decode_hex(hex),
        _ => Err(ChainkeeperError::validation(
            "custom extension must set exactly one value",
        )),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ChainkeeperError> {
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| ChainkeeperError::validation("custom extension hex is invalid"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::{ExtendedKeyUsage, KeyUsage, San};

    use super::{
        Extension, authority_key_identifier, basic_constraints, crl_distribution_points, encode,
        extended_key_usage, key_usage, subject_alt_name, subject_key_identifier,
    };

    #[test]
    fn basic_constraints_carry_ca_and_path_length() {
        let root = basic_constraints(true, Some(1));
        assert_eq!(root, vec![0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x01]);
        let leaf = basic_constraints(false, None);
        assert_eq!(leaf, vec![0x30, 0x03, 0x01, 0x01, 0x00]);
    }

    #[test]
    fn key_usage_is_critical_ready() {
        let usage = key_usage(&[KeyUsage::KeyCertSign, KeyUsage::CrlSign]).expect("encode");
        assert_eq!(usage, vec![0x03, 0x02, 0x01, 0x06]);
    }

    #[test]
    fn extended_key_usage_uses_rfc_oids() {
        let eku = extended_key_usage(&[ExtendedKeyUsage::OcspSigning]).expect("encode");
        assert_eq!(
            eku,
            vec![
                0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09
            ]
        );
    }

    #[test]
    fn san_encodes_every_supported_kind() {
        let sans = vec![
            San::Dns("example.test".to_owned()),
            San::Ip("192.0.2.1".to_owned()),
            San::Email("ops@example.test".to_owned()),
            San::Uri("https://example.test/acme".to_owned()),
        ];
        let encoded = subject_alt_name(&sans).expect("encode");
        assert_eq!(encoded[0], 0x30);
        assert!(encoded.windows(2).any(|window| window == [0x82, 0x0C]));
        assert!(encoded.contains(&0x87));
    }

    #[test]
    fn key_identifiers_are_context_tagged() {
        let ski = subject_key_identifier(&[0xAA, 0xBB]);
        assert_eq!(ski, vec![0x04, 0x02, 0xAA, 0xBB]);
        let aki = authority_key_identifier(&[0xAA, 0xBB]);
        assert_eq!(aki, vec![0x30, 0x04, 0x80, 0x02, 0xAA, 0xBB]);
    }

    #[test]
    fn crl_distribution_point_is_nested_context_tags() {
        let value = crl_distribution_points("https://example.test/crl");
        assert_eq!(value[0], 0x30);
        assert_eq!(value[2], 0x30);
    }

    #[test]
    fn extension_encoding_places_criticality_before_value() {
        let extension = Extension::new("2.5.29.19", true, vec![0x30, 0x00]);
        let encoded = encode(&extension).expect("encode");
        assert_eq!(encoded[0], 0x30);
        assert!(encoded.windows(2).any(|window| window == [0x01, 0x01]));
    }
}
