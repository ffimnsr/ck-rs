//! Minimal DER encoder for the structures OpenSSL's safe API cannot build.
//!
//! Certificates and CRLs are encoded by hand so that every signature is
//! produced through the [`Signer`](chainkeeper_core::Signer) trait. That keeps
//! HSM-backed signers usable without exporting private key material.

use chainkeeper_core::ChainkeeperError;
use time::{OffsetDateTime, UtcOffset};

/// Encodes a DER length.
#[must_use]
pub fn length(value: usize) -> Vec<u8> {
    if value < 0x80 {
        return vec![u8::try_from(value).unwrap_or(0x7F)];
    }
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    let significant = &bytes[first..];
    let mut out = Vec::with_capacity(significant.len() + 1);
    #[allow(clippy::cast_possible_truncation)]
    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
    out
}

/// Encodes a single tag-length-value element.
#[must_use]
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    out.extend_from_slice(&length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encodes a DER sequence from already encoded elements.
#[must_use]
pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &concat(parts))
}

fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}

/// Encodes a BOOLEAN.
#[must_use]
pub fn boolean(value: bool) -> Vec<u8> {
    tlv(0x01, &[if value { 0xFF } else { 0x00 }])
}

/// Encodes the DER NULL value.
#[must_use]
pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Encodes an OCTET STRING.
#[must_use]
pub fn octet_string(value: &[u8]) -> Vec<u8> {
    tlv(0x04, value)
}

/// Encodes a `UTF8String`.
#[must_use]
pub fn utf8_string(value: &str) -> Vec<u8> {
    tlv(0x0C, value.as_bytes())
}

/// Encodes an unsigned INTEGER from a big-endian magnitude.
#[must_use]
pub fn integer_unsigned(value: &[u8]) -> Vec<u8> {
    let mut bytes = value;
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    let mut content = Vec::with_capacity(bytes.len() + 1);
    if bytes.is_empty() {
        content.push(0);
    } else {
        if bytes[0] & 0x80 != 0 {
            content.push(0);
        }
        content.extend_from_slice(bytes);
    }
    tlv(0x02, &content)
}

/// Encodes an unsigned INTEGER from a `u64`.
#[must_use]
pub fn integer_u64(value: u64) -> Vec<u8> {
    integer_unsigned(&value.to_be_bytes())
}

/// Encodes an ENUMERATED value.
#[must_use]
pub fn enumerated(value: u8) -> Vec<u8> {
    tlv(0x0A, &[value])
}

/// Encodes a BIT STRING with an explicit unused-bit count.
#[must_use]
pub fn bit_string(unused_bits: u8, value: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(value.len() + 1);
    content.push(unused_bits);
    content.extend_from_slice(value);
    tlv(0x03, &content)
}

/// Encodes a BIT STRING from named bit positions.
///
/// Bit position zero is the most significant bit of the first content byte,
/// matching RFC 5280's key usage encoding.
#[must_use]
pub fn bit_string_from_positions(positions: &[usize]) -> Vec<u8> {
    let highest = positions.iter().copied().max().unwrap_or(0);
    let bits = highest + 1;
    let byte_len = bits.div_ceil(8);
    let mut value = vec![0_u8; byte_len];
    for position in positions {
        let byte = position / 8;
        let offset = 7 - (position % 8);
        if let Some(slot) = value.get_mut(byte) {
            *slot |= 1 << offset;
        }
    }
    #[allow(clippy::cast_possible_truncation)]
    let unused = (8 - bits % 8) as u8 % 8;
    bit_string(unused, &value)
}

/// Encodes a dotted numeric object identifier.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the value is not a valid OID.
pub fn oid(value: &str) -> Result<Vec<u8>, ChainkeeperError> {
    let parts: Vec<u64> = value
        .split('.')
        .map(|part| {
            part.parse::<u64>().map_err(|_| {
                ChainkeeperError::crypto(format!("invalid object identifier: {value}"))
            })
        })
        .collect::<Result<_, _>>()?;
    if parts.len() < 2 {
        return Err(ChainkeeperError::crypto(format!(
            "invalid object identifier: {value}"
        )));
    }
    let first = parts[0];
    let second = parts[1];
    if first > 2 || (first < 2 && second > 39) {
        return Err(ChainkeeperError::crypto(format!(
            "invalid object identifier: {value}"
        )));
    }
    let mut content = Vec::new();
    encode_base128(first * 40 + second, &mut content);
    for part in &parts[2..] {
        encode_base128(*part, &mut content);
    }
    Ok(tlv(0x06, &content))
}

fn encode_base128(mut value: u64, out: &mut Vec<u8>) {
    let mut buffer = [0_u8; 10];
    let mut index = 0;
    loop {
        buffer[index] = u8::try_from(value & 0x7F).unwrap_or(0);
        value >>= 7;
        index += 1;
        if value == 0 {
            break;
        }
    }
    for position in (0..index).rev() {
        let mut byte = buffer[position];
        if position != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
}

/// Encodes a UTC or generalised time.
#[must_use]
pub fn time(value: OffsetDateTime) -> Vec<u8> {
    let value = value.to_offset(UtcOffset::UTC);
    let year = value.year();
    let month = u8::from(value.month());
    let day = value.day();
    let hour = value.hour();
    let minute = value.minute();
    let second = value.second();
    if (1950..2050).contains(&year) {
        let text = format!(
            "{:02}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z",
            year.rem_euclid(100)
        );
        tlv(0x17, text.as_bytes())
    } else {
        let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
        tlv(0x18, text.as_bytes())
    }
}

/// Encodes a context-specific constructed value.
#[must_use]
pub fn context_constructed(tag: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xA0 | tag, content)
}

/// Encodes a context-specific primitive value.
#[must_use]
pub fn context_primitive(tag: u8, content: &[u8]) -> Vec<u8> {
    tlv(0x80 | tag, content)
}

/// Reads one tag-length-value element from the start of `input`.
///
/// Returns the tag, content, and remaining bytes.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the element is truncated or uses
/// an unsupported long-form length.
pub fn read_tlv(input: &[u8]) -> Result<(u8, Vec<u8>, &[u8]), ChainkeeperError> {
    let Some((&tag, rest)) = input.split_first() else {
        return Err(ChainkeeperError::crypto("truncated DER element"));
    };
    let Some((&first, rest)) = rest.split_first() else {
        return Err(ChainkeeperError::crypto("truncated DER length"));
    };
    let (length, rest) = if first & 0x80 == 0 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 8 || rest.len() < count {
            return Err(ChainkeeperError::crypto("unsupported DER length"));
        }
        let mut value = 0_usize;
        for byte in &rest[..count] {
            value = (value << 8) | usize::from(*byte);
        }
        (value, &rest[count..])
    };
    if rest.len() < length {
        return Err(ChainkeeperError::crypto("truncated DER content"));
    }
    let (content, remaining) = rest.split_at(length);
    Ok((tag, content.to_vec(), remaining))
}

#[cfg(test)]
mod tests {
    use super::{
        bit_string_from_positions, integer_u64, integer_unsigned, length, oid, read_tlv, sequence,
    };

    #[test]
    fn long_form_lengths_round_trip() {
        for value in [0_usize, 1, 127, 128, 255, 256, 70_000] {
            let encoded = length(value);
            let mut input = vec![0x04];
            input.extend_from_slice(&encoded);
            input.extend(std::iter::repeat_n(0xAA, value));
            let (tag, content, rest) = read_tlv(&input).expect("decodes");
            assert_eq!(tag, 0x04);
            assert_eq!(content.len(), value);
            assert_eq!(rest.len(), 0);
        }
    }

    #[test]
    fn oids_match_known_encodings() {
        assert_eq!(
            oid("2.5.29.19").expect("valid"),
            vec![0x06, 0x03, 0x55, 0x1D, 0x13]
        );
        assert_eq!(
            oid("1.2.840.113549.1.1.11").expect("valid"),
            vec![
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
            ]
        );
        assert!(oid("not-an-oid").is_err());
        assert!(oid("3.1").is_err());
    }

    #[test]
    fn integers_are_positive_and_minimal() {
        assert_eq!(integer_u64(1), vec![0x02, 0x01, 0x01]);
        assert_eq!(integer_u64(0), vec![0x02, 0x01, 0x00]);
        assert_eq!(
            integer_unsigned(&[0x00, 0x80]),
            vec![0x02, 0x02, 0x00, 0x80]
        );
        assert_eq!(integer_unsigned(&[0x00, 0x01]), vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn key_usage_bits_are_msb_first() {
        assert_eq!(
            bit_string_from_positions(&[0]),
            vec![0x03, 0x02, 0x07, 0x80]
        );
        assert_eq!(
            bit_string_from_positions(&[5, 6]),
            vec![0x03, 0x02, 0x01, 0x06]
        );
    }

    #[test]
    fn sequences_concatenate_children() {
        assert_eq!(sequence(&[vec![0x05, 0x00]]), vec![0x30, 0x02, 0x05, 0x00]);
    }
}
