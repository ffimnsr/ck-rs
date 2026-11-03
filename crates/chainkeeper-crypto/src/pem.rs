//! PEM encoding helpers.

/// Wraps DER bytes in a PEM block with 64 column base64 lines.
#[must_use]
pub fn encode(label: &str, der: &[u8]) -> String {
    let encoded = openssl::base64::encode_block(der);
    let mut out = String::with_capacity(encoded.len() + label.len() * 2 + 40);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::encode;

    #[test]
    fn wraps_at_sixty_four_columns() {
        let pem = encode("CERTIFICATE", &[0xAB; 200]);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(lines[lines.len() - 1], "-----END CERTIFICATE-----");
        for line in &lines[1..lines.len() - 1] {
            assert!(line.len() <= 64, "{line}");
        }
    }
}
