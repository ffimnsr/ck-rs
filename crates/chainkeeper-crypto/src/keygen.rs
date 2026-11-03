//! Key generation, loading, and raw signing primitives.

use chainkeeper_core::{ChainkeeperError, KeyAlgorithm, KeyMaterial, SignatureScheme};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, Id, PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::sign::Signer as OpenSslSigner;
use openssl::symm::Cipher;

use crate::der;
use crate::secret::SecretString;

/// OpenSSL key pair plus its serialized material.
pub struct GeneratedKey {
    /// Parsed private key used for signing.
    pub key: PKey<Private>,
    /// PEM and public DER representation handed to callers.
    pub material: KeyMaterial,
}

fn crypto<E: std::fmt::Display>(error: E) -> ChainkeeperError {
    ChainkeeperError::crypto(error.to_string())
}

/// Generates a key pair for the requested algorithm.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when OpenSSL cannot generate or encode
/// the key.
pub fn generate(
    algorithm: KeyAlgorithm,
    passphrase: Option<&SecretString>,
) -> Result<GeneratedKey, ChainkeeperError> {
    let key = match algorithm {
        KeyAlgorithm::Rsa3072 => {
            let rsa = Rsa::generate(3072).map_err(crypto)?;
            PKey::from_rsa(rsa).map_err(crypto)?
        }
        KeyAlgorithm::EcdsaP256 => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(crypto)?;
            let ec = EcKey::generate(&group).map_err(crypto)?;
            PKey::from_ec_key(ec).map_err(crypto)?
        }
        KeyAlgorithm::Ed25519 => PKey::generate_ed25519().map_err(crypto)?,
        _ => {
            return Err(ChainkeeperError::crypto("unsupported key algorithm for V1"));
        }
    };
    let material = key_material(&key, algorithm, passphrase)?;
    Ok(GeneratedKey { key, material })
}

/// Builds [`KeyMaterial`] from a parsed private key.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the key cannot be encoded.
pub fn key_material(
    key: &PKey<Private>,
    algorithm: KeyAlgorithm,
    passphrase: Option<&SecretString>,
) -> Result<KeyMaterial, ChainkeeperError> {
    let private_key_pem = match passphrase {
        Some(secret) => key
            .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), secret.expose().as_bytes())
            .map_err(crypto)?,
        None => key.private_key_to_pem_pkcs8().map_err(crypto)?,
    };
    let private_key_pem = string_from_utf8(private_key_pem)?;
    let public_key_der = key.public_key_to_der().map_err(crypto)?;
    Ok(KeyMaterial::new(algorithm, private_key_pem, public_key_der))
}

fn string_from_utf8(bytes: Vec<u8>) -> Result<String, ChainkeeperError> {
    String::from_utf8(bytes)
        .map_err(|_| ChainkeeperError::crypto("OpenSSL produced non UTF-8 PEM output"))
}

/// Loads a PEM private key, decrypting it when a passphrase is supplied.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the key is encrypted and no
/// passphrase is given, the passphrase is wrong, or the PEM is malformed.
pub fn load_pem(
    pem: &[u8],
    passphrase: Option<&SecretString>,
) -> Result<PKey<Private>, ChainkeeperError> {
    // An empty passphrase keeps OpenSSL from prompting on the terminal for
    // encrypted keys; unencrypted PEM still loads normally.
    passphrase
        .map_or_else(
            || PKey::private_key_from_pem_passphrase(pem, b""),
            |secret| PKey::private_key_from_pem_passphrase(pem, secret.expose().as_bytes()),
        )
        .map_err(|_| ChainkeeperError::crypto("cannot decrypt private key"))
}

/// Determines the algorithm of a parsed key.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] for keys outside the V1 algorithm set.
pub fn algorithm_of<T: HasPublic>(key: &PKeyRef<T>) -> Result<KeyAlgorithm, ChainkeeperError> {
    match key.id() {
        Id::RSA => Ok(KeyAlgorithm::Rsa3072),
        Id::ED25519 => Ok(KeyAlgorithm::Ed25519),
        Id::EC => {
            let ec = key.ec_key().map_err(crypto)?;
            match ec.group().curve_name() {
                Some(Nid::X9_62_PRIME256V1) => Ok(KeyAlgorithm::EcdsaP256),
                _ => Err(ChainkeeperError::crypto(
                    "unsupported elliptic curve, expected P-256",
                )),
            }
        }
        other => Err(ChainkeeperError::crypto(format!(
            "unsupported private key type: {other:?}"
        ))),
    }
}

/// Signs a message with a parsed key.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the scheme does not match the key
/// algorithm or OpenSSL reports a failure.
pub fn sign(
    key: &PKey<Private>,
    message: &[u8],
    scheme: SignatureScheme,
) -> Result<Vec<u8>, ChainkeeperError> {
    match scheme {
        SignatureScheme::Ed25519 => {
            let mut signer = OpenSslSigner::new_without_digest(key).map_err(crypto)?;
            signer.sign_oneshot_to_vec(message).map_err(crypto)
        }
        SignatureScheme::RsaPkcs1Sha256 | SignatureScheme::EcdsaSha256 => {
            let mut signer = OpenSslSigner::new(MessageDigest::sha256(), key).map_err(crypto)?;
            signer.update(message).map_err(crypto)?;
            signer.sign_to_vec().map_err(crypto)
        }
        _ => Err(ChainkeeperError::crypto(
            "unsupported signature scheme for V1",
        )),
    }
}

/// Computes the RFC 5280 key identifier for a DER `SubjectPublicKeyInfo`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the structure cannot be decoded.
pub fn key_id_from_spki(spki: &[u8]) -> Result<Vec<u8>, ChainkeeperError> {
    let (_, outer, _) = der::read_tlv(spki)?;
    let (_, _, after_algorithm) = der::read_tlv(&outer)?;
    let (tag, bit_string, _) = der::read_tlv(after_algorithm)?;
    if tag != 0x03 || bit_string.is_empty() {
        return Err(ChainkeeperError::crypto(
            "public key info does not contain a BIT STRING",
        ));
    }
    // The first content byte counts unused bits; hash the key bits only.
    hash(MessageDigest::sha1(), &bit_string[1..])
        .map(|digest| digest.to_vec())
        .map_err(crypto)
}

/// Serial bytes for a validated hexadecimal serial.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the serial is not hexadecimal.
pub fn serial_bytes(serial: &str) -> Result<Vec<u8>, ChainkeeperError> {
    if !serial.len().is_multiple_of(2) {
        return Err(ChainkeeperError::crypto(
            "serial has an odd number of digits",
        ));
    }
    serial
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|text| u8::from_str_radix(text, 16).ok())
                .ok_or_else(|| ChainkeeperError::crypto("serial is not hexadecimal"))
        })
        .collect()
}

/// Encodes a serial as an ASN.1 INTEGER.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the serial is not hexadecimal.
pub fn serial_integer(serial: &str) -> Result<Vec<u8>, ChainkeeperError> {
    Ok(der::integer_unsigned(&serial_bytes(serial)?))
}

#[cfg(test)]
mod tests {
    use super::{algorithm_of, generate, key_id_from_spki, serial_bytes};
    use chainkeeper_core::KeyAlgorithm;

    #[test]
    fn generated_keys_report_the_requested_algorithm() {
        for algorithm in KeyAlgorithm::ALL {
            let generated = generate(algorithm, None).expect("key generation");
            assert_eq!(
                algorithm_of(&generated.key).expect("detect"),
                algorithm,
                "{}",
                algorithm.as_str()
            );
            assert_eq!(generated.material.algorithm(), algorithm);
        }
    }

    #[test]
    fn rsa_public_key_is_3072_bits() {
        let generated = generate(KeyAlgorithm::Rsa3072, None).expect("key generation");
        let rsa = generated.key.rsa().expect("rsa key");
        assert_eq!(rsa.size() * 8, 3072);
    }

    #[test]
    fn key_id_is_derived_from_the_public_key() {
        let generated = generate(KeyAlgorithm::EcdsaP256, None).expect("key generation");
        let id = key_id_from_spki(generated.material.public_key_der()).expect("key id");
        assert_eq!(id.len(), 20);
    }

    #[test]
    fn serial_decoding_rejects_non_hex() {
        assert_eq!(serial_bytes("00FF").expect("valid"), vec![0x00, 0xFF]);
        assert!(serial_bytes("00FG").is_err());
        assert!(serial_bytes("0").is_err());
    }
}
