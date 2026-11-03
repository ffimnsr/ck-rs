//! Certificate revocation list generation.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chainkeeper_core::{
    AuthorityMaterial, CONFIG_VERSION, ChainkeeperError, CrlBundle, CrlRecord, CrlRequest,
    RevocationRecord, SignatureScheme, Signer,
};

use crate::certificate;
use crate::der;
use crate::extensions::{
    self, Extension, OID_AUTHORITY_KEY_IDENTIFIER, OID_CRL_NUMBER, OID_REASON_CODE,
};
use crate::keygen;
use crate::pem;

fn validation(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::validation(message)
}

/// Generates and signs a CRL for the authority described by `request`.
///
/// Only revocation records belonging to `request.authority` are included.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] for inconsistent input and
/// [`ChainkeeperError::Crypto`] when encoding or signing fails.
pub fn generate(
    request: &CrlRequest,
    issuer: &AuthorityMaterial,
    signer: &dyn Signer,
) -> Result<CrlBundle, ChainkeeperError> {
    if request.authority != issuer.config.name {
        return Err(validation(
            "CRL authority does not match the supplied authority material",
        ));
    }
    let issuer_certificate = certificate::parse_first(&issuer.cert_pem)?;
    let issuer_not_after = certificate::not_after(&issuer.cert_pem)?;
    let next_update = request.next_update.min(issuer_not_after);
    if next_update <= request.this_update {
        return Err(validation("CRL next_update must be after this_update"));
    }
    let issuer_der = certificate::subject_der(&issuer_certificate)?;
    let issuer_key_id = certificate::key_id(&issuer_certificate)?;
    let scheme = SignatureScheme::from_key_algorithm(signer.algorithm());
    let algorithm = certificate::signature_algorithm_identifier(signer.algorithm())?;

    let (entries, revoked_serials) = select_revocations(&request.revocations, request)?;

    let mut crl_extensions = [
        Extension::new(
            OID_AUTHORITY_KEY_IDENTIFIER,
            false,
            extensions::authority_key_identifier(&issuer_key_id),
        ),
        Extension::new(OID_CRL_NUMBER, false, der::integer_u64(request.number)),
    ];
    crl_extensions.sort_by(|left, right| left.oid.cmp(&right.oid));
    let encoded_extensions = crl_extensions
        .iter()
        .map(extensions::encode)
        .collect::<Result<Vec<_>, _>>()?;

    let revoked = if entries.is_empty() {
        None
    } else {
        Some(der::sequence(&entries))
    };

    let tbs = {
        let mut parts = vec![
            der::integer_u64(1),
            algorithm.clone(),
            issuer_der,
            der::time(request.this_update),
            der::time(next_update),
        ];
        if let Some(revoked) = revoked {
            parts.push(revoked);
        }
        parts.push(der::context_constructed(
            0,
            &der::sequence(&encoded_extensions),
        ));
        der::sequence(&parts)
    };

    let signature = signer.sign(&tbs, scheme)?;
    let crl = der::sequence(&[tbs, algorithm, der::bit_string(0, &signature)]);
    let pem_text = pem::encode("X509 CRL", &crl);
    let record = CrlRecord {
        version: CONFIG_VERSION,
        authority: request.authority.clone(),
        number: request.number,
        this_update: request.this_update,
        next_update,
        revoked_serials,
        der_path: PathBuf::from(format!("crls/{}.crl.der", request.authority)),
        pem_path: PathBuf::from(format!("crls/{}.crl.pem", request.authority)),
    };
    Ok(CrlBundle {
        record,
        der: crl,
        pem: pem_text,
    })
}

fn select_revocations(
    revocations: &[RevocationRecord],
    request: &CrlRequest,
) -> Result<(Vec<Vec<u8>>, Vec<chainkeeper_core::Serial>), ChainkeeperError> {
    let mut by_serial: BTreeMap<_, _> = BTreeMap::new();
    for revocation in revocations {
        if revocation.authority == request.authority {
            by_serial.insert(revocation.serial.clone(), revocation);
        }
    }
    let mut encoded = Vec::with_capacity(by_serial.len());
    let mut serials = Vec::with_capacity(by_serial.len());
    for revocation in by_serial.values() {
        encoded.push(encode_entry(revocation)?);
        serials.push(revocation.serial.clone());
    }
    Ok((encoded, serials))
}

/// Encodes one CRL entry.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Crypto`] when the serial cannot be encoded.
pub fn encode_entry(revocation: &RevocationRecord) -> Result<Vec<u8>, ChainkeeperError> {
    let reason = Extension::new(
        OID_REASON_CODE,
        false,
        der::enumerated(revocation.reason.code()),
    );
    Ok(der::sequence(&[
        keygen::serial_integer(revocation.serial.as_str())?,
        der::time(revocation.revoked_at),
        der::sequence(&[extensions::encode(&reason)?]),
    ]))
}

#[cfg(test)]
mod tests {
    use super::encode_entry;
    use chainkeeper_core::{AuthorityName, RevocationReason, RevocationRecord, Serial};
    use time::macros::datetime;

    #[test]
    fn entries_include_reason_codes() {
        let revocation = RevocationRecord {
            version: 1,
            serial: Serial::new("00AA").expect("serial"),
            authority: AuthorityName::new("tls").expect("authority"),
            reason: RevocationReason::KeyCompromise,
            comment: None,
            revoked_at: datetime!(2024-05-01 12:00:00 UTC),
            crl_number: 1,
        };
        let encoded = encode_entry(&revocation).expect("entry");
        assert_eq!(encoded[0], 0x30);
        assert!(encoded.contains(&0x0A));
    }
}
