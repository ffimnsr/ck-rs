//! CRL generation tests.

mod common;

use chainkeeper_core::{
    AuthorityName, CONFIG_VERSION, CertificateProvider, CrlRequest, RevocationReason,
    RevocationRecord, Serial,
};
use common::{Harness, NOW, verify_chain};
use openssl::x509::X509Crl;
use time::Duration;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer as _;

fn revocation(serial: Serial, reason: RevocationReason, authority: &str) -> RevocationRecord {
    RevocationRecord {
        version: CONFIG_VERSION,
        serial,
        authority: AuthorityName::new(authority).expect("authority"),
        reason,
        comment: None,
        revoked_at: NOW,
        crl_number: 1,
    }
}

fn crl_request(revocations: Vec<RevocationRecord>, number: u64) -> CrlRequest {
    CrlRequest {
        authority: AuthorityName::new("tls").expect("authority"),
        number,
        this_update: NOW,
        next_update: NOW + Duration::days(7),
        revocations,
    }
}

#[test]
fn crl_signature_verifies_and_reasons_round_trip() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);

    let mut revocations = Vec::new();
    for (index, reason) in RevocationReason::ALL.iter().enumerate() {
        let serial = Serial::from_bytes(&[u8::try_from(index).expect("index") + 1]);
        revocations.push(revocation(serial, *reason, "tls"));
    }
    revocations.push(revocation(
        Serial::from_bytes(&[0xEE]),
        RevocationReason::Superseded,
        "smime",
    ));

    let bundle = provider
        .generate_crl(&crl_request(revocations, 7), &Harness::signer_for(&tls))
        .expect("CRL generation");

    assert!(bundle.record.next_update > bundle.record.this_update);
    assert_eq!(bundle.record.number, 7);
    assert_eq!(bundle.record.revoked_serials.len(), 9);
    assert!(
        !bundle
            .record
            .revoked_serials
            .contains(&Serial::from_bytes(&[0xEE]))
    );

    let crl = X509Crl::from_der(&bundle.der).expect("parse CRL");
    let issuer_key =
        openssl::pkey::PKey::private_key_from_pem(tls.key.private_key_pem().as_bytes())
            .expect("issuer key");
    assert!(crl.verify(&issuer_key).expect("verify"), "CRL signature");

    let (_, parsed) =
        x509_parser::revocation_list::CertificateRevocationList::from_der(&bundle.der)
            .expect("parse CRL");
    assert_eq!(
        parsed.crl_number().expect("CRL number").to_u64_digits()[0],
        7
    );

    let mut seen = Vec::new();
    for revoked in parsed.iter_revoked_certificates() {
        let reason = revoked
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                ParsedExtension::ReasonCode(code) => Some(code.0),
                _ => None,
            })
            .expect("reason code");
        seen.push(reason);
    }
    seen.sort_unstable();
    let mut expected: Vec<u8> = RevocationReason::ALL
        .iter()
        .map(|reason| reason.code())
        .collect();
    expected.sort_unstable();
    assert_eq!(seen, expected);
}

#[test]
fn crl_number_increments_between_generations() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let serial = Serial::from_bytes(&[0x01]);
    let signer = Harness::signer_for(&tls);

    for number in [1_u64, 2] {
        let bundle = provider
            .generate_crl(
                &crl_request(
                    vec![revocation(
                        serial.clone(),
                        RevocationReason::Superseded,
                        "tls",
                    )],
                    number,
                ),
                &signer,
            )
            .expect("CRL generation");
        let (_, parsed) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&bundle.der)
                .expect("parse CRL");
        assert_eq!(
            parsed.crl_number().expect("number").to_u64_digits()[0],
            number
        );
    }
}

#[test]
fn crl_for_wrong_authority_is_rejected() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let mut request = crl_request(Vec::new(), 1);
    request.authority = AuthorityName::new("smime").expect("authority");
    let error = provider
        .generate_crl(&request, &Harness::signer_for(&tls))
        .expect_err("mismatched authority");
    assert!(error.to_string().contains("does not match"));
}

#[test]
fn crl_chain_still_verifies_after_signing() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    verify_chain(&tls.material.cert_pem, "", &harness.root.material.cert_pem);
}

#[test]
fn crl_next_update_is_clamped_to_authority_expiry() {
    let harness = Harness::new();
    let mut request = common::intermediate_request("tls");
    request.validity_days = 1;
    let provider =
        chainkeeper_crypto::OpenSslProvider::new(harness.clock.clone(), harness.ids.clone());
    let tls = provider
        .create_intermediate(&request, &harness.root.material, &harness.root_signer())
        .expect("short lived intermediate");
    let provider = harness.provider_for(&tls.material);
    let bundle = provider
        .generate_crl(&crl_request(Vec::new(), 1), &Harness::signer_for(&tls))
        .expect("CRL generation");
    assert_eq!(bundle.record.next_update, NOW + Duration::days(1));
    assert!(bundle.record.next_update > bundle.record.this_update);
}
