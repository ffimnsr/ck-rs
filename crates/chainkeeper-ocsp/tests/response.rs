mod common;

use std::io::Write as _;

use chainkeeper_core::OcspResponder;
use chainkeeper_ocsp::HashAlgorithm;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use rasn::types::OctetString;
use rasn_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponseBytes};

use common::{
    FailingSigners, Harness, MissingSigners, cert_id, expired, leaf_record, leaf_serial,
    other_serial, request, revoked,
};

fn decoded(bytes: &[u8]) -> OcspResponse {
    rasn::der::decode(bytes).expect("response decodes")
}

fn decode_basic(response: &OcspResponse) -> BasicOcspResponse {
    let ResponseBytes { response, .. } = response.bytes.as_ref().expect("response bytes");
    rasn::der::decode(response.as_ref()).expect("basic response decodes")
}

fn request_for(harness: &Harness, algorithm: HashAlgorithm) -> Vec<u8> {
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        algorithm,
    )
    .expect("cert id");
    request(vec![id], None, rasn::types::Integer::ZERO).expect("request")
}

#[test]
fn reports_good_for_active_certificates() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");

    for algorithm in [HashAlgorithm::Sha1, HashAlgorithm::Sha256] {
        let bytes = responder
            .respond(&request_for(&harness, algorithm))
            .expect("respond");
        let response = decoded(&bytes);
        assert_eq!(response.status, OcspResponseStatus::Successful);
        let basic = decode_basic(&response);
        assert_eq!(basic.tbs_response_data.responses.len(), 1);
        assert_eq!(
            basic.tbs_response_data.responses[0].cert_status,
            CertStatus::Good
        );
        assert_ne!(basic.certs.as_ref().expect("certs").len(), 0);
    }
}

#[test]
fn reports_revoked_with_reason_and_time() {
    let harness = Harness::without_leaf().expect("harness");
    harness
        .write_record(&revoked(leaf_record(&harness)))
        .expect("record");
    let responder = harness.responder().expect("responder");

    let bytes = responder
        .respond(&request_for(&harness, HashAlgorithm::Sha256))
        .expect("respond");
    let basic = decode_basic(&decoded(&bytes));
    match &basic.tbs_response_data.responses[0].cert_status {
        CertStatus::Revoked(info) => {
            assert_eq!(
                info.revocation_time.timestamp(),
                common::NOW.unix_timestamp()
            );
            assert_eq!(
                info.revocation_reason,
                Some(rasn_pkix::CrlReason::KeyCompromise)
            );
        }
        other => panic!("expected revoked status, got {other:?}"),
    }
}

#[test]
fn reports_unknown_for_expired_and_foreign_serials() {
    let harness = Harness::without_leaf().expect("harness");
    harness
        .write_record(&expired(leaf_record(&harness)))
        .expect("record");
    let responder = harness.responder().expect("responder");
    let basic = decode_basic(&decoded(
        &responder
            .respond(&request_for(&harness, HashAlgorithm::Sha256))
            .expect("respond"),
    ));
    assert_eq!(
        basic.tbs_response_data.responses[0].cert_status,
        CertStatus::Unknown(())
    );

    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        other_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("cert id");
    let bytes = responder
        .respond(&request(vec![id], None, rasn::types::Integer::ZERO).expect("request"))
        .expect("respond");
    let basic = decode_basic(&decoded(&bytes));
    assert_eq!(
        basic.tbs_response_data.responses[0].cert_status,
        CertStatus::Unknown(())
    );
}

#[test]
fn reports_unknown_for_serials_issued_by_another_authority() {
    let harness = Harness::without_leaf().expect("harness");
    let mut record = leaf_record(&harness);
    record.authority = chainkeeper_core::AuthorityName::new("smime").expect("name");
    harness.write_record(&record).expect("record");

    let responder = harness.responder().expect("responder");
    let basic = decode_basic(&decoded(
        &responder
            .respond(&request_for(&harness, HashAlgorithm::Sha256))
            .expect("respond"),
    ));
    assert_eq!(
        basic.tbs_response_data.responses[0].cert_status,
        CertStatus::Unknown(())
    );
}

#[test]
fn echoes_nonce_and_uses_fixed_clock() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");
    let nonce = vec![0xA5; 16];
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("cert id");
    let der = request(vec![id], Some(nonce.clone()), rasn::types::Integer::ZERO).expect("request");
    let basic = decode_basic(&decoded(&responder.respond(&der).expect("respond")));

    let extension = basic
        .tbs_response_data
        .response_extensions
        .as_ref()
        .expect("extensions")
        .iter()
        .find(|extension| extension.extn_id.as_ref() == [1, 3, 6, 1, 5, 5, 7, 48, 1, 2])
        .expect("nonce extension");
    assert_eq!(extension.extn_value, OctetString::from(nonce));

    let single = &basic.tbs_response_data.responses[0];
    assert_eq!(single.this_update.timestamp(), common::NOW.unix_timestamp());
    let next = single.next_update.expect("next update");
    assert_eq!(next.timestamp() - single.this_update.timestamp(), 3600);
    assert_eq!(
        basic.tbs_response_data.produced_at.timestamp(),
        common::NOW.unix_timestamp()
    );
}

#[test]
fn response_signature_verifies() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");
    let basic = decode_basic(&decoded(
        &responder
            .respond(&request_for(&harness, HashAlgorithm::Sha256))
            .expect("respond"),
    ));

    let tbs = rasn::der::encode(&basic.tbs_response_data).expect("encode");
    let public = PKey::public_key_from_der(harness.fixtures.ocsp_signer.key.public_key_der())
        .expect("public key");
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public).expect("verifier");
    verifier.update(&tbs).expect("update");
    assert!(
        verifier
            .verify(basic.signature.as_raw_slice())
            .expect("verify")
    );
}

#[test]
fn preserves_request_order_for_multiple_identifiers() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");
    let first = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("first");
    let second = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        other_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("second");
    let der = request(
        vec![first.clone(), second.clone()],
        None,
        rasn::types::Integer::ZERO,
    )
    .expect("request");
    let basic = decode_basic(&decoded(&responder.respond(&der).expect("respond")));
    assert_eq!(basic.tbs_response_data.responses.len(), 2);
    assert_eq!(basic.tbs_response_data.responses[0].cert_id, first);
    assert_eq!(basic.tbs_response_data.responses[1].cert_id, second);
    assert_eq!(
        basic.tbs_response_data.responses[0].cert_status,
        CertStatus::Good
    );
    assert_eq!(
        basic.tbs_response_data.responses[1].cert_status,
        CertStatus::Unknown(())
    );
}

#[test]
fn returns_malformed_request_status() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");
    let response = decoded(&responder.respond(b"not a request").expect("respond"));
    assert_eq!(response.status, OcspResponseStatus::MalformedRequest);
    assert!(response.bytes.is_none());
}

#[test]
fn returns_unauthorized_status_for_unknown_issuers() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");

    let mut wrong_name = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("cert id");
    wrong_name.issuer_name_hash = OctetString::from(vec![0u8; 32]);

    let mut wrong_key = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("cert id");
    wrong_key.issuer_key_hash = OctetString::from(vec![0u8; 32]);

    for id in [wrong_name, wrong_key] {
        let der = request(vec![id], None, rasn::types::Integer::ZERO).expect("request");
        let response = decoded(&responder.respond(&der).expect("respond"));
        assert_eq!(response.status, OcspResponseStatus::Unauthorized);
    }
}

#[test]
fn returns_try_later_before_state_is_loaded() {
    let harness = Harness::new().expect("harness");
    let responder = chainkeeper_ocsp::FileOcspResponder::new(
        harness.dependencies(std::sync::Arc::new(MissingSigners)),
    );
    assert!(!responder.ready());
    let response = decoded(
        &responder
            .respond(&request_for(&harness, HashAlgorithm::Sha256))
            .expect("respond"),
    );
    assert_eq!(response.status, OcspResponseStatus::TryLater);
}

#[test]
fn returns_internal_error_when_signing_fails() {
    let harness = Harness::new().expect("harness");
    let signer = FailingSigners::new(harness.fixtures.ocsp_signer.key.public_key_der().to_vec());
    let responder = chainkeeper_ocsp::FileOcspResponder::load(
        harness.dependencies(std::sync::Arc::new(signer)),
    )
    .expect("load");
    let response = decoded(
        &responder
            .respond(&request_for(&harness, HashAlgorithm::Sha256))
            .expect("respond"),
    );
    assert_eq!(response.status, OcspResponseStatus::InternalError);
}

#[test]
fn openssl_ocsp_parses_generated_responses() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");
    let bytes = responder
        .respond(&request_for(&harness, HashAlgorithm::Sha256))
        .expect("respond");

    let directory = tempfile::tempdir().expect("temp dir");
    let response_path = directory.path().join("response.der");
    let issuer_path = directory.path().join("issuer.pem");
    let leaf_path = directory.path().join("leaf.pem");
    std::fs::write(&response_path, &bytes).expect("write response");
    std::fs::write(&issuer_path, &harness.fixtures.tls.material.cert_pem).expect("write issuer");
    std::fs::write(&leaf_path, &harness.fixtures.leaf.cert_pem).expect("write leaf");

    let output = std::process::Command::new("openssl")
        .arg("ocsp")
        .arg("-respin")
        .arg(&response_path)
        .arg("-resp_text")
        .arg("-noverify")
        .arg("-sha256")
        .arg("-no_nonce")
        .arg("-issuer")
        .arg(&issuer_path)
        .arg("-cert")
        .arg(&leaf_path)
        .output();
    let Ok(output) = output else {
        eprintln!("openssl binary unavailable; skipping interop check");
        return;
    };
    if !output.status.success() {
        let mut stderr = std::io::stderr();
        stderr
            .write_all(&output.stderr)
            .expect("write openssl stderr");
    }
    assert!(
        output.status.success(),
        "openssl rejected the response: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("successful"), "unexpected output: {stdout}");
    assert!(stdout.contains("good"), "unexpected output: {stdout}");
}
