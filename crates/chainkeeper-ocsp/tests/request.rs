mod common;

use chainkeeper_ocsp::{
    HashAlgorithm, MAX_NONCE_BYTES, MAX_REQUEST_BYTES, MAX_REQUESTS, parse_request,
};
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_ocsp::CertId;
use rasn_pkix::AlgorithmIdentifier;

use common::{Harness, cert_id, leaf_serial, request};

fn invalid_hash_cert_id() -> CertId {
    CertId {
        hash_algorithm: AlgorithmIdentifier {
            algorithm: ObjectIdentifier::new(&[1, 2, 3, 4]).expect("valid"),
            parameters: None,
        },
        issuer_name_hash: OctetString::from(vec![0u8; 20]),
        issuer_key_hash: OctetString::from(vec![0u8; 20]),
        serial_number: Integer::from(10u64),
    }
}

#[test]
fn parses_sha1_and_sha256_requests() {
    let harness = Harness::new().expect("harness");
    for algorithm in [HashAlgorithm::Sha1, HashAlgorithm::Sha256] {
        let id = cert_id(
            &harness.fixtures.tls.material.cert_pem,
            leaf_serial(),
            algorithm,
        )
        .expect("id");
        let der = request(vec![id], None, Integer::ZERO).expect("request");
        let meta = parse_request(&der).expect("parse");
        assert_eq!(meta.entries.len(), 1);
        assert_eq!(meta.entries[0].hash, algorithm);
        assert_eq!(meta.entries[0].serial, leaf_serial());
        assert_eq!(meta.entries[0].serial_hex(), "A");
        assert!(meta.nonce.is_none());
    }
}

#[test]
fn rejects_empty_request_lists() {
    let der = request(Vec::new(), None, Integer::ZERO).expect("request");
    assert!(parse_request(&der).is_err());
}

#[test]
fn rejects_trailing_bytes() {
    let harness = Harness::new().expect("harness");
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("id");
    let mut der = request(vec![id], None, Integer::ZERO).expect("request");
    der.push(0);
    assert!(parse_request(&der).is_err());
}

#[test]
fn rejects_unsupported_hash_algorithms() {
    let der = request(vec![invalid_hash_cert_id()], None, Integer::ZERO).expect("request");
    assert!(parse_request(&der).is_err());
}

#[test]
fn rejects_malformed_der() {
    assert!(parse_request(b"not a request").is_err());
    assert!(parse_request(b"\x30\x03abc").is_err());
    assert!(parse_request(&[]).is_err());
}

#[test]
fn rejects_unsupported_version() {
    let harness = Harness::new().expect("harness");
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("id");
    let der = request(vec![id], None, Integer::from(1)).expect("request");
    assert!(parse_request(&der).is_err());
}

#[test]
fn rejects_oversized_nonce() {
    let harness = Harness::new().expect("harness");
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("id");
    let nonce = vec![0x5A; MAX_NONCE_BYTES + 1];
    let der = request(vec![id], Some(nonce), Integer::ZERO).expect("request");
    assert!(parse_request(&der).is_err());
}

#[test]
fn accepts_the_maximum_nonce_and_echoes_it() {
    let harness = Harness::new().expect("harness");
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("id");
    let nonce = vec![0x5A; MAX_NONCE_BYTES];
    let der = request(vec![id], Some(nonce.clone()), Integer::ZERO).expect("request");
    let meta = parse_request(&der).expect("parse");
    assert_eq!(meta.nonce, Some(nonce));
}

#[test]
fn rejects_oversized_input_before_decoding() {
    let oversized = vec![0u8; MAX_REQUEST_BYTES + 1];
    assert!(parse_request(&oversized).is_err());
}

#[test]
fn accepts_at_most_ten_identifiers() {
    let harness = Harness::new().expect("harness");
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("id");

    let accepted = request(vec![id.clone(); MAX_REQUESTS], None, Integer::ZERO).expect("request");
    let meta = parse_request(&accepted).expect("parse");
    assert_eq!(meta.entries.len(), MAX_REQUESTS);

    let rejected = request(vec![id; MAX_REQUESTS + 1], None, Integer::ZERO).expect("request");
    assert!(parse_request(&rejected).is_err());
}
