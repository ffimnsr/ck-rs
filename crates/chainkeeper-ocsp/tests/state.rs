mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chainkeeper_core::OcspResponder;
use chainkeeper_ocsp::{FileOcspResponder, HashAlgorithm};
use rasn_ocsp::{CertStatus, OcspResponse, OcspResponseStatus};

use common::{
    FixtureSigners, Harness, MissingSigners, cert_id, generate_signer, leaf_record, leaf_serial,
    ocsp_signer_name, other_serial, past_clock, rename_signer, request, signer_bundle_from,
};

fn request_for(harness: &Harness, serial: u128) -> Vec<u8> {
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        serial,
        HashAlgorithm::Sha256,
    )
    .expect("cert id");
    request(vec![id], None, rasn::types::Integer::ZERO).expect("request")
}

fn basic_status(bytes: &[u8]) -> CertStatus {
    let response: OcspResponse = rasn::der::decode(bytes).expect("response");
    assert_eq!(response.status, OcspResponseStatus::Successful);
    let bytes = response.bytes.expect("response bytes");
    let basic: rasn_ocsp::BasicOcspResponse =
        rasn::der::decode(bytes.response.as_ref()).expect("basic");
    basic.tbs_response_data.responses[0].cert_status.clone()
}

#[test]
fn loads_valid_state() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");
    assert!(responder.ready());
    assert_eq!(
        basic_status(
            &responder
                .respond(&request_for(&harness, leaf_serial()))
                .expect("respond")
        ),
        CertStatus::Good
    );
}

#[test]
fn missing_signer_key_fails_to_load() {
    let harness = Harness::new().expect("harness");
    let responder = FileOcspResponder::new(harness.dependencies(Arc::new(MissingSigners)));
    assert!(!responder.ready());
    assert!(responder.reload().is_err());
    assert!(!responder.ready());
}

#[test]
fn wrong_eku_fails_to_load() {
    let harness = Harness::new().expect("harness");
    let name = chainkeeper_core::AuthorityName::new("bad-ocsp").expect("name");
    let leaf_key = harness.fixtures.leaf.key.as_ref().expect("leaf key");
    let bundle = signer_bundle_from(
        &name,
        &harness.fixtures.leaf.cert_pem,
        &harness.fixtures.leaf.chain_pem,
        leaf_key,
    );
    harness.write_signer(&bundle).expect("write signer");

    let responder = FileOcspResponder::load(harness.dependencies_for(
        Arc::new(FixtureSigners::new(leaf_key.private_key_pem())),
        name,
    ));
    assert!(responder.is_err());
}

#[test]
fn expired_signer_fails_to_load() {
    let harness = Harness::new().expect("harness");
    let name = chainkeeper_core::AuthorityName::new("expired-ocsp").expect("name");
    let generated = generate_signer(&harness, past_clock(100), 1).expect("generate");
    let bundle = rename_signer(generated, &name);
    harness.write_signer(&bundle).expect("write signer");

    let responder = FileOcspResponder::load(harness.dependencies_for(
        Arc::new(FixtureSigners::new(bundle.key.private_key_pem())),
        name,
    ));
    assert!(responder.is_err());
}

#[test]
fn failed_reload_keeps_the_previous_state() {
    let harness = Harness::new().expect("harness");
    let signers = Arc::new(FixtureSigners::new(
        harness.fixtures.ocsp_signer.key.private_key_pem(),
    ));
    let resolver: Arc<dyn chainkeeper_ocsp::AuthoritySigners> = signers.clone();
    let responder = FileOcspResponder::load(harness.dependencies(resolver)).expect("load");

    signers.fail();
    assert!(responder.reload().is_err());
    assert!(responder.ready());
    assert_eq!(
        basic_status(
            &responder
                .respond(&request_for(&harness, leaf_serial()))
                .expect("respond")
        ),
        CertStatus::Good
    );
}

#[test]
fn reload_picks_up_new_certificates() {
    let harness = Harness::without_leaf().expect("harness");
    let responder = harness.responder().expect("responder");
    assert_eq!(
        basic_status(
            &responder
                .respond(&request_for(&harness, leaf_serial()))
                .expect("respond")
        ),
        CertStatus::Unknown(())
    );

    harness
        .write_record(&leaf_record(&harness))
        .expect("record");
    responder.reload().expect("reload");
    assert_eq!(
        basic_status(
            &responder
                .respond(&request_for(&harness, leaf_serial()))
                .expect("respond")
        ),
        CertStatus::Good
    );
    assert_eq!(
        basic_status(
            &responder
                .respond(&request_for(&harness, other_serial()))
                .expect("respond")
        ),
        CertStatus::Unknown(())
    );
}

#[test]
fn reload_swaps_state_under_concurrent_requests() {
    let harness = Harness::new().expect("harness");
    let responder = Arc::new(harness.responder().expect("responder"));
    let request = Arc::new(request_for(&harness, leaf_serial()));
    let failures = Arc::new(AtomicUsize::new(0));

    let mut workers = Vec::new();
    for _ in 0..8 {
        let responder = Arc::clone(&responder);
        let request = Arc::clone(&request);
        let failures = Arc::clone(&failures);
        workers.push(std::thread::spawn(move || {
            for _ in 0..50 {
                match responder.respond(&request) {
                    Ok(bytes) => {
                        if let Ok(response) = rasn::der::decode::<OcspResponse>(&bytes)
                            && response.status != OcspResponseStatus::Successful
                        {
                            failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    for _ in 0..20 {
        responder.reload().expect("reload");
    }
    for worker in workers {
        worker.join().expect("worker");
    }
    assert_eq!(failures.load(Ordering::Relaxed), 0);
    assert!(responder.ready());
    assert_eq!(ocsp_signer_name().as_str(), "ocsp-signer");
}
