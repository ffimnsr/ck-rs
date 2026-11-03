mod common;

use std::path::{Path, PathBuf};

use chainkeeper_core::OcspResponder;
use chainkeeper_ocsp::{MAX_REQUEST_BYTES, parse_request};
use rasn_ocsp::{OcspResponse, OcspResponseStatus};

use common::{Harness, HashAlgorithm, cert_id, leaf_serial, request};

fn source_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            source_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn runtime_sources_never_execute_subprocesses() {
    let mut files = Vec::new();
    source_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert_ne!(files.len(), 0);
    for path in files {
        let source = std::fs::read_to_string(&path).expect("read source");
        for needle in [
            "std::process::Command",
            "tokio::process::Command",
            "Command::new(",
        ] {
            assert!(
                !source.contains(needle),
                "{} contains {needle}",
                path.display()
            );
        }
    }
}

#[test]
fn fuzz_target_metadata_exists() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/fuzz_targets/ocsp_request.rs");
    let source = std::fs::read_to_string(path).expect("fuzz target");
    assert!(source.contains("fuzz_target!"));
}

#[test]
fn responses_never_contain_private_key_material() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");
    let id = cert_id(
        &harness.fixtures.tls.material.cert_pem,
        leaf_serial(),
        HashAlgorithm::Sha256,
    )
    .expect("cert id");
    let der = request(vec![id], None, rasn::types::Integer::ZERO).expect("request");
    let response = responder.respond(&der).expect("respond");
    for marker in [
        "PRIVATE KEY",
        "BEGIN RSA PRIVATE",
        "BEGIN EC PRIVATE",
        "BEGIN ENCRYPTED PRIVATE",
    ] {
        assert!(
            !response
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "response contains {marker}"
        );
    }
}

#[test]
fn oversized_requests_are_rejected_before_asn1_decoding() {
    let harness = Harness::new().expect("harness");
    let responder = harness.responder().expect("responder");
    let bytes = responder
        .respond(&vec![0u8; MAX_REQUEST_BYTES + 1])
        .expect("respond");
    let response: OcspResponse = rasn::der::decode(&bytes).expect("response");
    assert_eq!(response.status, OcspResponseStatus::MalformedRequest);
}

#[test]
fn malformed_der_corpus_does_not_panic() {
    let corpus: &[&[u8]] = &[
        b"",
        b"\x00",
        b"\x30",
        b"\x30\x80",
        b"\x30\x84\xff\xff\xff\xff",
        b"\x06\x01",
        b"\x05\x00",
        b"\xa0\x03\x02\x01\x01",
        b"\x30\x03\x30\x01\x00",
        b"OCSP",
    ];
    for bytes in corpus {
        let _ = parse_request(bytes);
    }
}

#[test]
fn bounded_random_input_does_not_panic() {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..10_000 {
        let length = (next() % 64) as usize;
        let bytes: Vec<u8> = (0..length)
            .map(|_| u8::try_from(next() % 256).unwrap_or_default())
            .collect();
        let _ = parse_request(&bytes);
    }
}
