//! Provider security invariants.

mod common;

use std::path::Path;
use std::sync::Arc;

use chainkeeper_core::{
    AuthorityName, CertificateProvider, CreateOcspSignerRequest, IssueRequest, KeyAlgorithm,
    ProfileName, SignatureScheme, Signer, SubjectName,
};
use chainkeeper_crypto::{FileSigner, OpenSslProvider, SecretString};
use common::{Harness, build_csr};
use openssl::hash::MessageDigest;
use openssl::sign::Verifier;

const PASSPHRASE: &str = "correct horse battery staple";

fn scan_sources(directory: &Path) {
    for entry in std::fs::read_dir(directory).expect("source directory") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            scan_sources(&path);
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("source file");
        for forbidden in [
            "std::process::Command",
            "tokio::process::Command",
            "Command::new(\"openssl\")",
        ] {
            assert!(
                !source.contains(forbidden),
                "{} contains {forbidden}",
                path.display()
            );
        }
    }
}

#[test]
fn provider_never_executes_subprocesses() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    scan_sources(&manifest.join("src"));
}

#[test]
fn certificate_pem_never_contains_private_keys() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let issued = provider
        .issue(
            &IssueRequest::new(
                ProfileName::new("tls-server").expect("profile"),
                SubjectName::new("leaf.example.test"),
            ),
            &Harness::signer_for(&tls),
        )
        .expect("issuance");

    for pem in [
        &harness.root.material.cert_pem,
        &harness.root.material.chain_pem,
        &tls.material.cert_pem,
        &tls.material.chain_pem,
        &issued.cert_pem,
        &issued.chain_pem,
    ] {
        assert!(!pem.contains("PRIVATE KEY"), "certificate PEM leaked a key");
    }
}

#[test]
fn passphrase_encrypts_and_decrypts_keys() {
    let provider = OpenSslProvider::default().with_passphrase(SecretString::new(PASSPHRASE));
    let key = provider
        .generate_key(KeyAlgorithm::EcdsaP256)
        .expect("key generation");
    assert!(key.private_key_pem().contains("ENCRYPTED PRIVATE KEY"));

    let secret = SecretString::new(PASSPHRASE);
    let signer =
        FileSigner::from_pem(key.private_key_pem().as_bytes(), Some(&secret)).expect("decrypt");
    let signature = signer
        .sign(b"message", SignatureScheme::EcdsaSha256)
        .expect("signature");
    assert_ne!(signature, Vec::<u8>::new());

    let missing = FileSigner::from_pem(key.private_key_pem().as_bytes(), None)
        .expect_err("missing passphrase");
    assert!(!missing.to_string().contains(PASSPHRASE));

    let wrong = FileSigner::from_pem(
        key.private_key_pem().as_bytes(),
        Some(&SecretString::new("wrong passphrase")),
    )
    .expect_err("wrong passphrase");
    assert!(!wrong.to_string().contains(PASSPHRASE));
    assert!(!wrong.to_string().contains("wrong passphrase"));
}

#[test]
fn unprotected_keys_work_without_a_passphrase() {
    let provider = OpenSslProvider::default();
    let key = provider
        .generate_key(KeyAlgorithm::Rsa3072)
        .expect("key generation");
    let signer = FileSigner::from_pem(key.private_key_pem().as_bytes(), None).expect("load");
    assert_eq!(signer.algorithm(), KeyAlgorithm::Rsa3072);
    assert!(
        signer
            .sign(b"message", SignatureScheme::RsaPkcs1Sha256)
            .is_ok()
    );
}

#[test]
fn signatures_do_not_verify_with_a_different_key() {
    let provider = OpenSslProvider::default();
    let first = FileSigner::from_pem(
        provider
            .generate_key(KeyAlgorithm::EcdsaP256)
            .expect("key")
            .private_key_pem()
            .as_bytes(),
        None,
    )
    .expect("signer");
    let second = provider.generate_key(KeyAlgorithm::EcdsaP256).expect("key");

    let message = b"chainkeeper";
    let signature = first
        .sign(message, SignatureScheme::EcdsaSha256)
        .expect("signature");
    let public =
        openssl::pkey::PKey::public_key_from_der(second.public_key_der()).expect("public key");
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public).expect("verifier");
    verifier.update(message).expect("update");
    assert!(!verifier.verify(&signature).expect("verify"));
}

#[test]
fn file_signer_is_usable_as_a_trait_object() {
    let provider = OpenSslProvider::default();
    let key = provider
        .generate_key(KeyAlgorithm::Ed25519)
        .expect("key generation");
    let signer: Arc<dyn Signer> =
        Arc::new(FileSigner::from_pem(key.private_key_pem().as_bytes(), None).expect("signer"));
    assert_eq!(signer.algorithm(), KeyAlgorithm::Ed25519);
    assert!(signer.sign(b"message", SignatureScheme::Ed25519).is_ok());
}

#[test]
fn self_signed_root_cannot_be_an_intermediate_child() {
    let harness = Harness::new();
    let provider = OpenSslProvider::new(harness.clock.clone(), harness.ids.clone());
    let error = provider
        .create_ocsp_signer(
            &CreateOcspSignerRequest {
                name: AuthorityName::new("ocsp-signer").expect("name"),
                parent: AuthorityName::new("root").expect("name"),
                subject: None,
                algorithm: KeyAlgorithm::EcdsaP256,
                validity_days: 90,
            },
            &harness.root.material,
            &harness.root_signer(),
        )
        .expect_err("root as OCSP parent");
    assert!(error.to_string().contains("intermediate authority"));

    let mut request = common::intermediate_request("tls");
    request.kind = chainkeeper_core::AuthorityKind::Root;
    let error = provider
        .create_intermediate(&request, &harness.root.material, &harness.root_signer())
        .expect_err("root kind as intermediate");
    assert!(error.to_string().contains("kind intermediate"));
}

#[test]
fn csr_cannot_reuse_the_issuer_key() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let issuer_key =
        openssl::pkey::PKey::private_key_from_pem(tls.key.private_key_pem().as_bytes())
            .expect("issuer key");
    let csr = build_csr("reused.example.test", &[], &issuer_key);
    let mut request = IssueRequest::new(
        ProfileName::new("tls-server").expect("profile"),
        SubjectName::new("reused.example.test"),
    );
    request.csr_pem = Some(csr);
    let error = provider
        .issue(&request, &Harness::signer_for(&tls))
        .expect_err("issuer key reuse");
    assert!(error.to_string().contains("issuing authority"));
}

#[test]
fn file_signer_loads_keys_from_a_path() {
    let provider = OpenSslProvider::default();
    let key = provider
        .generate_key(KeyAlgorithm::EcdsaP256)
        .expect("key generation");
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("key.pem");
    std::fs::write(&path, key.private_key_pem()).expect("write key");
    let signer = FileSigner::from_path(&path, None).expect("load");
    assert_eq!(signer.algorithm(), KeyAlgorithm::EcdsaP256);
}
