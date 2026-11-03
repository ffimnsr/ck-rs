//! Root, intermediate, and OCSP signer tests.

mod common;

use chainkeeper_core::{CertificateProvider, KeyAlgorithm, Signer};
use chainkeeper_crypto::FileSigner;
use common::{Harness, NOW, extension, is_critical, parsed, pem_der, verify_chain};
use openssl::pkey::PKey;
use time::Duration;
use x509_parser::extensions::ParsedExtension;

const BASIC_CONSTRAINTS: &str = "2.5.29.19";
const KEY_USAGE: &str = "2.5.29.15";
const EKU: &str = "2.5.29.37";
const SKI: &str = "2.5.29.14";
const AKI: &str = "2.5.29.35";

#[test]
fn root_is_self_signed_with_ca_constraints() {
    let harness = Harness::new();
    let root_der = pem_der(&harness.root.material.cert_pem);
    let certificate = parsed(&root_der);
    let key = PKey::private_key_from_pem(harness.root.key.private_key_pem().as_bytes())
        .expect("private key");
    assert!(
        openssl::x509::X509::from_pem(harness.root.material.cert_pem.as_bytes())
            .expect("certificate")
            .verify(&key)
            .expect("verify"),
        "root must be self-signed"
    );

    assert_eq!(certificate.subject(), certificate.issuer());
    assert_eq!(
        certificate
            .subject()
            .iter_common_name()
            .next()
            .expect("cn")
            .as_str()
            .expect("str"),
        "Chainkeeper Test Root"
    );

    let Some(ParsedExtension::BasicConstraints(constraints)) =
        extension(&certificate, BASIC_CONSTRAINTS)
    else {
        panic!("missing basic constraints");
    };
    assert!(constraints.ca);
    assert_eq!(constraints.path_len_constraint, Some(1));
    assert!(is_critical(&certificate, BASIC_CONSTRAINTS));

    let Some(ParsedExtension::KeyUsage(usage)) = extension(&certificate, KEY_USAGE) else {
        panic!("missing key usage");
    };
    assert!(usage.key_cert_sign());
    assert!(usage.crl_sign());
    assert!(!usage.digital_signature());
    assert!(!usage.key_encipherment());
    assert!(is_critical(&certificate, KEY_USAGE));
}

#[test]
fn root_has_matching_key_identifiers() {
    let harness = Harness::new();
    let root_der = pem_der(&harness.root.material.cert_pem);
    let certificate = parsed(&root_der);
    let Some(ParsedExtension::SubjectKeyIdentifier(subject)) = extension(&certificate, SKI) else {
        panic!("missing SKI");
    };
    let Some(ParsedExtension::AuthorityKeyIdentifier(authority)) = extension(&certificate, AKI)
    else {
        panic!("missing AKI");
    };
    let authority = authority.key_identifier.as_ref().expect("AKI key id");
    assert_eq!(subject.0, authority.0);
}

#[test]
fn root_validity_matches_request_and_clock() {
    let harness = Harness::new();
    let root_der = pem_der(&harness.root.material.cert_pem);
    let certificate = parsed(&root_der);
    assert_eq!(
        certificate.validity().not_before.timestamp(),
        NOW.unix_timestamp()
    );
    assert_eq!(
        certificate.validity().not_after.timestamp(),
        (NOW + Duration::days(7300)).unix_timestamp()
    );
    assert_eq!(
        harness.root.material.chain_pem,
        harness.root.material.cert_pem
    );
}

#[test]
fn root_chain_verifies_against_itself() {
    let harness = Harness::new();
    verify_chain(
        &harness.root.material.cert_pem,
        "",
        &harness.root.material.cert_pem,
    );
}

#[test]
fn intermediate_verifies_to_root_and_is_not_self_signed() {
    let harness = Harness::new();
    let intermediate = harness.intermediate();
    verify_chain(
        &intermediate.material.cert_pem,
        "",
        &harness.root.material.cert_pem,
    );

    let intermediate_der = pem_der(&intermediate.material.cert_pem);
    let certificate = parsed(&intermediate_der);
    let key = PKey::private_key_from_pem(intermediate.key.private_key_pem().as_bytes())
        .expect("private key");
    assert!(
        !openssl::x509::X509::from_pem(intermediate.material.cert_pem.as_bytes())
            .expect("certificate")
            .verify(&key)
            .expect("verify"),
        "intermediate must not be self-signed"
    );
    assert_ne!(certificate.subject(), certificate.issuer());
}

#[test]
fn intermediate_has_zero_path_length_and_parent_aki() {
    let harness = Harness::new();
    let intermediate = harness.intermediate();
    let intermediate_der = pem_der(&intermediate.material.cert_pem);
    let certificate = parsed(&intermediate_der);
    let Some(ParsedExtension::BasicConstraints(constraints)) =
        extension(&certificate, BASIC_CONSTRAINTS)
    else {
        panic!("missing basic constraints");
    };
    assert!(constraints.ca);
    assert_eq!(constraints.path_len_constraint, Some(0));
    assert!(is_critical(&certificate, BASIC_CONSTRAINTS));

    let root_der = pem_der(&harness.root.material.cert_pem);
    let root = parsed(&root_der);
    let Some(ParsedExtension::SubjectKeyIdentifier(root_ski)) = extension(&root, SKI) else {
        panic!("missing root SKI");
    };
    let Some(ParsedExtension::AuthorityKeyIdentifier(aki)) = extension(&certificate, AKI) else {
        panic!("missing intermediate AKI");
    };
    assert_eq!(aki.key_identifier.as_ref().expect("key id").0, root_ski.0);
}

#[test]
fn intermediate_validity_does_not_exceed_parent() {
    let harness = Harness::new();
    let intermediate = harness.intermediate();
    let intermediate_der = pem_der(&intermediate.material.cert_pem);
    let certificate = parsed(&intermediate_der);
    let root_der = pem_der(&harness.root.material.cert_pem);
    let root = parsed(&root_der);
    assert_eq!(
        certificate.validity().not_after.timestamp(),
        (NOW + Duration::days(3650)).unix_timestamp()
    );
    assert!(certificate.validity().not_after.timestamp() <= root.validity().not_after.timestamp());
}

#[test]
fn intermediate_chain_contains_intermediate_then_root() {
    let harness = Harness::new();
    let intermediate = harness.intermediate();
    let certificates =
        openssl::x509::X509::stack_from_pem(intermediate.material.chain_pem.as_bytes())
            .expect("chain");
    assert_eq!(certificates.len(), 2);
    assert_eq!(
        certificates[0]
            .subject_name()
            .entries()
            .next()
            .and_then(|entry| entry.data().to_string().ok()),
        Some("Chainkeeper Test tls".to_owned())
    );
}

#[test]
fn ocsp_signer_has_dedicated_extensions_and_chain() {
    let harness = Harness::new();
    let intermediate = harness.intermediate();
    let signer = harness.ocsp_signer(&intermediate);
    verify_chain(
        &signer.cert_pem,
        &signer.chain_pem,
        &harness.root.material.cert_pem,
    );

    let signer_der = pem_der(&signer.cert_pem);
    let certificate = parsed(&signer_der);
    let Some(ParsedExtension::BasicConstraints(constraints)) =
        extension(&certificate, BASIC_CONSTRAINTS)
    else {
        panic!("missing basic constraints");
    };
    assert!(!constraints.ca);
    assert!(is_critical(&certificate, BASIC_CONSTRAINTS));

    let Some(ParsedExtension::KeyUsage(usage)) = extension(&certificate, KEY_USAGE) else {
        panic!("missing key usage");
    };
    assert!(usage.digital_signature());
    assert!(!usage.key_cert_sign());
    assert!(!usage.crl_sign());

    let Some(ParsedExtension::ExtendedKeyUsage(eku)) = extension(&certificate, EKU) else {
        panic!("missing EKU");
    };
    assert!(eku.ocsp_signing);
    assert!(!eku.server_auth);
    assert!(!eku.client_auth);
    assert!(!eku.code_signing);
    assert!(!eku.email_protection);
    assert!(!eku.time_stamping);

    assert_eq!(
        certificate.validity().not_after.timestamp(),
        (NOW + Duration::days(90)).unix_timestamp()
    );
    assert_eq!(
        openssl::x509::X509::stack_from_pem(signer.chain_pem.as_bytes())
            .expect("chain")
            .len(),
        3
    );
    assert_eq!(signer.config.algorithm, KeyAlgorithm::EcdsaP256);
    let loaded =
        FileSigner::from_pem(signer.key.private_key_pem().as_bytes(), None).expect("signer key");
    assert_eq!(loaded.algorithm(), KeyAlgorithm::EcdsaP256);
}

#[test]
fn roots_support_every_algorithm() {
    for algorithm in KeyAlgorithm::ALL {
        let clock = std::sync::Arc::new(chainkeeper_testkit::FakeClock::new(NOW));
        let ids = std::sync::Arc::new(chainkeeper_testkit::FakeIdGenerator::new());
        let provider = chainkeeper_crypto::OpenSslProvider::new(clock, ids);
        let mut request = common::root_request();
        request.algorithm = algorithm;
        let root = provider.create_root(&request).expect("root creation");
        assert_eq!(root.material.config.algorithm, algorithm);
        verify_chain(&root.material.cert_pem, "", &root.material.cert_pem);
    }
}
