//! Leaf issuance tests, including CSR handling.

mod common;

use chainkeeper_core::{
    CertificateProvider, CustomExtension, ExtendedKeyUsage, IssueRequest, KeyAlgorithm, KeyUsage,
    ProfileName, San, SubjectName,
};
use chainkeeper_crypto::OpenSslProvider;
use common::{
    Harness, NOW, build_csr, ec_key, extension, is_critical, parsed, pem_der, pem_encode,
    verify_chain,
};
use openssl::x509::X509;
use time::Duration;
use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};

const BASIC_CONSTRAINTS: &str = "2.5.29.19";
const KEY_USAGE: &str = "2.5.29.15";
const EKU: &str = "2.5.29.37";
const AIA: &str = "1.3.6.1.5.5.7.1.1";
const CRL_DP: &str = "2.5.29.31";

fn tls_request() -> IssueRequest {
    let mut request = IssueRequest::new(
        ProfileName::new("tls-server").expect("profile"),
        SubjectName::new("leaf.example.test"),
    );
    request.sans = vec![
        San::Dns("leaf.example.test".to_owned()),
        San::Ip("192.0.2.10".to_owned()),
    ];
    request
}

#[test]
fn issued_leaf_verifies_and_carries_profile_extensions() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let issued = provider
        .issue(&tls_request(), &Harness::signer_for(&tls))
        .expect("issuance");

    verify_chain(
        &issued.cert_pem,
        &issued.chain_pem,
        &harness.root.material.cert_pem,
    );

    let issued_der = pem_der(&issued.cert_pem);
    let certificate = parsed(&issued_der);
    let leaf = X509::from_pem(issued.cert_pem.as_bytes()).expect("leaf");
    let issuing_certificate = X509::from_pem(tls.material.cert_pem.as_bytes()).expect("issuer");
    assert_eq!(
        leaf.issuer_name()
            .try_cmp(issuing_certificate.subject_name())
            .expect("compare"),
        std::cmp::Ordering::Equal
    );

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
    assert!(usage.key_encipherment());
    assert!(!usage.key_cert_sign());

    let Some(ParsedExtension::ExtendedKeyUsage(eku)) = extension(&certificate, EKU) else {
        panic!("missing EKU");
    };
    assert!(eku.server_auth);
    assert!(!eku.client_auth);

    let san = certificate
        .subject_alternative_name()
        .expect("san")
        .expect("san present");
    let names: Vec<_> = san.value.general_names.iter().collect();
    assert_eq!(names.len(), 2);
    assert!(
        names
            .iter()
            .any(|name| matches!(name, GeneralName::DNSName("leaf.example.test")))
    );
    assert!(names.iter().any(|name| match name {
        GeneralName::IPAddress(bytes) => *bytes == [192, 0, 2, 10],
        _ => false,
    }));

    let Some(ParsedExtension::AuthorityInfoAccess(aia)) = extension(&certificate, AIA) else {
        panic!("missing AIA");
    };
    assert_eq!(aia.accessdescs.len(), 1);
    assert!(matches!(
        aia.accessdescs[0].access_location,
        GeneralName::URI("https://pki.example.test/tls/ca.pem")
    ));

    let Some(ParsedExtension::CRLDistributionPoints(points)) = extension(&certificate, CRL_DP)
    else {
        panic!("missing CRL distribution points");
    };
    assert_eq!(points.points.len(), 1);
    let Some(DistributionPointName::FullName(names)) = &points.points[0].distribution_point else {
        panic!("missing full name");
    };
    assert!(matches!(
        names[0],
        GeneralName::URI("https://pki.example.test/tls/crl.pem")
    ));

    assert_eq!(issued.record.issued_at, NOW);
    assert_eq!(issued.record.expires_at, NOW + Duration::days(397));
    assert_eq!(issued.record.algorithm, KeyAlgorithm::EcdsaP256);
    assert_eq!(
        issued.record.key_usages,
        vec![KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment]
    );
    assert_eq!(issued.record.ekus, vec![ExtendedKeyUsage::ServerAuth]);
    assert!(issued.key.is_some());
    assert_eq!(
        issued.record.path,
        std::path::PathBuf::from(format!("certificates/active/{}.pem", issued.record.serial))
    );
}

#[test]
fn custom_extensions_round_trip_with_criticality() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let mut request = tls_request();
    request.custom_extensions = vec![CustomExtension {
        oid: "1.2.3.4.5".to_owned(),
        critical: true,
        value_utf8: Some("chainkeeper".to_owned()),
        value_hex: None,
    }];
    let issued = provider
        .issue(&request, &Harness::signer_for(&tls))
        .expect("issuance");

    let issued_der = pem_der(&issued.cert_pem);
    let certificate = parsed(&issued_der);
    let extension = common::raw_extension(&certificate, "1.2.3.4.5").expect("custom extension");
    assert!(extension.critical);
    assert_eq!(extension.value, b"\x0C\x0Bchainkeeper");
}

#[test]
fn supplied_csr_issues_without_generating_a_key() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let key = ec_key();
    let csr = build_csr("csr.example.test", &["csr.example.test"], &key);
    let mut request = IssueRequest::new(
        ProfileName::new("tls-server").expect("profile"),
        SubjectName::new("csr.example.test"),
    );
    request.csr_pem = Some(csr);
    let issued = provider
        .issue(&request, &Harness::signer_for(&tls))
        .expect("issuance");
    assert!(issued.key.is_none());
    assert_eq!(
        issued.record.sans,
        vec![San::Dns("csr.example.test".to_owned())]
    );
    assert_eq!(issued.record.algorithm, KeyAlgorithm::EcdsaP256);
    verify_chain(
        &issued.cert_pem,
        &issued.chain_pem,
        &harness.root.material.cert_pem,
    );
}

#[test]
fn invalid_csr_signature_is_rejected() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let key = ec_key();
    let csr = build_csr("csr.example.test", &[], &key);
    let request = X509ReqFixture::tamper(&csr);
    let mut issue = IssueRequest::new(
        ProfileName::new("tls-server").expect("profile"),
        SubjectName::new("csr.example.test"),
    );
    issue.csr_pem = Some(request);
    let error = provider
        .issue(&issue, &Harness::signer_for(&tls))
        .expect_err("invalid CSR");
    assert!(error.to_string().contains("CSR signature is invalid"));
}

#[test]
fn csr_public_key_already_in_issuer_chain_is_rejected() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let key = openssl::pkey::PKey::private_key_from_pem(tls.key.private_key_pem().as_bytes())
        .expect("issuer key");
    let csr = build_csr("reused.example.test", &[], &key);
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
fn conflicting_csr_subject_and_sans_are_rejected() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    let provider = harness.provider_for(&tls.material);
    let key = ec_key();
    let csr = build_csr("csr.example.test", &["csr.example.test"], &key);

    let mut conflicting_subject = IssueRequest::new(
        ProfileName::new("tls-server").expect("profile"),
        SubjectName::new("other.example.test"),
    );
    conflicting_subject.csr_pem = Some(csr.clone());
    let error = provider
        .issue(&conflicting_subject, &Harness::signer_for(&tls))
        .expect_err("subject conflict");
    assert!(error.to_string().contains("subject conflicts"));

    let mut conflicting_sans = IssueRequest::new(
        ProfileName::new("tls-server").expect("profile"),
        SubjectName::new("csr.example.test"),
    );
    conflicting_sans.sans = vec![San::Dns("other.example.test".to_owned())];
    conflicting_sans.csr_pem = Some(csr);
    let error = provider
        .issue(&conflicting_sans, &Harness::signer_for(&tls))
        .expect_err("SAN conflict");
    assert!(error.to_string().contains("SANs conflict"));
}

#[test]
fn generated_keys_cover_every_algorithm() {
    let harness = Harness::new();
    let tls = harness.intermediate();
    for algorithm in KeyAlgorithm::ALL {
        let provider: OpenSslProvider = harness.provider_for(&tls.material);
        let mut request = tls_request();
        request.algorithm = Some(algorithm);
        let issued = provider
            .issue(&request, &Harness::signer_for(&tls))
            .expect("issuance");
        assert_eq!(issued.record.algorithm, algorithm);
        let key = issued.key.expect("generated key");
        assert_eq!(key.algorithm(), algorithm);
        let parsed_key =
            openssl::pkey::PKey::private_key_from_pem(key.private_key_pem().as_bytes())
                .expect("private key");
        assert_eq!(
            parsed_key.id(),
            match algorithm {
                KeyAlgorithm::Rsa3072 => openssl::pkey::Id::RSA,
                KeyAlgorithm::EcdsaP256 => openssl::pkey::Id::EC,
                KeyAlgorithm::Ed25519 => openssl::pkey::Id::ED25519,
                _ => unreachable!(),
            }
        );
        verify_chain(
            &issued.cert_pem,
            &issued.chain_pem,
            &harness.root.material.cert_pem,
        );
    }
}

struct X509ReqFixture;

impl X509ReqFixture {
    fn tamper(pem_text: &str) -> String {
        let request = openssl::x509::X509Req::from_pem(pem_text.as_bytes()).expect("request");
        let mut der = request.to_der().expect("der");
        let last = der.len() - 1;
        der[last] ^= 0xFF;
        pem_encode("CERTIFICATE REQUEST", &der)
    }
}
