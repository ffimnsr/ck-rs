//! Shared integration-test helpers.

#![allow(dead_code)]

use std::sync::Arc;

use chainkeeper_core::{
    AuthorityBundle, AuthorityMaterial, AuthorityName, CONFIG_VERSION, CertificateProvider,
    CreateAuthorityRequest, CreateOcspSignerRequest, KeyAlgorithm, ProfileName, SignerBundle,
    SubjectName, TenantConfig,
};
use chainkeeper_crypto::{FileSigner, OpenSslProvider};
use chainkeeper_testkit::{FakeClock, FakeIdGenerator};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509, X509NameBuilder, X509ReqBuilder, X509StoreContext};
use time::OffsetDateTime;
use time::macros::datetime;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer as _;

/// Fixed start time used by every provider test.
pub const NOW: OffsetDateTime = datetime!(2024-01-01 00:00:00 UTC);

/// Test harness owning the provider, clock, and identifier source.
pub struct Harness {
    /// Clock pinned to [`NOW`].
    pub clock: Arc<FakeClock>,
    /// Deterministic serial and ULID source.
    pub ids: Arc<FakeIdGenerator>,
    /// Root authority built by the harness.
    pub root: AuthorityBundle,
}

impl Harness {
    /// Creates a provider and a root authority.
    pub fn new() -> Self {
        let clock = Arc::new(FakeClock::new(NOW));
        let ids = Arc::new(FakeIdGenerator::new());
        let provider = OpenSslProvider::new(clock.clone(), ids.clone());
        let root = provider
            .create_root(&root_request())
            .expect("root creation");
        Self { clock, ids, root }
    }

    /// Creates an intermediate signed by the harness root.
    pub fn intermediate(&self) -> AuthorityBundle {
        let provider = OpenSslProvider::new(self.clock.clone(), self.ids.clone());
        provider
            .create_intermediate(
                &intermediate_request("tls"),
                &self.root.material,
                &self.root_signer(),
            )
            .expect("intermediate creation")
    }

    /// Creates an OCSP signer under the supplied intermediate.
    pub fn ocsp_signer(&self, parent: &AuthorityBundle) -> SignerBundle {
        let provider = OpenSslProvider::new(self.clock.clone(), self.ids.clone());
        provider
            .create_ocsp_signer(
                &CreateOcspSignerRequest {
                    name: AuthorityName::new("ocsp-signer").expect("name"),
                    parent: parent.material.config.name.clone(),
                    subject: None,
                    algorithm: KeyAlgorithm::EcdsaP256,
                    validity_days: 90,
                },
                &parent.material,
                &FileSigner::from_pem(parent.key.private_key_pem().as_bytes(), None)
                    .expect("parent signer"),
            )
            .expect("ocsp signer creation")
    }

    /// Signer for the harness root key.
    pub fn root_signer(&self) -> FileSigner {
        FileSigner::from_pem(self.root.key.private_key_pem().as_bytes(), None).expect("root signer")
    }

    /// Signer for any authority bundle.
    pub fn signer_for(bundle: &AuthorityBundle) -> FileSigner {
        FileSigner::from_pem(bundle.key.private_key_pem().as_bytes(), None).expect("signer")
    }

    /// Provider configured with an issuing authority and tenant.
    pub fn provider_for(&self, issuer: &AuthorityMaterial) -> OpenSslProvider {
        OpenSslProvider::new(self.clock.clone(), self.ids.clone())
            .with_issuer(issuer.clone())
            .with_tenant(tenant())
    }
}

/// Root creation request used by tests.
pub fn root_request() -> CreateAuthorityRequest {
    CreateAuthorityRequest {
        name: AuthorityName::new("root").expect("name"),
        kind: chainkeeper_core::AuthorityKind::Root,
        parent: None,
        subject: SubjectName::new("Chainkeeper Test Root").with_organization("Chainkeeper Test"),
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 7300,
        path_len: 1,
    }
}

/// Intermediate creation request.
pub fn intermediate_request(name: &str) -> CreateAuthorityRequest {
    CreateAuthorityRequest {
        name: AuthorityName::new(name).expect("name"),
        kind: chainkeeper_core::AuthorityKind::Intermediate,
        parent: Some(AuthorityName::new("root").expect("name")),
        subject: SubjectName::new(format!("Chainkeeper Test {name}"))
            .with_organization("Chainkeeper Test"),
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 3650,
        path_len: 0,
    }
}

/// Tenant configuration with AIA and CRL templates.
pub fn tenant() -> TenantConfig {
    TenantConfig {
        version: CONFIG_VERSION,
        tenant_id: chainkeeper_core::TenantId::new("acme").expect("tenant"),
        display_name: "Acme".to_owned(),
        created_at: NOW,
        default_profile: ProfileName::new("tls-server").expect("profile"),
        ocsp_url: Some("http://ocsp.example.test".to_owned()),
        ca_issuers_url_template: Some("https://pki.example.test/{authority}/ca.pem".to_owned()),
        crl_url_template: Some("https://pki.example.test/{authority}/crl.pem".to_owned()),
    }
}

/// Decodes the DER contents of a PEM certificate.
pub fn pem_der(pem_text: &str) -> Vec<u8> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem_text.as_bytes()).expect("pem");
    pem.contents
}

/// Parses DER certificate bytes for extension assertions.
pub fn parsed(der: &[u8]) -> X509Certificate<'_> {
    let (_, certificate) = X509Certificate::from_der(der).expect("certificate");
    certificate
}

/// Returns the parsed extension with the given dotted OID.
pub fn extension<'a>(
    certificate: &'a X509Certificate<'a>,
    oid: &str,
) -> Option<&'a ParsedExtension<'a>> {
    raw_extension(certificate, oid).map(x509_parser::extensions::X509Extension::parsed_extension)
}

/// Returns the raw extension with the given dotted OID.
pub fn raw_extension<'a>(
    certificate: &'a X509Certificate<'a>,
    oid: &str,
) -> Option<&'a x509_parser::extensions::X509Extension<'a>> {
    certificate
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == oid)
}

/// Returns true when the extension with the given OID is marked critical.
pub fn is_critical(certificate: &X509Certificate<'_>, oid: &str) -> bool {
    raw_extension(certificate, oid).is_some_and(|extension| extension.critical)
}

/// Verifies a certificate against a root trust anchor and an untrusted chain.
pub fn verify_chain(leaf_pem: &str, chain_pem: &str, root_pem: &str) {
    let leaf = X509::from_pem(leaf_pem.as_bytes()).expect("leaf");
    let root = X509::from_pem(root_pem.as_bytes()).expect("root");
    let chain = X509::stack_from_pem(chain_pem.as_bytes()).expect("chain");
    let leaf_der = leaf.to_der().expect("leaf der");
    let mut chain_stack = Stack::new().expect("stack");
    for certificate in chain {
        // Bundles may include the leaf itself; the chain stack must not.
        if certificate.to_der().expect("der") == leaf_der {
            continue;
        }
        chain_stack.push(certificate).expect("push");
    }

    let mut builder = X509StoreBuilder::new().expect("store builder");
    builder.add_cert(root).expect("add root");
    // Tests pin the certificate clock, so wall-clock expiry is not meaningful.
    let mut param = X509VerifyParam::new().expect("verify param");
    param
        .set_flags(X509VerifyFlags::NO_CHECK_TIME)
        .expect("no check time");
    builder.set_param(&param).expect("param");
    let store = builder.build();

    let mut context = X509StoreContext::new().expect("context");
    let verified = context
        .init(&store, &leaf, &chain_stack, |context| {
            let verified = context.verify_cert()?;
            assert!(verified, "chain verification failed: {}", context.error());
            Ok(verified)
        })
        .expect("verification");
    assert!(verified, "chain verification failed");
}

/// Generates a fresh P-256 key for CSR tests.
pub fn ec_key() -> PKey<Private> {
    let group =
        openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).expect("group");
    let key = openssl::ec::EcKey::generate(&group).expect("ec key");
    PKey::from_ec_key(key).expect("pkey")
}

/// Builds a PEM CSR with a default SAN extension.
pub fn build_csr(cn: &str, sans: &[&str], key: &PKey<Private>) -> String {
    let mut builder = X509ReqBuilder::new().expect("request builder");
    builder.set_version(0).expect("version");

    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, cn)
        .expect("cn");
    let name = name.build();
    builder.set_subject_name(&name).expect("subject");
    builder.set_pubkey(key).expect("public key");

    if !sans.is_empty() {
        let context = builder.x509v3_context(None);
        let mut san = SubjectAlternativeName::new();
        for value in sans {
            san.dns(value);
        }
        let san = san.build(&context).expect("san");
        let mut stack = Stack::new().expect("stack");
        stack.push(san).expect("push");
        builder.add_extensions(&stack).expect("extensions");
    }

    builder
        .sign(key, MessageDigest::sha256())
        .expect("sign request");
    let request = builder.build();
    String::from_utf8(request.to_pem().expect("pem")).expect("utf8")
}

/// Wraps DER bytes in a PEM block.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        openssl::base64::encode_block(der)
    )
}
