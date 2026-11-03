//! Real X.509 fixtures generated with the `openssl` crate at test time.
//!
//! Fixtures are created inside a temporary test context and never read files
//! from outside the caller's temp directory.

use chainkeeper_core::{
    AuthorityBundle, AuthorityConfig, AuthorityKind, AuthorityMaterial, AuthorityName,
    CertificateRecord, ChainkeeperError, ExtendedKeyUsage, IssuedCertificate, KeyAlgorithm,
    KeyMaterial, KeyUsage, ProfileName, San, Serial, SignerBundle, SubjectName,
};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage as OpensslEku, KeyUsage as OpensslKeyUsage,
    SubjectAlternativeName,
};
use openssl::x509::{X509, X509Builder, X509Name, X509NameBuilder};
use time::{Duration, OffsetDateTime};

const ORGANIZATION: &str = "Chainkeeper Test";

type KeyPair = (X509, PKey<Private>);

/// Valid root, intermediate, OCSP signer, and leaf fixtures.
#[derive(Debug, Clone)]
pub struct CertificateFixtures {
    /// Self-signed root authority.
    pub root: AuthorityBundle,
    /// TLS intermediate signed by the root.
    pub tls: AuthorityBundle,
    /// S/MIME intermediate signed by the root.
    pub smime: AuthorityBundle,
    /// OCSP signer issued by the TLS intermediate.
    pub ocsp_signer: SignerBundle,
    /// Leaf certificate issued by the TLS intermediate.
    pub leaf: IssuedCertificate,
}

#[derive(Debug, Clone, Copy)]
struct FixtureDates {
    not_before: i64,
    root_not_after: i64,
    intermediate_not_after: i64,
    leaf_not_after: i64,
    ocsp_not_after: i64,
}

impl FixtureDates {
    fn new(now: OffsetDateTime) -> Self {
        Self {
            not_before: now.unix_timestamp(),
            root_not_after: (now + Duration::days(7300)).unix_timestamp(),
            intermediate_not_after: (now + Duration::days(3650)).unix_timestamp(),
            leaf_not_after: (now + Duration::days(397)).unix_timestamp(),
            ocsp_not_after: (now + Duration::days(90)).unix_timestamp(),
        }
    }
}

#[derive(Debug, Clone)]
struct Intermediate {
    bundle: AuthorityBundle,
    pair: KeyPair,
    chain_pem: String,
}

fn crypto<E: std::fmt::Display>(error: E) -> ChainkeeperError {
    ChainkeeperError::crypto(error.to_string())
}

fn generate_ec_key() -> Result<PKey<Private>, ChainkeeperError> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(crypto)?;
    let key = EcKey::generate(&group).map_err(crypto)?;
    PKey::from_ec_key(key).map_err(crypto)
}

fn x509_name(cn: &str) -> Result<X509Name, ChainkeeperError> {
    let mut builder = X509NameBuilder::new().map_err(crypto)?;
    builder
        .append_entry_by_nid(Nid::COMMONNAME, cn)
        .map_err(crypto)?;
    builder
        .append_entry_by_nid(Nid::ORGANIZATIONNAME, ORGANIZATION)
        .map_err(crypto)?;
    Ok(builder.build())
}

fn asn1_time(unix_seconds: i64) -> Result<Asn1Time, ChainkeeperError> {
    Asn1Time::from_unix(unix_seconds).map_err(crypto)
}

fn set_serial(builder: &mut X509Builder, serial: u32) -> Result<(), ChainkeeperError> {
    let number = BigNum::from_u32(serial).map_err(crypto)?;
    let integer = number.to_asn1_integer().map_err(crypto)?;
    builder.set_serial_number(&integer).map_err(crypto)
}

fn set_validity(
    builder: &mut X509Builder,
    not_before: i64,
    not_after: i64,
) -> Result<(), ChainkeeperError> {
    let before = asn1_time(not_before)?;
    builder.set_not_before(&before).map_err(crypto)?;
    let after = asn1_time(not_after)?;
    builder.set_not_after(&after).map_err(crypto)
}

fn build_ca(
    cn: &str,
    serial: u32,
    key: &PKey<Private>,
    issuer: Option<&KeyPair>,
    path_len: u32,
    dates: (i64, i64),
) -> Result<X509, ChainkeeperError> {
    let mut builder = X509Builder::new().map_err(crypto)?;
    builder.set_version(2).map_err(crypto)?;
    set_serial(&mut builder, serial)?;
    let subject = x509_name(cn)?;
    builder.set_subject_name(&subject).map_err(crypto)?;
    let issuer_name = match issuer {
        Some((certificate, _)) => certificate.subject_name().to_owned().map_err(crypto)?,
        None => x509_name(cn)?,
    };
    builder.set_issuer_name(&issuer_name).map_err(crypto)?;
    set_validity(&mut builder, dates.0, dates.1)?;
    builder.set_pubkey(key).map_err(crypto)?;

    let constraints = BasicConstraints::new()
        .critical()
        .ca()
        .pathlen(path_len)
        .build()
        .map_err(crypto)?;
    builder.append_extension(constraints).map_err(crypto)?;
    let usage = OpensslKeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .map_err(crypto)?;
    builder.append_extension(usage).map_err(crypto)?;

    let signing_key = issuer.map_or(key, |(_, issuer_key)| issuer_key);
    builder
        .sign(signing_key, MessageDigest::sha256())
        .map_err(crypto)?;
    Ok(builder.build())
}

fn build_leaf(
    cn: &str,
    serial: u32,
    key: &PKey<Private>,
    issuer: &KeyPair,
    sans: &[&str],
    eku: &OpensslEku,
    dates: (i64, i64),
) -> Result<X509, ChainkeeperError> {
    let mut builder = X509Builder::new().map_err(crypto)?;
    builder.set_version(2).map_err(crypto)?;
    set_serial(&mut builder, serial)?;
    let subject = x509_name(cn)?;
    builder.set_subject_name(&subject).map_err(crypto)?;
    builder
        .set_issuer_name(issuer.0.subject_name())
        .map_err(crypto)?;
    set_validity(&mut builder, dates.0, dates.1)?;
    builder.set_pubkey(key).map_err(crypto)?;

    builder
        .append_extension(BasicConstraints::new().critical().build().map_err(crypto)?)
        .map_err(crypto)?;
    builder
        .append_extension(
            OpensslKeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .map_err(crypto)?,
        )
        .map_err(crypto)?;
    builder
        .append_extension(eku.build().map_err(crypto)?)
        .map_err(crypto)?;

    let mut san_builder = SubjectAlternativeName::new();
    for name in sans {
        san_builder.dns(name);
    }
    let san = san_builder
        .build(&builder.x509v3_context(Some(&issuer.0), None))
        .map_err(crypto)?;
    builder.append_extension(san).map_err(crypto)?;

    builder
        .sign(&issuer.1, MessageDigest::sha256())
        .map_err(crypto)?;
    Ok(builder.build())
}

fn cert_pem(certificate: &X509) -> Result<String, ChainkeeperError> {
    String::from_utf8(certificate.to_pem().map_err(crypto)?).map_err(crypto)
}

fn key_material(key: &PKey<Private>) -> Result<KeyMaterial, ChainkeeperError> {
    let private_pem =
        String::from_utf8(key.private_key_to_pem_pkcs8().map_err(crypto)?).map_err(crypto)?;
    Ok(KeyMaterial::new(
        KeyAlgorithm::EcdsaP256,
        private_pem,
        key.public_key_to_der().map_err(crypto)?,
    ))
}

fn serial(value: u32) -> Result<Serial, ChainkeeperError> {
    Serial::new(format!("{value:04X}"))
}

fn name(value: &str) -> Result<AuthorityName, ChainkeeperError> {
    AuthorityName::new(value)
}

fn authority_config(
    name: &str,
    kind: AuthorityKind,
    parent: Option<&str>,
    validity_days: u32,
    path_len: u32,
    now: OffsetDateTime,
) -> Result<AuthorityConfig, ChainkeeperError> {
    Ok(AuthorityConfig::new(
        AuthorityName::new(name)?,
        kind,
        parent.map(AuthorityName::new).transpose()?,
        KeyAlgorithm::EcdsaP256,
        validity_days,
        path_len,
        vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign],
        now,
    ))
}

fn build_intermediate(
    cn: &str,
    authority: &str,
    serial_number: u32,
    parent: &KeyPair,
    root_pem: &str,
    dates: &FixtureDates,
    now: OffsetDateTime,
) -> Result<Intermediate, ChainkeeperError> {
    let key = generate_ec_key()?;
    let certificate = build_ca(
        cn,
        serial_number,
        &key,
        Some(parent),
        1,
        (dates.not_before, dates.intermediate_not_after),
    )?;
    let pem = cert_pem(&certificate)?;
    let chain_pem = format!("{pem}{root_pem}");
    let config = authority_config(
        authority,
        AuthorityKind::Intermediate,
        Some("root"),
        3650,
        1,
        now,
    )?;
    Ok(Intermediate {
        bundle: AuthorityBundle::new(
            AuthorityMaterial::new(config, pem, chain_pem.clone()),
            key_material(&key)?,
        ),
        pair: (certificate, key),
        chain_pem,
    })
}

fn build_ocsp_signer(
    intermediate: &Intermediate,
    dates: &FixtureDates,
    now: OffsetDateTime,
) -> Result<SignerBundle, ChainkeeperError> {
    let key = generate_ec_key()?;
    let mut eku = OpensslEku::new();
    eku.other("1.3.6.1.5.5.7.3.9");
    let certificate = build_leaf(
        "Chainkeeper Test OCSP",
        4,
        &key,
        &intermediate.pair,
        &[],
        &eku,
        (dates.not_before, dates.ocsp_not_after),
    )?;
    Ok(SignerBundle {
        config: authority_config(
            "ocsp-signer",
            AuthorityKind::OcspSigner,
            Some("tls"),
            90,
            0,
            now,
        )?,
        cert_pem: cert_pem(&certificate)?,
        chain_pem: intermediate.chain_pem.clone(),
        key: key_material(&key)?,
    })
}

fn build_leaf_fixture(
    intermediate: &Intermediate,
    dates: &FixtureDates,
    now: OffsetDateTime,
) -> Result<IssuedCertificate, ChainkeeperError> {
    let key = generate_ec_key()?;
    let mut eku = OpensslEku::new();
    eku.server_auth();
    let certificate = build_leaf(
        "leaf.example.test",
        10,
        &key,
        &intermediate.pair,
        &["leaf.example.test"],
        &eku,
        (dates.not_before, dates.leaf_not_after),
    )?;
    let record = CertificateRecord {
        serial: serial(10)?,
        subject: SubjectName::new("leaf.example.test"),
        issuer: "CN=Chainkeeper Test TLS, O=Chainkeeper Test".to_owned(),
        profile: ProfileName::new("tls-server")?,
        authority: name("tls")?,
        algorithm: KeyAlgorithm::EcdsaP256,
        sans: vec![San::Dns("leaf.example.test".to_owned())],
        ekus: vec![ExtendedKeyUsage::ServerAuth],
        key_usages: vec![KeyUsage::DigitalSignature],
        issued_at: now,
        expires_at: now + Duration::days(397),
        path: "certificates/active/000A.pem".into(),
        revoked_at: None,
        revocation_reason: None,
        replaces: None,
    };
    Ok(IssuedCertificate::new(
        record,
        cert_pem(&certificate)?,
        intermediate.chain_pem.clone(),
        Some(key_material(&key)?),
    ))
}

impl CertificateFixtures {
    /// Generates the fixture hierarchy.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when OpenSSL cannot generate a key
    /// or certificate.
    pub fn generate(now: OffsetDateTime) -> Result<Self, ChainkeeperError> {
        let dates = FixtureDates::new(now);
        let root_key = generate_ec_key()?;
        let root_certificate = build_ca(
            "Chainkeeper Test Root",
            1,
            &root_key,
            None,
            2,
            (dates.not_before, dates.root_not_after),
        )?;
        let root_pem = cert_pem(&root_certificate)?;
        let root_pair: KeyPair = (root_certificate, root_key);

        let tls = build_intermediate(
            "Chainkeeper Test TLS",
            "tls",
            2,
            &root_pair,
            &root_pem,
            &dates,
            now,
        )?;
        let smime = build_intermediate(
            "Chainkeeper Test SMIME",
            "smime",
            3,
            &root_pair,
            &root_pem,
            &dates,
            now,
        )?;
        let ocsp_signer = build_ocsp_signer(&tls, &dates, now)?;
        let leaf = build_leaf_fixture(&tls, &dates, now)?;

        let root = AuthorityBundle::new(
            AuthorityMaterial::new(
                authority_config("root", AuthorityKind::Root, None, 7300, 2, now)?,
                root_pem.clone(),
                root_pem,
            ),
            key_material(&root_pair.1)?,
        );

        Ok(Self {
            root,
            tls: tls.bundle,
            smime: smime.bundle,
            ocsp_signer,
            leaf,
        })
    }
}
