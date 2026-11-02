//! Shared fixtures for store integration tests.

#![allow(dead_code)]

use std::sync::Arc;

use chainkeeper_core::{
    AuthorityName, CertificateRecord, ExtendedKeyUsage, IssuedCertificate, KeyAlgorithm,
    KeyMaterial, KeyUsage, ProfileName, San, Serial, SubjectName,
};
use chainkeeper_store::{FileStore, SqliteIndex};
use chainkeeper_testkit::{CertificateFixtures, FakeClock, TempTenant};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Builder, X509NameBuilder};
use time::{Duration, OffsetDateTime};

/// Fixed test time.
#[must_use]
pub const fn now() -> OffsetDateTime {
    time::macros::datetime!(2024-06-01 00:00:00 UTC)
}

/// Repository fixture with a clock the test controls.
pub struct TestRepo {
    pub tenant: TempTenant,
    pub store: FileStore,
    pub clock: Arc<FakeClock>,
    pub fixtures: CertificateFixtures,
}

impl TestRepo {
    /// Creates an empty repository with generated X.509 fixtures.
    #[must_use]
    pub fn new() -> Self {
        let tenant = TempTenant::new().expect("temp tenant");
        let clock = Arc::new(FakeClock::new(now()));
        let store = FileStore::with_clock(tenant.paths().clone(), clock.clone());
        let fixtures = CertificateFixtures::generate(now()).expect("fixtures");
        Self {
            tenant,
            store,
            clock,
            fixtures,
        }
    }

    /// Opens the repository index.
    #[must_use]
    pub fn index(&self) -> SqliteIndex {
        SqliteIndex::open_with_clock(&self.tenant.paths().index_path(), self.clock.clone())
            .expect("index opens")
    }
}

/// Certificate fields used to build a record or an issued certificate.
pub struct CertSpec {
    pub serial: u32,
    pub cn: String,
    pub profile: String,
    pub authority: String,
    pub days: i64,
    pub sans: Vec<San>,
    pub email: Option<String>,
    pub revoked_at: Option<OffsetDateTime>,
}

impl CertSpec {
    /// Builds a spec with TLS defaults.
    #[must_use]
    pub fn new(serial: u32, cn: &str) -> Self {
        Self {
            serial,
            cn: cn.to_owned(),
            profile: "tls-server".to_owned(),
            authority: "tls".to_owned(),
            days: 397,
            sans: vec![San::Dns(cn.to_owned())],
            email: None,
            revoked_at: None,
        }
    }

    /// Changes the profile.
    #[must_use]
    pub fn profile(mut self, profile: &str) -> Self {
        profile.clone_into(&mut self.profile);
        self
    }

    /// Changes the issuing authority.
    #[must_use]
    pub fn authority(mut self, authority: &str) -> Self {
        authority.clone_into(&mut self.authority);
        self
    }

    /// Changes the validity in days.
    #[must_use]
    pub const fn days(mut self, days: i64) -> Self {
        self.days = days;
        self
    }

    /// Replaces the subject alternative names.
    #[must_use]
    pub fn sans(mut self, sans: Vec<San>) -> Self {
        self.sans = sans;
        self
    }

    /// Sets the subject email.
    #[must_use]
    pub fn email(mut self, email: &str) -> Self {
        self.email = Some(email.to_owned());
        self
    }

    /// Marks the record as revoked.
    #[must_use]
    pub const fn revoked_at(mut self, time: OffsetDateTime) -> Self {
        self.revoked_at = Some(time);
        self
    }

    /// Serial rendered as uppercase hexadecimal.
    #[must_use]
    pub fn serial(&self) -> Serial {
        Serial::new(format!("{:04X}", self.serial)).expect("valid serial")
    }
}

/// Builds metadata without generating a certificate.
#[must_use]
pub fn record(spec: &CertSpec) -> CertificateRecord {
    let mut subject = SubjectName::new(spec.cn.clone());
    subject.email.clone_from(&spec.email);
    CertificateRecord {
        serial: spec.serial(),
        subject,
        issuer: format!("CN=Chainkeeper Test {}", spec.authority),
        profile: ProfileName::new(spec.profile.clone()).expect("valid profile"),
        authority: AuthorityName::new(spec.authority.clone()).expect("valid authority"),
        algorithm: KeyAlgorithm::EcdsaP256,
        sans: spec.sans.clone(),
        ekus: vec![ExtendedKeyUsage::ServerAuth],
        key_usages: vec![KeyUsage::DigitalSignature],
        issued_at: now() - Duration::days(30),
        expires_at: now() + Duration::days(spec.days),
        path: format!("certificates/active/{}.pem", spec.serial()).into(),
        revoked_at: spec.revoked_at,
        revocation_reason: spec
            .revoked_at
            .map(|_| chainkeeper_core::RevocationReason::KeyCompromise),
        replaces: None,
    }
}

/// Builds an issued certificate with a matching serial and key pair.
#[must_use]
pub fn issued(spec: &CertSpec) -> IssuedCertificate {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("curve");
    let key = EcKey::generate(&group).expect("key");
    let key = PKey::from_ec_key(key).expect("pkey");

    let mut builder = X509Builder::new().expect("builder");
    builder.set_version(2).expect("version");
    let serial_number = BigNum::from_u32(spec.serial)
        .expect("serial")
        .to_asn1_integer()
        .expect("integer");
    builder.set_serial_number(&serial_number).expect("serial");
    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_nid(Nid::COMMONNAME, &spec.cn)
        .expect("cn");
    let name = name.build();
    builder.set_subject_name(&name).expect("subject");
    builder.set_issuer_name(&name).expect("issuer");
    let not_before = Asn1Time::from_unix(now().unix_timestamp()).expect("not before");
    let not_after = Asn1Time::from_unix((now() + Duration::days(spec.days)).unix_timestamp())
        .expect("not after");
    builder.set_not_before(&not_before).expect("not before");
    builder.set_not_after(&not_after).expect("not after");
    builder.set_pubkey(&key).expect("pubkey");
    builder.sign(&key, MessageDigest::sha256()).expect("sign");
    let certificate = builder.build();

    let cert_pem = String::from_utf8(certificate.to_pem().expect("pem")).expect("utf8");
    let private_pem =
        String::from_utf8(key.private_key_to_pem_pkcs8().expect("key pem")).expect("utf8");
    let public_der = key.public_key_to_der().expect("public der");
    let material = KeyMaterial::new(KeyAlgorithm::EcdsaP256, private_pem, public_der);
    IssuedCertificate::new(record(spec), cert_pem, String::new(), Some(material))
}

/// Reads every file below `root` recursively.
#[must_use]
pub fn files_below(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}
