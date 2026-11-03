#![allow(dead_code)]

//! Shared OCSP test harness.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chainkeeper_core::{
    AuthorityBundle, AuthorityConfig, AuthorityKind, AuthorityMaterial, AuthorityName,
    CertificateProvider as _, CertificateRecord, CertificateStore as _, ChainkeeperError, Clock,
    IdGenerator, KeyAlgorithm, ProfileName, SignatureScheme, Signer, SignerBundle, TenantConfig,
    TenantId,
};
use chainkeeper_crypto::FileSigner;
pub use chainkeeper_ocsp::HashAlgorithm;
use chainkeeper_ocsp::{AuthoritySigners, FileOcspResponder, OcspDependencies};
use chainkeeper_store::FileStore;
use chainkeeper_testkit::{
    CertificateFixtures, FakeCertificateProvider, FakeClock, FakeIdGenerator, TempTenant,
};
use openssl::hash::{MessageDigest, hash};
use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_ocsp::{CertId, OcspRequest, Request, TbsRequest};
use rasn_pkix::AlgorithmIdentifier;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};

/// Fixed test time shared by every double.
pub const NOW: OffsetDateTime = datetime!(2024-06-01 00:00:00 UTC);

/// Signer resolver backed by one exported key.
pub struct FixtureSigners {
    key: Vec<u8>,
    fail: AtomicBool,
}

impl FixtureSigners {
    /// Creates a resolver for `key`.
    #[must_use]
    pub fn new(key: &str) -> Self {
        Self {
            key: key.as_bytes().to_vec(),
            fail: AtomicBool::new(false),
        }
    }

    /// Makes later resolutions fail.
    pub fn fail(&self) {
        self.fail.store(true, Ordering::SeqCst);
    }
}

impl std::fmt::Debug for FixtureSigners {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixtureSigners")
            .field("key_bytes", &self.key.len())
            .field("fail", &self.fail.load(Ordering::SeqCst))
            .finish()
    }
}

impl AuthoritySigners for FixtureSigners {
    fn signer_for(&self, _authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ChainkeeperError::crypto("signer key is unavailable"));
        }
        let signer = FileSigner::from_pem(&self.key, None)?;
        Ok(Arc::new(signer))
    }
}

/// Resolver that returns a signer whose signature operation always fails.
#[derive(Debug, Clone)]
pub struct FailingSigners {
    public_key: Vec<u8>,
}

impl FailingSigners {
    /// Creates a resolver advertising `public_key`.
    #[must_use]
    pub const fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }
}

impl AuthoritySigners for FailingSigners {
    fn signer_for(&self, _authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        Ok(Arc::new(FailingSigner::new(self.public_key.clone())))
    }
}

/// Resolver that always fails to produce a signer.
#[derive(Debug, Clone, Copy, Default)]
pub struct MissingSigners;

impl AuthoritySigners for MissingSigners {
    fn signer_for(&self, authority: &AuthorityName) -> Result<Arc<dyn Signer>, ChainkeeperError> {
        Err(ChainkeeperError::not_found(
            "authority key",
            authority.as_str(),
        ))
    }
}

/// Signer that produces a valid public key but always fails to sign.
#[derive(Debug, Clone)]
pub struct FailingSigner {
    public_key: Vec<u8>,
}

impl FailingSigner {
    /// Creates a signer that advertises `public_key`.
    #[must_use]
    pub const fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }
}

impl Signer for FailingSigner {
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EcdsaP256
    }

    fn public_key_der(&self) -> Result<Vec<u8>, ChainkeeperError> {
        Ok(self.public_key.clone())
    }

    fn sign(&self, _message: &[u8], _scheme: SignatureScheme) -> Result<Vec<u8>, ChainkeeperError> {
        Err(ChainkeeperError::crypto("signature backend failed"))
    }
}

/// Repository fixture with authorities, one leaf, and an OCSP signer.
pub struct Harness {
    tenant: TempTenant,
    pub clock: Arc<FakeClock>,
    pub store: Arc<FileStore>,
    pub fixtures: CertificateFixtures,
}

impl Harness {
    /// Builds a repository and writes the fixture hierarchy.
    ///
    /// # Errors
    ///
    /// Returns the first fixture or store error.
    pub fn new() -> Result<Self, ChainkeeperError> {
        Self::build(true)
    }

    /// Builds a repository without the fixture leaf certificate.
    ///
    /// # Errors
    ///
    /// Returns the first fixture or store error.
    pub fn without_leaf() -> Result<Self, ChainkeeperError> {
        Self::build(false)
    }

    fn build(with_leaf: bool) -> Result<Self, ChainkeeperError> {
        let tenant = TempTenant::new()?;
        let clock = Arc::new(FakeClock::new(NOW));
        let store = Arc::new(FileStore::with_clock(
            tenant.paths().clone(),
            Arc::clone(&clock) as Arc<dyn Clock>,
        ));
        store.write_tenant(&TenantConfig::new(
            TenantId::new("acme")?,
            "Acme",
            ProfileName::new("tls-server")?,
            NOW,
        ))?;

        let provider = Arc::new(FakeCertificateProvider::with_time(NOW)?);
        let fixtures = provider.fixtures().clone();
        store.write_authority(&fixtures.root)?;
        store.write_authority(&fixtures.tls)?;
        store.write_authority(&fixtures.smime)?;
        if with_leaf {
            store.write_certificate(&fixtures.leaf)?;
        }
        store.write_authority(&authority_bundle(&fixtures.ocsp_signer))?;

        Ok(Self {
            tenant,
            clock,
            store,
            fixtures,
        })
    }

    /// Repository paths.
    #[must_use]
    pub const fn paths(&self) -> &chainkeeper_core::RepositoryPaths {
        self.tenant.paths()
    }

    /// Builds a loaded responder with the fixture OCSP signer.
    ///
    /// # Errors
    ///
    /// Returns a load error when the state is invalid.
    pub fn responder(&self) -> Result<FileOcspResponder, ChainkeeperError> {
        FileOcspResponder::load(self.dependencies(Arc::new(FixtureSigners::new(
            self.fixtures.ocsp_signer.key.private_key_pem(),
        ))))
    }

    /// Builds dependencies with an explicit signer resolver.
    #[must_use]
    pub fn dependencies(&self, signers: Arc<dyn AuthoritySigners>) -> OcspDependencies {
        self.dependencies_for(signers, ocsp_signer_name())
    }

    /// Builds dependencies for a named OCSP signer.
    #[must_use]
    pub fn dependencies_for(
        &self,
        signers: Arc<dyn AuthoritySigners>,
        ocsp_signer: AuthorityName,
    ) -> OcspDependencies {
        OcspDependencies::new(
            Arc::clone(&self.clock) as Arc<dyn Clock>,
            Arc::clone(&self.store) as Arc<dyn chainkeeper_core::CertificateStore>,
            signers,
            self.paths().clone(),
            ocsp_signer,
        )
    }

    /// Writes a certificate record in place of the fixture leaf.
    ///
    /// # Errors
    ///
    /// Returns a store error when the record cannot be written.
    pub fn write_record(&self, record: &CertificateRecord) -> Result<(), ChainkeeperError> {
        let issued = chainkeeper_core::IssuedCertificate::new(
            record.clone(),
            self.fixtures.leaf.cert_pem.clone(),
            self.fixtures.leaf.chain_pem.clone(),
            None,
        );
        self.store.write_certificate(&issued)?;
        Ok(())
    }

    /// Writes a signer bundle as an authority with its original name.
    ///
    /// # Errors
    ///
    /// Returns a store error when the authority cannot be written.
    pub fn write_signer(&self, signer: &SignerBundle) -> Result<(), ChainkeeperError> {
        self.store.write_authority(&authority_bundle(signer))
    }
}

/// Builds an authority bundle from a signer bundle.
#[must_use]
pub fn authority_bundle(signer: &SignerBundle) -> AuthorityBundle {
    AuthorityBundle::new(
        AuthorityMaterial::new(
            signer.config.clone(),
            signer.cert_pem.clone(),
            signer.chain_pem.clone(),
        ),
        signer.key.clone(),
    )
}

/// Renames a signer bundle so it can coexist with the fixture signer.
#[must_use]
pub fn rename_signer(mut signer: SignerBundle, name: &AuthorityName) -> SignerBundle {
    signer.config.name = name.clone();
    signer
}

/// Returns a bundle that presents `cert_pem` as an OCSP signer.
#[must_use]
pub fn signer_bundle_from(
    name: &AuthorityName,
    cert_pem: &str,
    chain_pem: &str,
    key: &chainkeeper_core::KeyMaterial,
) -> SignerBundle {
    SignerBundle {
        config: AuthorityConfig::new(
            name.clone(),
            AuthorityKind::OcspSigner,
            Some(AuthorityName::new("tls").expect("valid slug")),
            KeyAlgorithm::EcdsaP256,
            90,
            0,
            Vec::new(),
            NOW,
        ),
        cert_pem: cert_pem.to_owned(),
        chain_pem: chain_pem.to_owned(),
        key: key.clone(),
    }
}

/// Returns the fixture leaf record.
#[must_use]
pub fn leaf_record(harness: &Harness) -> CertificateRecord {
    harness.fixtures.leaf.record.clone()
}

/// Returns the fixed OCSP signer authority name.
#[must_use]
pub fn ocsp_signer_name() -> AuthorityName {
    AuthorityName::new("ocsp-signer").expect("valid slug")
}

/// Returns the fixture leaf serial as a number.
#[must_use]
pub const fn leaf_serial() -> u128 {
    10
}

/// Returns a serial that is not issued by the fixtures.
#[must_use]
pub const fn other_serial() -> u128 {
    11
}

/// Returns `record` with a revocation applied at the fixed clock.
#[must_use]
pub const fn revoked(mut record: CertificateRecord) -> CertificateRecord {
    record.revoked_at = Some(NOW);
    record.revocation_reason = Some(chainkeeper_core::RevocationReason::KeyCompromise);
    record
}

/// Returns `record` moved into the past so it is expired at the fixed clock.
#[must_use]
pub fn expired(mut record: CertificateRecord) -> CertificateRecord {
    record.issued_at = NOW - Duration::days(400);
    record.expires_at = NOW - Duration::days(1);
    record
}

/// Builds a `CertId` for `issuer_pem` and `serial`.
///
/// # Errors
///
/// Returns a decode error when the issuer certificate cannot be parsed.
pub fn cert_id(
    issuer_pem: &str,
    serial: u128,
    algorithm: HashAlgorithm,
) -> Result<CertId, ChainkeeperError> {
    let x509 = openssl::x509::X509::from_pem(issuer_pem.as_bytes())
        .map_err(|error| ChainkeeperError::ocsp(error.to_string()))?;
    let der = x509
        .to_der()
        .map_err(|error| ChainkeeperError::ocsp(error.to_string()))?;
    let certificate: rasn_pkix::Certificate =
        rasn::der::decode(&der).map_err(|error| ChainkeeperError::ocsp(error.to_string()))?;

    let name_der = rasn::der::encode(&certificate.tbs_certificate.subject)
        .map_err(|error| ChainkeeperError::ocsp(error.to_string()))?;
    let key_der = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_raw_slice()
        .to_vec();

    let message_digest = match algorithm {
        HashAlgorithm::Sha1 => MessageDigest::sha1(),
        HashAlgorithm::Sha256 => MessageDigest::sha256(),
    };
    let name_hash = hash(message_digest, &name_der)
        .map_err(|error| ChainkeeperError::ocsp(error.to_string()))?;
    let key_hash = hash(message_digest, &key_der)
        .map_err(|error| ChainkeeperError::ocsp(error.to_string()))?;

    Ok(CertId {
        hash_algorithm: hash_algorithm(algorithm)?,
        issuer_name_hash: OctetString::from(name_hash.as_ref().to_vec()),
        issuer_key_hash: OctetString::from(key_hash.as_ref().to_vec()),
        serial_number: Integer::from(serial),
    })
}

/// Builds a request containing `ids`.
///
/// # Errors
///
/// Returns an encode error when the request cannot be serialized.
pub fn request(
    ids: Vec<CertId>,
    nonce: Option<Vec<u8>>,
    version: Integer,
) -> Result<Vec<u8>, ChainkeeperError> {
    let request_extensions = match nonce {
        Some(nonce) => Some(rasn_pkix::Extensions::from(vec![rasn_pkix::Extension {
            extn_id: nonce_oid()?,
            critical: false,
            extn_value: OctetString::from(nonce),
        }])),
        None => None,
    };
    let request_list = ids
        .into_iter()
        .map(|req_cert| Request {
            req_cert,
            single_request_extensions: None,
        })
        .collect();
    let request = OcspRequest {
        tbs_request: TbsRequest {
            version,
            requestor_name: None,
            request_list,
            request_extensions,
        },
        optional_signature: None,
    };
    rasn::der::encode(&request)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot encode request: {error}")))
}

fn hash_algorithm(algorithm: HashAlgorithm) -> Result<AlgorithmIdentifier, ChainkeeperError> {
    let arcs: Vec<u32> = match algorithm {
        HashAlgorithm::Sha1 => vec![1, 3, 14, 3, 2, 26],
        HashAlgorithm::Sha256 => vec![2, 16, 840, 1, 101, 3, 4, 2, 1],
    };
    Ok(AlgorithmIdentifier {
        algorithm: ObjectIdentifier::new(arcs)
            .ok_or_else(|| ChainkeeperError::ocsp("invalid hash OID"))?,
        parameters: None,
    })
}

fn nonce_oid() -> Result<ObjectIdentifier, ChainkeeperError> {
    ObjectIdentifier::new(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 2])
        .ok_or_else(|| ChainkeeperError::ocsp("invalid nonce OID"))
}

/// Returns a clock offset behind the fixed test time.
#[must_use]
pub fn past_clock(days: i64) -> Arc<FakeClock> {
    Arc::new(FakeClock::new(NOW - Duration::days(days)))
}

/// Generates an OCSP signer issued by the fixture TLS authority.
///
/// # Errors
///
/// Returns a crypto error when generation fails.
pub fn generate_signer(
    harness: &Harness,
    clock: Arc<FakeClock>,
    validity_days: u32,
) -> Result<SignerBundle, ChainkeeperError> {
    let ids: Arc<dyn IdGenerator> = Arc::new(FakeIdGenerator::new());
    let provider =
        chainkeeper_crypto::OpenSslProvider::new(clock as Arc<dyn Clock>, Arc::clone(&ids));
    let parent_signer =
        FileSigner::from_pem(harness.fixtures.tls.key.private_key_pem().as_bytes(), None)?;
    provider.create_ocsp_signer(
        &chainkeeper_core::CreateOcspSignerRequest {
            name: ocsp_signer_name(),
            parent: AuthorityName::new("tls")?,
            subject: None,
            algorithm: KeyAlgorithm::EcdsaP256,
            validity_days,
        },
        &harness.fixtures.tls.material,
        &parent_signer,
    )
}
