//! Fake certificate provider backed by real OpenSSL fixtures.

use std::collections::BTreeSet;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use chainkeeper_core::{
    AuthorityBundle, AuthorityConfig, AuthorityKind, AuthorityMaterial, CertificateProvider,
    CertificateRecord, ChainkeeperError, CreateAuthorityRequest, CreateOcspSignerRequest,
    CrlBundle, CrlRecord, CrlRequest, IssuedCertificate, KeyAlgorithm, KeyMaterial, KeyUsage,
    Serial, Signer, SignerBundle, builtin_profile,
};
use time::{Duration, OffsetDateTime};

use crate::fixtures::CertificateFixtures;

/// Provider method whose failure can be injected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FakeOperation {
    /// `generate_key`.
    GenerateKey,
    /// `create_root`.
    CreateRoot,
    /// `create_intermediate`.
    CreateIntermediate,
    /// `create_ocsp_signer`.
    CreateOcspSigner,
    /// `issue`.
    Issue,
    /// `issue` after the key pair was generated but before returning.
    IssueAfterKey,
    /// `generate_crl`.
    GenerateCrl,
}

/// Provider that returns deterministic fixtures and supports failure injection.
#[derive(Debug)]
pub struct FakeCertificateProvider {
    fixtures: CertificateFixtures,
    now: OffsetDateTime,
    failures: RwLock<BTreeSet<FakeOperation>>,
    serials: AtomicU64,
}

fn authority_config(request: &CreateAuthorityRequest, now: OffsetDateTime) -> AuthorityConfig {
    AuthorityConfig::new(
        request.name.clone(),
        request.kind,
        request.parent.clone(),
        request.algorithm,
        request.validity_days,
        request.path_len,
        vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign],
        now,
    )
}

fn ocsp_config(request: &CreateOcspSignerRequest, now: OffsetDateTime) -> AuthorityConfig {
    AuthorityConfig::new(
        request.name.clone(),
        AuthorityKind::OcspSigner,
        Some(request.parent.clone()),
        request.algorithm,
        request.validity_days,
        0,
        vec![KeyUsage::DigitalSignature],
        now,
    )
}

impl FakeCertificateProvider {
    /// Builds fixtures and returns the provider.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when fixture generation fails.
    pub fn new() -> Result<Self, ChainkeeperError> {
        Self::with_time(time::macros::datetime!(2024-01-01 00:00:00 UTC))
    }

    /// Builds fixtures at a fixed time and returns the provider.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Crypto`] when fixture generation fails.
    pub fn with_time(now: OffsetDateTime) -> Result<Self, ChainkeeperError> {
        Ok(Self {
            fixtures: CertificateFixtures::generate(now)?,
            now,
            failures: RwLock::new(BTreeSet::new()),
            serials: AtomicU64::new(0),
        })
    }

    /// Makes the given operation fail.
    pub fn inject_failure(&self, operation: FakeOperation) {
        self.failures
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(operation);
    }

    /// Clears failure injection.
    pub fn clear_failures(&self) {
        self.failures
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    /// Returns the generated fixtures.
    #[must_use]
    pub const fn fixtures(&self) -> &CertificateFixtures {
        &self.fixtures
    }

    fn check(&self, operation: FakeOperation) -> Result<(), ChainkeeperError> {
        let failures = self
            .failures
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failures.contains(&operation) {
            Err(ChainkeeperError::crypto(format!(
                "injected failure for {operation:?}"
            )))
        } else {
            Ok(())
        }
    }
}

impl CertificateProvider for FakeCertificateProvider {
    fn generate_key(&self, algorithm: KeyAlgorithm) -> Result<KeyMaterial, ChainkeeperError> {
        self.check(FakeOperation::GenerateKey)?;
        let source = &self.fixtures.leaf;
        let key = source
            .key
            .as_ref()
            .ok_or_else(|| ChainkeeperError::crypto("fixture leaf has no key"))?;
        Ok(KeyMaterial::new(
            algorithm,
            key.private_key_pem(),
            key.public_key_der().to_vec(),
        ))
    }

    fn create_root(
        &self,
        request: &CreateAuthorityRequest,
    ) -> Result<AuthorityBundle, ChainkeeperError> {
        self.check(FakeOperation::CreateRoot)?;
        let material = AuthorityMaterial::new(
            authority_config(request, self.now),
            self.fixtures.root.material.cert_pem.clone(),
            self.fixtures.root.material.chain_pem.clone(),
        );
        Ok(AuthorityBundle::new(
            material,
            self.fixtures.root.key.clone(),
        ))
    }

    fn create_intermediate(
        &self,
        request: &CreateAuthorityRequest,
        _parent: &AuthorityMaterial,
        _parent_signer: &dyn Signer,
    ) -> Result<AuthorityBundle, ChainkeeperError> {
        self.check(FakeOperation::CreateIntermediate)?;
        let material = AuthorityMaterial::new(
            authority_config(request, self.now),
            self.fixtures.tls.material.cert_pem.clone(),
            self.fixtures.tls.material.chain_pem.clone(),
        );
        Ok(AuthorityBundle::new(
            material,
            self.fixtures.tls.key.clone(),
        ))
    }

    fn create_ocsp_signer(
        &self,
        request: &CreateOcspSignerRequest,
        _parent: &AuthorityMaterial,
        _parent_signer: &dyn Signer,
    ) -> Result<SignerBundle, ChainkeeperError> {
        self.check(FakeOperation::CreateOcspSigner)?;
        Ok(SignerBundle {
            config: ocsp_config(request, self.now),
            cert_pem: self.fixtures.ocsp_signer.cert_pem.clone(),
            chain_pem: self.fixtures.ocsp_signer.chain_pem.clone(),
            key: self.fixtures.ocsp_signer.key.clone(),
        })
    }

    fn issue(
        &self,
        request: &chainkeeper_core::IssueRequest,
        _signer: &dyn Signer,
    ) -> Result<IssuedCertificate, ChainkeeperError> {
        self.check(FakeOperation::Issue)?;
        let profile = builtin_profile(&request.profile)
            .ok_or_else(|| ChainkeeperError::not_found("profile", request.profile.as_str()))?;
        let algorithm = request.algorithm.unwrap_or(profile.algorithm);
        let validity_days = request.validity_days.unwrap_or(profile.validity_days);
        let sequence = self.serials.fetch_add(1, Ordering::SeqCst) + 1;
        let serial = Serial::new(format!("{sequence:04X}"))?;
        let record = CertificateRecord {
            serial: serial.clone(),
            subject: request.subject.clone(),
            issuer: "CN=Chainkeeper Test TLS, O=Chainkeeper Test".to_owned(),
            profile: request.profile.clone(),
            authority: profile.authority.clone(),
            algorithm,
            sans: request.sans.clone(),
            ekus: profile.eku.clone(),
            key_usages: profile.key_usage,
            issued_at: self.now,
            expires_at: self.now + Duration::days(i64::from(validity_days)),
            path: format!("certificates/active/{serial}.pem").into(),
            revoked_at: None,
            revocation_reason: None,
            replaces: request.replaces.clone(),
        };
        let key = if request.csr_pem.is_some() {
            None
        } else {
            Some(self.generate_key(algorithm)?)
        };
        self.check(FakeOperation::IssueAfterKey)?;
        Ok(IssuedCertificate::new(
            record,
            self.fixtures.leaf.cert_pem.clone(),
            self.fixtures.leaf.chain_pem.clone(),
            key,
        ))
    }

    fn generate_crl(
        &self,
        request: &CrlRequest,
        _signer: &dyn Signer,
    ) -> Result<CrlBundle, ChainkeeperError> {
        self.check(FakeOperation::GenerateCrl)?;
        let record = CrlRecord {
            version: chainkeeper_core::CONFIG_VERSION,
            authority: request.authority.clone(),
            number: request.number,
            this_update: request.this_update,
            next_update: request.next_update,
            revoked_serials: request
                .revocations
                .iter()
                .map(|revocation| revocation.serial.clone())
                .collect(),
            der_path: format!("crls/{}.crl.der", request.authority).into(),
            pem_path: format!("crls/{}.crl.pem", request.authority).into(),
        };
        let mut der = b"FAKE-CRL:".to_vec();
        der.extend_from_slice(&request.number.to_be_bytes());
        Ok(CrlBundle {
            record,
            der,
            pem: format!(
                "-----BEGIN X509 CRL-----\nFAKE-{}\n-----END X509 CRL-----\n",
                request.number
            ),
        })
    }
}
