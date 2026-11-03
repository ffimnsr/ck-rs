//! Issuer index built from public authority certificates.

use chainkeeper_core::{AuthorityKind, AuthorityMaterial, AuthorityName, ChainkeeperError};

use crate::request::HashAlgorithm;
use crate::util::{digest, issuer_key_hash_input, name_der, rasn_certificate_from_pem};

/// One authority certificate that can issue certificates matched by OCSP.
#[derive(Debug)]
pub struct IssuerEntry {
    pub authority: AuthorityName,
    pub kind: AuthorityKind,
    name_der: Vec<u8>,
    key_der: Vec<u8>,
}

impl IssuerEntry {
    pub fn from_material(material: &AuthorityMaterial) -> Result<Self, ChainkeeperError> {
        let certificate = rasn_certificate_from_pem(&material.cert_pem)?;
        let name_der = name_der(&certificate.tbs_certificate.subject)?;
        let key_der = issuer_key_hash_input(&certificate);
        Ok(Self {
            authority: material.config.name.clone(),
            kind: material.config.kind,
            name_der,
            key_der,
        })
    }

    fn matches(
        &self,
        hash: HashAlgorithm,
        issuer_name_hash: &[u8],
        issuer_key_hash: &[u8],
    ) -> Result<bool, ChainkeeperError> {
        Ok(digest(hash, &self.name_der)? == issuer_name_hash
            && digest(hash, &self.key_der)? == issuer_key_hash)
    }
}

/// Index of every authority certificate that can issue leaf certificates.
#[derive(Debug, Default)]
pub struct IssuerIndex {
    entries: Vec<IssuerEntry>,
}

impl IssuerIndex {
    pub fn build(materials: &[AuthorityMaterial]) -> Result<Self, ChainkeeperError> {
        let entries = materials
            .iter()
            .filter(|material| material.config.kind != AuthorityKind::OcspSigner)
            .map(IssuerEntry::from_material)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries })
    }

    pub fn find(
        &self,
        hash: HashAlgorithm,
        issuer_name_hash: &[u8],
        issuer_key_hash: &[u8],
    ) -> Result<Option<&AuthorityName>, ChainkeeperError> {
        for entry in &self.entries {
            if entry.matches(hash, issuer_name_hash, issuer_key_hash)? {
                return Ok(Some(&entry.authority));
            }
        }
        Ok(None)
    }

    /// Returns true when `name_der` is the subject of an intermediate CA.
    pub fn is_intermediate_subject(&self, name_der: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.kind == AuthorityKind::Intermediate && entry.name_der == name_der)
    }

    /// Authorities that can serve as trust anchors for signer validation.
    #[must_use]
    pub fn root_names(&self) -> Vec<&AuthorityName> {
        self.entries
            .iter()
            .filter(|entry| entry.kind == AuthorityKind::Root)
            .map(|entry| &entry.authority)
            .collect()
    }
}
