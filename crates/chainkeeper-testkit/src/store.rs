//! In-memory canonical certificate store.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

use chainkeeper_core::{
    AuthorityBundle, AuthorityMaterial, AuthorityName, AuthorityRecord, CertificateRecord,
    CertificateStatus, CertificateStore, ChainkeeperError, IssuedCertificate, Policy, Profile,
    ProfileName, RevocationRecord, Serial, TenantConfig, builtin_profiles,
};

/// Store that keeps every record in memory.
#[derive(Debug)]
pub struct InMemoryCertificateStore {
    tenant: RwLock<Option<TenantConfig>>,
    policy: RwLock<Option<Policy>>,
    profiles: RwLock<BTreeMap<ProfileName, Profile>>,
    authorities: RwLock<BTreeMap<AuthorityName, AuthorityMaterial>>,
    certificates: RwLock<BTreeMap<Serial, CertificateRecord>>,
    revocations: RwLock<BTreeMap<Serial, RevocationRecord>>,
}

impl Default for InMemoryCertificateStore {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_relative(path: &std::path::Path) -> Result<(), ChainkeeperError> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ChainkeeperError::storage(format!(
            "record path {} must stay inside the repository",
            path.display()
        )));
    }
    Ok(())
}

fn certificate_status_path(status: CertificateStatus, serial: &Serial) -> PathBuf {
    PathBuf::from(format!("certificates/{status}/{serial}.pem"))
}

impl InMemoryCertificateStore {
    /// Creates an empty store preloaded with the built-in profiles.
    #[must_use]
    pub fn new() -> Self {
        let profiles = builtin_profiles()
            .into_iter()
            .map(|profile| (profile.name.clone(), profile))
            .collect();
        Self {
            tenant: RwLock::new(None),
            policy: RwLock::new(None),
            profiles: RwLock::new(profiles),
            authorities: RwLock::new(BTreeMap::new()),
            certificates: RwLock::new(BTreeMap::new()),
            revocations: RwLock::new(BTreeMap::new()),
        }
    }

    /// Creates a store seeded with tenant, policy, and profiles.
    #[must_use]
    pub fn with_config(tenant: TenantConfig, policy: Policy) -> Self {
        let store = Self::new();
        store.set_tenant(tenant);
        store.set_policy(policy);
        store
    }

    /// Replaces the tenant configuration.
    pub fn set_tenant(&self, tenant: TenantConfig) {
        let mut guard = self
            .tenant
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(tenant);
    }

    /// Replaces the policy.
    pub fn set_policy(&self, policy: Policy) {
        let mut guard = self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = Some(policy);
    }

    /// Inserts or replaces a profile.
    pub fn set_profile(&self, profile: Profile) {
        let mut guard = self
            .profiles
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.insert(profile.name.clone(), profile);
    }

    /// Number of stored certificates.
    #[must_use]
    pub fn certificate_count(&self) -> usize {
        self.certificates
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl CertificateStore for InMemoryCertificateStore {
    fn load_tenant(&self) -> Result<TenantConfig, ChainkeeperError> {
        self.tenant
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| ChainkeeperError::not_found("tenant", "tenant.yaml"))
    }

    fn load_policy(&self) -> Result<Policy, ChainkeeperError> {
        self.policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| ChainkeeperError::not_found("policy", "policy/policy.yaml"))
    }

    fn load_profiles(&self) -> Result<Vec<Profile>, ChainkeeperError> {
        Ok(self
            .profiles
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect())
    }

    fn write_certificate(
        &self,
        certificate: &IssuedCertificate,
    ) -> Result<PathBuf, ChainkeeperError> {
        let record = &certificate.record;
        validate_relative(&record.path)?;
        let mut certificates = self
            .certificates
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if certificates.contains_key(&record.serial) {
            return Err(ChainkeeperError::already_exists(format!(
                "certificate {}",
                record.serial
            )));
        }
        let path = record.path.clone();
        certificates.insert(record.serial.clone(), record.clone());
        drop(certificates);
        Ok(path)
    }

    fn get_certificate(
        &self,
        serial: &Serial,
    ) -> Result<Option<CertificateRecord>, ChainkeeperError> {
        Ok(self
            .certificates
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(serial)
            .cloned())
    }

    fn list_certificates(&self) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        Ok(self
            .certificates
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect())
    }

    fn move_certificate(
        &self,
        serial: &Serial,
        to: CertificateStatus,
    ) -> Result<(), ChainkeeperError> {
        let mut certificates = self
            .certificates
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let record = certificates
            .get_mut(serial)
            .ok_or_else(|| ChainkeeperError::not_found("certificate", serial.as_str()))?;
        record.path = certificate_status_path(to, serial);
        drop(certificates);
        Ok(())
    }

    fn write_revocation(&self, record: &RevocationRecord) -> Result<PathBuf, ChainkeeperError> {
        let mut revocations = self
            .revocations
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if revocations.contains_key(&record.serial) {
            return Err(ChainkeeperError::already_exists(format!(
                "revocation {}",
                record.serial
            )));
        }
        revocations.insert(record.serial.clone(), record.clone());
        drop(revocations);
        Ok(PathBuf::from(format!("revocations/{}.yaml", record.serial)))
    }

    fn list_revocations(&self) -> Result<Vec<RevocationRecord>, ChainkeeperError> {
        Ok(self
            .revocations
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect())
    }

    fn write_authority(&self, bundle: &AuthorityBundle) -> Result<(), ChainkeeperError> {
        let mut authorities = self
            .authorities
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        authorities.insert(bundle.material.config.name.clone(), bundle.material.clone());
        drop(authorities);
        Ok(())
    }

    fn load_authority(
        &self,
        name: &AuthorityName,
    ) -> Result<Option<AuthorityMaterial>, ChainkeeperError> {
        Ok(self
            .authorities
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .cloned())
    }

    fn list_authorities(&self) -> Result<Vec<AuthorityRecord>, ChainkeeperError> {
        let authorities = self
            .authorities
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(authorities
            .values()
            .map(|material| {
                AuthorityRecord::from_config(
                    &material.config,
                    PathBuf::from(format!("authorities/{}/cert.pem", material.config.name)),
                    PathBuf::from(format!("authorities/{}/chain.pem", material.config.name)),
                )
            })
            .collect())
    }
}
