//! Canonical filesystem layout operations.
//!
//! The filesystem is authoritative. Every write goes through
//! [`chainkeeper_core::atomic_write`], public artifacts use mode `0644`, private
//! keys use mode `0600`, and created directories use mode `0700`.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chainkeeper_core::{
    AuditEvent, AuthorityBundle, AuthorityConfig, AuthorityMaterial, AuthorityName,
    AuthorityRecord, CONFIG_VERSION, CertificateRecord, CertificateStatus, CertificateStore,
    ChainkeeperError, Clock, CrlBundle, CrlRecord, FileMode, IndexRecords, IndexedCrl,
    IssuedCertificate, KeyMaterial, Policy, Profile, RepositoryPaths, RevocationRecord, Serial,
    SystemClock, TenantConfig, atomic_write, atomic_write_new,
};

use crate::{canonical, fsutil, parse};

const CERTIFICATE_EXTENSIONS: [&str; 3] = ["pem", "yaml", "key.pem"];
const STATUSES: [CertificateStatus; 3] = [
    CertificateStatus::Active,
    CertificateStatus::Revoked,
    CertificateStatus::Expired,
];

fn ensure_version(version: u32, object: &str) -> Result<(), ChainkeeperError> {
    if version == CONFIG_VERSION {
        Ok(())
    } else {
        Err(ChainkeeperError::storage(format!(
            "{object} uses unsupported version {version}, expected {CONFIG_VERSION}"
        )))
    }
}

/// Creates every canonical directory and returns the paths it created.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Storage`] when a directory cannot be created.
pub fn init_layout(paths: &RepositoryPaths) -> Result<Vec<PathBuf>, ChainkeeperError> {
    let mut created = Vec::new();
    for directory in paths.required_directories() {
        if !directory.is_dir() {
            fsutil::ensure_directory(&directory)?;
            created.push(directory);
        }
    }
    Ok(created)
}

/// Canonical filesystem store rooted at one repository.
#[derive(Clone)]
pub struct FileStore {
    paths: RepositoryPaths,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for FileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileStore")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

impl FileStore {
    /// Creates a store that reads the system clock.
    #[must_use]
    pub fn new(paths: RepositoryPaths) -> Self {
        Self {
            paths,
            clock: Arc::new(SystemClock),
        }
    }

    /// Creates a store with an injected clock.
    #[must_use]
    pub fn with_clock(paths: RepositoryPaths, clock: Arc<dyn Clock>) -> Self {
        Self { paths, clock }
    }

    /// Repository layout helpers.
    #[must_use]
    pub const fn paths(&self) -> &RepositoryPaths {
        &self.paths
    }

    /// Current time according to the injected clock.
    #[must_use]
    pub fn now(&self) -> time::OffsetDateTime {
        self.clock.now()
    }

    /// Creates every canonical directory.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a directory cannot be created.
    pub fn init_layout(&self) -> Result<Vec<PathBuf>, ChainkeeperError> {
        init_layout(&self.paths)
    }

    fn absolute(&self, relative: &Path) -> PathBuf {
        self.paths.root().join(relative)
    }

    fn certificate_location(
        &self,
        status: CertificateStatus,
        serial: &Serial,
        ext: &str,
    ) -> Result<PathBuf, ChainkeeperError> {
        self.paths.certificate_path_in(status, serial, ext)
    }

    fn existing_status(
        &self,
        serial: &Serial,
    ) -> Result<Option<CertificateStatus>, ChainkeeperError> {
        for status in STATUSES {
            if self.certificate_location(status, serial, "yaml")?.is_file() {
                return Ok(Some(status));
            }
        }
        Ok(None)
    }

    /// Writes `tenant.yaml`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when the configuration is invalid.
    pub fn write_tenant(&self, config: &TenantConfig) -> Result<PathBuf, ChainkeeperError> {
        config.validate()?;
        let path = self.paths.tenant_yaml();
        canonical::write_yaml(&path, config, FileMode::Public)?;
        Ok(path)
    }

    /// Writes `policy/policy.yaml`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Config`] when the policy is invalid.
    pub fn write_policy(&self, policy: &Policy) -> Result<PathBuf, ChainkeeperError> {
        policy.validate()?;
        fsutil::ensure_directory(&self.paths.policy_dir())?;
        let path = self.paths.policy_yaml();
        canonical::write_yaml(&path, policy, FileMode::Public)?;
        Ok(path)
    }

    /// Writes `profiles/<name>.yaml`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Profile`] when the profile is invalid.
    pub fn write_profile(&self, profile: &Profile) -> Result<PathBuf, ChainkeeperError> {
        profile.validate()?;
        fsutil::ensure_directory(&self.paths.profiles_dir())?;
        let path = self.paths.profile_path(&profile.name);
        canonical::write_yaml(&path, profile, FileMode::Public)?;
        Ok(path)
    }

    /// Loads `policy/policy.yaml`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::NotFound`] when the file is missing or
    /// [`ChainkeeperError::Storage`] when it cannot be parsed.
    pub fn read_policy(&self) -> Result<Policy, ChainkeeperError> {
        let path = self.paths.policy_yaml();
        let policy: Policy = canonical::read_yaml(&path, "policy")?;
        policy.validate()?;
        Ok(policy)
    }

    /// Loads every profile under `profiles/` in lexical order.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a profile cannot be parsed.
    pub fn read_profiles(&self) -> Result<Vec<Profile>, ChainkeeperError> {
        let directory = self.paths.profiles_dir();
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let mut profiles = Vec::new();
        for path in fsutil::sorted_entries(&directory)? {
            if !fsutil::has_extension(&path, "yaml") {
                continue;
            }
            let profile: Profile = canonical::read_yaml(&path, "profile")?;
            profile.validate()?;
            let stem = path
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default();
            if stem != profile.name.as_str() {
                return Err(ChainkeeperError::storage(format!(
                    "profile {} declares name {}",
                    path.display(),
                    profile.name
                )));
            }
            profiles.push(profile);
        }
        profiles.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(profiles)
    }

    /// Writes public authority material without a private key.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::AlreadyExists`] when an authority with the
    /// same name already exists with a different certificate.
    pub fn write_authority_material(
        &self,
        material: &AuthorityMaterial,
    ) -> Result<(), ChainkeeperError> {
        material.config.validate()?;
        let directory = self.paths.authority_dir(&material.config.name);
        fsutil::ensure_directory(&directory)?;

        let certificate_path = self
            .paths
            .authority_path(&material.config.name, "cert.pem")?;
        if certificate_path.is_file() {
            let existing = std::fs::read_to_string(&certificate_path).map_err(|error| {
                ChainkeeperError::storage(format!(
                    "could not read {}: {error}",
                    certificate_path.display()
                ))
            })?;
            if existing != material.cert_pem {
                return Err(ChainkeeperError::already_exists(format!(
                    "authority {} already exists with a different certificate",
                    material.config.name
                )));
            }
        }

        atomic_write(
            &certificate_path,
            material.cert_pem.as_bytes(),
            FileMode::Public,
        )?;
        atomic_write(
            &self
                .paths
                .authority_path(&material.config.name, "chain.pem")?,
            material.chain_pem.as_bytes(),
            FileMode::Public,
        )?;
        canonical::write_yaml(
            &self
                .paths
                .authority_path(&material.config.name, "authority.yaml")?,
            &material.config,
            FileMode::Public,
        )
    }

    /// Loads one authority by name.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when existing material cannot be
    /// parsed.
    pub fn read_authority(
        &self,
        name: &AuthorityName,
    ) -> Result<Option<AuthorityMaterial>, ChainkeeperError> {
        let directory = self.paths.authority_dir(name);
        if !directory.is_dir() {
            return Ok(None);
        }
        let config_path = self.paths.authority_path(name, "authority.yaml")?;
        let certificate_path = self.paths.authority_path(name, "cert.pem")?;
        let chain_path = self.paths.authority_path(name, "chain.pem")?;

        // `init` pre-creates every authority directory before any key exists.
        // A directory without `authority.yaml` is therefore an empty slot, not
        // a corrupt authority.
        if !config_path.is_file() {
            return Ok(None);
        }

        let config: AuthorityConfig = canonical::read_yaml(&config_path, "authority")?;
        config.validate()?;
        if config.name != *name {
            return Err(ChainkeeperError::storage(format!(
                "authority {} declares name {}",
                config_path.display(),
                config.name
            )));
        }
        let cert_pem = String::from_utf8(fsutil::read_file(&certificate_path, "authority")?)
            .map_err(|error| {
                ChainkeeperError::storage(format!(
                    "authority certificate {} is not UTF-8: {error}",
                    certificate_path.display()
                ))
            })?;
        let chain_pem =
            String::from_utf8(fsutil::read_file(&chain_path, "authority")?).map_err(|error| {
                ChainkeeperError::storage(format!(
                    "authority chain {} is not UTF-8: {error}",
                    chain_path.display()
                ))
            })?;
        Ok(Some(AuthorityMaterial::new(config, cert_pem, chain_pem)))
    }

    /// Lists every authority in lexical order.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when an authority cannot be read.
    pub fn read_authorities(&self) -> Result<Vec<AuthorityRecord>, ChainkeeperError> {
        let directory = self.paths.authorities_dir();
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for entry in fsutil::sorted_entries(&directory)? {
            if !entry.is_dir() {
                continue;
            }
            let Some(name) = entry
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(AuthorityName::new)
                .transpose()?
            else {
                continue;
            };
            let Some(material) = self.read_authority(&name)? else {
                continue;
            };
            let cert_path = self.absolute(&self.paths.authority_path(&name, "cert.pem")?);
            let chain_path = self.absolute(&self.paths.authority_path(&name, "chain.pem")?);
            records.push(AuthorityRecord::from_config(
                &material.config,
                fsutil::relative_path(&cert_path, &self.paths)?,
                fsutil::relative_path(&chain_path, &self.paths)?,
            ));
        }
        records.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(records)
    }

    /// Writes a revocation record using create-new semantics.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::AlreadyExists`] when a record for the serial
    /// already exists.
    fn write_revocation_new(&self, record: &RevocationRecord) -> Result<PathBuf, ChainkeeperError> {
        ensure_version(record.version, "revocation record")?;
        fsutil::ensure_directory(&self.paths.revocations_dir())?;
        let path = self.paths.revocation_path(&record.serial);
        let rendered = canonical::to_yaml(record)?;
        atomic_write_new(&path, rendered.as_bytes(), FileMode::Public)?;
        Ok(path)
    }

    /// Lists every revocation record in lexical order.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a record cannot be parsed.
    pub fn read_revocations(&self) -> Result<Vec<RevocationRecord>, ChainkeeperError> {
        let directory = self.paths.revocations_dir();
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for path in fsutil::sorted_entries(&directory)? {
            if !fsutil::has_extension(&path, "yaml") {
                continue;
            }
            let record: RevocationRecord = canonical::read_yaml(&path, "revocation")?;
            ensure_version(record.version, "revocation record")?;
            let stem = path
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default();
            if stem != record.serial.as_str() {
                return Err(ChainkeeperError::storage(format!(
                    "revocation {} declares serial {}",
                    path.display(),
                    record.serial
                )));
            }
            records.push(record);
        }
        records.sort_by(|left, right| left.serial.cmp(&right.serial));
        Ok(records)
    }

    /// Writes every part of a generated CRL.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a file cannot be written.
    pub fn write_crl(&self, bundle: &CrlBundle) -> Result<(), ChainkeeperError> {
        ensure_version(bundle.record.version, "CRL record")?;
        if bundle.record.number == 0 {
            return Err(ChainkeeperError::storage(
                "CRL number must be positive".to_owned(),
            ));
        }
        fsutil::ensure_directory(&self.paths.crls_dir())?;
        let der_path = self.paths.crl_path(&bundle.record.authority, "crl.der")?;
        let pem_path = self.paths.crl_path(&bundle.record.authority, "crl.pem")?;
        atomic_write(&der_path, &bundle.der, FileMode::Public)?;
        atomic_write(&pem_path, bundle.pem.as_bytes(), FileMode::Public)?;

        let mut stored = bundle.record.clone();
        stored.der_path = fsutil::relative_path(&der_path, &self.paths)?;
        stored.pem_path = fsutil::relative_path(&pem_path, &self.paths)?;
        canonical::write_yaml(
            &self.paths.crl_path(&bundle.record.authority, "yaml")?,
            &stored,
            FileMode::Public,
        )?;
        self.write_crl_number(&bundle.record.authority, bundle.record.number)
    }

    /// Writes the CRL number file.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when the file cannot be written.
    pub fn write_crl_number(
        &self,
        authority: &AuthorityName,
        number: u64,
    ) -> Result<(), ChainkeeperError> {
        fsutil::ensure_directory(&self.paths.crls_dir())?;
        atomic_write(
            &self.paths.crl_number_path(authority),
            format!("{number}\n").as_bytes(),
            FileMode::Public,
        )
    }

    /// Returns the next CRL number for an authority.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when the number file is invalid.
    pub fn next_crl_number(&self, authority: &AuthorityName) -> Result<u64, ChainkeeperError> {
        let path = self.paths.crl_number_path(authority);
        let current = match std::fs::read_to_string(&path) {
            Ok(value) => value.trim().parse::<u64>().map_err(|error| {
                ChainkeeperError::storage(format!(
                    "could not parse CRL number {}: {error}",
                    path.display()
                ))
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => {
                return Err(ChainkeeperError::storage(format!(
                    "could not read {}: {error}",
                    path.display()
                )));
            }
        };
        Ok(current + 1)
    }

    /// Loads CRL metadata by authority.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when the file cannot be parsed.
    pub fn read_crl(
        &self,
        authority: &AuthorityName,
    ) -> Result<Option<CrlRecord>, ChainkeeperError> {
        let path = self.paths.crl_path(authority, "yaml")?;
        if !path.is_file() {
            return Ok(None);
        }
        let record: CrlRecord = canonical::read_yaml(&path, "CRL")?;
        ensure_version(record.version, "CRL record")?;
        Ok(Some(record))
    }

    /// Lists every CRL with its DER digest.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a CRL cannot be read.
    pub fn read_crls(&self) -> Result<Vec<IndexedCrl>, ChainkeeperError> {
        let directory = self.paths.crls_dir();
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let mut crls = Vec::new();
        for path in fsutil::sorted_entries(&directory)? {
            if !fsutil::has_extension(&path, "yaml") {
                continue;
            }
            let record: CrlRecord = canonical::read_yaml(&path, "CRL")?;
            ensure_version(record.version, "CRL record")?;
            let der =
                fsutil::read_file(&self.paths.crl_path(&record.authority, "crl.der")?, "CRL")?;
            crls.push(IndexedCrl {
                sha256: canonical::sha256_hex(&der),
                record,
            });
        }
        crls.sort_by(|left, right| left.record.authority.cmp(&right.record.authority));
        Ok(crls)
    }

    /// Writes an audit event using create-new semantics.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::AlreadyExists`] when the event id exists.
    pub fn write_audit_event(&self, event: &AuditEvent) -> Result<PathBuf, ChainkeeperError> {
        fsutil::ensure_directory(&self.paths.audit_events_dir())?;
        let path = self.paths.audit_event_path(&event.id);
        let rendered = canonical::to_json(event)?;
        atomic_write_new(&path, rendered.as_bytes(), FileMode::Public)?;
        Ok(path)
    }

    /// Lists every audit event in lexical ULID order.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when an event cannot be parsed.
    pub fn list_audit_events(&self) -> Result<Vec<AuditEvent>, ChainkeeperError> {
        let directory = self.paths.audit_events_dir();
        if !directory.is_dir() {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        for path in fsutil::sorted_entries(&directory)? {
            if !fsutil::has_extension(&path, "json") {
                continue;
            }
            let event: AuditEvent = canonical::read_json(&path, "audit event")?;
            let stem = path
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or_default();
            if stem != event.id.as_str() {
                return Err(ChainkeeperError::storage(format!(
                    "audit event {} declares id {}",
                    path.display(),
                    event.id
                )));
            }
            events.push(event);
        }
        events.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(events)
    }

    /// Collects every canonical record for an index rebuild.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when a record cannot be parsed.
    pub fn load_index_records(&self) -> Result<IndexRecords, ChainkeeperError> {
        Ok(IndexRecords {
            certificates: self.read_certificates()?,
            revocations: self.read_revocations()?,
            authorities: self.read_authorities()?,
            profiles: self.read_profiles()?,
            crls: self.read_crls()?,
            audit_events: self.list_audit_events()?,
        })
    }

    fn certificate_files(
        &self,
        status: CertificateStatus,
        serial: &Serial,
    ) -> Result<(PathBuf, PathBuf, PathBuf), ChainkeeperError> {
        Ok((
            self.absolute(&self.certificate_location(status, serial, "pem")?),
            self.absolute(&self.certificate_location(status, serial, "yaml")?),
            self.absolute(&self.certificate_location(status, serial, "key.pem")?),
        ))
    }

    fn read_certificate_at(
        &self,
        status: CertificateStatus,
        serial: &Serial,
    ) -> Result<CertificateRecord, ChainkeeperError> {
        let (pem_path, yaml_path, _) = self.certificate_files(status, serial)?;
        let relative_pem = fsutil::relative_path(&pem_path, &self.paths)?;
        parse::read_certificate_record(&yaml_path, &pem_path, &relative_pem)
    }

    /// Lists every certificate in serial order.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when metadata cannot be parsed.
    pub fn read_certificates(&self) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        let mut records = Vec::new();
        for status in STATUSES {
            let directory = self.paths.certificates_dir_for(status);
            if !directory.is_dir() {
                continue;
            }
            for path in fsutil::sorted_entries(&directory)? {
                if !fsutil::has_extension(&path, "yaml") {
                    continue;
                }
                let stem = path
                    .file_stem()
                    .and_then(std::ffi::OsStr::to_str)
                    .unwrap_or_default();
                let serial = Serial::new(stem).map_err(|error| {
                    ChainkeeperError::storage(format!(
                        "certificate metadata {} has an invalid name: {error}",
                        path.display()
                    ))
                })?;
                records.push(self.read_certificate_at(status, &serial)?);
            }
        }
        records.sort_by(|left, right| left.serial.cmp(&right.serial));
        Ok(records)
    }
}

impl CertificateStore for FileStore {
    fn load_tenant(&self) -> Result<TenantConfig, ChainkeeperError> {
        let path = self.paths.tenant_yaml();
        let config: TenantConfig = canonical::read_yaml(&path, "tenant configuration")?;
        config.validate()?;
        Ok(config)
    }

    fn load_policy(&self) -> Result<Policy, ChainkeeperError> {
        self.read_policy()
    }

    fn load_profiles(&self) -> Result<Vec<Profile>, ChainkeeperError> {
        self.read_profiles()
    }

    fn write_certificate(
        &self,
        certificate: &IssuedCertificate,
    ) -> Result<PathBuf, ChainkeeperError> {
        let record = &certificate.record;
        if record.issued_at >= record.expires_at {
            return Err(ChainkeeperError::storage(format!(
                "certificate {} has issued_at not before expires_at",
                record.serial
            )));
        }
        record.subject.validate()?;
        for san in &record.sans {
            san.validate()?;
        }

        let status = record.status(self.now());
        for existing in STATUSES {
            for extension in CERTIFICATE_EXTENSIONS {
                if self
                    .certificate_location(existing, &record.serial, extension)?
                    .exists()
                {
                    return Err(ChainkeeperError::already_exists(format!(
                        "certificate {} already exists",
                        record.serial
                    )));
                }
            }
        }

        let pem_path = self.absolute(&self.certificate_location(status, &record.serial, "pem")?);
        let yaml_path =
            self.absolute(&self.certificate_location(status, &record.serial, "yaml")?);
        fsutil::ensure_directory(&self.paths.certificates_dir_for(status))?;

        let parsed = parse::parse_certificate_pem(&certificate.cert_pem, &pem_path)?;
        if !parse::serials_equal(&parsed.serial, &record.serial) {
            return Err(ChainkeeperError::storage(format!(
                "certificate {} PEM serial {} does not match metadata",
                record.serial, parsed.serial
            )));
        }

        let mut stored = record.clone();
        stored.path = fsutil::relative_path(&pem_path, &self.paths)?;

        atomic_write(&pem_path, certificate.cert_pem.as_bytes(), FileMode::Public)?;
        canonical::write_yaml(&yaml_path, &stored, FileMode::Public)?;
        if let Some(key) = &certificate.key {
            self.write_certificate_key(&record.serial, key)?;
        }
        Ok(pem_path)
    }

    fn get_certificate(
        &self,
        serial: &Serial,
    ) -> Result<Option<CertificateRecord>, ChainkeeperError> {
        if let Some(status) = self.existing_status(serial)? {
            return self.read_certificate_at(status, serial).map(Some);
        }
        for status in STATUSES {
            let (pem_path, _, _) = self.certificate_files(status, serial)?;
            if pem_path.is_file() {
                return Err(ChainkeeperError::storage(format!(
                    "certificate {} has no metadata",
                    pem_path.display()
                )));
            }
        }
        Ok(None)
    }

    fn list_certificates(&self) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
        self.read_certificates()
    }

    fn move_certificate(
        &self,
        serial: &Serial,
        to: CertificateStatus,
    ) -> Result<(), ChainkeeperError> {
        let Some(from) = self.existing_status(serial)? else {
            return Err(ChainkeeperError::not_found("certificate", serial.as_str()));
        };
        if from == to {
            return Ok(());
        }

        let mut moves = Vec::new();
        for extension in CERTIFICATE_EXTENSIONS {
            let source = self.absolute(&self.certificate_location(from, serial, extension)?);
            let destination = self.absolute(&self.certificate_location(to, serial, extension)?);
            let required = extension != "key.pem";
            if !source.is_file() {
                if required {
                    return Err(ChainkeeperError::storage(format!(
                        "certificate {} is missing {}",
                        serial,
                        source.display()
                    )));
                }
                continue;
            }
            if destination.exists() {
                return Err(ChainkeeperError::already_exists(format!(
                    "certificate {serial} already exists in {to}"
                )));
            }
            moves.push((source, destination));
        }

        let mut completed: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (source, destination) in moves {
            if let Err(error) = std::fs::rename(&source, &destination) {
                for (source, destination) in completed.iter().rev() {
                    let _ = std::fs::rename(destination, source);
                }
                return Err(ChainkeeperError::storage(format!(
                    "could not move {} to {}: {error}",
                    source.display(),
                    destination.display()
                )));
            }
            completed.push((source, destination));
        }
        Ok(())
    }

    fn write_revocation(&self, record: &RevocationRecord) -> Result<PathBuf, ChainkeeperError> {
        self.write_revocation_new(record)
    }

    fn list_revocations(&self) -> Result<Vec<RevocationRecord>, ChainkeeperError> {
        self.read_revocations()
    }

    fn write_authority(&self, bundle: &AuthorityBundle) -> Result<(), ChainkeeperError> {
        self.write_authority_material(&bundle.material)?;
        let key_path = self
            .paths
            .authority_path(&bundle.material.config.name, "key.pem")?;
        atomic_write(
            &key_path,
            bundle.key.private_key_pem().as_bytes(),
            FileMode::Private,
        )
    }

    fn load_authority(
        &self,
        name: &AuthorityName,
    ) -> Result<Option<AuthorityMaterial>, ChainkeeperError> {
        self.read_authority(name)
    }

    fn list_authorities(&self) -> Result<Vec<AuthorityRecord>, ChainkeeperError> {
        self.read_authorities()
    }

    fn list_crls(&self) -> Result<Vec<CrlRecord>, ChainkeeperError> {
        Ok(self
            .read_crls()?
            .into_iter()
            .map(|indexed| indexed.record)
            .collect())
    }
}

impl FileStore {
    fn write_certificate_key(
        &self,
        serial: &Serial,
        key: &KeyMaterial,
    ) -> Result<(), ChainkeeperError> {
        let status = self
            .existing_status(serial)?
            .unwrap_or(CertificateStatus::Active);
        let path = self.absolute(&self.certificate_location(status, serial, "key.pem")?);
        atomic_write(&path, key.private_key_pem().as_bytes(), FileMode::Private)
    }
}
