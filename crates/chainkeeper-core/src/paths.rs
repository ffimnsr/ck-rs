//! Repository layout helpers.
//!
//! Every path builder validates its newtype and its file name before joining,
//! so a valid [`RepositoryPaths`] can never produce a path outside the
//! repository root.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::error::ChainkeeperError;
use crate::ids::{AuthorityName, EventId, ProfileName, Serial};
use crate::records::CertificateStatus;

const AUTHORITY_FILES: [&str; 4] = ["cert.pem", "key.pem", "chain.pem", "authority.yaml"];
const CERTIFICATE_EXTENSIONS: [&str; 3] = ["pem", "yaml", "key.pem"];
const CRL_EXTENSIONS: [&str; 4] = ["crl.der", "crl.pem", "yaml", "number"];

fn file_component(value: &str, allowed: &[&str]) -> Result<(), ChainkeeperError> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(ChainkeeperError::storage(format!(
            "unsupported repository file name {value:?}"
        )))
    }
}

/// Permissions applied to atomically written files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileMode {
    /// Private key material, `0600` on Unix.
    Private,
    /// Public artifacts and metadata, `0644` on Unix.
    Public,
}

impl FileMode {
    /// Numeric Unix mode.
    #[must_use]
    pub const fn unix_mode(self) -> u32 {
        match self {
            Self::Private => 0o600,
            Self::Public => 0o644,
        }
    }
}

/// Atomically writes `bytes` to `destination`.
///
/// The bytes are written to a temporary file created in the destination
/// directory, flushed to disk, and renamed over the destination.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Storage`] when the parent directory is missing,
/// the write fails, or the temporary file cannot be persisted.
pub fn atomic_write(
    destination: &Path,
    bytes: &[u8],
    mode: FileMode,
) -> Result<(), ChainkeeperError> {
    let parent = destination.parent().ok_or_else(|| {
        ChainkeeperError::storage(format!(
            "destination {} has no parent directory",
            destination.display()
        ))
    })?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        ChainkeeperError::storage(format!(
            "could not create temporary file in {}: {error}",
            parent.display()
        ))
    })?;
    temporary.write_all(bytes).map_err(|error| {
        ChainkeeperError::storage(format!(
            "could not write temporary file in {}: {error}",
            parent.display()
        ))
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        ChainkeeperError::storage(format!(
            "could not flush temporary file in {}: {error}",
            parent.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(
            temporary.path(),
            std::fs::Permissions::from_mode(mode.unix_mode()),
        )
        .map_err(|error| {
            ChainkeeperError::storage(format!(
                "could not set permissions on temporary file: {error}"
            ))
        })?;
    }

    temporary.persist(destination).map_err(|error| {
        ChainkeeperError::storage(format!(
            "could not persist {}: {}",
            destination.display(),
            error.error
        ))
    })?;

    #[cfg(unix)]
    {
        // Best effort directory sync so the rename survives a crash.
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }

    Ok(())
}

/// Atomically writes `bytes` to `destination`, failing when it exists.
///
/// Like [`atomic_write`], the bytes are written to a temporary file in the
/// destination directory and persisted without overwriting an existing file.
/// Use this for append-only records whose file names are unique identifiers.
///
/// # Errors
///
/// Returns [`ChainkeeperError::AlreadyExists`] when `destination` already
/// exists, or [`ChainkeeperError::Storage`] on any other failure.
pub fn atomic_write_new(
    destination: &Path,
    bytes: &[u8],
    mode: FileMode,
) -> Result<(), ChainkeeperError> {
    let parent = destination.parent().ok_or_else(|| {
        ChainkeeperError::storage(format!(
            "destination {} has no parent directory",
            destination.display()
        ))
    })?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent).map_err(|error| {
        ChainkeeperError::storage(format!(
            "could not create temporary file in {}: {error}",
            parent.display()
        ))
    })?;
    temporary.write_all(bytes).map_err(|error| {
        ChainkeeperError::storage(format!(
            "could not write temporary file in {}: {error}",
            parent.display()
        ))
    })?;
    temporary.as_file().sync_all().map_err(|error| {
        ChainkeeperError::storage(format!(
            "could not flush temporary file in {}: {error}",
            parent.display()
        ))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(
            temporary.path(),
            std::fs::Permissions::from_mode(mode.unix_mode()),
        )
        .map_err(|error| {
            ChainkeeperError::storage(format!(
                "could not set permissions on temporary file: {error}"
            ))
        })?;
    }

    temporary.persist_noclobber(destination).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            ChainkeeperError::already_exists(format!("{} already exists", destination.display()))
        } else {
            ChainkeeperError::storage(format!(
                "could not persist {}: {}",
                destination.display(),
                error.error
            ))
        }
    })?;

    #[cfg(unix)]
    {
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }

    Ok(())
}

/// Paths inside one Chainkeeper repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryPaths {
    root: PathBuf,
}

impl RepositoryPaths {
    /// Creates path helpers for an existing repository root.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when `root` is not a directory.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, ChainkeeperError> {
        let root = root.into();
        if !root.is_dir() {
            return Err(ChainkeeperError::storage(format!(
                "repository root {} is not a directory",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    /// Repository root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `tenant.yaml`.
    #[must_use]
    pub fn tenant_yaml(&self) -> PathBuf {
        self.root.join("tenant.yaml")
    }

    /// `policy/`.
    #[must_use]
    pub fn policy_dir(&self) -> PathBuf {
        self.root.join("policy")
    }

    /// `policy/policy.yaml`.
    #[must_use]
    pub fn policy_yaml(&self) -> PathBuf {
        self.policy_dir().join("policy.yaml")
    }

    /// `profiles/`.
    #[must_use]
    pub fn profiles_dir(&self) -> PathBuf {
        self.root.join("profiles")
    }

    /// `profiles/<name>.yaml`.
    #[must_use]
    pub fn profile_path(&self, name: &ProfileName) -> PathBuf {
        self.profiles_dir().join(format!("{name}.yaml"))
    }

    /// `authorities/`.
    #[must_use]
    pub fn authorities_dir(&self) -> PathBuf {
        self.root.join("authorities")
    }

    /// `authorities/<name>/`.
    #[must_use]
    pub fn authority_dir(&self, name: &AuthorityName) -> PathBuf {
        self.authorities_dir().join(name.as_str())
    }

    /// `authorities/<name>/<file>` where `file` is one of the known authority
    /// files.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when `file` is not a known
    /// authority file name.
    pub fn authority_path(
        &self,
        name: &AuthorityName,
        file: &str,
    ) -> Result<PathBuf, ChainkeeperError> {
        file_component(file, &AUTHORITY_FILES)?;
        Ok(self.authority_dir(name).join(file))
    }

    /// `certificates/`.
    #[must_use]
    pub fn certificates_dir(&self) -> PathBuf {
        self.root.join("certificates")
    }

    /// `certificates/<status>/`.
    #[must_use]
    pub fn certificates_dir_for(&self, status: CertificateStatus) -> PathBuf {
        self.certificates_dir().join(status.as_str())
    }

    /// `certificates/<status>/<SERIAL>.<ext>` where `ext` is one of `pem`,
    /// `yaml`, or `key.pem`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when `ext` is not supported.
    pub fn certificate_path_in(
        &self,
        status: CertificateStatus,
        serial: &Serial,
        ext: &str,
    ) -> Result<PathBuf, ChainkeeperError> {
        file_component(ext, &CERTIFICATE_EXTENSIONS)?;
        Ok(self
            .certificates_dir_for(status)
            .join(format!("{serial}.{ext}")))
    }

    /// `certificates/active/<SERIAL>.<ext>`.
    ///
    /// Newly issued certificates always land in the active directory; use
    /// [`Self::certificate_path_in`] for revoked and expired directories.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when `ext` is not supported.
    pub fn certificate_path(
        &self,
        serial: &Serial,
        ext: &str,
    ) -> Result<PathBuf, ChainkeeperError> {
        self.certificate_path_in(CertificateStatus::Active, serial, ext)
    }

    /// `revocations/`.
    #[must_use]
    pub fn revocations_dir(&self) -> PathBuf {
        self.root.join("revocations")
    }

    /// `revocations/<SERIAL>.yaml`.
    #[must_use]
    pub fn revocation_path(&self, serial: &Serial) -> PathBuf {
        self.revocations_dir().join(format!("{serial}.yaml"))
    }

    /// `audit/`.
    #[must_use]
    pub fn audit_dir(&self) -> PathBuf {
        self.root.join("audit")
    }

    /// `audit/events/`.
    #[must_use]
    pub fn audit_events_dir(&self) -> PathBuf {
        self.audit_dir().join("events")
    }

    /// `audit/events/<ULID>.json`.
    #[must_use]
    pub fn audit_event_path(&self, id: &EventId) -> PathBuf {
        self.audit_events_dir().join(format!("{id}.json"))
    }

    /// `crls/`.
    #[must_use]
    pub fn crls_dir(&self) -> PathBuf {
        self.root.join("crls")
    }

    /// `crls/<authority>.<ext>` where `ext` is one of `crl.der`, `crl.pem`,
    /// `yaml`, or `number`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when `ext` is not supported.
    pub fn crl_path(
        &self,
        authority: &AuthorityName,
        ext: &str,
    ) -> Result<PathBuf, ChainkeeperError> {
        file_component(ext, &CRL_EXTENSIONS)?;
        Ok(self.crls_dir().join(format!("{authority}.{ext}")))
    }

    /// `crls/<authority>.number`.
    #[must_use]
    pub fn crl_number_path(&self, authority: &AuthorityName) -> PathBuf {
        self.crls_dir().join(format!("{authority}.number"))
    }

    /// `publish/`.
    #[must_use]
    pub fn publish_dir(&self) -> PathBuf {
        self.root.join("publish")
    }

    /// `cache/`.
    #[must_use]
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }

    /// `cache/index.sqlite`.
    #[must_use]
    pub fn index_path(&self) -> PathBuf {
        self.cache_dir().join("index.sqlite")
    }

    /// `.chainkeeper/`.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.root.join(".chainkeeper")
    }

    /// `.chainkeeper/lock`.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.state_dir().join("lock")
    }

    /// Directories required by a complete repository layout.
    #[must_use]
    pub fn required_directories(&self) -> Vec<PathBuf> {
        vec![
            self.policy_dir(),
            self.profiles_dir(),
            self.authorities_dir(),
            self.certificates_dir_for(CertificateStatus::Active),
            self.certificates_dir_for(CertificateStatus::Revoked),
            self.certificates_dir_for(CertificateStatus::Expired),
            self.revocations_dir(),
            self.crls_dir(),
            self.audit_events_dir(),
            self.publish_dir(),
            self.cache_dir(),
            self.state_dir(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::{FileMode, RepositoryPaths, atomic_write};
    use crate::ids::{AuthorityName, EventId, Serial};

    #[test]
    fn builders_stay_inside_the_repository() {
        let directory = tempfile::tempdir().expect("temp dir");
        let paths = RepositoryPaths::new(directory.path()).expect("valid root");
        let serial = Serial::from_str("00FF").expect("valid");
        let authority = AuthorityName::from_str("tls").expect("valid");
        let event = EventId::from_str("01J00000000000000000000001").expect("valid");

        for path in [
            paths.certificate_path(&serial, "pem").expect("known ext"),
            paths.revocation_path(&serial),
            paths
                .authority_path(&authority, "cert.pem")
                .expect("known file"),
            paths.audit_event_path(&event),
            paths.crl_path(&authority, "crl.der").expect("known ext"),
        ] {
            assert!(path.starts_with(paths.root()), "{}", path.display());
        }
    }

    #[test]
    fn unknown_file_names_are_rejected() {
        let directory = tempfile::tempdir().expect("temp dir");
        let paths = RepositoryPaths::new(directory.path()).expect("valid root");
        let serial = Serial::from_str("00FF").expect("valid");
        let authority = AuthorityName::from_str("tls").expect("valid");
        assert!(paths.certificate_path(&serial, "../x").is_err());
        assert!(paths.authority_path(&authority, "../x").is_err());
        assert!(paths.crl_path(&authority, "key.pem").is_err());
    }

    #[test]
    fn atomic_write_sets_private_permissions() {
        let directory = tempfile::tempdir().expect("temp dir");
        let destination = directory.path().join("key.pem");
        atomic_write(&destination, b"secret", FileMode::Private).expect("write succeeds");
        assert_eq!(std::fs::read(&destination).expect("readable"), b"secret");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = std::fs::metadata(&destination)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn missing_root_is_rejected() {
        assert!(RepositoryPaths::new("/nonexistent/chainkeeper-root").is_err());
    }
}
