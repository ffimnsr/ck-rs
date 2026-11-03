//! File-backed CRL manager.

use std::path::PathBuf;

use chainkeeper_core::{
    AuditAction, AuthorityKind, AuthorityName, CONFIG_VERSION, ChainkeeperError, CrlBundle,
    CrlManager, CrlRecord, CrlRequest, IndexedCrl, NewAuditEvent, RevocationRecord,
};
use time::Duration;

use crate::deps::CrlDependencies;
use crate::{fsops, manifest};

/// Validity window applied to every generated CRL.
const CRL_VALIDITY_DAYS: i64 = 7;

/// Actor recorded on generated CRL audit events.
const ACTOR: &str = "ck";

/// CRL manager that writes canonical CRL files into the repository.
pub struct FileCrlManager {
    deps: CrlDependencies,
}

impl std::fmt::Debug for FileCrlManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileCrlManager")
            .field("root", &self.deps.paths.root())
            .finish_non_exhaustive()
    }
}

impl FileCrlManager {
    /// Creates a manager from its dependency bundle.
    #[must_use]
    pub const fn new(deps: CrlDependencies) -> Self {
        Self { deps }
    }

    /// Returns the next CRL number for `authority`.
    ///
    /// A missing number file starts at one. A file containing zero or a
    /// non-integer is rejected rather than silently reset.
    fn next_number(&self, authority: &AuthorityName) -> Result<u64, ChainkeeperError> {
        let path = self.deps.paths.crl_number_path(authority);
        let current = match std::fs::read_to_string(&path) {
            Ok(value) => {
                let parsed = value.trim().parse::<u64>().map_err(|error| {
                    ChainkeeperError::storage(format!(
                        "could not parse CRL number {}: {error}",
                        path.display()
                    ))
                })?;
                if parsed == 0 {
                    return Err(ChainkeeperError::storage(format!(
                        "CRL number {} must be positive",
                        path.display()
                    )));
                }
                parsed
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => {
                return Err(ChainkeeperError::storage(format!(
                    "could not read {}: {error}",
                    path.display()
                )));
            }
        };
        current
            .checked_add(1)
            .ok_or_else(|| ChainkeeperError::storage("CRL number overflow"))
    }

    fn write_bundle(
        &self,
        bundle: &CrlBundle,
        sha256: &str,
    ) -> Result<CrlRecord, ChainkeeperError> {
        let der_path = self
            .deps
            .paths
            .crl_path(&bundle.record.authority, "crl.der")?;
        let pem_path = self
            .deps
            .paths
            .crl_path(&bundle.record.authority, "crl.pem")?;
        fsops::write_file(&der_path, &bundle.der)?;
        fsops::write_file(&pem_path, bundle.pem.as_bytes())?;

        let mut stored = bundle.record.clone();
        stored.der_path = fsops::relative_to(self.deps.paths.root(), &der_path)?;
        stored.pem_path = fsops::relative_to(self.deps.paths.root(), &pem_path)?;

        let yaml_path = self.deps.paths.crl_path(&stored.authority, "yaml")?;
        let rendered = serde_yaml_ng::to_string(&stored).map_err(|error| {
            ChainkeeperError::storage(format!(
                "could not serialize CRL metadata {}: {error}",
                yaml_path.display()
            ))
        })?;
        fsops::write_file(&yaml_path, rendered.as_bytes())?;

        fsops::write_file(
            &self.deps.paths.crl_number_path(&stored.authority),
            format!("{}\n", stored.number).as_bytes(),
        )?;

        self.deps.audit.append(
            NewAuditEvent::new(
                stored.this_update,
                AuditAction::CrlGenerated,
                "crl",
                stored.authority.as_str(),
                format!(
                    "generated CRL {} for authority {}",
                    stored.number, stored.authority
                ),
                ACTOR,
            )
            .with_details(serde_json::json!({
                "number": stored.number,
                "revoked_count": stored.revoked_serials.len(),
            })),
        )?;

        self.deps.index.upsert_crl(&IndexedCrl {
            record: stored.clone(),
            sha256: sha256.to_owned(),
        })?;

        Ok(stored)
    }
}

impl CrlManager for FileCrlManager {
    fn update_for_authority(
        &self,
        authority: &AuthorityName,
    ) -> Result<CrlBundle, ChainkeeperError> {
        let material = self
            .deps
            .store
            .load_authority(authority)?
            .ok_or_else(|| ChainkeeperError::not_found("authority", authority.as_str()))?;
        if material.config.kind == AuthorityKind::OcspSigner {
            return Err(ChainkeeperError::validation(format!(
                "authority {authority} is an OCSP signer and cannot sign a CRL"
            )));
        }

        let revocations = self
            .deps
            .store
            .list_revocations()?
            .into_iter()
            .filter(|revocation| &revocation.authority == authority)
            .collect::<Vec<RevocationRecord>>();

        let number = self.next_number(authority)?;
        let this_update = self.deps.clock.now();
        let request = CrlRequest {
            authority: authority.clone(),
            number,
            this_update,
            next_update: this_update + Duration::days(CRL_VALIDITY_DAYS),
            revocations,
        };

        let provider = self.deps.providers.provider_for(authority)?;
        let signer = self.deps.signers.signer_for(authority)?;
        let mut bundle = provider.generate_crl(&request, signer.as_ref())?;
        if bundle.record.number == 0 {
            return Err(ChainkeeperError::crypto(
                "certificate provider returned CRL number zero",
            ));
        }
        if bundle.record.version != CONFIG_VERSION {
            return Err(ChainkeeperError::crypto(format!(
                "certificate provider returned unsupported CRL version {}",
                bundle.record.version
            )));
        }
        bundle.record.authority = authority.clone();

        let sha256 = manifest::sha256_hex(&bundle.der);
        let stored = self.write_bundle(&bundle, &sha256)?;
        bundle.record = stored;
        Ok(bundle)
    }

    fn list_crls(&self) -> Result<Vec<CrlRecord>, ChainkeeperError> {
        let mut records = Vec::new();
        for path in fsops::sorted_entries(&self.deps.paths.crls_dir())? {
            let is_yaml = path
                .extension()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("yaml"));
            if !is_yaml {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|error| {
                ChainkeeperError::storage(format!("could not read {}: {error}", path.display()))
            })?;
            let record: CrlRecord = serde_yaml_ng::from_slice(&bytes).map_err(|error| {
                ChainkeeperError::storage(format!("could not parse {}: {error}", path.display()))
            })?;
            if record.version != CONFIG_VERSION {
                return Err(ChainkeeperError::storage(format!(
                    "CRL {} uses unsupported version {}",
                    path.display(),
                    record.version
                )));
            }
            records.push(record);
        }
        records.sort_by(|left, right| left.authority.cmp(&right.authority));
        Ok(records)
    }
}

/// Returns the canonical CRL file paths for `authority`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Storage`] when a path cannot be built.
pub fn crl_paths(
    paths: &chainkeeper_core::RepositoryPaths,
    authority: &AuthorityName,
) -> Result<Vec<PathBuf>, ChainkeeperError> {
    let files = vec![
        paths.crl_path(authority, "crl.der")?,
        paths.crl_path(authority, "crl.pem")?,
        paths.crl_path(authority, "yaml")?,
        paths.crl_number_path(authority),
    ];
    Ok(files)
}
