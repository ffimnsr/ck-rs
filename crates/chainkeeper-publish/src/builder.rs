//! File-backed publish builder.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use chainkeeper_core::{
    AuthorityKind, AuthorityMaterial, AuthorityName, ChainkeeperError, PublishBuilder,
    PublishManifest, PublishOptions,
};

use crate::deps::PublishDependencies;
use crate::diff::ChangedPaths;
use crate::{MANIFEST_FILE, fsops, manifest, validate};

/// Publish builder that renders public artifacts into a destination directory.
pub struct FilePublishBuilder {
    deps: PublishDependencies,
}

impl std::fmt::Debug for FilePublishBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FilePublishBuilder")
            .field("root", &self.deps.paths.root())
            .field("allowed_root", &self.deps.allowed_root)
            .finish_non_exhaustive()
    }
}

impl FilePublishBuilder {
    /// Creates a builder from its dependency bundle.
    #[must_use]
    pub const fn new(deps: PublishDependencies) -> Self {
        Self { deps }
    }

    /// Returns the artifact paths that differ between two manifests.
    #[must_use]
    pub fn changed_paths(previous: &PublishManifest, next: &PublishManifest) -> ChangedPaths {
        crate::diff::changed_paths(previous, next)
    }

    fn ensure_destination(&self, destination: &Path) -> Result<(), ChainkeeperError> {
        if destination
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(ChainkeeperError::publish(format!(
                "publish destination {} must not traverse directories",
                destination.display()
            )));
        }
        match std::fs::symlink_metadata(destination) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ChainkeeperError::publish(format!(
                    "publish destination {} is a symlink",
                    destination.display()
                )));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(ChainkeeperError::publish(format!(
                    "publish destination {} is not a directory",
                    destination.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ChainkeeperError::publish(format!(
                    "could not inspect {}: {error}",
                    destination.display()
                )));
            }
        }

        let allowed_root = self.deps.allowed_root.canonicalize().map_err(|error| {
            ChainkeeperError::publish(format!(
                "could not resolve allowed publish root {}: {error}",
                self.deps.allowed_root.display()
            ))
        })?;
        let candidate = canonical_candidate(destination).ok_or_else(|| {
            ChainkeeperError::publish(format!(
                "could not resolve publish destination {}",
                destination.display()
            ))
        })?;
        if !candidate.starts_with(&allowed_root) {
            return Err(ChainkeeperError::publish(format!(
                "publish destination {} is outside {}",
                destination.display(),
                self.deps.allowed_root.display()
            )));
        }
        Ok(())
    }

    fn load_materials(
        &self,
    ) -> Result<BTreeMap<AuthorityName, AuthorityMaterial>, ChainkeeperError> {
        let mut materials = BTreeMap::new();
        for authority in self.deps.store.list_authorities()? {
            let material = self
                .deps
                .store
                .load_authority(&authority.name)?
                .ok_or_else(|| {
                    ChainkeeperError::publish(format!(
                        "authority {} is listed but its material cannot be loaded",
                        authority.name
                    ))
                })?;
            materials.insert(authority.name, material);
        }
        Ok(materials)
    }

    fn collect_artifacts(
        &self,
        materials: &BTreeMap<AuthorityName, AuthorityMaterial>,
    ) -> Result<BTreeMap<PathBuf, Vec<u8>>, ChainkeeperError> {
        let mut artifacts = BTreeMap::new();

        let root = materials
            .values()
            .find(|material| material.config.kind == AuthorityKind::Root)
            .ok_or_else(|| ChainkeeperError::publish("repository has no root authority"))?;
        artifacts.insert(PathBuf::from("root.pem"), root.cert_pem.as_bytes().to_vec());

        for (name, material) in materials {
            if material.config.kind == AuthorityKind::Intermediate {
                artifacts.insert(
                    PathBuf::from(format!("intermediates/{name}.pem")),
                    material.cert_pem.as_bytes().to_vec(),
                );
                artifacts.insert(
                    PathBuf::from(format!("aia/{name}.pem")),
                    material.cert_pem.as_bytes().to_vec(),
                );
            }
        }
        artifacts.insert(
            PathBuf::from(format!("aia/{}.pem", root.config.name)),
            root.cert_pem.as_bytes().to_vec(),
        );

        for certificate in self.deps.store.list_certificates()? {
            let relative = fsops::safe_relative(&certificate.path)?;
            let pem = fsops::read_optional(&self.deps.paths.root().join(&relative))?.ok_or_else(
                || {
                    ChainkeeperError::publish(format!(
                        "certificate {} is missing its PEM at {}",
                        certificate.serial,
                        relative.display()
                    ))
                },
            )?;
            let authority = materials.get(&certificate.authority).ok_or_else(|| {
                ChainkeeperError::publish(format!(
                    "certificate {} references unknown authority {}",
                    certificate.serial, certificate.authority
                ))
            })?;
            let mut chain = pem;
            if !chain.ends_with(b"\n") {
                chain.push(b'\n');
            }
            chain.extend_from_slice(authority.chain_pem.as_bytes());
            artifacts.insert(
                PathBuf::from(format!(
                    "chains/{}/{}.pem",
                    certificate.profile.as_str(),
                    certificate.serial.as_str()
                )),
                chain,
            );
        }

        for name in materials.keys() {
            let der_path = self.deps.paths.crl_path(name, "crl.der")?;
            if let Some(bytes) = fsops::read_optional(&der_path)? {
                artifacts.insert(PathBuf::from(format!("crl/{name}.crl")), bytes);
            }
            let pem_path = self.deps.paths.crl_path(name, "crl.pem")?;
            if let Some(bytes) = fsops::read_optional(&pem_path)? {
                artifacts.insert(PathBuf::from(format!("crl/{name}.crl.pem")), bytes);
            }
        }

        Ok(artifacts)
    }

    fn write_tree(
        directory: &Path,
        artifacts: &BTreeMap<PathBuf, Vec<u8>>,
        manifest: &PublishManifest,
    ) -> Result<(), ChainkeeperError> {
        for (path, bytes) in artifacts {
            let destination = directory.join(fsops::safe_relative(path)?);
            fsops::ensure_parent(&destination)?;
            fsops::write_file(&destination, bytes)?;
        }
        fsops::write_file(&directory.join(MANIFEST_FILE), &manifest::render(manifest)?)
    }

    fn install(
        &self,
        source: &Path,
        destination: &Path,
        manifest: &PublishManifest,
    ) -> Result<(), ChainkeeperError> {
        self.ensure_destination(destination)?;
        fsops::create_directory(destination)?;

        let mut keep = BTreeSet::new();
        keep.insert(PathBuf::from(MANIFEST_FILE));
        for artifact in &manifest.artifacts {
            let relative = fsops::safe_relative(&artifact.path)?;
            fsops::move_file(&source.join(&relative), &destination.join(&relative))?;
            keep.insert(relative);
        }
        fsops::move_file(
            &source.join(MANIFEST_FILE),
            &destination.join(MANIFEST_FILE),
        )?;
        fsops::prune(destination, &keep)
    }
}

impl PublishBuilder for FilePublishBuilder {
    fn build(&self, options: &PublishOptions) -> Result<PublishManifest, ChainkeeperError> {
        self.ensure_destination(&options.output_dir)?;
        let tenant = self.deps.store.load_tenant()?;
        let materials = self.load_materials()?;
        let artifacts = self.collect_artifacts(&materials)?;
        let generated_at = self.deps.clock.now();
        let source_commit = self.deps.git.head_commit().ok();
        let manifest = manifest::build(&artifacts, generated_at, source_commit, tenant.tenant_id)?;

        let parent = options.output_dir.parent().ok_or_else(|| {
            ChainkeeperError::publish(format!(
                "publish destination {} has no parent directory",
                options.output_dir.display()
            ))
        })?;
        fsops::create_directory(parent)?;
        let temporary = tempfile::Builder::new()
            .prefix(".chainkeeper-publish-")
            .tempdir_in(parent)
            .map_err(|error| {
                ChainkeeperError::publish(format!(
                    "could not create temporary publish directory in {}: {error}",
                    parent.display()
                ))
            })?;

        Self::write_tree(temporary.path(), &artifacts, &manifest)?;
        validate::validate_tree(temporary.path(), &manifest)?;
        self.install(temporary.path(), &options.output_dir, &manifest)?;
        Ok(manifest)
    }

    fn validate_publish_dir(&self, path: &Path) -> Result<(), ChainkeeperError> {
        validate::validate_directory(path)
    }
}

fn canonical_candidate(path: &Path) -> Option<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    if path.exists() {
        return path.canonicalize().ok();
    }
    let parent = path.parent()?;
    let name = path.file_name()?;
    let parent = parent.canonicalize().ok()?;
    Some(parent.join(name))
}
