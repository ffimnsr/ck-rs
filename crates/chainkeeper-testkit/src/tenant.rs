//! Temporary repository layout for tests.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use chainkeeper_core::{ChainkeeperError, RepositoryPaths};
use tempfile::TempDir;

static NEXT_TENANT: AtomicU64 = AtomicU64::new(0);

/// Temporary directory containing a complete repository layout.
#[derive(Debug)]
pub struct TempTenant {
    directory: TempDir,
    paths: RepositoryPaths,
}

impl TempTenant {
    /// Creates a temporary repository with every required directory.
    ///
    /// The directory prefix contains the process id and a per-process counter so
    /// parallel test binaries and parallel tests never collide.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Storage`] when the temporary directory or a
    /// layout directory cannot be created.
    pub fn new() -> Result<Self, ChainkeeperError> {
        let sequence = NEXT_TENANT.fetch_add(1, Ordering::Relaxed);
        let prefix = format!("chainkeeper-{}-{sequence}", std::process::id());
        let directory = tempfile::Builder::new()
            .prefix(&prefix)
            .tempdir()
            .map_err(|error| {
                ChainkeeperError::storage(format!("could not create temp tenant: {error}"))
            })?;
        let paths = RepositoryPaths::new(directory.path())?;
        for required in paths.required_directories() {
            std::fs::create_dir_all(&required)?;
        }
        Ok(Self { directory, paths })
    }

    /// Temporary directory root.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.directory.path()
    }

    /// Repository layout helpers.
    #[must_use]
    pub const fn paths(&self) -> &RepositoryPaths {
        &self.paths
    }
}
