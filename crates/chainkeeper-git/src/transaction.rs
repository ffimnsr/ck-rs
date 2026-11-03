//! Repository transaction boundary.

use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chainkeeper_core::{ChainkeeperError, GitRepository, LockGuard, RepositoryLock};

use crate::repo::GitRepo;

/// Default wait for the repository lock.
pub const DEFAULT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);

fn git(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::git(message)
}

/// Mutating operation that holds the repository lock until it finishes.
///
/// Dropping a transaction without committing releases the lock and leaves every
/// file in place for inspection. Created files are only removed by an explicit
/// [`RepositoryTransaction::rollback_created`].
#[derive(Debug)]
pub struct RepositoryTransaction {
    repo: GitRepo,
    lock: LockGuard,
    staged: BTreeSet<PathBuf>,
    created: Vec<PathBuf>,
    committed: bool,
}

impl RepositoryTransaction {
    /// Acquires the exclusive lock and starts a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Lock`] when the lock cannot be acquired.
    pub fn begin(
        repo: GitRepo,
        lock: &dyn RepositoryLock,
        timeout: Duration,
    ) -> Result<Self, ChainkeeperError> {
        let guard = lock.acquire_exclusive(timeout)?;
        Ok(Self {
            repo,
            lock: guard,
            staged: BTreeSet::new(),
            created: Vec::new(),
            committed: false,
        })
    }

    /// Schedules a path for the next commit.
    ///
    /// The path is validated immediately. Missing-path validation happens when
    /// [`RepositoryTransaction::commit`] runs, so a caller may stage a file it is
    /// about to create.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the path escapes the repository.
    pub fn stage_path(&mut self, path: impl AsRef<Path>) -> Result<(), ChainkeeperError> {
        let relative = self.repo.relative_path(path.as_ref())?;
        self.staged.insert(relative);
        Ok(())
    }

    /// Records a path that this transaction created, for rollback.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the path escapes the repository.
    pub fn track_created(&mut self, path: impl AsRef<Path>) -> Result<(), ChainkeeperError> {
        let relative = self.repo.relative_path(path.as_ref())?;
        if !self.created.contains(&relative) {
            self.created.push(relative);
        }
        Ok(())
    }

    /// Records and stages a file that this transaction created.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the path escapes the repository.
    pub fn stage_created(&mut self, path: impl AsRef<Path>) -> Result<(), ChainkeeperError> {
        self.track_created(path.as_ref())?;
        self.stage_path(path.as_ref())
    }

    /// Paths scheduled for the next commit, relative to the repository root.
    #[must_use]
    pub fn staged_paths(&self) -> Vec<&Path> {
        self.staged.iter().map(PathBuf::as_path).collect()
    }

    /// Whether this transaction has committed.
    #[must_use]
    pub const fn committed(&self) -> bool {
        self.committed
    }

    /// Commits the staged paths and returns the commit SHA.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when a staged path is missing or the
    /// commit fails.
    pub fn commit(&mut self, message: &str) -> Result<String, ChainkeeperError> {
        if self.staged.is_empty() {
            return Err(git("transaction has no staged paths"));
        }
        let paths: Vec<PathBuf> = self.staged.iter().cloned().collect();
        let oid = self.repo.commit(message, &paths)?;
        self.committed = true;
        Ok(oid)
    }

    /// Deletes files created by this transaction.
    ///
    /// Pre-existing files are never tracked as created, so they are untouched.
    /// Paths that have already disappeared are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when a created file cannot be removed.
    pub fn rollback_created(&mut self) -> Result<Vec<PathBuf>, ChainkeeperError> {
        let mut removed = Vec::new();
        for relative in &self.created {
            let absolute = self.repo.root().join(relative);
            match fs::remove_file(&absolute) {
                Ok(()) => removed.push(relative.clone()),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(git(format!(
                        "could not roll back {}: {error}",
                        absolute.display()
                    )));
                }
            }
        }
        self.created.clear();
        Ok(removed)
    }

    /// Releases the lock without committing. Files remain on disk.
    pub fn release(self) {
        self.lock.release();
    }
}
