//! Exclusive repository locking.
//!
//! The lock is advisory and filesystem backed. Concurrent writers that follow
//! the contract acquire it before touching canonical records.

use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::time::{Duration, Instant};

use chainkeeper_core::{ChainkeeperError, LockGuard, RepositoryLock, RepositoryPaths};
use fs2::FileExt;

use crate::fsutil;

/// Retry interval used while waiting for the lock.
const RETRY_INTERVAL: Duration = Duration::from_millis(25);

/// Lock backed by `.chainkeeper/lock`.
#[derive(Debug, Clone)]
pub struct FileRepositoryLock {
    paths: RepositoryPaths,
}

impl FileRepositoryLock {
    /// Creates a lock helper for a repository.
    #[must_use]
    pub const fn new(paths: RepositoryPaths) -> Self {
        Self { paths }
    }

    /// Path of the lock file.
    #[must_use]
    pub fn path(&self) -> std::path::PathBuf {
        self.paths.lock_path()
    }

    fn open_lock_file(&self) -> Result<File, ChainkeeperError> {
        let state_dir = self.paths.state_dir();
        fsutil::ensure_directory(&state_dir)?;
        let lock_path = self.paths.lock_path();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|error| {
                ChainkeeperError::lock(format!(
                    "could not open lock file {}: {error}",
                    lock_path.display()
                ))
            })?;
        fsutil::set_mode(&lock_path, 0o600)?;
        Ok(file)
    }
}

impl RepositoryLock for FileRepositoryLock {
    fn acquire_exclusive(&self, timeout: Duration) -> Result<LockGuard, ChainkeeperError> {
        let file = self.open_lock_file()?;
        let deadline = Instant::now() + timeout;
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => {
                    let path = self.paths.lock_path();
                    let guard = LockGuard::new(Some(path), move || {
                        let _ = FileExt::unlock(&file);
                    });
                    return Ok(guard);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(ChainkeeperError::lock(format!(
                            "timed out after {timeout:?} waiting for {}",
                            self.paths.lock_path().display()
                        )));
                    }
                    std::thread::sleep(RETRY_INTERVAL);
                }
                Err(error) => {
                    return Err(ChainkeeperError::lock(format!(
                        "could not lock {}: {error}",
                        self.paths.lock_path().display()
                    )));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use chainkeeper_core::{RepositoryLock, RepositoryPaths};

    use super::FileRepositoryLock;

    fn lock_for(root: &std::path::Path) -> FileRepositoryLock {
        FileRepositoryLock::new(RepositoryPaths::new(root).expect("root"))
    }

    #[test]
    fn contention_times_out_and_release_frees_the_lock() {
        let directory = tempfile::tempdir().expect("temp dir");
        let lock = Arc::new(lock_for(directory.path()));
        let held = lock
            .acquire_exclusive(Duration::from_millis(10))
            .expect("first lock");

        let contender = Arc::clone(&lock);
        let thread =
            std::thread::spawn(move || contender.acquire_exclusive(Duration::from_millis(100)));
        let error = thread
            .join()
            .expect("thread")
            .expect_err("second acquisition times out");
        assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Lock);

        held.release();
        lock.acquire_exclusive(Duration::from_millis(100))
            .expect("lock is free after release")
            .release();
    }

    #[test]
    fn panic_releases_the_lock() {
        let directory = tempfile::tempdir().expect("temp dir");
        let lock = Arc::new(lock_for(directory.path()));
        let panicking = Arc::clone(&lock);
        let thread = std::thread::spawn(move || {
            let _guard = panicking
                .acquire_exclusive(Duration::from_millis(100))
                .expect("lock acquired");
            panic!("intentional panic while holding the lock");
        });
        assert!(thread.join().is_err());

        lock.acquire_exclusive(Duration::from_millis(100))
            .expect("lock is free after panic")
            .release();
    }
}
