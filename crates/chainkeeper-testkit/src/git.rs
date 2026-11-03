//! In-memory Git repository.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use chainkeeper_core::{ChainkeeperError, GitChange, GitChangeKind, GitRepository, GitStatus};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
struct FakeCommit {
    oid: String,
    message: String,
    paths: Vec<PathBuf>,
}

/// Git repository that keeps commits in memory.
#[derive(Debug, Default)]
pub struct InMemoryGitRepository {
    commits: RwLock<Vec<FakeCommit>>,
}

impl InMemoryGitRepository {
    /// Creates an empty repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every recorded commit in order.
    ///
    /// # Errors
    ///
    /// Never fails; provided so tests can inspect state without locking.
    pub fn commits(&self) -> Result<Vec<(String, String)>, ChainkeeperError> {
        Ok(self
            .commits
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|commit| (commit.oid.clone(), commit.message.clone()))
            .collect())
    }
}

fn commit_oid(index: usize, message: &str, paths: &[PathBuf]) -> String {
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    hasher.update(message.as_bytes());
    for path in paths {
        hasher.update(path.to_string_lossy().as_bytes());
    }
    let digest = hasher.finalize();
    let mut oid = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Writing to a `String` cannot fail.
        let _ = write!(oid, "{byte:02x}");
    }
    oid
}

impl GitRepository for InMemoryGitRepository {
    fn init(&self, _path: &Path) -> Result<(), ChainkeeperError> {
        // Mirror the production repository, which creates the initial commit.
        self.commit("feat(ck): initialize repository", &[])?;
        Ok(())
    }

    fn head_commit(&self) -> Result<String, ChainkeeperError> {
        self.commits
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last()
            .map(|commit| commit.oid.clone())
            .ok_or_else(|| ChainkeeperError::not_found("commit", "HEAD"))
    }

    fn commit(&self, message: &str, paths: &[PathBuf]) -> Result<String, ChainkeeperError> {
        let mut commits = self
            .commits
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let oid = commit_oid(commits.len(), message, paths);
        commits.push(FakeCommit {
            oid: oid.clone(),
            message: message.to_owned(),
            paths: paths.to_vec(),
        });
        drop(commits);
        Ok(oid)
    }

    fn diff(&self, from: &str, to: &str) -> Result<Vec<GitChange>, ChainkeeperError> {
        let commits = self
            .commits
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let from_index = commits
            .iter()
            .position(|commit| commit.oid == from)
            .ok_or_else(|| ChainkeeperError::not_found("commit", from))?;
        let to_index = commits
            .iter()
            .position(|commit| commit.oid == to)
            .ok_or_else(|| ChainkeeperError::not_found("commit", to))?;
        if from_index > to_index {
            return Err(ChainkeeperError::git("diff range is reversed"));
        }
        Ok(commits[from_index + 1..=to_index]
            .iter()
            .flat_map(|commit| commit.paths.iter())
            .map(|path| GitChange {
                path: path.clone(),
                kind: GitChangeKind::Added,
            })
            .collect())
    }

    fn status(&self) -> Result<GitStatus, ChainkeeperError> {
        let head = self.head_commit().ok();
        Ok(GitStatus {
            branch: Some("main".to_owned()),
            head,
            clean: true,
            changes: Vec::new(),
            untracked: Vec::new(),
        })
    }

    fn is_clean(&self) -> Result<bool, ChainkeeperError> {
        Ok(true)
    }
}
