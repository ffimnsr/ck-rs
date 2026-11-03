//! Commit signing support.
//!
//! `git2` can attach a signature to a commit buffer but does not invoke a
//! signing program. This module bridges that gap with a narrow [`CommitSigner`]
//! boundary so product code and tests can select the same code path.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use chainkeeper_core::ChainkeeperError;
use git2::Repository;

/// Produces an armored detached signature over commit content.
pub trait CommitSigner: Send + Sync {
    /// Signs `content` and returns the armored signature.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when signing is unavailable or fails.
    fn sign(&self, content: &[u8]) -> Result<String, ChainkeeperError>;
}

/// Returns true when `commit.gpgsign` is enabled for the repository.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Git`] when Git config cannot be read.
pub fn signing_enabled(repository: &Repository) -> Result<bool, ChainkeeperError> {
    let config = repository
        .config()
        .map_err(|error| ChainkeeperError::git(format!("could not read git config: {error}")))?;
    match config.get_bool("commit.gpgsign") {
        Ok(enabled) => Ok(enabled),
        Err(error) if error.code() == git2::ErrorCode::NotFound => Ok(false),
        Err(error) => Err(ChainkeeperError::git(format!(
            "could not read commit.gpgsign: {error}"
        ))),
    }
}

/// GPG backed signer using the configured program and signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgCommitSigner {
    program: String,
    key: Option<String>,
    homedir: Option<PathBuf>,
}

impl GpgCommitSigner {
    /// Builds a signer with an explicit program and key.
    #[must_use]
    pub fn new(program: impl Into<String>, key: Option<String>) -> Self {
        Self {
            program: program.into(),
            key,
            homedir: None,
        }
    }

    /// Overrides the GPG home directory. Used by tests with a throwaway keyring.
    #[must_use]
    pub fn with_homedir(mut self, homedir: impl Into<PathBuf>) -> Self {
        self.homedir = Some(homedir.into());
        self
    }
    /// Builds a signer from `gpg.program` and `user.signingkey`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the configuration cannot be read.
    pub fn from_repository(repository: &Repository) -> Result<Self, ChainkeeperError> {
        let config = repository.config().map_err(|error| {
            ChainkeeperError::git(format!("could not read git config: {error}"))
        })?;
        let program = config
            .get_string("gpg.program")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "gpg".to_owned());
        let key = config
            .get_string("user.signingkey")
            .ok()
            .filter(|value| !value.trim().is_empty());
        Ok(Self {
            program,
            key,
            homedir: None,
        })
    }

    /// Signing program path.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// Configured signing key, if any.
    #[must_use]
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }
}

impl CommitSigner for GpgCommitSigner {
    fn sign(&self, content: &[u8]) -> Result<String, ChainkeeperError> {
        let mut command = Command::new(&self.program);
        command
            .arg("--batch")
            .arg("--armor")
            .arg("--detach-sign")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(key) = &self.key {
            command.arg("--local-user").arg(key);
        }
        if let Some(homedir) = &self.homedir {
            command.arg("--homedir").arg(homedir);
        }

        let mut child = command.spawn().map_err(|error| {
            ChainkeeperError::git(format!(
                "could not start commit signer {:?}: {error}",
                self.program
            ))
        })?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| ChainkeeperError::git("commit signer did not expose standard input"))?;
        stdin.write_all(content).map_err(|error| {
            ChainkeeperError::git(format!("could not write to commit signer: {error}"))
        })?;
        drop(stdin);

        let output = child.wait_with_output().map_err(|error| {
            ChainkeeperError::git(format!("could not wait for commit signer: {error}"))
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ChainkeeperError::git(format!(
                "commit signing failed: {}",
                stderr.trim()
            )));
        }
        String::from_utf8(output.stdout).map_err(|error| {
            ChainkeeperError::git(format!("commit signer returned invalid UTF-8: {error}"))
        })
    }
}
