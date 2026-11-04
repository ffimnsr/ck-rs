//! Remote fetch and fast-forward.
//!
//! The read-only server polls the repository for new commits. When remote
//! synchronisation is enabled it may only move the working tree forward: a
//! dirty tree or a diverged history is refused instead of being reset.

use std::fmt;

use chainkeeper_core::{ChainkeeperError, GitRepository};
use git2::ResetType;

use crate::repo::GitRepo;

/// Result of a remote synchronisation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Whether the working tree moved to a new commit.
    pub changed: bool,
    /// Commit the working tree points at after synchronisation.
    pub commit: String,
}

fn git(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::git(message)
}

fn validate_branch(branch: &str) -> Result<(), ChainkeeperError> {
    if branch.is_empty() || branch.starts_with('-') || branch.contains("..") {
        return Err(git("branch name is invalid"));
    }
    if branch
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(git("branch name is invalid"));
    }
    Ok(())
}

impl fmt::Display for SyncOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({})",
            self.commit,
            if self.changed {
                "fast-forwarded"
            } else {
                "unchanged"
            }
        )
    }
}

impl GitRepo {
    /// Fetches `remote` and fast-forwards `branch`.
    ///
    /// The working tree must be clean. A remote history that is not a
    /// descendant of the local `HEAD` is rejected, so synchronisation can never
    /// discard local commits.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the tree is dirty, the remote
    /// cannot be fetched, or the update is not a fast-forward.
    pub fn fetch_and_fast_forward(
        &self,
        remote: &str,
        branch: &str,
    ) -> Result<SyncOutcome, ChainkeeperError> {
        if remote.is_empty() {
            return Err(git("remote name must not be empty"));
        }
        validate_branch(branch)?;
        if !GitRepository::is_clean(self)? {
            return Err(git(
                "working tree is dirty; refusing to synchronise remote changes",
            ));
        }

        let repository = self.repository()?;
        let head = repository
            .head()
            .and_then(|head| head.peel_to_commit())
            .map_err(|error| git(format!("could not read HEAD: {error}")))?;

        let mut handle = repository
            .find_remote(remote)
            .map_err(|error| git(format!("could not find remote {remote}: {error}")))?;
        let tracking = format!("refs/remotes/{remote}/{branch}");
        let refspec = format!("refs/heads/{branch}:{tracking}");
        handle
            .fetch(&[refspec.as_str()], None, None)
            .map_err(|error| git(format!("could not fetch {remote}/{branch}: {error}")))?;

        let fetched = repository
            .refname_to_id(&tracking)
            .map_err(|error| git(format!("could not read {tracking}: {error}")))?;

        if fetched == head.id() {
            return Ok(SyncOutcome {
                changed: false,
                commit: fetched.to_string(),
            });
        }

        let fast_forward = repository
            .graph_descendant_of(fetched, head.id())
            .map_err(|error| git(format!("could not compare histories: {error}")))?;
        if !fast_forward {
            return Err(git(format!(
                "remote {remote}/{branch} is not a fast-forward of HEAD"
            )));
        }

        let object = repository
            .find_object(fetched, None)
            .map_err(|error| git(format!("could not read fetched commit: {error}")))?;
        repository
            .reset(&object, ResetType::Hard, None)
            .map_err(|error| git(format!("could not fast-forward working tree: {error}")))?;

        Ok(SyncOutcome {
            changed: true,
            commit: fetched.to_string(),
        })
    }
}
