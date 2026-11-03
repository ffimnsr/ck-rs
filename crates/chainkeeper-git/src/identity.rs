//! Git commit identity resolution.

use std::env;
use std::fmt;

use chainkeeper_core::ChainkeeperError;
use git2::{Repository, Signature};

/// Author and committer identity used for commits.
#[derive(Clone, PartialEq, Eq)]
pub struct GitIdentity {
    name: String,
    email: String,
}

impl GitIdentity {
    /// Validates and builds an identity.
    ///
    /// # Errors
    ///
    /// Returns [`ChainkeeperError::Git`] when the name is blank or the email is
    /// not a bare `local@domain` address.
    pub fn new(
        name: impl Into<String>,
        email: impl Into<String>,
    ) -> Result<Self, ChainkeeperError> {
        let name = name.into();
        let email = email.into();
        if name.trim().is_empty() {
            return Err(ChainkeeperError::git("git identity name must not be empty"));
        }
        let (local, domain) = email.split_once('@').ok_or_else(|| {
            ChainkeeperError::git(format!("git identity email {email:?} is not an address"))
        })?;
        if local.is_empty()
            || domain.is_empty()
            || email.chars().any(char::is_whitespace)
            || domain.contains('@')
        {
            return Err(ChainkeeperError::git(format!(
                "git identity email {email:?} is not an address"
            )));
        }
        Ok(Self { name, email })
    }

    /// Display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Email address.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }
}

impl fmt::Debug for GitIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitIdentity")
            .field("name", &self.name)
            .field("email", &self.email)
            .finish()
    }
}

fn config_value(repository: &Repository, key: &str) -> Option<String> {
    repository
        .config()
        .ok()
        .and_then(|config| config.get_string(key).ok())
        .filter(|value| !value.trim().is_empty())
}

fn env_value(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| env::var(key).ok())
        .filter(|value| !value.trim().is_empty())
}

/// Resolves a signature from the explicit identity, repository and global Git
/// config, then the Git author/committer environment variables.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Git`] with actionable configuration guidance when
/// no identity can be resolved.
pub fn resolve_signature(
    repository: &Repository,
    explicit: Option<&GitIdentity>,
) -> Result<Signature<'static>, ChainkeeperError> {
    if let Some(identity) = explicit {
        return Signature::now(identity.name(), identity.email()).map_err(|error| {
            ChainkeeperError::git(format!("could not build git signature: {error}"))
        });
    }

    let name = config_value(repository, "user.name")
        .or_else(|| env_value(&["GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"]));
    let email = config_value(repository, "user.email")
        .or_else(|| env_value(&["GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"]));

    match (name, email) {
        (Some(name), Some(email)) => {
            let identity = GitIdentity::new(name, email)?;
            Signature::now(identity.name(), identity.email()).map_err(|error| {
                ChainkeeperError::git(format!("could not build git signature: {error}"))
            })
        }
        _ => Err(ChainkeeperError::git(
            "git identity is not configured: set user.name and user.email with \
             `git config user.name ...` and `git config user.email ...`, or export \
             GIT_AUTHOR_NAME and GIT_AUTHOR_EMAIL",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::GitIdentity;

    #[test]
    fn identity_is_validated() {
        assert!(GitIdentity::new("Chainkeeper", "ck@example.com").is_ok());
        assert!(GitIdentity::new("  ", "ck@example.com").is_err());
        assert!(GitIdentity::new("Chainkeeper", "ck").is_err());
        assert!(GitIdentity::new("Chainkeeper", "@example.com").is_err());
        assert!(GitIdentity::new("Chainkeeper", "ck@").is_err());
        assert!(GitIdentity::new("Chainkeeper", "ck@exa mple.com").is_err());
    }
}
