//! Gitignore maintenance and private key staging guards.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use chainkeeper_core::{ChainkeeperError, FileMode, atomic_write};
use git2::{Index, Repository};

/// Rules written by [`ensure_gitignore`], in order.
pub const GITIGNORE_RULES: [&str; 6] = [
    "/target/",
    "/cache/",
    "/.chainkeeper/",
    "authorities/**/key.pem",
    "certificates/**/*.key.pem",
    "*.key",
];

/// Exact contents written when `.gitignore` does not exist.
pub const GITIGNORE_CONTENT: &str =
    "/target/\n/cache/\n/.chainkeeper/\nauthorities/**/key.pem\ncertificates/**/*.key.pem\n*.key\n";

/// Returns true when a staged path looks like private key material.
#[must_use]
pub fn is_private_key_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name == "key.pem"
                || name.ends_with(".key.pem")
                || Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension == "key")
        })
}

/// Ensures the repository `.gitignore` contains every required rule.
///
/// Existing unrelated rules are preserved. Missing rules are appended, and the
/// file is only rewritten when something changed.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Git`] when the file cannot be read or written.
pub fn ensure_gitignore(root: &Path) -> Result<(), ChainkeeperError> {
    let path = root.join(".gitignore");
    let existing = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(ChainkeeperError::git(format!(
                "could not read {}: {error}",
                path.display()
            )));
        }
    };

    let present: Vec<&str> = existing.lines().map(str::trim).collect();
    let missing: Vec<&str> = GITIGNORE_RULES
        .into_iter()
        .filter(|rule| !present.contains(rule))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let mut updated = existing.clone();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    for rule in missing {
        updated.push_str(rule);
        updated.push('\n');
    }

    atomic_write(&path, updated.as_bytes(), FileMode::Public)
        .map_err(|error| error.with_context("could not write .gitignore"))
}

/// Rejects an index that stages private key material.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Git`] naming the first offending path.
pub fn assert_index_has_no_private_keys(index: &Index) -> Result<(), ChainkeeperError> {
    for entry in index.iter() {
        let path = String::from_utf8_lossy(&entry.path);
        if is_private_key_path(Path::new(path.as_ref())) {
            return Err(
                ChainkeeperError::git(format!("private key {path} must not be staged"))
                    .with_context("refusing to create a commit"),
            );
        }
    }
    Ok(())
}

/// Rejects a repository whose index stages private key material.
///
/// The guard inspects the index, so it catches keys staged by either this crate
/// or an external `git add`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Git`] when the repository cannot be opened or a
/// private key is staged.
pub fn assert_no_staged_private_keys(root: &Path) -> Result<(), ChainkeeperError> {
    let repository = Repository::open(root).map_err(|error| {
        ChainkeeperError::git(format!(
            "could not open git repository {}: {}",
            root.display(),
            error.message()
        ))
    })?;
    let index = repository
        .index()
        .map_err(|error| ChainkeeperError::git(format!("could not read git index: {error}")))?;
    assert_index_has_no_private_keys(&index)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{GITIGNORE_CONTENT, is_private_key_path};

    #[test]
    fn private_key_names_are_recognised() {
        assert!(is_private_key_path(Path::new("authorities/root/key.pem")));
        assert!(is_private_key_path(Path::new("a/b/leaf.key")));
        assert!(is_private_key_path(Path::new(
            "certificates/active/AB.key.pem"
        )));
        assert!(!is_private_key_path(Path::new("authorities/root/cert.pem")));
        assert!(!is_private_key_path(Path::new(
            "certificates/active/AB.pem"
        )));
        assert!(!is_private_key_path(Path::new("a/b/monkey.pem")));
    }

    #[test]
    fn gitignore_content_matches_the_global_decision() {
        assert_eq!(
            GITIGNORE_CONTENT,
            "/target/\n/cache/\n/.chainkeeper/\nauthorities/**/key.pem\ncertificates/**/*.key.pem\n*.key\n"
        );
    }
}
