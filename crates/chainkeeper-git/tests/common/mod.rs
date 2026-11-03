#![allow(dead_code)]

//! Shared fixtures for the Git integration tests.

use std::path::Path;

use chainkeeper_core::GitRepository;
use chainkeeper_git::{GitIdentity, GitRepo};
use tempfile::TempDir;

/// Identity used by every fixture. Tests never read the host Git config.
pub fn identity() -> GitIdentity {
    GitIdentity::new("Chainkeeper Tests", "tests@example.com").expect("valid identity")
}

/// Writes a file, creating parent directories.
pub fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("parent directory");
    }
    std::fs::write(path, contents).expect("write file");
}

/// Creates a tenant repository with one initial commit.
pub fn repository() -> (TempDir, GitRepo) {
    let directory = tempfile::tempdir().expect("temp dir");
    write(
        directory.path(),
        "tenant.yaml",
        "version: 1\ntenant_id: acme\ndisplay_name: Acme\ncreated_at: 2024-05-01T12:00:00Z\ndefault_profile: tls-server\n",
    );
    init_raw(directory.path());
    let repo = GitRepo::new(directory.path()).with_identity(identity());
    GitRepository::init(&repo, directory.path()).expect("init");
    (directory, repo)
}

/// Creates an empty Git repository with signing disabled locally.
///
/// Tests must never inherit the host global `commit.gpgsign` setting.
pub fn init_raw(root: &Path) {
    let repository = git2::Repository::init_opts(
        root,
        git2::RepositoryInitOptions::new().initial_head("main"),
    )
    .expect("raw init");
    let mut config = repository.config().expect("config");
    config
        .set_bool("commit.gpgsign", false)
        .expect("disable signing");
}

/// Opens the raw `git2` repository for assertions.
pub fn raw(root: &Path) -> git2::Repository {
    git2::Repository::open(root).expect("git repository")
}
