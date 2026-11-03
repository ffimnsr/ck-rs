//! Gitignore maintenance and tracked key checks.

mod common;

use chainkeeper_core::GitRepository;
use chainkeeper_git::{
    GITIGNORE_CONTENT, GITIGNORE_RULES, GitRepo, assert_no_staged_private_keys, ensure_gitignore,
};

#[test]
fn missing_gitignore_is_created_exactly() {
    let directory = tempfile::tempdir().expect("temp dir");
    ensure_gitignore(directory.path()).expect("ensure");
    let contents = std::fs::read_to_string(directory.path().join(".gitignore")).expect("readable");
    assert_eq!(contents, GITIGNORE_CONTENT);
}

#[test]
fn missing_rules_are_appended_and_custom_rules_survive() {
    let directory = tempfile::tempdir().expect("temp dir");
    common::write(directory.path(), ".gitignore", "*.log\n/target/\n");

    ensure_gitignore(directory.path()).expect("ensure");
    let contents = std::fs::read_to_string(directory.path().join(".gitignore")).expect("readable");

    assert!(contents.starts_with("*.log\n/target/\n"), "{contents}");
    for rule in GITIGNORE_RULES {
        assert!(
            contents.lines().any(|line| line == rule),
            "missing {rule} in {contents}"
        );
    }
    assert_eq!(
        contents.matches("/target/").count(),
        1,
        "existing rules are not duplicated: {contents}"
    );
}

#[test]
fn complete_gitignore_is_not_rewritten() {
    let directory = tempfile::tempdir().expect("temp dir");
    common::write(directory.path(), ".gitignore", GITIGNORE_CONTENT);
    ensure_gitignore(directory.path()).expect("ensure");
    let contents = std::fs::read_to_string(directory.path().join(".gitignore")).expect("readable");
    assert_eq!(contents, GITIGNORE_CONTENT);
}

#[test]
fn init_tracks_no_private_keys() {
    let directory = tempfile::tempdir().expect("temp dir");
    common::write(
        directory.path(),
        "tenant.yaml",
        "version: 1\ntenant_id: acme\ndisplay_name: Acme\ncreated_at: 2024-05-01T12:00:00Z\ndefault_profile: tls-server\n",
    );
    common::write(
        directory.path(),
        "authorities/root/key.pem",
        "-----BEGIN PRIVATE KEY-----",
    );
    common::write(directory.path(), "authorities/root/cert.pem", "cert");
    common::init_raw(directory.path());

    let repo = GitRepo::new(directory.path()).with_identity(common::identity());
    GitRepository::init(&repo, directory.path()).expect("init");

    assert!(repo.is_clean().expect("clean"));
    assert_no_staged_private_keys(directory.path()).expect("no staged keys");
}
