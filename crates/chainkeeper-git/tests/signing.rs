//! Commit signing compatibility.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chainkeeper_core::{ChainkeeperError, GitRepository};
use chainkeeper_git::{CommitSigner, GitRepo, GpgCommitSigner, signing_enabled};

#[derive(Debug)]
struct FailingSigner {
    calls: Arc<AtomicUsize>,
}

impl CommitSigner for FailingSigner {
    fn sign(&self, _content: &[u8]) -> Result<String, ChainkeeperError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ChainkeeperError::git("signing is unavailable in this test"))
    }
}

fn enable_signing(root: &std::path::Path) {
    let mut config = common::raw(root).config().expect("config");
    config
        .set_bool("commit.gpgsign", true)
        .expect("set commit.gpgsign");
}

#[test]
fn signing_enabled_reads_the_repository_config() {
    let (directory, _repo) = common::repository();
    let raw = common::raw(directory.path());
    assert!(!signing_enabled(&raw).expect("reads config"));

    enable_signing(directory.path());
    assert!(signing_enabled(&raw).expect("reads config"));
}

#[test]
fn signing_enabled_never_falls_back_to_an_unsigned_commit() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "a.txt", "a");
    let calls = Arc::new(AtomicUsize::new(0));
    let repo = repo.with_commit_signer(Arc::new(FailingSigner {
        calls: Arc::clone(&calls),
    }));
    enable_signing(directory.path());
    let before = repo.head_commit().expect("head");

    let error = repo
        .commit("feat(ck): signed", &[directory.path().join("a.txt")])
        .expect_err("signing failure aborts the commit");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Git);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(repo.head_commit().expect("head"), before);
}

#[test]
fn signing_disabled_does_not_invoke_the_signer() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "a.txt", "a");
    let calls = Arc::new(AtomicUsize::new(0));
    let repo = repo.with_commit_signer(Arc::new(FailingSigner {
        calls: Arc::clone(&calls),
    }));

    repo.commit("feat(ck): unsigned", &[directory.path().join("a.txt")])
        .expect("commit");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn gpg_signing_round_trip_when_available() {
    if std::env::var("CHAINKEEPER_TEST_GPG").as_deref() != Ok("1") {
        return;
    }

    let (directory, repo) = common::repository();
    let home = tempfile::tempdir().expect("gpg home");
    let generated = std::process::Command::new("gpg")
        .arg("--homedir")
        .arg(home.path())
        .args([
            "--batch",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Chainkeeper GPG <ck-gpg@example.com>",
            "default",
            "default",
            "never",
        ])
        .status();
    let Ok(generated) = generated else {
        return;
    };
    if !generated.success() {
        return;
    }

    enable_signing(directory.path());
    let signer = GpgCommitSigner::new("gpg", Some("ck-gpg@example.com".to_owned()))
        .with_homedir(home.path());
    let repo: GitRepo = repo.with_commit_signer(Arc::new(signer));
    common::write(directory.path(), "a.txt", "a");

    let oid = repo
        .commit("feat(ck): signed", &[directory.path().join("a.txt")])
        .expect("signed commit");
    let raw = common::raw(directory.path());
    let oid = git2::Oid::from_str(&oid).expect("oid");
    raw.extract_signature(&oid, None)
        .expect("commit carries a signature");
}
