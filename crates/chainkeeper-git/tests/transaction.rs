//! Repository transaction boundary.

mod common;

use std::sync::Arc;
use std::time::Duration;

use chainkeeper_core::{GitRepository, RepositoryLock, RepositoryPaths};
use chainkeeper_git::{GitRepo, RepositoryTransaction};
use chainkeeper_store::FileRepositoryLock;

fn lock(root: &std::path::Path) -> Arc<dyn RepositoryLock> {
    Arc::new(FileRepositoryLock::new(
        RepositoryPaths::new(root).expect("valid root"),
    ))
}

#[test]
fn successful_transaction_commits() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "authorities/tls/cert.pem", "cert");

    let mut transaction = RepositoryTransaction::begin(
        repo,
        lock(directory.path()).as_ref(),
        Duration::from_secs(2),
    )
    .expect("begin");
    transaction
        .stage_path(directory.path().join("authorities/tls/cert.pem"))
        .expect("stage");
    let oid = transaction
        .commit("feat(ck): create intermediate authority tls")
        .expect("commit");
    assert!(transaction.committed());
    assert_eq!(oid.len(), 40);
    drop(transaction);

    let repo = GitRepo::open(directory.path()).expect("open");
    let log = repo.log(1).expect("log");
    assert_eq!(
        log[0].message,
        "feat(ck): create intermediate authority tls"
    );
    assert!(repo.is_clean().expect("clean"));
}

#[test]
fn rollback_removes_only_created_files() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "pre-existing.pem", "keep");

    let mut transaction = RepositoryTransaction::begin(
        repo,
        lock(directory.path()).as_ref(),
        Duration::from_secs(2),
    )
    .expect("begin");
    common::write(directory.path(), "created.pem", "new");

    transaction
        .stage_path(directory.path().join("pre-existing.pem"))
        .expect("stage existing");
    transaction
        .stage_created(directory.path().join("created.pem"))
        .expect("stage created");

    let removed = transaction.rollback_created().expect("rollback");
    assert_eq!(removed, vec![std::path::PathBuf::from("created.pem")]);
    assert!(!directory.path().join("created.pem").exists());
    assert!(directory.path().join("pre-existing.pem").exists());

    drop(transaction);
}

#[test]
fn lock_is_released_after_rollback() {
    let (directory, repo) = common::repository();
    let shared = lock(directory.path());
    let mut transaction =
        RepositoryTransaction::begin(repo, shared.as_ref(), Duration::from_millis(500))
            .expect("begin");
    transaction.rollback_created().expect("rollback");
    drop(transaction);

    shared
        .acquire_exclusive(Duration::from_millis(500))
        .expect("lock is free after rollback")
        .release();
}

#[test]
fn concurrent_transactions_cannot_overlap() {
    let (directory, repo) = common::repository();
    let shared = lock(directory.path());
    let first = RepositoryTransaction::begin(repo, shared.as_ref(), Duration::from_millis(500))
        .expect("first transaction");

    let second = RepositoryTransaction::begin(
        GitRepo::open(directory.path()).expect("open"),
        shared.as_ref(),
        Duration::from_millis(50),
    );
    let error = second.expect_err("second transaction blocked");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Lock);

    drop(first);
    RepositoryTransaction::begin(
        GitRepo::open(directory.path()).expect("open"),
        shared.as_ref(),
        Duration::from_millis(500),
    )
    .expect("lock is free after drop");
}

#[test]
fn dropping_without_commit_leaves_files_for_inspection() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "inspect.pem", "left behind");

    let shared = lock(directory.path());
    let mut transaction =
        RepositoryTransaction::begin(repo, shared.as_ref(), Duration::from_millis(500))
            .expect("begin");
    transaction
        .stage_created(directory.path().join("inspect.pem"))
        .expect("stage");
    drop(transaction);

    assert!(directory.path().join("inspect.pem").exists());
    shared
        .acquire_exclusive(Duration::from_millis(500))
        .expect("lock released")
        .release();
}

#[test]
fn commit_requires_a_staged_path() {
    let (directory, repo) = common::repository();
    let mut transaction = RepositoryTransaction::begin(
        repo,
        lock(directory.path()).as_ref(),
        Duration::from_millis(500),
    )
    .expect("begin");
    let error = transaction
        .commit("feat(ck): empty")
        .expect_err("no staged paths");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Git);
}
