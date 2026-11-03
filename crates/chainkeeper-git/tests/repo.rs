//! Git repository wrapper contract.

mod common;

use std::path::PathBuf;

use chainkeeper_core::{GitChangeKind, GitRepository};
use chainkeeper_git::{GITIGNORE_CONTENT, GitRepo, WORKTREE, assert_no_staged_private_keys};

#[test]
fn init_creates_one_commit_and_a_clean_tree() {
    let (directory, repo) = common::repository();
    let head = repo.head_commit().expect("head");
    assert_eq!(head.len(), 40, "{head}");
    assert!(head.chars().all(|character| character.is_ascii_hexdigit()));

    let status = repo.status().expect("status");
    assert!(status.clean, "{status:?}");
    assert_eq!(status.branch.as_deref(), Some("main"));
    assert_eq!(status.head.as_deref(), Some(head.as_str()));
    assert_eq!(status.untracked, Vec::<PathBuf>::new());

    let log = repo.log(10).expect("log");
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].message, "feat(ck): initialize tenant acme");
    assert_eq!(log[0].author, "Chainkeeper Tests");
    assert_eq!(log[0].email, "tests@example.com");

    let gitignore = std::fs::read_to_string(directory.path().join(".gitignore")).expect("readable");
    assert_eq!(gitignore, GITIGNORE_CONTENT);
    assert_no_staged_private_keys(directory.path()).expect("no tracked keys");
    assert!(repo.is_clean().expect("clean"));
}

#[test]
fn init_rejects_an_existing_history() {
    let (directory, repo) = common::repository();
    let error = GitRepository::init(&repo, directory.path()).expect_err("already initialised");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Git);
}

#[test]
fn commit_stages_only_supplied_paths() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "a.txt", "a");
    common::write(directory.path(), "b.txt", "b");

    let before = repo.head_commit().expect("head");
    let after = repo
        .commit("feat(ck): test a", &[directory.path().join("a.txt")])
        .expect("commit");
    assert_ne!(before, after);

    let status = repo.status().expect("status");
    assert!(status.changes.is_empty(), "{status:?}");
    assert_eq!(status.untracked, vec![PathBuf::from("b.txt")]);
    assert!(!status.clean);

    let changes = repo.diff(&before, &after).expect("diff");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, PathBuf::from("a.txt"));
    assert_eq!(changes[0].kind, GitChangeKind::Added);
}

#[test]
fn commit_leaves_unrelated_changes_untouched() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "one.txt", "one");
    common::write(directory.path(), "two.txt", "two");
    let base = repo
        .commit(
            "feat(ck): add both",
            &[
                directory.path().join("one.txt"),
                directory.path().join("two.txt"),
            ],
        )
        .expect("commit");

    common::write(directory.path(), "one.txt", "one changed");
    common::write(directory.path(), "two.txt", "two changed");
    let head = repo
        .commit("feat(ck): change one", &[directory.path().join("one.txt")])
        .expect("commit");

    let status = repo.status().expect("status");
    assert_eq!(
        status.changes,
        vec![chainkeeper_core::GitChange {
            path: PathBuf::from("two.txt"),
            kind: GitChangeKind::Modified,
        }]
    );
    let changes = repo.diff(&base, &head).expect("diff");
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].path, PathBuf::from("one.txt"));
}

#[test]
fn commit_with_a_missing_path_leaves_the_index_unchanged() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "a.txt", "a");
    let before = repo.head_commit().expect("head");

    let error = repo
        .commit(
            "feat(ck): missing",
            &[
                directory.path().join("a.txt"),
                directory.path().join("missing.txt"),
            ],
        )
        .expect_err("missing path rejected");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Git);
    assert_eq!(repo.head_commit().expect("head"), before);

    let status = repo.status().expect("status");
    assert!(status.changes.is_empty(), "{status:?}");
    assert_eq!(status.untracked, vec![PathBuf::from("a.txt")]);
}

#[test]
fn path_traversal_is_rejected() {
    let (directory, repo) = common::repository();
    let outside = directory
        .path()
        .parent()
        .expect("parent")
        .join("escape.txt");

    let traversal = repo
        .commit("feat(ck): escape", &[PathBuf::from("../escape.txt")])
        .expect_err("traversal rejected");
    assert_eq!(traversal.kind(), chainkeeper_core::ErrorKind::Git);

    let absolute = repo
        .commit("feat(ck): escape", &[outside])
        .expect_err("outside path rejected");
    assert_eq!(absolute.kind(), chainkeeper_core::ErrorKind::Git);
}

#[test]
fn private_keys_cannot_be_committed() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "authorities/root/key.pem", "private");
    common::write(directory.path(), "authorities/root/cert.pem", "public");
    let before = repo.head_commit().expect("head");

    let error = repo
        .commit(
            "feat(ck): key",
            &[directory.path().join("authorities/root/key.pem")],
        )
        .expect_err("private key rejected");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Git);
    assert!(error.to_string().contains("private key"));
    assert_eq!(repo.head_commit().expect("head"), before);
}

#[test]
fn externally_staged_private_keys_are_rejected() {
    let (directory, _repo) = common::repository();
    common::write(directory.path(), "authorities/root/key.pem", "private");

    let raw = common::raw(directory.path());
    let mut index = raw.index().expect("index");
    index
        .add_path(std::path::Path::new("authorities/root/key.pem"))
        .expect("stage key");
    index.write().expect("write index");

    let error = assert_no_staged_private_keys(directory.path()).expect_err("guard");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::Git);
    assert!(error.to_string().contains("private key"));
}

#[test]
fn diff_reports_added_modified_and_deleted_files() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "a.txt", "a");
    common::write(directory.path(), "c.txt", "c");
    let base = repo
        .commit(
            "feat(ck): base",
            &[
                directory.path().join("a.txt"),
                directory.path().join("c.txt"),
            ],
        )
        .expect("commit");

    common::write(directory.path(), "a.txt", "a changed");
    common::write(directory.path(), "b.txt", "b");

    // The public commit API intentionally refuses missing paths, so stage the
    // deletion directly to exercise diff's deleted handling.
    let raw = common::raw(directory.path());
    let mut index = raw.index().expect("index");
    index
        .remove_path(std::path::Path::new("c.txt"))
        .expect("stage deletion");
    index.write().expect("write index");
    drop(index);

    let head = repo
        .commit(
            "feat(ck): change",
            &[
                directory.path().join("a.txt"),
                directory.path().join("b.txt"),
            ],
        )
        .expect("commit");

    let changes = repo.diff(&base, &head).expect("diff");
    assert_eq!(
        changes,
        vec![
            chainkeeper_core::GitChange {
                path: PathBuf::from("a.txt"),
                kind: GitChangeKind::Modified,
            },
            chainkeeper_core::GitChange {
                path: PathBuf::from("b.txt"),
                kind: GitChangeKind::Added,
            },
            chainkeeper_core::GitChange {
                path: PathBuf::from("c.txt"),
                kind: GitChangeKind::Deleted,
            },
        ]
    );
}

#[test]
fn diff_detects_renames() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "old.txt", "stable contents\n");
    let base = repo
        .commit("feat(ck): base", &[directory.path().join("old.txt")])
        .expect("commit");

    std::fs::rename(
        directory.path().join("old.txt"),
        directory.path().join("new.txt"),
    )
    .expect("rename");
    let raw = common::raw(directory.path());
    let mut index = raw.index().expect("index");
    index
        .remove_path(std::path::Path::new("old.txt"))
        .expect("stage removal");
    index
        .add_path(std::path::Path::new("new.txt"))
        .expect("stage addition");
    index.write().expect("write index");
    drop(index);

    let head = repo
        .commit("feat(ck): rename", &[directory.path().join("new.txt")])
        .expect("commit");
    let changes = repo.diff(&base, &head).expect("diff");
    assert_eq!(
        changes,
        vec![chainkeeper_core::GitChange {
            path: PathBuf::from("new.txt"),
            kind: GitChangeKind::Renamed,
        }]
    );
}

#[test]
fn diff_supports_the_working_tree() {
    let (directory, repo) = common::repository();
    common::write(directory.path(), "a.txt", "a");
    let base = repo
        .commit("feat(ck): base", &[directory.path().join("a.txt")])
        .expect("commit");

    common::write(directory.path(), "a.txt", "changed");
    common::write(directory.path(), "new.txt", "new");

    let changes = repo.diff(&base, WORKTREE).expect("diff");
    assert_eq!(
        changes,
        vec![
            chainkeeper_core::GitChange {
                path: PathBuf::from("a.txt"),
                kind: GitChangeKind::Modified,
            },
            chainkeeper_core::GitChange {
                path: PathBuf::from("new.txt"),
                kind: GitChangeKind::Added,
            },
        ]
    );
}

#[test]
fn head_commit_requires_a_history() {
    let directory = tempfile::tempdir().expect("temp dir");
    common::write(
        directory.path(),
        "tenant.yaml",
        "version: 1\ntenant_id: acme\ndisplay_name: Acme\ncreated_at: 2024-05-01T12:00:00Z\ndefault_profile: tls-server\n",
    );
    git2::Repository::init(directory.path()).expect("init");
    let repo = GitRepo::new(directory.path());
    let error = repo.head_commit().expect_err("no commits");
    assert_eq!(error.kind(), chainkeeper_core::ErrorKind::NotFound);
}
