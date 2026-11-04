//! Remote synchronisation tests.
//!
//! Every fixture owns its own temporary directory and bare remote, so tests
//! never share paths, ports, or process state.

use std::path::Path;

use chainkeeper_git::GitRepo;
use git2::{Repository, RepositoryInitOptions, Signature};
use tempfile::TempDir;

struct Fixture {
    _directory: TempDir,
    origin: std::path::PathBuf,
    seed: std::path::PathBuf,
    work: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temp dir");
        let origin = directory.path().join("origin.git");
        Repository::init_opts(
            &origin,
            RepositoryInitOptions::new().bare(true).initial_head("main"),
        )
        .expect("bare origin");

        let seed = directory.path().join("seed");
        Repository::clone(origin.to_str().expect("utf-8 path"), &seed).expect("seed clone");
        Repository::open(&seed)
            .expect("seed repository")
            .set_head("refs/heads/main")
            .expect("seed head");
        commit_file(&seed, "tenant.yaml", "tenant: acme\n", true);

        let work = directory.path().join("work");
        Repository::clone(origin.to_str().expect("utf-8 path"), &work).expect("work clone");
        Repository::open(&work)
            .expect("work repository")
            .set_head("refs/heads/main")
            .expect("work head");

        Self {
            _directory: directory,
            origin,
            seed,
            work,
        }
    }

    fn advance_remote(&self, file: &str, contents: &str) {
        commit_file(&self.seed, file, contents, true);
    }

    fn repo(&self) -> GitRepo {
        GitRepo::open(&self.work).expect("open work repository")
    }
}

fn signature() -> Signature<'static> {
    Signature::now("Chainkeeper Tests", "tests@example.com").expect("signature")
}

fn commit_file(root: &Path, name: &str, contents: &str, push: bool) {
    std::fs::write(root.join(name), contents).expect("write file");
    let repository = Repository::open(root).expect("repository");
    let mut index = repository.index().expect("index");
    index.add_path(Path::new(name)).expect("stage file");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("tree");
    let tree = repository.find_tree(tree_id).expect("find tree");
    let parent = repository
        .head()
        .ok()
        .and_then(|head| head.peel_to_commit().ok());
    let parents: Vec<_> = parent.iter().collect();
    repository
        .commit(
            Some("HEAD"),
            &signature(),
            &signature(),
            "test commit",
            &tree,
            &parents,
        )
        .expect("commit");
    if push {
        let mut remote = repository.find_remote("origin").expect("origin remote");
        remote
            .push(&["refs/heads/main:refs/heads/main"], None)
            .expect("push");
    }
}

fn head_of(root: &Path) -> String {
    Repository::open(root)
        .expect("repository")
        .head()
        .expect("head")
        .target()
        .expect("target")
        .to_string()
}

#[test]
fn fetches_and_fast_forwards_to_a_new_commit() {
    let fixture = Fixture::new();
    let before = head_of(&fixture.work);
    fixture.advance_remote("tenant.yaml", "tenant: acme\nversion: 2\n");
    let remote_head = head_of(&fixture.seed);

    let outcome = fixture
        .repo()
        .fetch_and_fast_forward("origin", "main")
        .expect("sync");

    assert!(outcome.changed);
    assert_eq!(outcome.commit, remote_head);
    assert_eq!(head_of(&fixture.work), remote_head);
    assert_ne!(before, remote_head);
}

#[test]
fn unchanged_remote_is_not_a_change() {
    let fixture = Fixture::new();
    let head = head_of(&fixture.work);

    let outcome = fixture
        .repo()
        .fetch_and_fast_forward("origin", "main")
        .expect("sync");

    assert!(!outcome.changed);
    assert_eq!(outcome.commit, head);
    assert_eq!(head_of(&fixture.work), head);
}

#[test]
fn dirty_working_tree_is_refused() {
    let fixture = Fixture::new();
    fixture.advance_remote("tenant.yaml", "tenant: acme\nversion: 2\n");
    std::fs::write(fixture.work.join("tenant.yaml"), "tenant: local\n").expect("dirty tree");

    let error = fixture
        .repo()
        .fetch_and_fast_forward("origin", "main")
        .expect_err("dirty tree must be refused");

    assert!(error.to_string().contains("dirty"), "{error}");
}

#[test]
fn diverged_history_is_refused() {
    let fixture = Fixture::new();
    commit_file(&fixture.work, "local.yaml", "local: true\n", false);
    fixture.advance_remote("tenant.yaml", "tenant: acme\nversion: 2\n");
    let local_head = head_of(&fixture.work);

    let error = fixture
        .repo()
        .fetch_and_fast_forward("origin", "main")
        .expect_err("non fast-forward must be refused");

    assert!(error.to_string().contains("fast-forward"), "{error}");
    assert_eq!(head_of(&fixture.work), local_head);
}

#[test]
fn missing_remote_is_reported() {
    let fixture = Fixture::new();
    let error = fixture
        .repo()
        .fetch_and_fast_forward("upstream", "main")
        .expect_err("unknown remote must fail");
    assert!(error.to_string().contains("remote"), "{error}");
    assert!(fixture.origin.exists());
}
