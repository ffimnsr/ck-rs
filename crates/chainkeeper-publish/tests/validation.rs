mod common;

use std::path::{Path, PathBuf};

use chainkeeper_core::{
    ChainkeeperError, PUBLISH_MANIFEST_VERSION, PublishArtifact, PublishBuilder as _,
    PublishManifest, PublishOptions, TenantId,
};
use chainkeeper_publish::{ChangedPaths, MANIFEST_FILE, changed_paths, read_manifest};
use common::{Harness, NOW};
use sha2::{Digest as _, Sha256};

fn sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut encoded = String::new();
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn manifest_with(artifacts: &[(&str, &[u8])]) -> PublishManifest {
    let artifacts = artifacts
        .iter()
        .map(|(path, bytes)| PublishArtifact {
            path: PathBuf::from(path),
            sha256: sha256(bytes),
            bytes: u64::try_from(bytes.len()).expect("fits"),
        })
        .collect();
    PublishManifest {
        version: PUBLISH_MANIFEST_VERSION,
        generated_at: NOW,
        source_commit: Some("deadbeef".to_owned()),
        tenant_id: TenantId::new("acme").expect("tenant"),
        artifacts,
    }
}

fn write_manifest(directory: &Path, manifest: &PublishManifest) {
    let mut rendered = serde_json::to_string_pretty(manifest).expect("render");
    rendered.push('\n');
    std::fs::write(directory.join(MANIFEST_FILE), rendered).expect("manifest");
}

fn write_file(directory: &Path, relative: &str, bytes: &[u8]) {
    let path = directory.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("parent");
    }
    std::fs::write(path, bytes).expect("file");
}

fn directory() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

#[test]
fn unlisted_files_are_rejected() {
    let h = Harness::new().expect("harness");
    h.publisher()
        .build(&PublishOptions::new(h.paths().publish_dir()))
        .expect("published");
    write_file(&h.paths().publish_dir(), "extra.txt", b"extra");

    let error = h
        .publisher()
        .validate_publish_dir(&h.paths().publish_dir())
        .expect_err("unlisted file rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[test]
fn hash_mismatch_is_rejected() {
    let h = Harness::new().expect("harness");
    h.publisher()
        .build(&PublishOptions::new(h.paths().publish_dir()))
        .expect("published");
    write_file(&h.paths().publish_dir(), "root.pem", b"tampered");

    let error = h
        .publisher()
        .validate_publish_dir(&h.paths().publish_dir())
        .expect_err("digest mismatch rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[test]
fn manifest_path_traversal_is_rejected() {
    let directory = directory();
    let manifest = manifest_with(&[("../evil.pem", b"evil")]);
    write_manifest(directory.path(), &manifest);
    write_file(directory.path(), "../evil.pem", b"evil");

    let h = Harness::new().expect("harness");
    let error = h
        .publisher()
        .validate_publish_dir(directory.path())
        .expect_err("traversal rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[test]
fn key_pem_is_rejected() {
    let directory = directory();
    let manifest = manifest_with(&[("key.pem", b"public")]);
    write_manifest(directory.path(), &manifest);
    write_file(directory.path(), "key.pem", b"public");

    let h = Harness::new().expect("harness");
    let error = h
        .publisher()
        .validate_publish_dir(directory.path())
        .expect_err("key file rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[test]
fn private_key_material_is_rejected_in_any_file() {
    let directory = directory();
    let secret = b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n";
    let manifest = manifest_with(&[("notes.txt", secret)]);
    write_manifest(directory.path(), &manifest);
    write_file(directory.path(), "notes.txt", secret);

    let h = Harness::new().expect("harness");
    let error = h
        .publisher()
        .validate_publish_dir(directory.path())
        .expect_err("private key rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[test]
fn missing_artifact_is_rejected() {
    let directory = directory();
    let manifest = manifest_with(&[("root.pem", b"root")]);
    write_manifest(directory.path(), &manifest);

    let h = Harness::new().expect("harness");
    let error = h
        .publisher()
        .validate_publish_dir(directory.path())
        .expect_err("missing artifact rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[test]
fn missing_manifest_is_rejected() {
    let directory = directory();
    let h = Harness::new().expect("harness");
    let error = h
        .publisher()
        .validate_publish_dir(directory.path())
        .expect_err("missing manifest rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[test]
fn manifest_listing_itself_is_rejected() {
    let directory = directory();
    let manifest = manifest_with(&[(MANIFEST_FILE, b"{}")]);
    write_manifest(directory.path(), &manifest);
    write_file(directory.path(), MANIFEST_FILE, b"{}");

    let h = Harness::new().expect("harness");
    let error = h
        .publisher()
        .validate_publish_dir(directory.path())
        .expect_err("self listing rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[cfg(unix)]
#[test]
fn symlink_in_publish_tree_is_rejected() {
    let directory = directory();
    write_file(directory.path(), "root.pem", b"root");
    let manifest = manifest_with(&[("root.pem", b"root")]);
    write_manifest(directory.path(), &manifest);
    let target = directory.path().join("root.pem");
    std::os::unix::fs::symlink(target, directory.path().join("link.pem")).expect("symlink");

    let h = Harness::new().expect("harness");
    let error = h
        .publisher()
        .validate_publish_dir(directory.path())
        .expect_err("symlink rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[test]
fn read_manifest_returns_none_when_absent() {
    let directory = directory();
    assert!(read_manifest(directory.path()).expect("read").is_none());
}

#[test]
fn unchanged_manifests_have_no_changed_paths() {
    let manifest = manifest_with(&[("root.pem", b"root")]);
    assert_eq!(changed_paths(&manifest, &manifest), ChangedPaths::default());
}

#[test]
fn changed_paths_reports_additions_removals_and_modifications() {
    let previous = manifest_with(&[("a.pem", b"a"), ("old.pem", b"old")]);
    let next = manifest_with(&[("a.pem", b"changed"), ("b.pem", b"b")]);

    let changed = changed_paths(&previous, &next);
    assert_eq!(changed.added, vec![PathBuf::from("b.pem")]);
    assert_eq!(changed.removed, vec![PathBuf::from("old.pem")]);
    assert_eq!(changed.modified, vec![PathBuf::from("a.pem")]);
    assert_eq!(
        chainkeeper_publish::FilePublishBuilder::changed_paths(&previous, &next),
        changed
    );
}

#[test]
fn duplicate_artifact_paths_are_rejected() {
    let directory = directory();
    let mut manifest = manifest_with(&[("root.pem", b"root")]);
    let duplicate = manifest.artifacts[0].clone();
    manifest.artifacts.push(duplicate);
    write_manifest(directory.path(), &manifest);
    write_file(directory.path(), "root.pem", b"root");

    let h = Harness::new().expect("harness");
    let error = h
        .publisher()
        .validate_publish_dir(directory.path())
        .expect_err("duplicate rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}
