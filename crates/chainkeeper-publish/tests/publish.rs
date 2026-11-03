mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chainkeeper_core::{ChainkeeperError, PublishBuilder as _, PublishManifest, PublishOptions};
use common::{Harness, tls};
use sha2::{Digest as _, Sha256};

fn build(h: &Harness) -> PublishManifest {
    h.publisher()
        .build(&PublishOptions::new(h.paths().publish_dir()))
        .expect("publish succeeds")
}

fn hash(path: &Path) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(std::fs::read(path).expect("readable"));
    let mut encoded = String::new();
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[test]
fn exact_publish_paths_are_produced() {
    let h = Harness::new().expect("harness");
    h.seed_crl(&tls().expect("authority")).expect("crl");
    let manifest = build(&h);

    let paths: BTreeSet<PathBuf> = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect();
    let expected: BTreeSet<PathBuf> = [
        "root.pem",
        "intermediates/tls.pem",
        "intermediates/smime.pem",
        "aia/root.pem",
        "aia/tls.pem",
        "aia/smime.pem",
        "chains/tls-server/000A.pem",
        "crl/tls.crl",
        "crl/tls.crl.pem",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    assert_eq!(paths, expected);
    assert!(
        manifest
            .artifacts
            .windows(2)
            .all(|pair| pair[0].path < pair[1].path)
    );
}

#[test]
fn chain_files_are_leaf_first_then_authority_chain() {
    let h = Harness::new().expect("harness");
    build(&h);
    let chain = std::fs::read_to_string(h.paths().publish_dir().join("chains/tls-server/000A.pem"))
        .expect("chain readable");

    assert_eq!(
        chain,
        format!(
            "{}{}",
            h.fixtures.leaf.cert_pem, h.fixtures.tls.material.chain_pem
        )
    );
    assert_eq!(chain.matches("-----BEGIN CERTIFICATE-----").count(), 3);
}

#[test]
fn root_and_aia_files_hold_public_certificates() {
    let h = Harness::new().expect("harness");
    build(&h);
    let directory = h.paths().publish_dir();

    assert_eq!(
        std::fs::read_to_string(directory.join("root.pem")).expect("root"),
        h.fixtures.root.material.cert_pem
    );
    assert_eq!(
        std::fs::read_to_string(directory.join("aia/tls.pem")).expect("aia tls"),
        h.fixtures.tls.material.cert_pem
    );
    assert_eq!(
        std::fs::read_to_string(directory.join("intermediates/smime.pem")).expect("smime"),
        h.fixtures.smime.material.cert_pem
    );
}

#[test]
fn manifest_hashes_and_lengths_match_files() {
    let h = Harness::new().expect("harness");
    h.seed_crl(&tls().expect("authority")).expect("crl");
    let manifest = build(&h);
    let directory = h.paths().publish_dir();

    for artifact in &manifest.artifacts {
        let path = directory.join(&artifact.path);
        let bytes = std::fs::read(&path).expect("artifact readable");
        assert_eq!(u64::try_from(bytes.len()).expect("fits"), artifact.bytes);
        assert_eq!(hash(&path), artifact.sha256);
    }
}

#[test]
fn manifest_is_deterministic_and_excludes_itself() {
    let h = Harness::new().expect("harness");
    build(&h);
    let first = std::fs::read(h.paths().publish_dir().join("manifest.json")).expect("manifest");
    build(&h);
    let second = std::fs::read(h.paths().publish_dir().join("manifest.json")).expect("manifest");

    assert_eq!(first, second);
    assert!(first.ends_with(b"\n"));
    let text = String::from_utf8(first).expect("utf8");
    assert!(!text.contains("manifest.json"));
    assert_eq!(
        manifest_version(&text),
        chainkeeper_core::PUBLISH_MANIFEST_VERSION
    );
}

fn manifest_version(text: &str) -> u32 {
    let value: serde_json::Value = serde_json::from_str(text).expect("json");
    u32::try_from(value["version"].as_u64().expect("version")).expect("fits")
}

#[test]
fn manifest_lists_no_private_material() {
    let h = Harness::new().expect("harness");
    let manifest = build(&h);
    for artifact in &manifest.artifacts {
        let path = artifact.path.to_string_lossy().to_lowercase();
        assert!(!path.contains("key"), "unexpected path {path}");
    }

    for entry in walk(&h.paths().publish_dir()) {
        let bytes = std::fs::read(&entry).expect("readable");
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("PRIVATE KEY-----"), "{}", entry.display());
    }
}

fn walk(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![directory.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(directory).expect("readable") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

#[test]
fn stale_files_are_removed_and_existing_files_are_replaced() {
    let h = Harness::new().expect("harness");
    let directory = h.paths().publish_dir();
    std::fs::write(directory.join("stale.txt"), b"stale").expect("stale");
    std::fs::write(directory.join("root.pem"), b"garbage").expect("garbage");

    build(&h);

    assert!(!directory.join("stale.txt").exists());
    assert_eq!(
        std::fs::read_to_string(directory.join("root.pem")).expect("root"),
        h.fixtures.root.material.cert_pem
    );
}

#[test]
fn failed_build_leaves_previous_publish_intact() {
    let h = Harness::new().expect("harness");
    build(&h);
    let directory = h.paths().publish_dir();
    let manifest = std::fs::read(directory.join("manifest.json")).expect("manifest");
    let root = std::fs::read(directory.join("root.pem")).expect("root");

    std::fs::remove_file(h.absolute("certificates/active/000A.pem")).expect("remove leaf");
    let _error = h
        .publisher()
        .build(&PublishOptions::new(directory.clone()))
        .expect_err("missing leaf rejected");

    assert_eq!(
        std::fs::read(directory.join("manifest.json")).expect("manifest"),
        manifest
    );
    assert_eq!(
        std::fs::read(directory.join("root.pem")).expect("root"),
        root
    );
}

#[test]
fn destination_outside_allowed_root_is_rejected() {
    let h = Harness::new().expect("harness");
    let elsewhere = tempfile::tempdir().expect("temp");
    let error = h
        .publisher()
        .build(&PublishOptions::new(elsewhere.path().join("publish")))
        .expect_err("outside root rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[cfg(unix)]
#[test]
fn destination_symlink_is_rejected() {
    let h = Harness::new().expect("harness");
    let target = h.absolute("publish-target");
    std::fs::create_dir(&target).expect("target");
    let link = h.absolute("publish-link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let error = h
        .publisher()
        .build(&PublishOptions::new(link))
        .expect_err("symlink rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}

#[test]
fn built_directory_validates() {
    let h = Harness::new().expect("harness");
    build(&h);
    h.publisher()
        .validate_publish_dir(&h.paths().publish_dir())
        .expect("valid publish directory");
}

#[test]
fn missing_root_authority_is_rejected() {
    let h = Harness::new().expect("harness");
    let directory = h
        .paths()
        .authority_dir(&chainkeeper_core::AuthorityName::new("root").expect("name"));
    std::fs::remove_dir_all(directory).expect("remove root");

    let error = h
        .publisher()
        .build(&PublishOptions::new(h.paths().publish_dir()))
        .expect_err("missing root rejected");
    assert!(matches!(error, ChainkeeperError::Publish(_)));
}
