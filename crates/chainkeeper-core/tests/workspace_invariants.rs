//! Workspace-level invariants enforced by tests.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use chainkeeper_core::{ChainkeeperError, ErrorKind};

const CRATES: [&str; 12] = [
    "chainkeeper-core",
    "chainkeeper-store",
    "chainkeeper-crypto",
    "chainkeeper-policy",
    "chainkeeper-audit",
    "chainkeeper-git",
    "chainkeeper-engine",
    "chainkeeper-publish",
    "chainkeeper-ocsp",
    "chainkeeper-cli",
    "chainkeeper-server",
    "chainkeeper-testkit",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn source_files(root: &Path) -> Vec<PathBuf> {
    fn walk(directory: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(root, &mut found);
    found.sort();
    found
}

#[test]
fn workspace_contains_exactly_the_planned_crates() {
    let root = workspace_root();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("workspace manifest");
    let value: toml::Value = toml::from_str(&manifest).expect("workspace manifest is TOML");
    let members: BTreeSet<String> = value["workspace"]["members"]
        .as_array()
        .expect("members")
        .iter()
        .map(|member| {
            member
                .as_str()
                .expect("member path")
                .trim_start_matches("crates/")
                .to_owned()
        })
        .collect();
    let planned: BTreeSet<String> = CRATES.iter().map(ToString::to_string).collect();
    assert_eq!(
        members, planned,
        "workspace must contain the twelve planned crates"
    );
    assert_eq!(members.len(), 12);

    let publishable: Vec<String> = members
        .iter()
        .filter(|name| {
            let manifest = fs::read_to_string(root.join("crates").join(name).join("Cargo.toml"))
                .expect("crate manifest");
            let workspace_publish = manifest.contains("publish.workspace = true");
            let value = toml::from_str::<toml::Value>(&manifest).expect("crate manifest");
            let explicit = value["package"]["publish"].as_bool();
            !workspace_publish && explicit != Some(false)
        })
        .cloned()
        .collect();
    assert!(
        publishable.is_empty(),
        "no crate may be publishable: {publishable:?}"
    );
}

#[test]
fn product_crates_never_execute_openssl() {
    let root = workspace_root();
    let mut offenders = Vec::new();
    for name in CRATES {
        let source = root.join("crates").join(name).join("src");
        for path in source_files(&source) {
            let contents = fs::read_to_string(&path).expect("source file");
            if contents.contains("Command::new(\"openssl\")")
                || contents.contains("Command::new(\"openssl ")
                || contents.contains("std::process::Command") && contents.contains("openssl")
            {
                offenders.push(path);
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "product crates must never shell out to openssl: {offenders:?}"
    );
}

#[test]
fn test_only_code_is_confined_to_test_modules() {
    let root = workspace_root();
    let mut offenders = Vec::new();
    for name in CRATES {
        let source = root.join("crates").join(name).join("src");
        for path in source_files(&source) {
            let contents = fs::read_to_string(&path).expect("source file");
            let lines: Vec<&str> = contents.lines().collect();
            for (index, line) in lines.iter().enumerate() {
                if line.trim() != "#[cfg(test)]" {
                    continue;
                }
                let next = lines.iter().skip(index + 1).find(|candidate| {
                    !candidate.trim().is_empty() && !candidate.trim().starts_with("//")
                });
                let confined = next.is_some_and(|candidate| {
                    let candidate = candidate.trim();
                    candidate.starts_with("mod tests")
                        || candidate.starts_with("mod test")
                        || candidate.starts_with("#[")
                });
                if !confined {
                    offenders.push(format!("{}:{}", path.display(), index + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "production paths must not be gated behind #[cfg(test)]: {offenders:?}"
    );
}

fn error_for(kind: ErrorKind) -> ChainkeeperError {
    match kind {
        ErrorKind::Config => ChainkeeperError::config("test"),
        ErrorKind::Validation => ChainkeeperError::validation("test"),
        ErrorKind::Policy => ChainkeeperError::policy("test"),
        ErrorKind::Profile => ChainkeeperError::profile("test"),
        ErrorKind::Crypto => ChainkeeperError::crypto("test"),
        ErrorKind::Storage => ChainkeeperError::storage("test"),
        ErrorKind::Index => ChainkeeperError::index("test"),
        ErrorKind::Audit => ChainkeeperError::audit("test"),
        ErrorKind::Git => ChainkeeperError::git("test"),
        ErrorKind::Lock => ChainkeeperError::lock("test"),
        ErrorKind::Publish => ChainkeeperError::publish("test"),
        ErrorKind::Ocsp => ChainkeeperError::ocsp("test"),
        ErrorKind::NotFound => ChainkeeperError::not_found("object", "id"),
        ErrorKind::AlreadyExists => ChainkeeperError::already_exists("object"),
        ErrorKind::Conflict => ChainkeeperError::conflict("test"),
        ErrorKind::NotImplemented => ChainkeeperError::not_implemented("test"),
        ErrorKind::Io => ChainkeeperError::io_error("test"),
        // `ErrorKind` is non-exhaustive; new variants must be added above.
        _ => ChainkeeperError::storage("unknown error kind"),
    }
}

#[test]
fn every_error_kind_has_a_documented_failure_exit_code() {
    let mut labels = BTreeSet::new();
    for kind in ErrorKind::ALL {
        let error = error_for(kind);
        assert_eq!(error.kind(), kind);
        assert_eq!(error.exit_code(), 1, "{kind:?} must exit 1");
        assert!(
            labels.insert(kind.as_str().to_owned()),
            "duplicate label {kind:?}"
        );
        assert_ne!(kind.as_str(), "");
    }
    assert_eq!(labels.len(), ErrorKind::ALL.len());
}
