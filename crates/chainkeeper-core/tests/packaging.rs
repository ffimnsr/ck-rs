//! Release packaging invariants: workflows, Dockerfile, and checksums.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn workflows(root: &Path) -> Vec<PathBuf> {
    let directory = root.join(".github/workflows");
    let mut files: Vec<PathBuf> = fs::read_dir(&directory)
        .expect("workflow directory")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
        })
        .collect();
    files.sort();
    assert!(!files.is_empty(), "at least one workflow is required");
    files
}

#[test]
fn workflows_are_valid_yaml_and_linted_when_actionlint_is_available() {
    let root = workspace_root();
    for path in workflows(&root) {
        let text = fs::read_to_string(&path).expect("workflow");
        let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text)
            .unwrap_or_else(|error| panic!("{} is not valid YAML: {error}", path.display()));
        assert!(
            value
                .get("jobs")
                .is_some_and(serde_yaml_ng::Value::is_mapping),
            "{} must define jobs",
            path.display()
        );
        assert!(
            value.get("on").is_some(),
            "{} must define triggers",
            path.display()
        );
    }

    if Command::new("actionlint")
        .arg("--version")
        .output()
        .is_err()
    {
        // actionlint is part of CI, not of the Rust toolchain.
        return;
    }
    let output = Command::new("actionlint")
        .arg("-no-color")
        .current_dir(&root)
        .output()
        .expect("run actionlint");
    assert!(
        output.status.success(),
        "actionlint failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn release_workflow_packages_both_binaries_and_checksums() {
    let root = workspace_root();
    let release = fs::read_to_string(root.join(".github/workflows/release.yml")).expect("release");
    for expected in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "ck ck-server",
        "sha256sum",
        "SHA256SUMS",
    ] {
        assert!(
            release.contains(expected),
            "release workflow misses {expected}"
        );
    }

    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).expect("ci");
    for expected in ["cargo-deny-action", "audit-check", "actionlint", "docker"] {
        assert!(ci.contains(expected), "CI workflow misses {expected}");
    }
}

#[test]
fn dockerfile_uses_a_non_root_runtime_user_and_healthz() {
    let root = workspace_root();
    let dockerfile = fs::read_to_string(root.join("Dockerfile")).expect("Dockerfile");
    assert!(
        dockerfile.contains("HEALTHCHECK"),
        "healthcheck is required"
    );
    assert!(
        dockerfile.contains("/healthz"),
        "healthcheck must probe /healthz"
    );
    assert!(
        dockerfile.contains("EXPOSE 8080"),
        "server port must be exposed"
    );

    let runtime = dockerfile
        .split("FROM debian")
        .nth(1)
        .expect("runtime stage");
    let user = runtime
        .lines()
        .find_map(|line| line.trim().strip_prefix("USER "))
        .expect("runtime stage must set USER");
    assert!(
        !user.trim().is_empty() && user.trim() != "root" && user.trim() != "0",
        "runtime user must not be root: {user}"
    );
}

#[test]
fn docker_bake_defines_both_images() {
    let root = workspace_root();
    let bake = fs::read_to_string(root.join("docker-bake.hcl")).expect("docker-bake.hcl");
    assert!(bake.contains("target \"ck\""));
    assert!(bake.contains("target \"ck-server\""));
    assert!(bake.contains("dockerfile = \"Dockerfile\""));
}
