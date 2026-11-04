//! Enforces the compile-time dependency direction between workspace crates.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

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
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn allowed(name: &str) -> BTreeSet<&'static str> {
    match name {
        "chainkeeper-core" => BTreeSet::new(),
        // Binary crates compose the concrete implementations. Library crates
        // keep the strict core-only direction.
        "chainkeeper-cli" => BTreeSet::from([
            "chainkeeper-core",
            "chainkeeper-engine",
            "chainkeeper-store",
            "chainkeeper-crypto",
            "chainkeeper-policy",
            "chainkeeper-audit",
            "chainkeeper-git",
            "chainkeeper-publish",
        ]),
        // The engine is the composition root for the concrete implementations.
        "chainkeeper-engine" => BTreeSet::from([
            "chainkeeper-core",
            "chainkeeper-store",
            "chainkeeper-crypto",
            "chainkeeper-policy",
            "chainkeeper-audit",
            "chainkeeper-git",
            "chainkeeper-publish",
            "chainkeeper-ocsp",
        ]),
        "chainkeeper-server" => BTreeSet::from([
            "chainkeeper-core",
            "chainkeeper-store",
            "chainkeeper-crypto",
            "chainkeeper-policy",
            "chainkeeper-publish",
            "chainkeeper-git",
            "chainkeeper-audit",
            "chainkeeper-ocsp",
            "chainkeeper-engine",
        ]),
        _ => BTreeSet::from(["chainkeeper-core"]),
    }
}

#[test]
fn crates_respect_the_dependency_direction() {
    let root = workspace_root();
    for name in CRATES {
        let manifest_path = root.join("crates").join(name).join("Cargo.toml");
        let raw = fs::read_to_string(&manifest_path).expect("crate manifest is readable");
        let manifest: toml::Value = toml::from_str(&raw).expect("crate manifest is valid TOML");
        let actual: BTreeSet<&str> = manifest
            .get("dependencies")
            .and_then(|value| value.as_table())
            .map(|table| {
                table
                    .keys()
                    .map(String::as_str)
                    .filter(|key| key.starts_with("chainkeeper-"))
                    .collect()
            })
            .unwrap_or_default();
        let allowed = allowed(name);
        assert!(
            actual.is_subset(&allowed),
            "{name} depends on {actual:?} but may only depend on {allowed:?}"
        );
        if name == "chainkeeper-core" {
            assert!(actual.is_empty(), "core must not depend on other crates");
        } else if name != "chainkeeper-testkit" {
            assert!(
                actual.contains("chainkeeper-core"),
                "{name} must depend on chainkeeper-core"
            );
        }
    }
}
