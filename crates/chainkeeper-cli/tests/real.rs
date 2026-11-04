//! End-to-end tests against the real `ck` binary.
//!
//! Each test gets a hermetic `HOME` so the host Git configuration cannot affect
//! commits, and a temporary repository.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use chainkeeper_store::FileRepositoryLock;
use tempfile::TempDir;

/// Hermetic CLI environment.
struct Cli {
    home: TempDir,
    repo: TempDir,
}

impl Cli {
    fn new() -> Self {
        let home = tempfile::tempdir().expect("home directory");
        std::fs::write(
            home.path().join(".gitconfig"),
            "[user]\n\tname = Chainkeeper Test\n\temail = test@example.test\n[commit]\n\tgpgsign = false\n",
        )
        .expect("git config");
        let repo = tempfile::tempdir().expect("repository");
        let cli = Self { home, repo };
        cli.run(&["init", "--tenant-id", "acme"]);
        cli
    }

    fn repo_path(&self) -> &Path {
        self.repo.path()
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("ck"));
        command
            .arg("--repo")
            .arg(self.repo.path())
            .args(args)
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join(".config"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_CONFIG_GLOBAL")
            .env_remove("CHAINKEEPER_KEY_PASSPHRASE")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn try_run(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run ck")
    }

    fn run(&self, args: &[&str]) -> String {
        let output = self.try_run(args);
        assert!(
            output.status.success(),
            "ck {args:?} failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn with_authorities() -> Self {
        let cli = Self::new();
        cli.run(&["root", "create", "--cn", "Chainkeeper Test Root"]);
        cli.run(&["intermediate", "create", "--name", "tls"]);
        cli
    }

    fn issue(&self, cn: &str) -> String {
        self.run(&[
            "issue",
            "--profile",
            "tls-server",
            "--cn",
            cn,
            "--dns",
            cn,
            "--json",
        ])
    }

    fn active_certificates(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.repo_path().join("certificates/active"))
            .expect("active directory")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.ends_with(".pem") && !name.ends_with(".key.pem")
                })
            })
            .collect()
    }

    fn audit_events(&self) -> usize {
        std::fs::read_dir(self.repo_path().join("audit/events"))
            .expect("audit directory")
            .flatten()
            .count()
    }

    fn commits(&self) -> usize {
        let output = Command::new("git")
            .arg("-C")
            .arg(self.repo_path())
            .args(["rev-list", "--count", "HEAD"])
            .output()
            .expect("git rev-list");
        assert!(output.status.success(), "git rev-list failed");
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("commit count")
    }
}

#[test]
fn cli_uses_the_real_service_and_never_logs_private_keys() {
    let cli = Cli::with_authorities();
    let output = cli.try_run(&[
        "--verbose",
        "issue",
        "--profile",
        "tls-server",
        "--cn",
        "api.example.test",
        "--dns",
        "api.example.test",
    ]);
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for marker in [
        "PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "CHAINKEEPER_KEY_PASSPHRASE",
    ] {
        assert!(!combined.contains(marker), "log leaked {marker}");
    }

    let certificates = cli.active_certificates();
    assert_eq!(certificates.len(), 1);
    let key = certificates[0].with_extension("key.pem");
    assert!(key.is_file(), "generated key is written next to the leaf");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key)
            .expect("key metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "private key mode");
    }

    let doctor = cli.try_run(&["doctor", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&doctor.stdout).expect("doctor JSON");
    assert!(report["findings"].is_array(), "{report}");

    let search = cli.run(&["search", "--query", "api", "--json"]);
    let results: serde_json::Value = serde_json::from_str(&search).expect("search JSON");
    assert_eq!(results["total"], 1);
    cli.run(&["tree", "--json"]);
    cli.run(&["analyze", "policy", "--json"]);
    cli.run(&["audit", "--json"]);
}

#[test]
fn twenty_parallel_issues_produce_unique_certificates() {
    let cli = Cli::with_authorities();
    let before_events = cli.audit_events();
    let before_commits = cli.commits();

    let mut children = Vec::new();
    for index in 0..20 {
        let cn = format!("parallel-{index}.example.test");
        let output = cli
            .command(&[
                "issue",
                "--profile",
                "tls-server",
                "--cn",
                &cn,
                "--dns",
                &cn,
                "--json",
            ])
            .spawn()
            .expect("spawn ck issue");
        children.push((cn, output));
    }

    let mut serials = std::collections::BTreeSet::new();
    for (cn, child) in children {
        let output = child.wait_with_output().expect("wait for ck issue");
        assert!(
            output.status.success(),
            "{cn} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("issue JSON");
        let serial = report["certificate"]["serial"]
            .as_str()
            .expect("serial")
            .to_owned();
        assert!(serials.insert(serial), "duplicate serial in {cn}");
    }

    assert_eq!(serials.len(), 20);
    assert_eq!(cli.active_certificates().len(), 20);
    assert_eq!(cli.audit_events(), before_events + 20);
    assert_eq!(cli.commits(), before_commits + 20);
}

#[test]
fn conflicting_revocations_leave_exactly_one_winner() {
    let cli = Cli::with_authorities();
    let report: serde_json::Value =
        serde_json::from_str(&cli.issue("revoke.example.test")).expect("issue JSON");
    let serial = report["certificate"]["serial"]
        .as_str()
        .expect("serial")
        .to_owned();

    let first = cli
        .command(&["revoke", "--serial", &serial, "--json"])
        .spawn()
        .expect("first revoke");
    let second = cli
        .command(&["revoke", "--serial", &serial, "--json"])
        .spawn()
        .expect("second revoke");
    let first = first.wait_with_output().expect("first revoke output");
    let second = second.wait_with_output().expect("second revoke output");

    let successes = usize::from(first.status.success()) + usize::from(second.status.success());
    assert_eq!(successes, 1, "exactly one revocation must succeed");
    let failure = if first.status.success() {
        second
    } else {
        first
    };
    let message = String::from_utf8_lossy(&failure.stderr).to_lowercase();
    assert!(
        message.contains("already revoked") || message.contains("conflict"),
        "{message}"
    );
}

#[test]
fn a_held_lock_makes_the_cli_time_out_without_writing() {
    let cli = Cli::with_authorities();
    let before = cli.active_certificates().len();
    let paths = chainkeeper_core::RepositoryPaths::new(cli.repo_path()).expect("paths");
    let lock = FileRepositoryLock::new(paths);
    let guard = chainkeeper_core::RepositoryLock::acquire_exclusive(&lock, Duration::from_secs(1))
        .expect("hold lock");

    let output = cli.try_run(&[
        "issue",
        "--profile",
        "tls-server",
        "--cn",
        "locked.example.test",
        "--dns",
        "locked.example.test",
    ]);
    drop(guard);

    assert_eq!(output.status.code(), Some(1), "lock timeout exits 1");
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.to_lowercase().contains("timed out"), "{message}");
    assert_eq!(cli.active_certificates().len(), before);
}

#[test]
fn a_corrupt_index_is_moved_aside_and_rebuilt() {
    let cli = Cli::with_authorities();
    cli.issue("index.example.test");
    let index = cli.repo_path().join("cache/index.sqlite");
    std::fs::write(&index, b"this is not a sqlite database").expect("corrupt index");

    let search = cli.run(&["search", "--json"]);
    assert!(!search.trim().is_empty(), "search produced no JSON");
    let results: serde_json::Value = serde_json::from_str(&search)
        .unwrap_or_else(|error| panic!("search JSON {error}: {search:?}"));
    assert_eq!(results["total"], 1);
    assert!(
        cli.repo_path().join("cache/index.sqlite.corrupt").is_file(),
        "corrupt index is preserved"
    );
}

#[test]
fn doctor_reports_the_exact_corrupt_certificate_path() {
    let cli = Cli::with_authorities();
    cli.issue("corrupt.example.test");
    let certificate = cli.active_certificates().remove(0);
    std::fs::write(&certificate, b"not a certificate").expect("corrupt certificate");

    let doctor = cli.try_run(&["doctor", "--json"]);
    let report: serde_json::Value = serde_json::from_slice(&doctor.stdout).expect("doctor JSON");
    assert_eq!(report["healthy"], serde_json::Value::Bool(false));
    let findings = report["findings"].as_array().expect("findings");
    let path = certificate.display().to_string();
    let finding = findings
        .iter()
        .find(|finding| {
            finding["severity"] == "error"
                && finding["message"]
                    .as_str()
                    .is_some_and(|message| message.contains(&path))
        })
        .unwrap_or_else(|| panic!("corrupt certificate finding: {report}"));
    assert!(
        finding["message"]
            .as_str()
            .is_some_and(|message| message.contains(&certificate.display().to_string())),
        "finding must name the exact path: {finding}"
    );
}

#[test]
fn read_only_publish_directory_leaves_the_previous_publish_intact() {
    let cli = Cli::with_authorities();
    cli.issue("publish.example.test");
    let destination = cli.repo_path().join("publish");
    cli.run(&["publish"]);

    let manifest = destination.join("manifest.json");
    let before = std::fs::read(&manifest).expect("manifest");
    let before_files = count_files(&destination);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o500))
            .expect("read-only publish directory");
        let probe = destination.join("probe.tmp");
        if std::fs::write(&probe, b"probe").is_ok() {
            // Root ignores mode bits; the failure path cannot be exercised.
            let _ = std::fs::remove_file(&probe);
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700))
                .expect("restore permissions");
            return;
        }
    }

    let output = cli.try_run(&["publish"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700))
            .expect("restore permissions");
    }
    assert!(!output.status.success(), "publish must fail");
    assert_eq!(std::fs::read(&manifest).expect("manifest"), before);
    assert_eq!(count_files(&destination), before_files);
}

#[test]
fn interrupted_publish_leaves_a_complete_publish_tree() {
    let cli = Cli::with_authorities();
    cli.issue("interrupt.example.test");
    cli.run(&["publish"]);
    let destination = cli.repo_path().join("publish");

    let mut child = cli.command(&["publish"]).spawn().expect("spawn publish");
    std::thread::sleep(Duration::from_millis(1));
    let _ = child.kill();
    let _ = child.wait();

    let manifest_path = destination.join("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest"))
            .expect("manifest JSON");
    let artifacts = manifest["artifacts"].as_array().expect("artifacts");
    assert_ne!(artifacts.len(), 0);
    for artifact in artifacts {
        let path = artifact["path"].as_str().expect("artifact path");
        assert!(
            destination.join(path).is_file(),
            "artifact {path} missing after interrupted publish"
        );
    }
}

fn count_files(directory: &Path) -> usize {
    fn walk(directory: &Path) -> usize {
        std::fs::read_dir(directory).map_or(0, |entries| {
            entries
                .flatten()
                .map(|entry| {
                    let path = entry.path();
                    if path.is_dir() { walk(&path) } else { 1 }
                })
                .sum()
        })
    }
    walk(directory)
}
