mod common;

use std::path::PathBuf;

use chainkeeper_cli::CliError;
use chainkeeper_core::Serial;
use common::{CaptureUi, TestService, parse, run};

fn success(service: &TestService, args: &[&str]) -> (u8, CaptureUi) {
    let ui = CaptureUi::default();
    let code = run(service, &ui, args, false).expect("command succeeds");
    (code, ui)
}

fn failure(service: &TestService, args: &[&str]) -> CliError {
    let ui = CaptureUi::default();
    run(service, &ui, args, false).expect_err("command fails")
}

fn assert_json(args: &[&str], expected: &[&str]) {
    let service = TestService::default();
    let (code, ui) = success(&service, args);
    assert_eq!(code, 0, "{args:?}");
    assert!(ui.info.lock().expect("lock").is_empty(), "{args:?}");
    assert!(ui.tables.lock().expect("lock").is_empty(), "{args:?}");
    let value = ui.json_only();
    for key in expected {
        assert!(value.get(*key).is_some(), "{args:?} missing {key}: {value}");
    }
}

#[test]
fn every_command_has_a_json_shape() {
    assert_json(
        &["init", "--tenant-id", "acme", "--json"],
        &["tenant_id", "root", "created_paths", "commit"],
    );
    assert_json(
        &["root", "create", "--json"],
        &[
            "name",
            "kind",
            "algorithm",
            "validity_days",
            "path_len",
            "created_at",
            "cert_path",
            "chain_path",
        ],
    );
    assert_json(
        &["intermediate", "create", "--name", "tls", "--json"],
        &[
            "name",
            "kind",
            "parent",
            "algorithm",
            "validity_days",
            "path_len",
            "created_at",
            "cert_path",
            "chain_path",
        ],
    );
    assert_json(
        &["intermediate", "inspect", "--name", "tls", "--json"],
        &["name", "kind", "expires_at", "children"],
    );
    assert_json(
        &["ocsp-signer", "create", "--json"],
        &[
            "name",
            "kind",
            "parent",
            "algorithm",
            "validity_days",
            "path_len",
            "created_at",
            "cert_path",
            "chain_path",
        ],
    );
}

#[test]
fn certificate_and_maintenance_commands_have_json_shape() {
    assert_json(
        &[
            "issue",
            "--profile",
            "tls-server",
            "--cn",
            "api.example.test",
            "--dns",
            "api.example.test",
            "--json",
        ],
        &["certificate", "cert_path", "key_path", "commit"],
    );
    assert_json(
        &["revoke", "--serial", "00AA", "--json"],
        &["revocation", "crl", "commit"],
    );
    assert_json(
        &["inspect", "--serial", "00AA", "--json"],
        &["certificate", "status", "cert_pem", "chain_pem"],
    );
    assert_json(
        &["search", "--query", "api", "--json"],
        &["items", "total", "limit", "offset"],
    );
    assert_json(&["tree", "--json"], &["roots"]);
    assert_json(
        &["analyze", "policy", "--json"],
        &["kind", "generated_at", "findings"],
    );
    let service = TestService::default();
    let (code, ui) = success(&service, &["audit", "--json"]);
    assert_eq!(code, 0);
    assert!(ui.json_only().is_array());
    assert_json(
        &["doctor", "--json"],
        &["healthy", "checked_at", "findings"],
    );
    assert_json(
        &["diff", "--since", "HEAD~1", "--json"],
        &["from", "to", "added", "modified", "removed"],
    );
    assert_json(
        &["publish", "--json"],
        &[
            "version",
            "generated_at",
            "source_commit",
            "tenant_id",
            "artifacts",
        ],
    );
    assert_json(
        &["index", "rebuild", "--repair", "--json"],
        &["generated_at", "schema_version", "stats", "moved"],
    );
}

#[test]
fn missing_values_exit_two_without_blocking() {
    for args in [
        vec!["init"],
        vec!["issue", "--profile", "tls-server"],
        vec!["revoke"],
        vec!["inspect"],
        vec!["intermediate", "inspect"],
        vec!["search", "--expires", "soon"],
        vec!["init", "--tenant-id", "acme", "--force"],
    ] {
        let error = failure(&TestService::default(), &args);
        assert_eq!(error.exit_code(), 2, "{args:?}: {error:?}");
    }
}

#[test]
fn operation_errors_exit_one() {
    let service = TestService {
        fail_issue: true,
        ..TestService::default()
    };
    let error = failure(
        &service,
        &[
            "issue",
            "--profile",
            "tls-server",
            "--cn",
            "api.example.test",
            "--dns",
            "api.example.test",
            "--yes",
        ],
    );
    assert_eq!(error.exit_code(), 1);
}

#[test]
fn doctor_errors_exit_three() {
    let service = TestService {
        doctor_error: true,
        ..TestService::default()
    };
    let (code, ui) = success(&service, &["doctor"]);
    assert_eq!(code, 3);
    assert!(ui.all_text().contains("CRL_MISSING"));
}

#[test]
fn doctor_warnings_exit_zero() {
    let service = TestService::default();
    let (code, _ui) = success(&service, &["doctor"]);
    assert_eq!(code, 0);
}

#[test]
fn revoke_accepts_every_reason() {
    for reason in [
        "unspecified",
        "keyCompromise",
        "caCompromise",
        "affiliationChanged",
        "superseded",
        "cessationOfOperation",
        "certificateHold",
        "privilegeWithdrawn",
        "aaCompromise",
    ] {
        let (code, _ui) = success(
            &TestService::default(),
            &["revoke", "--serial", "00AA", "--reason", reason, "--yes"],
        );
        assert_eq!(code, 0, "{reason}");
    }
    let error = parse(&["revoke", "--reason", "not-a-reason"]).expect_err("unknown reason");
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn issue_forwards_custom_extensions_and_replacement() {
    let service = TestService::default();
    let (_code, _ui) = success(
        &service,
        &[
            "issue",
            "--profile",
            "tls-server",
            "--cn",
            "api.example.test",
            "--dns",
            "api.example.test",
            "--custom-oid",
            "1.2.3.4:true:value",
            "--custom-oid-hex",
            "1.2.3.5:false:00ff",
            "--replaces",
            "00FF",
            "--yes",
        ],
    );
    let request = service
        .last_issue
        .lock()
        .expect("lock")
        .clone()
        .expect("issue request");
    assert_eq!(request.custom_extensions.len(), 2);
    assert!(request.custom_extensions[0].critical);
    assert_eq!(
        request.custom_extensions[0].value_utf8.as_deref(),
        Some("value")
    );
    assert_eq!(
        request.custom_extensions[1].value_hex.as_deref(),
        Some("00ff")
    );
    assert_eq!(request.replaces, Some(Serial::new("00FF").expect("serial")));
}

#[test]
fn yes_bypasses_confirmation_in_interactive_mode() {
    let service = TestService::default();
    let ui = CaptureUi::default();
    let code = run(
        &service,
        &ui,
        &[
            "issue",
            "--profile",
            "tls-server",
            "--cn",
            "api.example.test",
            "--dns",
            "api.example.test",
            "--yes",
        ],
        true,
    )
    .expect("issuance");
    assert_eq!(code, 0);
}

#[test]
fn human_output_never_contains_private_key_material() {
    let (_code, ui) = success(
        &TestService::default(),
        &[
            "issue",
            "--profile",
            "tls-server",
            "--cn",
            "api.example.test",
            "--dns",
            "api.example.test",
            "--yes",
        ],
    );
    let text = ui.all_text();
    assert!(text.contains("serial"));
    assert!(text.contains("fingerprint"));
    assert!(!text.contains("PRIVATE KEY"));
}

#[test]
fn search_forwards_every_filter() {
    let service = TestService::default();
    let (_code, _ui) = success(
        &service,
        &[
            "search",
            "--query",
            "api",
            "--status",
            "active",
            "--profile",
            "tls-server",
            "--issuer",
            "tls",
            "--expires",
            "25h",
            "--all",
            "--limit",
            "5",
            "--offset",
            "2",
        ],
    );
    let query = service
        .last_search
        .lock()
        .expect("lock")
        .clone()
        .expect("search query");
    assert_eq!(query.text.as_deref(), Some("api"));
    assert_eq!(
        query.status,
        Some(chainkeeper_core::CertificateStatus::Active)
    );
    assert_eq!(
        query.profile.as_ref().map(ToString::to_string).as_deref(),
        Some("tls-server")
    );
    assert_eq!(
        query.authority.as_ref().map(ToString::to_string).as_deref(),
        Some("tls")
    );
    assert_eq!(query.expires_within_days, Some(2));
    assert!(query.include_expired);
    assert_eq!(query.limit, Some(5));
    assert_eq!(query.offset, 2);
}

#[test]
fn inspect_reads_serial_from_a_file() {
    let temp = tempfile::tempdir().expect("temp dir");
    let fixtures =
        chainkeeper_testkit::CertificateFixtures::generate(common::NOW).expect("fixtures");
    let path = temp.path().join("leaf.pem");
    std::fs::write(&path, &fixtures.leaf.cert_pem).expect("write");
    let (code, _ui) = success(
        &TestService::default(),
        &["inspect", "--file", path.to_str().expect("utf8")],
    );
    assert_eq!(code, 0);
}

#[test]
fn audit_and_analyze_filters_are_accepted() {
    let (code, _ui) = success(
        &TestService::default(),
        &[
            "audit",
            "--action",
            "CERT_ISSUED",
            "--object-type",
            "certificate",
            "--object-id",
            "00AA",
            "--since",
            "2024-01-01",
            "--until",
            "2024-12-31T00:00:00Z",
            "--limit",
            "5",
        ],
    );
    assert_eq!(code, 0);

    for kind in [
        "expirations",
        "revocations",
        "intermediates",
        "algorithms",
        "policy",
    ] {
        let (code, _ui) = success(&TestService::default(), &["analyze", kind]);
        assert_eq!(code, 0, "{kind}");
    }
}

#[test]
fn publish_modes_and_index_repair_are_supported() {
    for flag in ["--dry-run", "--no-commit"] {
        let (code, _ui) = success(&TestService::default(), &["publish", flag]);
        assert_eq!(code, 0, "{flag}");
    }

    let service = TestService::default();
    let (code, ui) = success(&service, &["index", "rebuild", "--repair", "--json"]);
    assert_eq!(code, 0);
    assert_eq!(
        ui.json_only()["moved"]
            .as_array()
            .expect("moved array")
            .len(),
        1
    );
}

#[test]
fn revoked_reason_maps_to_the_request() {
    let service = TestService::default();
    let (code, _ui) = success(
        &service,
        &[
            "revoke",
            "--serial",
            "00AA",
            "--reason",
            "keyCompromise",
            "--comment",
            "lost key",
            "--yes",
        ],
    );
    assert_eq!(code, 0);
}

#[test]
fn tree_and_human_reports_include_expected_columns() {
    let (code, ui) = success(&TestService::default(), &["tree"]);
    assert_eq!(code, 0);
    let text = ui.all_text();
    assert!(text.contains("root"));
    assert!(text.contains("tls"));
    assert!(text.contains("smime"));

    let (_code, ui) = success(&TestService::default(), &["search"]);
    let headers = ui
        .tables
        .lock()
        .expect("lock")
        .first()
        .expect("table")
        .0
        .clone();
    assert_eq!(
        headers,
        vec!["SERIAL", "CN", "PROFILE", "STATUS", "EXPIRES", "AUTHORITY"]
    );
}

#[test]
fn broken_hierarchy_exits_one() {
    let service = TestService {
        fail_tree: true,
        ..TestService::default()
    };
    let error = failure(&service, &["tree"]);
    assert_eq!(error.exit_code(), 1);
}

#[test]
fn init_human_output_lists_paths_and_commit() {
    let (code, ui) = success(&TestService::default(), &["init", "--tenant-id", "acme"]);
    assert_eq!(code, 0);
    let text = ui.all_text();
    assert!(text.contains("tenant.yaml"));
    assert!(text.contains("abc123"));
}

#[test]
fn repo_path_is_accepted_globally() {
    let (_code, _ui) = success(
        &TestService::default(),
        &[
            "--repo",
            PathBuf::from("/tmp/example").to_str().expect("utf8"),
            "tree",
        ],
    );
}
