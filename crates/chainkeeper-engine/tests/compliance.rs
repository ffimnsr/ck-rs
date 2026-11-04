//! RFC 5280, RFC 6960, and OpenSSL interoperability checks.
//!
//! `openssl` is used only to verify the product's output independently; the
//! product itself never shells out to it.

mod real;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use chainkeeper_core::{
    AuthorityName, ChainkeeperService, IssueReport, OcspResponder, RevocationReason, RevokeRequest,
};
use chainkeeper_server::config::ServerConfig;
use chainkeeper_server::runtime::{Runtime, build_state};
use real::{
    Tenant, generate_crls, init_tenant, intermediate_request, issue, issue_every_profile,
    root_request,
};
use tempfile::TempDir;

const INTERMEDIATES: [&str; 4] = ["tls", "smime", "codesign", "ocsp"];

fn openssl(args: &[&str]) -> Output {
    Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl is installed")
}

fn openssl_text(args: &[&str]) -> String {
    let output = openssl(args);
    assert!(
        output.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn authority_path(root: &Path, authority: &str, file: &str) -> PathBuf {
    root.join("authorities").join(authority).join(file)
}

fn leaf_path(root: &Path, report: &IssueReport) -> PathBuf {
    let serial = &report.certificate.serial;
    for status in ["active", "revoked", "expired"] {
        let candidate = root
            .join("certificates")
            .join(status)
            .join(format!("{serial}.pem"));
        if candidate.is_file() {
            return candidate;
        }
    }
    root.join(&report.cert_path)
}

/// Tenant with every authority and one certificate per profile.
fn fixture() -> (Tenant, Vec<IssueReport>, IssueReport) {
    let tenant = init_tenant("compliance");
    tenant.engine.create_root(&root_request()).expect("root");
    for name in INTERMEDIATES {
        tenant
            .engine
            .create_intermediate(&intermediate_request(name))
            .expect("intermediate");
    }
    tenant
        .engine
        .create_ocsp_signer(&real::ocsp_signer_request())
        .expect("ocsp signer");
    let issued = issue_every_profile(&tenant.engine);
    tenant
        .engine
        .revoke(&RevokeRequest {
            reason: RevocationReason::KeyCompromise,
            ..RevokeRequest::new(issued[0].certificate.serial.clone())
        })
        .expect("revoke tls-server leaf");
    // RFC 6960 delegation: the dedicated signer is issued by the OCSP
    // intermediate, so strict clients accept responses for certificates from
    // that same intermediate.
    let revoked_ocsp = issue(&tenant.engine, "ocsp", "revoked-ocsp.example.test");
    tenant
        .engine
        .revoke(&RevokeRequest {
            reason: RevocationReason::KeyCompromise,
            ..RevokeRequest::new(revoked_ocsp.certificate.serial.clone())
        })
        .expect("revoke ocsp leaf");
    generate_crls(&tenant.engine, false);
    (tenant, issued, revoked_ocsp)
}

#[test]
#[allow(clippy::too_many_lines)]
fn openssl_verifies_every_generated_chain() {
    let (tenant, issued, _revoked_ocsp) = fixture();
    let root = tenant.root();
    let root_pem = authority_path(root, "root", "cert.pem");

    for report in &issued {
        let authority = report.certificate.authority.as_str();
        let intermediate = authority_path(root, authority, "cert.pem");
        let leaf = leaf_path(root, report);
        let output = openssl(&[
            "verify",
            "-CAfile",
            &path_text(&root_pem),
            "-untrusted",
            &path_text(&intermediate),
            &path_text(&leaf),
        ]);
        assert!(
            output.status.success(),
            "openssl verify failed for {}: {}{}",
            report.certificate.profile,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(": OK"),
            "unexpected verify output for {}",
            report.certificate.profile
        );

        let rendered = openssl_text(&["x509", "-in", &path_text(&leaf), "-noout", "-text"]);
        assert!(
            rendered.contains("Version: 3"),
            "{}",
            report.certificate.profile
        );
        for extension in [
            "X509v3 Basic Constraints",
            "X509v3 Key Usage",
            "X509v3 Extended Key Usage",
            "X509v3 Subject Key Identifier",
            "X509v3 Authority Key Identifier",
            "Authority Information Access",
            "X509v3 CRL Distribution Points",
        ] {
            assert!(
                rendered.contains(extension),
                "{} is missing {extension}",
                report.certificate.profile
            );
        }
        assert!(rendered.contains("CA:FALSE"), "leaf must not be a CA");
        assert!(rendered.contains("http://ca.example.test/"));
        assert!(rendered.contains("http://crl.example.test/"));
        if report.certificate.profile.as_str() != "codesign"
            && report.certificate.profile.as_str() != "ocsp"
        {
            assert!(
                rendered.contains("Subject Alternative Name"),
                "{} is missing SANs",
                report.certificate.profile
            );
        }

        let serial = openssl_text(&["x509", "-in", &path_text(&leaf), "-noout", "-serial"]);
        let serial_hex = serial.trim().strip_prefix("serial=").expect("serial line");
        let value = u128::from_str_radix(serial_hex, 16).expect("serial is hexadecimal");
        assert!(value > 0, "serial must be positive");

        let leaf_issuer = openssl_text(&[
            "x509",
            "-in",
            &path_text(&leaf),
            "-noout",
            "-issuer",
            "-nameopt",
            "RFC2253",
        ]);
        let intermediate_subject = openssl_text(&[
            "x509",
            "-in",
            &path_text(&intermediate),
            "-noout",
            "-subject",
            "-nameopt",
            "RFC2253",
        ]);
        assert_eq!(
            leaf_issuer.trim().replace("issuer=", ""),
            intermediate_subject.trim().replace("subject=", ""),
            "leaf issuer must encode the intermediate subject"
        );

        let dates = openssl_text(&["x509", "-in", &path_text(&leaf), "-noout", "-dates"]);
        assert!(dates.contains("notBefore="));
        assert!(dates.contains("notAfter="));

        // No extension OID may appear twice.
        let pem = std::fs::read(&leaf).expect("leaf pem");
        let (_, block) = x509_parser::pem::parse_x509_pem(&pem).expect("parse pem");
        let certificate = block.parse_x509().expect("parse certificate");
        let mut seen = std::collections::BTreeSet::new();
        for extension in certificate.extensions() {
            assert!(
                seen.insert(extension.oid.to_id_string()),
                "duplicate extension {} in {}",
                extension.oid,
                report.certificate.profile
            );
        }
    }
}

#[test]
fn path_length_constraints_hold() {
    let (tenant, issued, _revoked_ocsp) = fixture();
    let root = tenant.root();
    let root_pem = authority_path(root, "root", "cert.pem");
    let tls = authority_path(root, "tls", "cert.pem");
    let rendered = openssl_text(&["x509", "-in", &path_text(&tls), "-noout", "-text"]);
    assert!(rendered.contains("CA:TRUE"));
    assert!(rendered.contains("pathlen:0"), "intermediate path length");

    let root_text = openssl_text(&["x509", "-in", &path_text(&root_pem), "-noout", "-text"]);
    assert!(root_text.contains("CA:TRUE"));
    assert!(root_text.contains("pathlen:1"), "root path length");

    // A leaf cannot substitute for the issuing intermediate: verifying with
    // only the leaf as an untrusted issuer must fail.
    let first = leaf_path(root, &issued[1]);
    let second = leaf_path(root, &issued[2]);
    let output = openssl(&[
        "verify",
        "-CAfile",
        &path_text(&root_pem),
        "-untrusted",
        &path_text(&first),
        &path_text(&second),
    ]);
    assert!(
        !output.status.success(),
        "a leaf must not verify as an intermediate"
    );
}

#[test]
fn crls_verify_and_track_revocations() {
    let (tenant, issued, _revoked_ocsp) = fixture();
    let root = tenant.root();
    let tls = authority_path(root, "tls", "cert.pem");
    let crl = root.join("crls/tls.crl.pem");
    let listing: Vec<String> = std::fs::read_dir(root.join("crls"))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    assert!(crl.is_file(), "CRL for tls is missing; found {listing:?}");

    let verify = openssl(&[
        "crl",
        "-in",
        &path_text(&crl),
        "-noout",
        "-verify",
        "-CAfile",
        &path_text(&tls),
    ]);
    assert!(
        verify.status.success(),
        "CRL verification failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let text = openssl_text(&["crl", "-in", &path_text(&crl), "-noout", "-text"]);
    let revoked = issued[0].certificate.serial.to_string().to_uppercase();
    assert!(
        text.to_uppercase().contains(&revoked),
        "revoked serial {revoked} missing from CRL"
    );
    assert!(text.contains("Key Compromise"));
    let active = issued[1].certificate.serial.to_string().to_uppercase();
    assert!(
        !text.to_uppercase().contains(&active),
        "active serial {active} must not be revoked"
    );

    let before = crl_number(&openssl_text(&[
        "crl",
        "-in",
        &path_text(&crl),
        "-noout",
        "-text",
    ]));
    tenant
        .engine
        .crl
        .update_for_authority(&AuthorityName::new("tls").expect("authority"))
        .expect("second CRL");
    let after = crl_number(&openssl_text(&[
        "crl",
        "-in",
        &path_text(&crl),
        "-noout",
        "-text",
    ]));
    assert!(
        after > before,
        "CRL number must increase: {before} -> {after}"
    );
}

fn crl_number(text: &str) -> u64 {
    let marker = "CRL Number:";
    let start = text.find(marker).expect("CRL number extension") + marker.len();
    text[start..]
        .lines()
        .find_map(|line| line.trim().parse::<u64>().ok())
        .expect("CRL number value")
}

struct Server {
    address: std::net::SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
    handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    runtime: Arc<Runtime>,
    temporary: TempDir,
}

impl Server {
    async fn start(tenant: &Tenant) -> Self {
        let config = ServerConfig {
            bind: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            repo: tenant.root().to_path_buf(),
            publish_dir: PathBuf::from(".chainkeeper/publish"),
            ..ServerConfig::default()
        };
        config.validate().expect("server configuration");
        let runtime = Arc::new(build_state(&config).expect("server runtime"));
        assert!(runtime.ocsp().ready(), "OCSP responder must be ready");

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let (shutdown, mut receiver) = tokio::sync::watch::channel(false);
        let server = Arc::clone(&runtime);
        let handle = tokio::spawn(async move {
            server
                .serve(listener, async move {
                    loop {
                        if *receiver.borrow() {
                            break;
                        }
                        if receiver.changed().await.is_err() {
                            break;
                        }
                    }
                })
                .await
        });
        Self {
            address,
            shutdown,
            handle: Some(handle),
            runtime,
            temporary: tempfile::tempdir().expect("temporary response directory"),
        }
    }

    fn output_path(&self, name: &str) -> PathBuf {
        self.temporary.path().join(name)
    }

    /// Signals shutdown and awaits the server task.
    async fn stop(mut self) {
        let _ = self.shutdown.send(true);
        if let Some(handle) = self.handle.take() {
            handle
                .await
                .expect("server task joins")
                .expect("server stops");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ocsp_reports_good_revoked_and_unknown() {
    let (tenant, issued, revoked_ocsp) = fixture();
    let server = Server::start(&tenant).await;
    let root = tenant.root();
    let tls = authority_path(root, "ocsp", "cert.pem");
    let good = leaf_path(root, &issued[5]);
    let revoked = leaf_path(root, &revoked_ocsp);
    let url = format!("http://{}/ocsp", server.address);

    let good_response = server.output_path("good.der");
    let output = openssl(&[
        "ocsp",
        "-issuer",
        &path_text(&tls),
        "-cert",
        &path_text(&good),
        "-url",
        &url,
        "-respout",
        &path_text(&good_response),
        "-CAfile",
        &path_text(&authority_path(root, "root", "cert.pem")),
        "-no_nonce",
    ]);
    assert!(
        output.status.success(),
        "OCSP good request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(": good"), "unexpected OCSP output: {text}");

    let revoked_response = server.output_path("revoked.der");
    let output = openssl(&[
        "ocsp",
        "-issuer",
        &path_text(&tls),
        "-cert",
        &path_text(&revoked),
        "-url",
        &url,
        "-respout",
        &path_text(&revoked_response),
        "-CAfile",
        &path_text(&authority_path(root, "root", "cert.pem")),
        "-no_nonce",
    ]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(": revoked"), "unexpected OCSP output: {text}");
    assert!(text.contains("keyCompromise"), "{text}");

    // Remove a certificate from the canonical store so its serial is unknown.
    let unknown = issue(&tenant.engine, "ocsp", "unknown.example.test");
    let unknown_source = leaf_path(root, &unknown);
    let copy = server.output_path("unknown.pem");
    std::fs::copy(&unknown_source, &copy).expect("copy unknown certificate");
    std::fs::remove_file(&unknown_source).expect("remove certificate");
    std::fs::remove_file(unknown_source.with_extension("yaml")).expect("remove metadata");
    server.runtime.ocsp().reload().expect("reload OCSP state");
    let output = openssl(&[
        "ocsp",
        "-issuer",
        &path_text(&tls),
        "-cert",
        &path_text(&copy),
        "-url",
        &url,
        "-CAfile",
        &path_text(&authority_path(root, "root", "cert.pem")),
        "-no_nonce",
    ]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(": unknown"), "unexpected OCSP output: {text}");

    // The response is signed by the dedicated OCSP signer, not by a CA.
    let response_text = openssl_text(&[
        "ocsp",
        "-respin",
        &path_text(&good_response),
        "-text",
        "-noverify",
    ]);
    assert!(
        response_text.contains("CN = ocsp-signer"),
        "OCSP response must embed the signer certificate: {response_text}"
    );
    assert!(
        response_text.contains("OCSP Response Status: successful"),
        "{response_text}"
    );

    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ocsp_round_trips_a_nonce() {
    let (tenant, issued, _revoked_ocsp) = fixture();
    let server = Server::start(&tenant).await;
    let root = tenant.root();
    let tls = authority_path(root, "ocsp", "cert.pem");
    let good = leaf_path(root, &issued[5]);
    let url = format!("http://{}/ocsp", server.address);
    let response = server.output_path("nonce.der");

    let output = openssl(&[
        "ocsp",
        "-issuer",
        &path_text(&tls),
        "-cert",
        &path_text(&good),
        "-url",
        &url,
        "-respout",
        &path_text(&response),
        "-CAfile",
        &path_text(&authority_path(root, "root", "cert.pem")),
        "-nonce",
    ]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    assert!(!text.contains("does not match"), "nonce mismatch: {text}");

    let rendered = openssl_text(&[
        "ocsp",
        "-respin",
        &path_text(&response),
        "-text",
        "-noverify",
    ]);
    assert!(rendered.contains("Nonce"), "nonce missing from response");
    server.stop().await;
}

#[test]
fn open_service_runs_doctor() {
    let tenant = init_tenant("doctor");
    tenant.engine.create_root(&root_request()).expect("root");
    for name in INTERMEDIATES {
        tenant
            .engine
            .create_intermediate(&intermediate_request(name))
            .expect("intermediate");
    }
    generate_crls(&tenant.engine, false);

    let service = real::service_for(tenant.root()).expect("open_service");
    let report = service.doctor().expect("doctor");
    assert!(report.healthy, "{:?}", report.findings);
}
