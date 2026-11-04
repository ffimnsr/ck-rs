//! Security, OCSP, and lifecycle tests.

mod support;

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use chainkeeper_core::{ChainkeeperError, ServerStateProvider};
use chainkeeper_server::snapshot::{RepositoryDeps, RepositoryStateProvider};
use chainkeeper_server::{apply_layers, router};
use chainkeeper_testkit::{InMemoryAuditLog, InMemoryCertificateStore, InMemoryGitRepository};
use support::{TestServer, fixture, state};

async fn server(ocsp_ready: bool) -> TestServer {
    let (state, fixture) = state(ocsp_ready);
    TestServer::start_with_fixture(router(state), fixture).await
}

#[tokio::test]
async fn read_routes_reject_write_methods() {
    let server = server(true).await;
    for (method, path) in [
        ("POST", "/api/v1/certificates"),
        ("PUT", "/api/v1/certificates/AA"),
        ("PATCH", "/api/v1/root"),
        ("DELETE", "/api/v1/audit"),
        ("POST", "/root.pem"),
        ("PUT", "/crl/tls.crl"),
        ("DELETE", "/healthz"),
        ("POST", "/api/v1/health"),
    ] {
        let response = server.request(method, path, &[], b"").await;
        assert_eq!(response.status, 405, "{method} {path}");
        assert_eq!(
            response.json()["error"]["code"],
            "method_not_allowed",
            "{method} {path}"
        );
        assert!(response.header("allow").is_some(), "{method} {path}");
    }
    server.stop().await;
}

#[tokio::test]
async fn ocsp_route_accepts_only_post() {
    let server = server(true).await;
    let response = server
        .request(
            "POST",
            "/ocsp",
            &[("Content-Type", "application/ocsp-request")],
            b"request-bytes",
        )
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("application/ocsp-response")
    );
    assert_eq!(
        response.header("cache-control"),
        Some("public, max-age=3600")
    );
    assert_eq!(response.text(), "FAKE-OCSP:request-bytes");

    let response = server.request("GET", "/ocsp", &[], b"").await;
    assert_eq!(response.status, 405);
    assert_eq!(response.header("allow"), Some("POST"));

    server.stop().await;
}

#[tokio::test]
async fn ocsp_route_rejects_wrong_media_and_oversized_requests() {
    let server = server(true).await;
    let response = server
        .request(
            "POST",
            "/ocsp",
            &[("Content-Type", "application/json")],
            b"{}",
        )
        .await;
    assert_eq!(response.status, 415);
    assert_eq!(response.json()["error"]["code"], "unsupported_media_type");

    let oversized = vec![0_u8; 70 * 1024];
    let response = server
        .request(
            "POST",
            "/ocsp",
            &[("Content-Type", "application/ocsp-request")],
            &oversized,
        )
        .await;
    assert_eq!(response.status, 413);

    let response = server
        .request("GET", "/healthz", &[], &vec![0_u8; 70 * 1024])
        .await;
    assert_eq!(response.status, 413);
    server.stop().await;
}

#[tokio::test]
async fn ocsp_route_reports_not_ready() {
    let server = server(false).await;
    let response = server
        .request(
            "POST",
            "/ocsp",
            &[("Content-Type", "application/ocsp-request")],
            b"request",
        )
        .await;
    assert_eq!(response.status, 503);
    assert_eq!(response.json()["error"]["code"], "service_unavailable");
    server.stop().await;
}

#[tokio::test]
async fn server_rejects_publish_directories_with_private_keys() {
    let directory = tempfile::tempdir().expect("publish dir");
    std::fs::write(
        directory.path().join("leaked.pem"),
        b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
    )
    .expect("private key");
    let error = RepositoryStateProvider::open(deps(directory.path()))
        .expect_err("private key must be rejected");
    assert!(error.to_string().contains("private key"), "{error}");
}

#[tokio::test]
async fn failed_reload_preserves_the_previous_snapshot() {
    let fixture = fixture();
    let provider =
        RepositoryStateProvider::open(deps(fixture.directory.path())).expect("initial snapshot");
    let before = provider.snapshot();

    std::fs::write(fixture.directory.path().join("manifest.json"), b"not json").expect("corrupt");
    let error = provider.reload().expect_err("reload fails");

    assert!(error.to_string().contains("manifest") || error.to_string().contains("parse"));
    let after = provider.snapshot();
    assert!(Arc::ptr_eq(&before, &after));
    let health = provider.health();
    assert_eq!(health.status, chainkeeper_core::HealthStatus::Degraded);
    assert_ne!(health.errors.len(), 0);
}

#[tokio::test]
async fn snapshot_provider_never_touches_authority_private_keys() {
    let fixture = fixture();
    // The in-memory store fails `load_authority`; the provider must never call it.
    let provider = RepositoryStateProvider::open(deps(fixture.directory.path()))
        .expect("snapshot built from public records");
    let snapshot = provider.snapshot();
    assert_ne!(snapshot.repo_commit.len(), 0);
    assert_eq!(snapshot.certificates.len(), 0);
    assert!(
        snapshot
            .authorities
            .iter()
            .all(|authority| !authority.cert_path.ends_with("key.pem"))
    );
}

#[tokio::test]
async fn graceful_shutdown_completes_and_releases_the_port() {
    let (state, _fixture) = state(true);
    let server = TestServer::start(router(state)).await;
    let response = server.request("GET", "/healthz", &[], b"").await;
    assert_eq!(response.status, 200);
    server.stop().await;
}

#[tokio::test]
async fn request_timeout_returns_408() {
    let app = Router::new().route(
        "/slow",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            "done"
        }),
    );
    let app = apply_layers(app, Duration::from_millis(50), 1024);
    let server = TestServer::start(app).await;
    let response = server.request("GET", "/slow", &[], b"").await;
    assert_eq!(response.status, 408);
    server.stop().await;
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn logs_never_contain_private_key_markers() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (state, _fixture) = state(true);
    let server = TestServer::start(router(state)).await;
    let response = server.request("GET", "/api/v1/health", &[], b"").await;
    assert_eq!(response.status, 200);
    let response = server
        .request(
            "POST",
            "/ocsp",
            &[("Content-Type", "application/json")],
            b"{}",
        )
        .await;
    assert_eq!(response.status, 415);
    server.stop().await;

    let logs = String::from_utf8_lossy(
        &capture
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
    .into_owned();
    assert!(!logs.contains("PRIVATE KEY"), "{logs}");
    assert!(!logs.contains("BEGIN RSA PRIVATE KEY"), "{logs}");
}

fn deps(publish_dir: &std::path::Path) -> RepositoryDeps {
    let store = Arc::new(InMemoryCertificateStore::new());
    let audit = Arc::new(InMemoryAuditLog::new());
    let git = Arc::new(InMemoryGitRepository::new());
    chainkeeper_core::GitRepository::init(git.as_ref(), std::path::Path::new("."))
        .expect("initial commit");
    RepositoryDeps {
        clock: Arc::new(chainkeeper_core::SystemClock),
        store,
        audit,
        git,
        publish_dir: publish_dir.to_path_buf(),
    }
}

#[test]
fn chainkeeper_errors_map_to_safe_messages() {
    let error = ChainkeeperError::storage("could not read /secret/path");
    let api = chainkeeper_server::ApiError::from(error);
    assert!(!api.message().contains("/secret/path"));
    assert_eq!(api.status().as_u16(), 500);
}
