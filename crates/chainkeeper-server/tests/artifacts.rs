//! Artifact route tests.

mod support;

use std::sync::Arc;

use chainkeeper_server::{AppState, router};
use chainkeeper_testkit::{FakeOcspResponder, FakeServerStateProvider};
use support::{TestServer, fixture, state};

async fn server() -> TestServer {
    let (state, fixture) = state(true);
    TestServer::start_with_fixture(router(state), fixture).await
}

#[tokio::test]
async fn serves_root_with_cache_headers() {
    let server = server().await;
    let response = server.request("GET", "/root.pem", &[], b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("application/x-pem-file")
    );
    assert_eq!(
        response.header("cache-control"),
        Some("public, max-age=300")
    );
    assert!(response.header("etag").is_some());
    assert!(response.header("last-modified").is_some());
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    assert!(response.text().contains("ROOT"));
    server.stop().await;
}

#[tokio::test]
async fn serves_intermediate_aliases() {
    let server = server().await;
    let response = server
        .request("GET", "/tls-intermediate.pem", &[], b"")
        .await;
    assert_eq!(response.status, 200);
    assert!(response.text().contains("TLS"));

    for alias in [
        "/smime-intermediate.pem",
        "/codesign-intermediate.pem",
        "/ocsp-intermediate.pem",
    ] {
        let response = server.request("GET", alias, &[], b"").await;
        assert_eq!(response.status, 404, "{alias}");
        assert_eq!(response.json()["error"]["code"], "not_found");
    }
    server.stop().await;
}

#[tokio::test]
async fn serves_named_intermediates() {
    let server = server().await;
    let response = server
        .request("GET", "/intermediates/tls.pem", &[], b"")
        .await;
    assert_eq!(response.status, 200);

    let response = server
        .request("GET", "/intermediates/unknown.pem", &[], b"")
        .await;
    assert_eq!(response.status, 404);

    let response = server
        .request("GET", "/intermediates/TLS.pem", &[], b"")
        .await;
    assert_eq!(response.status, 400);

    let response = server
        .request("GET", "/intermediates/tls.txt", &[], b"")
        .await;
    assert_eq!(response.status, 404);
    server.stop().await;
}

#[tokio::test]
async fn serves_crl_and_aia() {
    let server = server().await;
    let response = server.request("GET", "/crl/tls.crl", &[], b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("application/pkix-crl")
    );
    assert_eq!(response.text(), "DER-CRL");

    let response = server.request("GET", "/crl/tls.crl.pem", &[], b"").await;
    assert_eq!(response.status, 404);
    let response = server.request("GET", "/crl/root.crl", &[], b"").await;
    assert_eq!(response.status, 404);
    let response = server
        .request("GET", "/crl/../etc/passwd.crl", &[], b"")
        .await;
    assert!(matches!(response.status, 400 | 404), "{}", response.status);

    let response = server.request("GET", "/aia/tls.pem", &[], b"").await;
    assert_eq!(response.status, 200);
    let response = server.request("GET", "/aia/unknown.pem", &[], b"").await;
    assert_eq!(response.status, 404);
    server.stop().await;
}

#[tokio::test]
async fn serves_chains() {
    let server = server().await;
    let response = server
        .request("GET", "/chains/tls-server/AA.pem", &[], b"")
        .await;
    assert_eq!(response.status, 200);
    assert!(response.text().contains("LEAF"));

    let response = server
        .request("GET", "/chains/tls-server/DD.pem", &[], b"")
        .await;
    assert_eq!(response.status, 404);

    let response = server.request("GET", "/chains/Bad/AA.pem", &[], b"").await;
    assert_eq!(response.status, 400);

    let response = server
        .request("GET", "/chains/tls-server/not-a-serial.pem", &[], b"")
        .await;
    assert_eq!(response.status, 400);
    server.stop().await;
}

#[tokio::test]
async fn conditional_requests_return_not_modified() {
    let server = server().await;
    let first = server.request("GET", "/root.pem", &[], b"").await;
    let etag = first.header("etag").expect("etag").to_owned();
    let last_modified = first
        .header("last-modified")
        .expect("last-modified")
        .to_owned();

    let response = server
        .request("GET", "/root.pem", &[("If-None-Match", &etag)], b"")
        .await;
    assert_eq!(response.status, 304);
    assert_eq!(response.body.len(), 0);
    assert_eq!(response.header("etag"), Some(etag.as_str()));
    assert_eq!(
        response.header("cache-control"),
        Some("public, max-age=300")
    );

    let response = server
        .request(
            "GET",
            "/root.pem",
            &[("If-Modified-Since", &last_modified)],
            b"",
        )
        .await;
    assert_eq!(response.status, 304);

    let response = server
        .request(
            "GET",
            "/root.pem",
            &[("If-Modified-Since", "Wed, 01 May 2024 11:59:59 GMT")],
            b"",
        )
        .await;
    assert_eq!(response.status, 200);

    let response = server
        .request("GET", "/root.pem", &[("If-None-Match", "\"other\"")], b"")
        .await;
    assert_eq!(response.status, 200);
    server.stop().await;
}

#[tokio::test]
async fn traversal_attempts_never_read_outside_the_publish_dir() {
    let server = server().await;
    for path in [
        "/intermediates/..%2F..%2Froot.pem",
        "/aia/..%2F..%2Fetc%2Fpasswd.pem",
        "/chains/..%2F..%2F/tls-server/AA.pem",
    ] {
        let response = server.request("GET", path, &[], b"").await;
        assert!(
            matches!(response.status, 400 | 404),
            "{path} returned {}",
            response.status
        );
    }
    server.stop().await;
}

#[tokio::test]
async fn missing_manifest_returns_404() {
    let mut fixture = fixture();
    fixture.snapshot.manifest = None;
    let provider = FakeServerStateProvider::new();
    provider.set_snapshot(fixture.snapshot);
    let state = AppState::new(
        Arc::new(provider),
        Arc::new(FakeOcspResponder::new()),
        fixture.directory.path(),
    );
    let server = TestServer::start(router(state)).await;

    let response = server.request("GET", "/root.pem", &[], b"").await;
    assert_eq!(response.status, 404);
    assert_eq!(response.json()["error"]["code"], "not_found");
    server.stop().await;
}

#[tokio::test]
async fn tampered_artifact_is_rejected() {
    let (state, fixture) = state(true);
    std::fs::write(fixture.directory.path().join("root.pem"), b"tampered").expect("tamper");
    let server = TestServer::start(router(state)).await;

    let response = server.request("GET", "/root.pem", &[], b"").await;
    assert_eq!(response.status, 500);
    assert_eq!(response.json()["error"]["code"], "internal");
    server.stop().await;
}
