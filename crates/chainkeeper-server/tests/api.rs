//! API route tests.

mod support;

use support::{TestServer, state};

use chainkeeper_server::router;

async fn start_server(ocsp_ready: bool) -> TestServer {
    let (state, fixture) = state(ocsp_ready);
    let app = router(state);
    TestServer::start_with_fixture(app, fixture).await
}

#[tokio::test]
async fn lists_certificates_with_pagination() {
    let server = start_server(true).await;
    let response = server
        .request("GET", "/api/v1/certificates", &[], b"")
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    let body = response.json();
    assert_eq!(body["items"].as_array().expect("items").len(), 3);
    assert!(body.get("next_cursor").is_none());

    let response = server
        .request("GET", "/api/v1/certificates?limit=1", &[], b"")
        .await;
    let body = response.json();
    assert_eq!(body["items"].as_array().expect("items").len(), 1);
    assert_eq!(body["next_cursor"], "AA");

    let response = server
        .request("GET", "/api/v1/certificates?limit=1&cursor=AA", &[], b"")
        .await;
    let body = response.json();
    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["serial"], "BB");

    server.stop().await;
}

#[tokio::test]
async fn filters_certificates() {
    let server = start_server(true).await;

    let response = server
        .request("GET", "/api/v1/certificates?status=active", &[], b"")
        .await;
    let body = response.json();
    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["serial"], "AA");

    let response = server
        .request("GET", "/api/v1/certificates?status=expired", &[], b"")
        .await;
    let body = response.json();
    let items = body["items"].as_array().expect("items");
    assert_eq!(items[0]["serial"], "BB");

    let response = server
        .request("GET", "/api/v1/certificates?status=revoked", &[], b"")
        .await;
    let body = response.json();
    let items = body["items"].as_array().expect("items");
    assert_eq!(items[0]["serial"], "CC");

    let response = server
        .request("GET", "/api/v1/certificates?profile=tls-client", &[], b"")
        .await;
    let body = response.json();
    assert_eq!(body["items"].as_array().expect("items").len(), 1);

    let response = server
        .request(
            "GET",
            "/api/v1/certificates?authority=tls&expires_within=15",
            &[],
            b"",
        )
        .await;
    let body = response.json();
    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["serial"], "BB");

    server.stop().await;
}

#[tokio::test]
async fn rejects_invalid_filters() {
    let server = start_server(true).await;
    for query in [
        "limit=0",
        "limit=1000",
        "limit=many",
        "status=lost",
        "profile=Bad%20Name",
        "authority=Bad%20Name",
        "expires_within=soon",
        "cursor=lowercase",
    ] {
        let response = server
            .request("GET", &format!("/api/v1/certificates?{query}"), &[], b"")
            .await;
        assert_eq!(response.status, 400, "{query}");
        assert_eq!(response.json()["error"]["code"], "validation", "{query}");
    }
    server.stop().await;
}

#[tokio::test]
async fn serves_one_certificate() {
    let server = start_server(true).await;
    let response = server
        .request("GET", "/api/v1/certificates/AA", &[], b"")
        .await;
    assert_eq!(response.status, 200);
    let body = response.json();
    assert_eq!(body["serial"], "AA");
    assert_eq!(body["status"], "active");
    assert_eq!(body["pem_url"], "/chains/tls-server/AA.pem");

    let response = server
        .request("GET", "/api/v1/certificates/FF", &[], b"")
        .await;
    assert_eq!(response.status, 404);
    assert_eq!(response.json()["error"]["code"], "not_found");

    let response = server
        .request("GET", "/api/v1/certificates/not-a-serial", &[], b"")
        .await;
    assert_eq!(response.status, 400);
    assert_eq!(response.json()["error"]["code"], "validation");

    server.stop().await;
}

#[tokio::test]
async fn serves_root_certificate() {
    let server = start_server(true).await;
    let response = server.request("GET", "/api/v1/root", &[], b"").await;
    assert_eq!(response.status, 200, "{}", response.text());
    assert_eq!(
        response.header("content-type"),
        Some("application/x-pem-file")
    );
    assert!(response.text().contains("BEGIN CERTIFICATE"));
    server.stop().await;
}

#[tokio::test]
async fn serves_intermediates() {
    let server = start_server(true).await;
    let response = server
        .request("GET", "/api/v1/intermediates", &[], b"")
        .await;
    assert_eq!(response.status, 200);
    let body = response.json();
    let items = body.as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["name"], "smime");
    assert_eq!(items[0]["kind"], "intermediate");
    assert_eq!(items[0]["parent"], "root");
    assert_eq!(items[0]["pem_url"], "/aia/smime.pem");
    assert_eq!(items[1]["name"], "tls");
    server.stop().await;
}

#[tokio::test]
async fn serves_revocations_and_crls() {
    let server = start_server(true).await;
    let response = server.request("GET", "/api/v1/revocations", &[], b"").await;
    assert_eq!(response.status, 200);
    let body = response.json();
    let items = body.as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["serial"], "CC");
    assert_eq!(items[0]["reason"], "keyCompromise");

    let response = server.request("GET", "/api/v1/crls", &[], b"").await;
    assert_eq!(response.status, 200);
    let body = response.json();
    let items = body.as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["authority"], "tls");
    assert_eq!(items[0]["revoked_count"], 1);
    assert_eq!(items[0]["url"], "/crl/tls.crl");

    server.stop().await;
}

#[tokio::test]
async fn filters_audit_events() {
    let server = start_server(true).await;
    let response = server.request("GET", "/api/v1/audit", &[], b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.json()["items"].as_array().expect("items").len(), 2);

    let response = server
        .request("GET", "/api/v1/audit?action=CERT_ISSUED", &[], b"")
        .await;
    let body = response.json();
    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["action"], "CERT_ISSUED");

    let response = server
        .request(
            "GET",
            "/api/v1/audit?limit=1&cursor=01J00000000000000000000000",
            &[],
            b"",
        )
        .await;
    let body = response.json();
    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["seq"], 2);

    let response = server
        .request("GET", "/api/v1/audit?since=yesterday", &[], b"")
        .await;
    assert_eq!(response.status, 400);
    assert_eq!(response.json()["error"]["code"], "validation");

    let response = server
        .request("GET", "/api/v1/audit?action=CERT_DESTROYED", &[], b"")
        .await;
    assert_eq!(response.status, 400);

    server.stop().await;
}

#[tokio::test]
async fn health_endpoints() {
    let server = start_server(true).await;
    let response = server.request("GET", "/healthz", &[], b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.json()["status"], "ok");

    let response = server.request("GET", "/readyz", &[], b"").await;
    assert_eq!(response.status, 200);
    assert!(response.json()["ocsp_ready"].as_bool().expect("ready"));

    let response = server.request("GET", "/api/v1/health", &[], b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.json()["status"], "ok");
    server.stop().await;

    let not_ready = start_server(false).await;
    let response = not_ready.request("GET", "/healthz", &[], b"").await;
    assert_eq!(response.status, 200);
    let response = not_ready.request("GET", "/readyz", &[], b"").await;
    assert_eq!(response.status, 503);
    let body = response.json();
    assert_eq!(body["status"], "degraded");
    assert_ne!(body["errors"].as_array().expect("errors").len(), 0);
    not_ready.stop().await;
}

#[tokio::test]
async fn unknown_routes_return_json_404() {
    let server = start_server(true).await;
    let response = server.request("GET", "/nope", &[], b"").await;
    assert_eq!(response.status, 404);
    assert_eq!(response.json()["error"]["code"], "not_found");
    server.stop().await;
}
