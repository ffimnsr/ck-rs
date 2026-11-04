//! Shared HTTP and repository fixtures.
//!
//! Servers bind `127.0.0.1:0` and every fixture owns its own temporary
//! directory, so tests never share ports or paths and can run in parallel.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::SocketAddr;

use axum::Router;
use chainkeeper_core::{
    AuditAction, AuditEvent, AuthorityKind, AuthorityName, AuthorityRecord, CertificateRecord,
    CertificateStatus, CrlRecord, EventId, KeyAlgorithm, ProfileName, PublishArtifact,
    PublishManifest, RevocationReason, RevocationRecord, Serial, ServerSnapshot, SubjectName,
    TenantId,
};
use chainkeeper_server::AppState;
use chainkeeper_testkit::{FakeOcspResponder, FakeServerStateProvider};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use tokio::sync::watch;

/// Raw HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Lowercase header map.
    pub headers: BTreeMap<String, String>,
    /// Response body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Returns a header value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// Decodes the body as UTF-8.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// Decodes the body as JSON.
    ///
    /// # Panics
    ///
    /// Panics when the body is not valid JSON.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("response is JSON")
    }
}

/// Server bound to an ephemeral loopback port.
pub struct TestServer {
    address: SocketAddr,
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<std::io::Result<()>>,
    // Keeps the publish tree alive for the lifetime of the server.
    fixture: Option<Fixture>,
}

impl std::fmt::Debug for TestServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TestServer")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl TestServer {
    /// Starts `app` on an ephemeral port.
    ///
    /// # Panics
    ///
    /// Panics when the listener cannot be bound.
    pub async fn start(app: Router) -> Self {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind ephemeral port");
        let address = listener.local_addr().expect("local address");
        let (shutdown, mut receiver) = watch::channel(false);
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
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
            handle,
            fixture: None,
        }
    }

    /// Starts `app` while keeping its publish tree alive.
    ///
    /// # Panics
    ///
    /// Panics when the listener cannot be bound.
    pub async fn start_with_fixture(app: Router, fixture: Fixture) -> Self {
        let mut server = Self::start(app).await;
        server.fixture = Some(fixture);
        server
    }

    /// Sends one HTTP/1.1 request over a fresh connection.
    ///
    /// # Panics
    ///
    /// Panics when the connection or response fails.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> HttpResponse {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut stream = tokio::net::TcpStream::connect(self.address)
            .await
            .expect("connect");
        let mut request = String::new();
        let _ = write!(
            request,
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            self.address,
            body.len()
        );
        for (name, value) in headers {
            let _ = write!(request, "{name}: {value}\r\n");
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        stream.write_all(body).await.expect("write body");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.expect("read response");
        parse_response(&raw)
    }

    /// Shuts the server down and awaits its task.
    ///
    /// # Panics
    ///
    /// Panics when the server task fails.
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        self.handle.await.expect("server task").expect("server");
    }
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("response headers");
    let head = std::str::from_utf8(&raw[..split]).expect("utf-8 headers");
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let body = &raw[split + 4..];
    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.contains("chunked"))
    {
        decode_chunked(body)
    } else {
        body.to_vec()
    };
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn decode_chunked(mut body: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    while let Some(position) = body.windows(2).position(|window| window == b"\r\n") {
        let size = std::str::from_utf8(&body[..position]).unwrap_or_default();
        let size = usize::from_str_radix(size.trim(), 16).unwrap_or_default();
        body = &body[position + 2..];
        if size == 0 {
            break;
        }
        let end = size.min(body.len());
        decoded.extend_from_slice(&body[..end]);
        body = body.get(end + 2..).unwrap_or_default();
    }
    decoded
}

/// Published artifact directory plus its manifest.
pub struct Fixture {
    /// Temporary directory holding the publish tree.
    pub directory: TempDir,
    /// Snapshot served by the app.
    pub snapshot: ServerSnapshot,
}

/// Fixed snapshot clock.
#[must_use]
pub const fn now() -> OffsetDateTime {
    datetime!(2024-05-01 12:00:00 UTC)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn certificate(
    serial: &str,
    profile: &str,
    expires_at: OffsetDateTime,
    revoked_at: Option<OffsetDateTime>,
) -> CertificateRecord {
    CertificateRecord {
        serial: Serial::new(serial).expect("serial"),
        subject: SubjectName::new(format!("{serial}.example.test")),
        issuer: "CN=Example TLS Intermediate".to_owned(),
        profile: ProfileName::new(profile).expect("profile"),
        authority: AuthorityName::new("tls").expect("authority"),
        algorithm: KeyAlgorithm::EcdsaP256,
        sans: Vec::new(),
        ekus: Vec::new(),
        key_usages: Vec::new(),
        issued_at: now() - Duration::days(10),
        expires_at,
        path: std::path::PathBuf::from(format!("certificates/active/{serial}.pem")),
        revoked_at,
        revocation_reason: revoked_at.map(|_| RevocationReason::KeyCompromise),
        replaces: None,
    }
}

fn authority(name: &str, kind: AuthorityKind, parent: Option<&str>) -> AuthorityRecord {
    AuthorityRecord {
        name: AuthorityName::new(name).expect("authority"),
        kind,
        parent: parent.map(|parent| AuthorityName::new(parent).expect("parent")),
        algorithm: KeyAlgorithm::EcdsaP256,
        validity_days: 3650,
        path_len: 0,
        created_at: now() - Duration::days(30),
        cert_path: std::path::PathBuf::from(format!("authorities/{name}/cert.pem")),
        chain_path: std::path::PathBuf::from(format!("authorities/{name}/chain.pem")),
    }
}

fn audit(id: &str, seq: u64, action: AuditAction) -> AuditEvent {
    AuditEvent {
        id: EventId::new(id).expect("event id"),
        seq,
        timestamp: now() - Duration::days(1),
        action,
        object_type: "certificate".to_owned(),
        object_id: "AA".to_owned(),
        summary: "test event".to_owned(),
        actor: "ck".to_owned(),
        details: serde_json::Value::Null,
    }
}

/// Builds a publish tree and the snapshot that describes it.
///
/// # Panics
///
/// Panics when the temporary tree cannot be written.
#[must_use]
pub fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("publish dir");
    let files: [(&str, &[u8]); 6] = [
        (
            "root.pem",
            b"-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n",
        ),
        (
            "intermediates/tls.pem",
            b"-----BEGIN CERTIFICATE-----\nTLS\n-----END CERTIFICATE-----\n",
        ),
        (
            "aia/tls.pem",
            b"-----BEGIN CERTIFICATE-----\nTLS\n-----END CERTIFICATE-----\n",
        ),
        (
            "aia/root.pem",
            b"-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n",
        ),
        (
            "chains/tls-server/AA.pem",
            b"-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n",
        ),
        ("crl/tls.crl", b"DER-CRL"),
    ];
    let mut artifacts = Vec::new();
    for (path, bytes) in files {
        let absolute = directory.path().join(path);
        if let Some(parent) = absolute.parent() {
            std::fs::create_dir_all(parent).expect("artifact directory");
        }
        std::fs::write(&absolute, bytes).expect("artifact");
        artifacts.push(PublishArtifact {
            path: std::path::PathBuf::from(path),
            sha256: sha256_hex(bytes),
            bytes: bytes.len() as u64,
        });
    }
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = PublishManifest {
        version: chainkeeper_core::PUBLISH_MANIFEST_VERSION,
        generated_at: now(),
        source_commit: Some("b".repeat(40)),
        tenant_id: TenantId::new("acme").expect("tenant"),
        artifacts,
    };
    std::fs::write(
        directory.path().join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("manifest"),
    )
    .expect("write manifest");

    let mut revoked = certificate("CC", "tls-server", now() + Duration::days(30), Some(now()));
    revoked.revocation_reason = Some(RevocationReason::KeyCompromise);
    let snapshot = ServerSnapshot {
        generated_at: now(),
        repo_commit: "a".repeat(40),
        manifest: Some(manifest),
        certificates: vec![
            certificate("AA", "tls-server", now() + Duration::days(30), None),
            certificate("BB", "tls-client", now() - Duration::days(1), None),
            revoked,
        ],
        revocations: vec![RevocationRecord {
            version: chainkeeper_core::CONFIG_VERSION,
            serial: Serial::new("CC").expect("serial"),
            authority: AuthorityName::new("tls").expect("authority"),
            reason: RevocationReason::KeyCompromise,
            comment: Some("test".to_owned()),
            revoked_at: now(),
            crl_number: 3,
        }],
        authorities: vec![
            authority("root", AuthorityKind::Root, None),
            authority("tls", AuthorityKind::Intermediate, Some("root")),
            authority("smime", AuthorityKind::Intermediate, Some("root")),
        ],
        crls: vec![CrlRecord {
            version: chainkeeper_core::CONFIG_VERSION,
            authority: AuthorityName::new("tls").expect("authority"),
            number: 3,
            this_update: now(),
            next_update: now() + Duration::days(7),
            revoked_serials: vec![Serial::new("CC").expect("serial")],
            der_path: std::path::PathBuf::from("crls/tls.crl.der"),
            pem_path: std::path::PathBuf::from("crls/tls.crl.pem"),
        }],
        audit_events: vec![
            audit(
                "01J00000000000000000000000",
                1,
                AuditAction::RepoInitialized,
            ),
            audit("01J00000000000000000000001", 2, AuditAction::CertIssued),
        ],
    };
    Fixture {
        directory,
        snapshot,
    }
}

/// Builds state with the fixture snapshot.
#[must_use]
pub fn state(ocsp_ready: bool) -> (AppState, Fixture) {
    let fixture = fixture();
    let provider = FakeServerStateProvider::new();
    provider.set_snapshot(fixture.snapshot.clone());
    let state = AppState::new(
        std::sync::Arc::new(provider),
        std::sync::Arc::new(FakeOcspResponder::with_ready(ocsp_ready)),
        fixture.directory.path(),
    );
    (state, fixture)
}

/// Returns true when a certificate is expired at fixture time.
#[must_use]
pub fn is_expired(record: &CertificateRecord) -> bool {
    record.status(now()) == CertificateStatus::Expired
}
