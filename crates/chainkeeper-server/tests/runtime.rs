//! Real runtime tests: temporary repository, real router, graceful shutdown.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use chainkeeper_core::{ChainkeeperService, InitRequest, OcspResponder, ProfileName, TenantId};
use chainkeeper_engine::{OpenMode, ServiceOptions, finalize_init, open_with};
use chainkeeper_git::GitIdentity;
use chainkeeper_server::config::ServerConfig;
use chainkeeper_server::runtime::{Runtime, build_state};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::watch;

fn init_repository(directory: &std::path::Path) {
    let options = ServiceOptions {
        mode: OpenMode::Init,
        git_identity: Some(GitIdentity::new("Chainkeeper Test", "test@example.test").expect("id")),
        commit_signing: Some(false),
    };
    let engine = open_with(directory, &options).expect("open init service");
    engine
        .init(&InitRequest::new(
            TenantId::new("acme").expect("tenant"),
            "Acme",
            ProfileName::new("tls-server").expect("profile"),
        ))
        .expect("init repository");
    finalize_init(&engine).expect("persist index");
}

fn config(directory: &std::path::Path) -> ServerConfig {
    let config = ServerConfig {
        bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        repo: directory.to_path_buf(),
        publish_dir: std::path::PathBuf::from(".chainkeeper/publish"),
        ..ServerConfig::default()
    };
    config.validate().expect("server configuration");
    config
}

async fn request(address: SocketAddr, path: &str) -> (u16, String) {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

async fn start(
    runtime: Arc<Runtime>,
) -> (
    SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let address = listener.local_addr().expect("address");
    let (shutdown, mut receiver) = watch::channel(false);
    let handle = tokio::spawn(async move {
        runtime
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
    (address, shutdown, handle)
}

#[tokio::test]
async fn real_runtime_serves_health_and_shuts_down() {
    let directory = tempfile::tempdir().expect("repository");
    init_repository(directory.path());
    let runtime = Arc::new(build_state(&config(directory.path())).expect("runtime"));
    assert!(!runtime.ocsp().ready(), "no OCSP signer is configured yet");

    let (address, shutdown, handle) = start(Arc::clone(&runtime)).await;

    let (status, body) = request(address, "/healthz").await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = request(address, "/readyz").await;
    assert_eq!(status, 503, "without OCSP the server is not ready: {body}");

    let (status, body) = request(address, "/api/v1/certificates").await;
    assert_eq!(status, 200, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(value["items"].as_array().map(Vec::len), Some(0));

    let (status, body) = request(address, "/missing").await;
    assert_eq!(status, 404, "{body}");

    shutdown.send(true).expect("signal shutdown");
    handle.await.expect("join server").expect("server stopped");

    // The listener must be released once the task finished.
    let rebound = tokio::net::TcpListener::bind(address)
        .await
        .expect("port is released after shutdown");
    drop(rebound);
}

#[tokio::test]
async fn cancelling_the_server_task_stops_serving() {
    let directory = tempfile::tempdir().expect("repository");
    init_repository(directory.path());
    let runtime = Arc::new(build_state(&config(directory.path())).expect("runtime"));
    let (address, shutdown, handle) = start(runtime).await;

    let (status, _) = request(address, "/healthz").await;
    assert_eq!(status, 200);

    drop(shutdown);
    handle.await.expect("join server").expect("server stopped");
    assert!(
        tokio::net::TcpStream::connect(address).await.is_err(),
        "no listener accepts connections after shutdown"
    );
}
