#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// Route handlers are internal; the public surface is the router and state.
#![allow(clippy::missing_errors_doc)]

//! Read-only PKI artifact server.
//!
//! The server never issues, revokes, or modifies repository state, and never
//! holds authority private keys. Every handler consumes
//! [`chainkeeper_core::ServerStateProvider`] and
//! [`chainkeeper_core::OcspResponder`] so route tests run against fakes.

pub mod config;
pub mod error;
mod http_time;
mod middleware;
mod router;
mod routes;
pub mod snapshot;
pub mod state;
pub mod views;
pub mod watcher;

pub use config::ServerConfig;
pub use error::ApiError;
pub use router::{apply_layers, router};
pub use routes::ocsp::NotReadyOcsp;
pub use snapshot::{RepositoryDeps, RepositoryStateProvider};
pub use state::AppState;
pub use watcher::{ReloadHook, WatchConfig, WatchHealth, WatchOutcome, WatchStatus, Watcher};

/// Serves `app` on `listener` until `shutdown` resolves.
///
/// # Errors
///
/// Returns an I/O error when accepting connections fails.
pub async fn serve<F>(
    listener: tokio::net::TcpListener,
    app: axum::Router,
    shutdown: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
}
