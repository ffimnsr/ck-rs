//! Router assembly and shared layers.

use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::{get, post};
use tower_http::compression::CompressionLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::error::ApiError;
use crate::middleware;
use crate::routes::{api, artifacts, health, ocsp};
use crate::state::AppState;

async fn not_found() -> ApiError {
    ApiError::not_found("route not found")
}

async fn method_not_allowed() -> ApiError {
    ApiError::method_not_allowed()
}

/// Builds the complete application router.
pub fn router(state: AppState) -> Router {
    let timeout = state.request_timeout();
    let max_body_bytes = state.max_body_bytes();
    let routes = Router::new()
        .route("/api/v1/certificates", get(api::certificates))
        .route("/api/v1/certificates/{serial}", get(api::certificate))
        .route("/api/v1/root", get(api::root))
        .route("/api/v1/intermediates", get(api::intermediates))
        .route("/api/v1/revocations", get(api::revocations))
        .route("/api/v1/crls", get(api::crls))
        .route("/api/v1/audit", get(api::audit))
        .route("/api/v1/health", get(api::health))
        .route("/healthz", get(health::healthz))
        .route("/readyz", get(health::readyz))
        .route("/root.pem", get(artifacts::root))
        .route("/intermediates/{file}", get(artifacts::intermediate))
        .route("/tls-intermediate.pem", get(artifacts::tls_alias))
        .route("/smime-intermediate.pem", get(artifacts::smime_alias))
        .route("/codesign-intermediate.pem", get(artifacts::codesign_alias))
        .route("/ocsp-intermediate.pem", get(artifacts::ocsp_alias))
        .route("/crl/{file}", get(artifacts::crl))
        .route("/aia/{file}", get(artifacts::aia))
        .route("/chains/{profile}/{file}", get(artifacts::chain))
        .route("/ocsp", post(ocsp::respond))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state);

    apply_layers(routes, timeout, max_body_bytes)
}

/// Applies body limits, compression, timeouts, and observability.
pub fn apply_layers(routes: Router, timeout: Duration, max_body_bytes: usize) -> Router {
    routes
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(CompressionLayer::new())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(middleware::request_context))
        .layer(axum::middleware::from_fn(middleware::security_headers))
}
