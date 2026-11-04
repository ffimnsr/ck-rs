//! Liveness and readiness probes.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chainkeeper_core::HealthStatus;
use serde::Serialize;

use crate::state::AppState;

/// Liveness body.
#[derive(Debug, Serialize)]
pub struct Liveness {
    /// Always `ok` when the process answers.
    pub status: &'static str,
}

/// `GET /healthz` reports that the process is alive.
pub async fn healthz() -> Json<Liveness> {
    Json(Liveness { status: "ok" })
}

/// `GET /readyz` reports `200` only when the snapshot and OCSP are ready.
pub async fn readyz(State(state): State<AppState>) -> Response {
    let health = state.health();
    let ready = health.ocsp_ready
        && health.status != HealthStatus::Error
        && !state.snapshot().repo_commit.is_empty();
    if ready {
        (StatusCode::OK, Json(health)).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(health)).into_response()
    }
}
