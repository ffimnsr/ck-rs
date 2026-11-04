//! HTTP error mapping.
//!
//! Every failure becomes `{ "error": { "code": "...", "message": "..." } }`.
//! Internal errors are logged in full but never leak paths or secrets to the
//! client.

use std::fmt;

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use chainkeeper_core::{ChainkeeperError, ErrorKind};
use serde::Serialize;

/// Machine-readable error payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    /// Error details.
    pub error: ErrorDetail,
}

/// Code and human readable message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorDetail {
    /// Stable machine-readable code.
    pub code: &'static str,
    /// Safe human readable message.
    pub message: String,
}

/// Error returned by every HTTP handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    /// Builds an error with an explicit status and code.
    #[must_use]
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    /// Builds a `400` validation error.
    #[must_use]
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "validation", message)
    }

    /// Builds a `404` not-found error.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    /// Builds a `405` method-not-allowed error.
    #[must_use]
    pub fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "method is not allowed for this route",
        )
    }

    /// Builds a `409` conflict error.
    #[must_use]
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    /// Builds an `415` unsupported-media-type error.
    #[must_use]
    pub fn unsupported_media_type(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
            message,
        )
    }

    /// Builds a `503` service-unavailable error.
    #[must_use]
    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            message,
        )
    }

    /// Maps a domain error onto an HTTP response.
    #[must_use]
    pub fn from_chainkeeper(error: &ChainkeeperError) -> Self {
        let status = match error.kind() {
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::Validation | ErrorKind::Policy | ErrorKind::Profile => {
                StatusCode::BAD_REQUEST
            }
            ErrorKind::AlreadyExists | ErrorKind::Conflict => StatusCode::CONFLICT,
            ErrorKind::Ocsp => StatusCode::SERVICE_UNAVAILABLE,
            ErrorKind::Config
            | ErrorKind::Crypto
            | ErrorKind::Storage
            | ErrorKind::Index
            | ErrorKind::Audit
            | ErrorKind::Git
            | ErrorKind::Lock
            | ErrorKind::Publish
            | ErrorKind::NotImplemented
            | ErrorKind::Io
            | _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status.is_server_error() {
            tracing::warn!(error = %error, "request failed");
            return Self::new(
                status,
                "internal",
                "internal server error while serving the request",
            );
        }
        let code = match status {
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::CONFLICT => "conflict",
            StatusCode::SERVICE_UNAVAILABLE => "service_unavailable",
            _ => "validation",
        };
        Self::new(status, code, error.to_string())
    }

    /// Response status code.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Human readable error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.status.as_u16(), self.message)
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorDetail {
                code: self.code,
                message: self.message,
            },
        };
        let mut response = (self.status, Json(body)).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            header::HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
        response
    }
}

impl From<ChainkeeperError> for ApiError {
    fn from(error: ChainkeeperError) -> Self {
        Self::from_chainkeeper(&error)
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use chainkeeper_core::ChainkeeperError;

    use super::ApiError;

    #[test]
    fn not_found_maps_to_404() {
        let error = ApiError::from_chainkeeper(&ChainkeeperError::not_found("certificate", "AA"));
        assert_eq!(error.status(), StatusCode::NOT_FOUND);
        assert_eq!(error.code(), "not_found");
    }

    #[test]
    fn validation_maps_to_400() {
        let error = ApiError::from_chainkeeper(&ChainkeeperError::validation("bad serial"));
        assert_eq!(error.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error.code(), "validation");
    }

    #[test]
    fn conflict_maps_to_409() {
        let error = ApiError::from_chainkeeper(&ChainkeeperError::conflict("already present"));
        assert_eq!(error.status(), StatusCode::CONFLICT);
        assert_eq!(error.code(), "conflict");
    }

    #[test]
    fn internal_errors_hide_details() {
        let error =
            ApiError::from_chainkeeper(&ChainkeeperError::storage("could not read /secret/path"));
        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code(), "internal");
        assert!(!error.message().contains("/secret/path"));
    }

    #[test]
    fn ocsp_errors_map_to_503() {
        let error = ApiError::from_chainkeeper(&ChainkeeperError::ocsp("responder is not ready"));
        assert_eq!(error.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
