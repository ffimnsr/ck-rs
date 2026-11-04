//! Cross-cutting request middleware.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

const REQUEST_ID_HEADER: &str = "x-request-id";
const MAX_REQUEST_ID_LEN: usize = 64;

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn generate_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:032x}{sequence:016x}")
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| valid_request_id(value))
        .map_or_else(generate_request_id, str::to_owned)
}

/// Adds `X-Content-Type-Options: nosniff` to every response.
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    response
}

/// Propagates or generates a request id and logs the completed request.
pub async fn request_context(request: Request, next: Next) -> Response {
    let id = request_id(request.headers());
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let started = Instant::now();

    let mut response = next.run(request).await;

    if let Ok(value) = HeaderValue::from_str(&id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), value);
    }
    let status = response.status().as_u16();
    let elapsed_ms = started.elapsed().as_millis();
    if response.status().is_server_error() {
        tracing::warn!(
            request_id = %id,
            %method,
            %path,
            status,
            elapsed_ms,
            "request failed"
        );
    } else {
        tracing::debug!(
            request_id = %id,
            %method,
            %path,
            status,
            elapsed_ms,
            "request completed"
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::{generate_request_id, valid_request_id};

    #[test]
    fn request_ids_are_unique_and_safe() {
        let first = generate_request_id();
        let second = generate_request_id();
        assert_ne!(first, second);
        assert!(valid_request_id(&first));
    }

    #[test]
    fn hostile_request_ids_are_rejected() {
        assert!(!valid_request_id(""));
        assert!(!valid_request_id("has space"));
        assert!(!valid_request_id("../../etc/passwd"));
        assert!(!valid_request_id(&"a".repeat(80)));
    }
}
