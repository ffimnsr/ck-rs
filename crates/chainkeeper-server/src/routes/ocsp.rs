//! `POST /ocsp`.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chainkeeper_core::{ChainkeeperError, OcspResponder};

use crate::error::ApiError;
use crate::state::AppState;

const OCSP_REQUEST: &str = "application/ocsp-request";
const OCSP_RESPONSE: &str = "application/ocsp-response";
const CACHE_CONTROL: &str = "public, max-age=3600";

/// OCSP responder that is never ready.
///
/// Phase 11 replaces this with the file-backed responder once the OCSP signer
/// key is wired.
#[derive(Debug, Default, Clone, Copy)]
pub struct NotReadyOcsp;

impl OcspResponder for NotReadyOcsp {
    fn respond(&self, _request_der: &[u8]) -> Result<Vec<u8>, ChainkeeperError> {
        Err(ChainkeeperError::ocsp("responder is not ready"))
    }

    fn reload(&self) -> Result<(), ChainkeeperError> {
        Ok(())
    }

    fn ready(&self) -> bool {
        false
    }
}

fn is_ocsp_request(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        .is_some_and(|value| value.eq_ignore_ascii_case(OCSP_REQUEST))
}

/// `POST /ocsp`.
///
/// # Errors
///
/// Returns 415 for a wrong content type, 503 when the responder is not ready,
/// and 500 when the response cannot be encoded.
pub async fn respond(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    if !is_ocsp_request(&headers) {
        return Err(ApiError::unsupported_media_type(
            "Content-Type must be application/ocsp-request",
        ));
    }
    let responder = state.ocsp();
    if !responder.ready() {
        return Err(ApiError::service_unavailable("ocsp responder is not ready"));
    }
    let bytes = responder
        .respond(&body)
        .map_err(|error| ApiError::from_chainkeeper(&error))?;
    let mut response = Response::new(axum::body::Body::from(bytes));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(OCSP_RESPONSE),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL),
    );
    Ok(response.into_response())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::is_ocsp_request;

    #[test]
    fn content_type_is_checked() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/ocsp-request"),
        );
        assert!(is_ocsp_request(&headers));

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/ocsp-request; charset=binary"),
        );
        assert!(is_ocsp_request(&headers));

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        assert!(!is_ocsp_request(&headers));
        assert!(!is_ocsp_request(&HeaderMap::new()));
    }
}
