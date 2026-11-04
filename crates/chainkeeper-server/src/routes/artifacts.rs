//! Published artifact routes.
//!
//! Artifacts are only served when they appear in the publish manifest. Reads
//! are confined to the publish directory, and the digest recorded in the
//! manifest is verified before the bytes are returned.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chainkeeper_core::{AuthorityName, ChainkeeperError, ProfileName, Serial};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::http_time;
use crate::snapshot::is_safe_relative;
use crate::state::AppState;

const PEM: &str = "application/x-pem-file";
const CRL: &str = "application/pkix-crl";
const CACHE_CONTROL: &str = "public, max-age=300";

/// `GET /root.pem`.
///
/// # Errors
///
/// Returns a 404 when the artifact is not published.
pub async fn root(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    serve(&state, Path::new("root.pem"), &headers)
}

/// `GET /intermediates/{file}`.
///
/// # Errors
///
/// Returns a 400 for an invalid authority name and 404 when the artifact is not
/// published.
pub async fn intermediate(
    State(state): State<AppState>,
    UrlPath(file): UrlPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let name = authority_file(&file)?;
    let path = PathBuf::from(format!("intermediates/{name}.pem"));
    serve(&state, &path, &headers)
}

/// `GET /tls-intermediate.pem`.
///
/// # Errors
///
/// Returns a 404 when the artifact is not published.
pub async fn tls_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    serve(&state, Path::new("intermediates/tls.pem"), &headers)
}

/// `GET /smime-intermediate.pem`.
///
/// # Errors
///
/// Returns a 404 when the artifact is not published.
pub async fn smime_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    serve(&state, Path::new("intermediates/smime.pem"), &headers)
}

/// `GET /codesign-intermediate.pem`.
///
/// # Errors
///
/// Returns a 404 when the artifact is not published.
pub async fn codesign_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    serve(&state, Path::new("intermediates/codesign.pem"), &headers)
}

/// `GET /ocsp-intermediate.pem`.
///
/// # Errors
///
/// Returns a 404 when the artifact is not published.
pub async fn ocsp_alias(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    serve(&state, Path::new("intermediates/ocsp.pem"), &headers)
}

/// `GET /crl/{file}` for DER and PEM CRLs.
///
/// # Errors
///
/// Returns a 400 for an invalid authority name and 404 when the artifact is not
/// published.
pub async fn crl(
    State(state): State<AppState>,
    UrlPath(file): UrlPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let (raw_name, extension) = if let Some(name) = file.strip_suffix(".crl.pem") {
        (name, "crl.pem")
    } else if let Some(name) = file.strip_suffix(".crl") {
        (name, "crl")
    } else {
        return Err(ApiError::not_found("CRL not found"));
    };
    let name =
        AuthorityName::new(raw_name).map_err(|error| ApiError::validation(error.to_string()))?;
    let path = PathBuf::from(format!("crl/{name}.{extension}"));
    serve(&state, &path, &headers)
}

/// `GET /aia/{file}`.
///
/// # Errors
///
/// Returns a 400 for an invalid authority name and 404 when the artifact is not
/// published.
pub async fn aia(
    State(state): State<AppState>,
    UrlPath(file): UrlPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let name = authority_file(&file)?;
    let path = PathBuf::from(format!("aia/{name}.pem"));
    serve(&state, &path, &headers)
}

/// `GET /chains/{profile}/{file}`.
///
/// # Errors
///
/// Returns a 400 for an invalid profile or serial and 404 when the artifact is
/// not published.
pub async fn chain(
    State(state): State<AppState>,
    UrlPath((profile, file)): UrlPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let profile =
        ProfileName::new(profile).map_err(|error| ApiError::validation(error.to_string()))?;
    let serial = file
        .strip_suffix(".pem")
        .ok_or_else(|| ApiError::not_found("certificate chain not found"))?;
    let serial = Serial::new(serial).map_err(|error| ApiError::validation(error.to_string()))?;
    let path = PathBuf::from(format!("chains/{profile}/{serial}.pem"));
    serve(&state, &path, &headers)
}

fn authority_file(file: &str) -> Result<AuthorityName, ApiError> {
    let name = file
        .strip_suffix(".pem")
        .ok_or_else(|| ApiError::not_found("artifact not found"))?;
    AuthorityName::new(name).map_err(|error| ApiError::validation(error.to_string()))
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(std::ffi::OsStr::to_str) {
        Some("pem") => PEM,
        Some("crl" | "der") => CRL,
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Writing to a `String` cannot fail.
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn etag_matches(value: &str, etag: &str) -> bool {
    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*"
            || candidate == etag
            || candidate
                .strip_prefix("W/")
                .is_some_and(|candidate| candidate == etag)
    })
}

fn cache_headers(response: &mut Response, etag: &str, last_modified: &str) {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL),
    );
    if let Ok(value) = HeaderValue::from_str(etag) {
        headers.insert(header::ETAG, value);
    }
    if let Ok(value) = HeaderValue::from_str(last_modified) {
        headers.insert(header::LAST_MODIFIED, value);
    }
}

/// Serves one manifest artifact with conditional request support.
///
/// # Errors
///
/// Returns a 404 when the manifest or artifact is missing, a 500 when the
/// artifact does not match the manifest digest, and a validation error for an
/// unsafe path.
pub fn serve(
    state: &AppState,
    relative: &Path,
    request_headers: &HeaderMap,
) -> Result<Response, ApiError> {
    if !is_safe_relative(relative) {
        return Err(ApiError::validation("artifact path is invalid"));
    }
    let index = state.index();
    let snapshot = index.snapshot();
    let Some(manifest) = snapshot.manifest.as_ref() else {
        return Err(ApiError::not_found("publish directory has no manifest"));
    };
    let Some(artifact) = index.artifact(relative) else {
        return Err(ApiError::not_found("artifact not found"));
    };
    let path = state.publish_dir().join(relative);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApiError::not_found("artifact not found"));
        }
        Err(error) => {
            return Err(ApiError::from_chainkeeper(&ChainkeeperError::publish(
                format!("could not read {}: {error}", path.display()),
            )));
        }
    };
    if sha256_hex(&bytes) != artifact.sha256 {
        return Err(ApiError::from_chainkeeper(&ChainkeeperError::publish(
            format!(
                "artifact {} does not match the manifest",
                relative.display()
            ),
        )));
    }

    let etag = format!("\"{}\"", artifact.sha256);
    let last_modified = http_time::format(manifest.generated_at);
    let not_modified = request_headers.get(header::IF_NONE_MATCH).map_or_else(
        || {
            request_headers
                .get(header::IF_MODIFIED_SINCE)
                .and_then(|value| value.to_str().ok())
                .and_then(http_time::parse)
                .is_some_and(|since| manifest.generated_at <= since)
        },
        |value| value.to_str().is_ok_and(|value| etag_matches(value, &etag)),
    );
    if not_modified {
        let mut response = StatusCode::NOT_MODIFIED.into_response();
        cache_headers(&mut response, &etag, &last_modified);
        return Ok(response);
    }

    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(relative)),
    );
    cache_headers(&mut response, &etag, &last_modified);
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::{content_type, etag_matches};
    use std::path::Path;

    #[test]
    fn etag_matching_handles_lists_and_weak_tags() {
        let etag = "\"abc\"";
        assert!(etag_matches("\"abc\"", etag));
        assert!(etag_matches("W/\"abc\"", etag));
        assert!(etag_matches("\"x\", \"abc\"", etag));
        assert!(etag_matches("*", etag));
        assert!(!etag_matches("\"def\"", etag));
    }

    #[test]
    fn content_types_follow_the_extension() {
        assert_eq!(
            content_type(Path::new("root.pem")),
            "application/x-pem-file"
        );
        assert_eq!(
            content_type(Path::new("crl/tls.crl")),
            "application/pkix-crl"
        );
        assert_eq!(content_type(Path::new("manifest.json")), "application/json");
    }
}
