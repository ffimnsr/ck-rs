//! OCSP response construction and signing.

use chainkeeper_core::{ChainkeeperError, SignatureScheme, Signer};
use rasn::types::{BitString, Integer, OctetString};
use rasn_ocsp::{
    BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId, ResponseBytes,
    ResponseData, RevokedInfo, SingleResponse,
};
use rasn_pkix::Extension;
use time::{Duration, OffsetDateTime};

use crate::request::OcspRequestEntry;
use crate::state::{OcspState, crl_reason};
use crate::status::StatusValue;
use crate::util::{OCSP_BASIC_OID, OCSP_NONCE_OID, generalized, oid, signature_algorithm};

/// Lifetime advertised by `nextUpdate`.
const RESPONSE_LIFETIME: Duration = Duration::hours(1);

pub fn success_response(
    state: &OcspState,
    entries: &[(OcspRequestEntry, StatusValue)],
    nonce: Option<&[u8]>,
    now: OffsetDateTime,
) -> Result<Vec<u8>, ChainkeeperError> {
    let produced_at = generalized(now)?;
    let this_update = generalized(now)?;
    let next_update = generalized(now + RESPONSE_LIFETIME)?;

    let responses = entries
        .iter()
        .map(|(entry, status)| {
            Ok(SingleResponse {
                cert_id: entry.cert_id.clone(),
                cert_status: cert_status(status)?,
                this_update,
                next_update: Some(next_update),
                single_extensions: None,
            })
        })
        .collect::<Result<Vec<_>, ChainkeeperError>>()?;

    let response_extensions = match nonce {
        Some(nonce) => Some(rasn_pkix::Extensions::from(vec![Extension {
            extn_id: oid(OCSP_NONCE_OID)?,
            critical: false,
            extn_value: OctetString::from(nonce.to_vec()),
        }])),
        None => None,
    };

    let data = ResponseData {
        version: Integer::ZERO,
        responder_id: ResponderId::ByName(state.signer_certificate.tbs_certificate.subject.clone()),
        produced_at,
        responses,
        response_extensions,
    };
    let tbs = rasn::der::encode(&data)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot encode response data: {error}")))?;
    let signature = sign(state.signer.as_ref(), &tbs)?;

    let mut certificates = Vec::with_capacity(state.chain.len() + 1);
    certificates.push(state.signer_certificate.clone());
    certificates.extend(state.chain.iter().cloned());

    let basic = BasicOcspResponse {
        tbs_response_data: data,
        signature_algorithm: signature_algorithm(state.signer.algorithm())?,
        signature: BitString::from_vec(signature),
        certs: Some(certificates),
    };
    let basic_der = rasn::der::encode(&basic).map_err(|error| {
        ChainkeeperError::ocsp(format!("cannot encode basic response: {error}"))
    })?;

    let response = OcspResponse {
        status: OcspResponseStatus::Successful,
        bytes: Some(ResponseBytes {
            r#type: oid(OCSP_BASIC_OID)?,
            response: OctetString::from(basic_der),
        }),
    };
    rasn::der::encode(&response)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot encode OCSP response: {error}")))
}

pub fn error_response(status: OcspResponseStatus) -> Result<Vec<u8>, ChainkeeperError> {
    let response = OcspResponse {
        status,
        bytes: None,
    };
    rasn::der::encode(&response)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot encode OCSP status: {error}")))
}

pub const fn status_label(status: OcspResponseStatus) -> &'static str {
    match status {
        OcspResponseStatus::Successful => "successful",
        OcspResponseStatus::MalformedRequest => "malformedRequest",
        OcspResponseStatus::InternalError => "internalError",
        OcspResponseStatus::TryLater => "tryLater",
        OcspResponseStatus::SigRequired => "sigRequired",
        OcspResponseStatus::Unauthorized => "unauthorized",
    }
}

fn sign(signer: &dyn Signer, message: &[u8]) -> Result<Vec<u8>, ChainkeeperError> {
    let scheme = SignatureScheme::from_key_algorithm(signer.algorithm());
    signer.sign(message, scheme)
}

fn cert_status(status: &StatusValue) -> Result<CertStatus, ChainkeeperError> {
    match status {
        StatusValue::Good => Ok(CertStatus::Good),
        StatusValue::Unknown => Ok(CertStatus::Unknown(())),
        StatusValue::Revoked { at, reason } => Ok(CertStatus::Revoked(RevokedInfo {
            revocation_time: generalized(*at)?,
            revocation_reason: reason.map(crl_reason),
        })),
    }
}
