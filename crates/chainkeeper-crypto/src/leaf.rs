//! Leaf certificate issuance.

use std::collections::HashSet;
use std::path::PathBuf;

use chainkeeper_core::{
    AuthorityMaterial, CertificateRecord, ChainkeeperError, Clock, IdGenerator, IssueRequest,
    IssuedCertificate, KeyAlgorithm, Profile, San, TenantConfig, builtin_profile,
};
use time::Duration;

use crate::certificate::{self, CertificateInput};
use crate::csr::CsrInfo;
use crate::extensions::{
    self, Extension, OID_AUTHORITY_INFO_ACCESS, OID_AUTHORITY_KEY_IDENTIFIER,
    OID_BASIC_CONSTRAINTS, OID_CRL_DISTRIBUTION_POINTS, OID_EXTENDED_KEY_USAGE, OID_KEY_USAGE,
    OID_SUBJECT_ALT_NAME, OID_SUBJECT_KEY_IDENTIFIER,
};
use crate::keygen;
use crate::names;
use crate::secret::SecretString;

/// Everything the issuance path needs beyond the request itself.
pub struct IssueContext<'a> {
    /// Issuing authority and its chain.
    pub issuer: &'a AuthorityMaterial,
    /// Repository configuration that supplies AIA and CRL URLs.
    pub tenant: Option<&'a TenantConfig>,
    /// Profile resolved by the caller, falling back to the built-in registry.
    pub profile: Option<&'a Profile>,
    /// Clock used for validity.
    pub clock: &'a dyn Clock,
    /// Serial generator.
    pub ids: &'a dyn IdGenerator,
    /// Optional passphrase for the generated leaf key.
    pub passphrase: Option<&'a SecretString>,
}

fn validation(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::validation(message)
}

fn resolve_profile(
    request: &IssueRequest,
    known: Option<&Profile>,
) -> Result<Profile, ChainkeeperError> {
    match known {
        Some(profile) => {
            if profile.name != request.profile {
                return Err(validation(
                    "resolved profile does not match the requested profile name",
                ));
            }
            Ok(profile.clone())
        }
        None => builtin_profile(&request.profile)
            .ok_or_else(|| ChainkeeperError::not_found("profile", request.profile.as_str())),
    }
}

fn merge_sans(requested: &[San], from_csr: &[San]) -> Result<Vec<San>, ChainkeeperError> {
    if requested.is_empty() {
        return Ok(from_csr.to_vec());
    }
    if from_csr.is_empty() {
        return Ok(requested.to_vec());
    }
    let requested_set: HashSet<&San> = requested.iter().collect();
    let csr_set: HashSet<&San> = from_csr.iter().collect();
    if requested_set != csr_set {
        return Err(validation(
            "request SANs conflict with the subject alternative names in the CSR",
        ));
    }
    Ok(requested.to_vec())
}

fn reject_issuer_key_reuse(
    csr: &CsrInfo,
    issuer: &AuthorityMaterial,
) -> Result<(), ChainkeeperError> {
    let mut certificates = certificate::parse_chain(&issuer.chain_pem)?;
    certificates.push(certificate::parse_first(&issuer.cert_pem)?);
    for certificate in certificates {
        let key = certificate
            .public_key()
            .map_err(|error| ChainkeeperError::crypto(error.to_string()))?;
        let der = key
            .public_key_to_der()
            .map_err(|error| ChainkeeperError::crypto(error.to_string()))?;
        if der == csr.public_key_der {
            return Err(validation(
                "CSR public key is already used by the issuing authority chain",
            ));
        }
    }
    Ok(())
}

fn load_csr(
    request: &IssueRequest,
    issuer: &AuthorityMaterial,
) -> Result<Option<CsrInfo>, ChainkeeperError> {
    let csr = request
        .csr_pem
        .as_deref()
        .map(crate::csr::parse)
        .transpose()?;
    if let Some(csr) = &csr {
        if request.subject != csr.subject {
            return Err(validation(
                "request subject conflicts with the subject in the CSR",
            ));
        }
        reject_issuer_key_reuse(csr, issuer)?;
    }
    Ok(csr)
}

fn resolve_algorithm(
    request: &IssueRequest,
    csr: Option<&CsrInfo>,
    profile: &Profile,
) -> Result<KeyAlgorithm, ChainkeeperError> {
    match (csr, request.algorithm) {
        (Some(csr), Some(algorithm)) if csr.algorithm != algorithm => Err(validation(
            "requested algorithm conflicts with the CSR public key",
        )),
        (Some(csr), _) => Ok(csr.algorithm),
        (None, Some(algorithm)) => Ok(algorithm),
        (None, None) => Ok(profile.algorithm),
    }
}

#[allow(clippy::literal_string_with_formatting_args)]
fn placeholder(template: &str, authority: &str) -> String {
    template.replace("{authority}", authority)
}

/// Issues a leaf certificate.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] for conflicting inputs and
/// [`ChainkeeperError::Crypto`] when generation, encoding, or signing fails.
pub fn issue(
    request: &IssueRequest,
    issuer_signer: &dyn chainkeeper_core::Signer,
    context: &IssueContext<'_>,
) -> Result<IssuedCertificate, ChainkeeperError> {
    let profile = resolve_profile(request, context.profile)?;
    profile.validate()?;
    request.subject.validate()?;

    let issuer_certificate = certificate::parse_first(&context.issuer.cert_pem)?;
    let issuer_not_after = certificate::not_after(&context.issuer.cert_pem)?;
    let issuer_key_id = certificate::key_id(&issuer_certificate)?;
    let now = context.clock.now();

    let csr = load_csr(request, context.issuer)?;
    let algorithm = resolve_algorithm(request, csr.as_ref(), &profile)?;

    let validity_days = request.validity_days.unwrap_or(profile.validity_days);
    if validity_days == 0 {
        return Err(validation("certificate validity must be positive"));
    }
    let not_after = (now + Duration::days(i64::from(validity_days))).min(issuer_not_after);
    if not_after <= now {
        return Err(validation("issuing authority is already expired"));
    }

    let sans = match &csr {
        Some(csr) => merge_sans(&request.sans, &csr.sans)?,
        None => request.sans.clone(),
    };

    let (public_key_der, key) = if let Some(csr) = &csr {
        (csr.public_key_der.clone(), None)
    } else {
        let generated = keygen::generate(algorithm, context.passphrase)?;
        let key = generated.material.clone();
        (
            generated
                .key
                .public_key_to_der()
                .map_err(|error| ChainkeeperError::crypto(error.to_string()))?,
            Some(key),
        )
    };
    let subject_key_id = keygen::key_id_from_spki(&public_key_der)?;
    let subject = csr.map_or_else(|| request.subject.clone(), |csr| csr.subject);
    let extensions = leaf_extensions(
        request,
        &profile,
        &sans,
        &subject_key_id,
        &issuer_key_id,
        context,
    )?;

    let serial = context.ids.serial();
    let (_, cert_pem) = certificate::build(
        &CertificateInput {
            serial: serial.clone(),
            issuer_der: certificate::subject_der(&issuer_certificate)?,
            subject_der: names::to_der(&subject)?,
            not_before: now,
            not_after,
            public_key_der,
            extensions,
        },
        issuer_signer,
    )?;

    let record = CertificateRecord {
        serial: serial.clone(),
        subject,
        issuer: names::render(issuer_certificate.subject_name()),
        profile: request.profile.clone(),
        authority: context.issuer.config.name.clone(),
        algorithm,
        sans,
        ekus: profile.eku.clone(),
        key_usages: profile.key_usage,
        issued_at: now,
        expires_at: not_after,
        path: PathBuf::from(format!("certificates/active/{serial}.pem")),
        revoked_at: None,
        revocation_reason: None,
        replaces: request.replaces.clone(),
    };
    Ok(IssuedCertificate::new(
        record,
        cert_pem,
        context.issuer.chain_pem.clone(),
        key,
    ))
}

fn leaf_extensions(
    request: &IssueRequest,
    profile: &Profile,
    sans: &[San],
    subject_key_id: &[u8],
    issuer_key_id: &[u8],
    context: &IssueContext<'_>,
) -> Result<Vec<Extension>, ChainkeeperError> {
    let mut extensions = vec![
        Extension::new(
            OID_BASIC_CONSTRAINTS,
            true,
            extensions::basic_constraints(false, None),
        ),
        Extension::new(
            OID_KEY_USAGE,
            true,
            extensions::key_usage(&profile.key_usage)?,
        ),
    ];
    if !profile.eku.is_empty() {
        extensions.push(Extension::new(
            OID_EXTENDED_KEY_USAGE,
            false,
            extensions::extended_key_usage(&profile.eku)?,
        ));
    }
    if !sans.is_empty() {
        extensions.push(Extension::new(
            OID_SUBJECT_ALT_NAME,
            false,
            extensions::subject_alt_name(sans)?,
        ));
    }
    extensions.push(Extension::new(
        OID_SUBJECT_KEY_IDENTIFIER,
        false,
        extensions::subject_key_identifier(subject_key_id),
    ));
    extensions.push(Extension::new(
        OID_AUTHORITY_KEY_IDENTIFIER,
        false,
        extensions::authority_key_identifier(issuer_key_id),
    ));
    if let Some(url) = context
        .tenant
        .and_then(|tenant| tenant.ca_issuers_url_template.as_deref())
    {
        extensions.push(Extension::new(
            OID_AUTHORITY_INFO_ACCESS,
            false,
            extensions::authority_info_access(&placeholder(
                url,
                context.issuer.config.name.as_str(),
            ))?,
        ));
    }
    if let Some(url) = context
        .tenant
        .and_then(|tenant| tenant.crl_url_template.as_deref())
    {
        extensions.push(Extension::new(
            OID_CRL_DISTRIBUTION_POINTS,
            false,
            extensions::crl_distribution_points(&placeholder(
                url,
                context.issuer.config.name.as_str(),
            )),
        ));
    }
    for custom in &request.custom_extensions {
        extensions.push(Extension::new(
            custom.oid.clone(),
            custom.critical,
            extensions::custom(custom)?,
        ));
    }
    Ok(extensions)
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::San;

    use super::merge_sans;

    #[test]
    fn matching_san_sets_are_accepted() {
        let requested = vec![San::Dns("example.test".to_owned())];
        let from_csr = vec![San::Dns("example.test".to_owned())];
        assert_eq!(merge_sans(&requested, &from_csr).expect("merge"), requested);
    }

    #[test]
    fn conflicting_san_sets_are_rejected() {
        let requested = vec![San::Dns("a.test".to_owned())];
        let from_csr = vec![San::Dns("b.test".to_owned())];
        assert!(merge_sans(&requested, &from_csr).is_err());
    }

    #[test]
    fn empty_request_uses_the_csr() {
        let from_csr = vec![San::Dns("a.test".to_owned())];
        assert_eq!(merge_sans(&[], &from_csr).expect("merge"), from_csr);
    }
}
