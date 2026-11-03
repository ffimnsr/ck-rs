//! Root, intermediate, and OCSP signer construction.

use chainkeeper_core::{
    AuthorityBundle, AuthorityConfig, AuthorityKind, AuthorityMaterial, ChainkeeperError, Clock,
    CreateAuthorityRequest, CreateOcspSignerRequest, ExtendedKeyUsage, IdGenerator, KeyUsage,
    Serial, Signer, SignerBundle, SubjectName,
};
use time::{Duration, OffsetDateTime};

use crate::certificate::{self, CertificateInput};
use crate::extensions::{
    self, Extension, OID_AUTHORITY_KEY_IDENTIFIER, OID_BASIC_CONSTRAINTS, OID_EXTENDED_KEY_USAGE,
    OID_KEY_USAGE, OID_SUBJECT_KEY_IDENTIFIER,
};
use crate::keygen;
use crate::names;
use crate::secret::SecretString;
use crate::signer::FileSigner;

/// Validity of an OCSP signer certificate.
const OCSP_SIGNER_VALIDITY_DAYS: u32 = 90;

fn validation(message: impl Into<String>) -> ChainkeeperError {
    ChainkeeperError::validation(message)
}

fn days(value: u32) -> Duration {
    Duration::days(i64::from(value))
}

struct AuthorityCertificate<'a> {
    subject: &'a SubjectName,
    issuer_der: Vec<u8>,
    issuer_key_id: Vec<u8>,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    serial: Serial,
    subject_public_key_der: Vec<u8>,
    key_usage: Vec<KeyUsage>,
    path_len: u32,
    ca: bool,
}

fn build_authority_certificate(
    input: &AuthorityCertificate<'_>,
    signing_signer: &dyn Signer,
) -> Result<(Vec<u8>, String), ChainkeeperError> {
    let subject_der = names::to_der(input.subject)?;
    let subject_key_id = keygen::key_id_from_spki(&input.subject_public_key_der)?;
    let key_usage = extensions::key_usage(&input.key_usage)?;
    let extensions = vec![
        Extension::new(
            OID_BASIC_CONSTRAINTS,
            true,
            extensions::basic_constraints(input.ca, Some(input.path_len)),
        ),
        Extension::new(OID_KEY_USAGE, true, key_usage),
        Extension::new(
            OID_SUBJECT_KEY_IDENTIFIER,
            false,
            extensions::subject_key_identifier(&subject_key_id),
        ),
        Extension::new(
            OID_AUTHORITY_KEY_IDENTIFIER,
            false,
            extensions::authority_key_identifier(&input.issuer_key_id),
        ),
    ];
    certificate::build(
        &CertificateInput {
            serial: input.serial.clone(),
            issuer_der: input.issuer_der.clone(),
            subject_der,
            not_before: input.not_before,
            not_after: input.not_after,
            public_key_der: input.subject_public_key_der.clone(),
            extensions,
        },
        signing_signer,
    )
}

/// Creates a self-signed root authority.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the request is inconsistent
/// and [`ChainkeeperError::Crypto`] when generation or signing fails.
pub fn create_root(
    request: &CreateAuthorityRequest,
    clock: &dyn Clock,
    ids: &dyn IdGenerator,
    passphrase: Option<&SecretString>,
) -> Result<AuthorityBundle, ChainkeeperError> {
    if request.kind != AuthorityKind::Root {
        return Err(validation("create_root requires authority kind root"));
    }
    request.subject.validate()?;
    if request.validity_days == 0 {
        return Err(validation("authority validity must be positive"));
    }
    let now = clock.now();
    let generated = keygen::generate(request.algorithm, passphrase)?;
    let signer = FileSigner::from_key_and_material(generated.key, generated.material);
    let public_key = signer.public_key_der()?;
    let key_id = keygen::key_id_from_spki(&public_key)?;
    let subject_der = names::to_der(&request.subject)?;
    let (_, cert_pem) = build_authority_certificate(
        &AuthorityCertificate {
            subject: &request.subject,
            issuer_der: subject_der,
            issuer_key_id: key_id,
            not_before: now,
            not_after: now + days(request.validity_days),
            serial: ids.serial(),
            subject_public_key_der: public_key,
            key_usage: vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign],
            path_len: 1,
            ca: true,
        },
        &signer,
    )?;
    let config = AuthorityConfig::new(
        request.name.clone(),
        AuthorityKind::Root,
        None,
        request.algorithm,
        request.validity_days,
        1,
        vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign],
        now,
    );
    Ok(AuthorityBundle::new(
        AuthorityMaterial::new(config, cert_pem.clone(), cert_pem),
        signer.key_material().clone(),
    ))
}

/// Creates an intermediate authority signed by `parent`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the request is inconsistent
/// and [`ChainkeeperError::Crypto`] when generation or signing fails.
pub fn create_intermediate(
    request: &CreateAuthorityRequest,
    parent: &AuthorityMaterial,
    parent_signer: &dyn Signer,
    clock: &dyn Clock,
    ids: &dyn IdGenerator,
    passphrase: Option<&SecretString>,
) -> Result<AuthorityBundle, ChainkeeperError> {
    if request.kind != AuthorityKind::Intermediate {
        return Err(validation(
            "create_intermediate requires authority kind intermediate",
        ));
    }
    if request.parent.as_ref() != Some(&parent.config.name) {
        return Err(validation(
            "intermediate parent does not match the supplied authority",
        ));
    }
    if parent.config.kind != AuthorityKind::Root {
        return Err(validation(
            "an intermediate authority must be signed by a root authority",
        ));
    }
    request.subject.validate()?;
    if request.validity_days == 0 {
        return Err(validation("authority validity must be positive"));
    }
    let parent_certificate = certificate::parse_first(&parent.cert_pem)?;
    let parent_not_after = certificate::not_after(&parent.cert_pem)?;
    let now = clock.now();
    let not_after = (now + days(request.validity_days)).min(parent_not_after);
    if not_after <= now {
        return Err(validation("parent authority is already expired"));
    }
    let generated = keygen::generate(request.algorithm, passphrase)?;
    let signer = FileSigner::from_key_and_material(generated.key, generated.material);
    let (_, cert_pem) = build_authority_certificate(
        &AuthorityCertificate {
            subject: &request.subject,
            issuer_der: certificate::subject_der(&parent_certificate)?,
            issuer_key_id: certificate::key_id(&parent_certificate)?,
            not_before: now,
            not_after,
            serial: ids.serial(),
            subject_public_key_der: signer.public_key_der()?,
            key_usage: vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign],
            path_len: 0,
            ca: true,
        },
        parent_signer,
    )?;
    let chain_pem = format!("{cert_pem}{}", parent.chain_pem);
    let config = AuthorityConfig::new(
        request.name.clone(),
        AuthorityKind::Intermediate,
        Some(parent.config.name.clone()),
        request.algorithm,
        request.validity_days,
        0,
        vec![KeyUsage::KeyCertSign, KeyUsage::CrlSign],
        now,
    );
    Ok(AuthorityBundle::new(
        AuthorityMaterial::new(config, cert_pem, chain_pem),
        signer.key_material().clone(),
    ))
}

/// Creates a dedicated OCSP signer signed by `parent`.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Validation`] when the request is inconsistent
/// and [`ChainkeeperError::Crypto`] when generation or signing fails.
pub fn create_ocsp_signer(
    request: &CreateOcspSignerRequest,
    parent: &AuthorityMaterial,
    parent_signer: &dyn Signer,
    clock: &dyn Clock,
    ids: &dyn IdGenerator,
    passphrase: Option<&SecretString>,
) -> Result<SignerBundle, ChainkeeperError> {
    if request.parent != parent.config.name {
        return Err(validation(
            "OCSP signer parent does not match the supplied authority",
        ));
    }
    if parent.config.kind != AuthorityKind::Intermediate {
        return Err(validation(
            "an OCSP signer must be signed by an intermediate authority",
        ));
    }
    let parent_certificate = certificate::parse_first(&parent.cert_pem)?;
    let parent_not_after = certificate::not_after(&parent.cert_pem)?;
    let now = clock.now();
    let not_after = (now + days(OCSP_SIGNER_VALIDITY_DAYS)).min(parent_not_after);
    if not_after <= now {
        return Err(validation("parent authority is already expired"));
    }
    let subject = request.subject.clone().unwrap_or_else(|| {
        names::ocsp_signer_subject(request.name.as_str(), parent_certificate.subject_name())
    });
    subject.validate()?;
    let generated = keygen::generate(request.algorithm, passphrase)?;
    let signer = FileSigner::from_key_and_material(generated.key, generated.material);
    let subject_der = names::to_der(&subject)?;
    let public_key = signer.public_key_der()?;
    let subject_key_id = keygen::key_id_from_spki(&public_key)?;
    let key_usage = extensions::key_usage(&[KeyUsage::DigitalSignature])?;
    let extensions = vec![
        Extension::new(
            OID_BASIC_CONSTRAINTS,
            true,
            extensions::basic_constraints(false, None),
        ),
        Extension::new(OID_KEY_USAGE, true, key_usage),
        Extension::new(
            OID_EXTENDED_KEY_USAGE,
            false,
            extensions::extended_key_usage(&[ExtendedKeyUsage::OcspSigning])?,
        ),
        Extension::new(
            OID_SUBJECT_KEY_IDENTIFIER,
            false,
            extensions::subject_key_identifier(&subject_key_id),
        ),
        Extension::new(
            OID_AUTHORITY_KEY_IDENTIFIER,
            false,
            extensions::authority_key_identifier(&certificate::key_id(&parent_certificate)?),
        ),
    ];
    let (_, cert_pem) = certificate::build(
        &CertificateInput {
            serial: ids.serial(),
            issuer_der: certificate::subject_der(&parent_certificate)?,
            subject_der,
            not_before: now,
            not_after,
            public_key_der: public_key,
            extensions,
        },
        parent_signer,
    )?;
    let chain_pem = format!("{cert_pem}{}", parent.chain_pem);
    let config = AuthorityConfig::new(
        request.name.clone(),
        AuthorityKind::OcspSigner,
        Some(parent.config.name.clone()),
        request.algorithm,
        OCSP_SIGNER_VALIDITY_DAYS,
        0,
        vec![KeyUsage::DigitalSignature],
        now,
    );
    Ok(SignerBundle {
        config,
        cert_pem,
        chain_pem,
        key: signer.key_material().clone(),
    })
}
