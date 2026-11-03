//! OCSP responder state and validation.

use std::path::PathBuf;
use std::sync::Arc;

use chainkeeper_core::{
    AuthorityKind, AuthorityMaterial, AuthorityName, AuthorityRecord, ChainkeeperError,
    RevocationReason, Signer,
};
use openssl::asn1::Asn1Time;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509, X509StoreContext};
use rasn_pkix::Certificate;
use time::OffsetDateTime;

use crate::deps::OcspDependencies;
use crate::issuer::IssuerIndex;
use crate::status::{StatusMap, StatusValue};
use crate::util::{name_der, rasn_certificate_from_pem, x509_from_pem};

/// Immutable responder snapshot swapped atomically on reload.
pub struct OcspState {
    pub issuers: IssuerIndex,
    pub statuses: StatusMap,
    pub signer: Arc<dyn Signer>,
    pub signer_certificate: Certificate,
    pub chain: Vec<Certificate>,
    pub key_path: PathBuf,
    pub loaded_at: OffsetDateTime,
}

impl std::fmt::Debug for OcspState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OcspState")
            .field("authorities", &self.issuers.root_names().len())
            .field("key_path", &self.key_path)
            .field("loaded_at", &self.loaded_at)
            .finish_non_exhaustive()
    }
}

impl OcspState {
    /// Looks up the status of `serial` issued by `authority`.
    #[must_use]
    pub fn status(&self, authority: &AuthorityName, serial: u128) -> StatusValue {
        self.statuses.get(authority, serial)
    }
}

pub fn load_state(deps: &OcspDependencies) -> Result<OcspState, ChainkeeperError> {
    let now = deps.clock.now();
    let records = deps.store.list_authorities()?;
    let certificates = deps.store.list_certificates()?;

    let mut materials = Vec::new();
    let mut roots = Vec::new();
    for record in &records {
        if record.kind == AuthorityKind::OcspSigner {
            continue;
        }
        let Some(material) = deps.store.load_authority(&record.name)? else {
            continue;
        };
        if record.kind == AuthorityKind::Root {
            roots.push(x509_from_pem(&material.cert_pem)?);
        }
        materials.push(material);
    }
    let issuers = IssuerIndex::build(&materials)?;

    let signer_material = signer_material(deps, &records)?;
    let signer = deps.signers.signer_for(&deps.ocsp_signer)?;
    let signer_x509 = x509_from_pem(&signer_material.cert_pem)?;

    validate_signer(
        &signer_x509,
        &signer_material,
        &deps.ocsp_signer,
        signer.as_ref(),
        &roots,
        &issuers,
        now,
    )?;

    let signer_certificate = rasn_certificate_from_pem(&signer_material.cert_pem)?;
    let chain = chain_certificates(&signer_material.chain_pem)?;
    let key_path = deps.paths.authority_path(&deps.ocsp_signer, "key.pem")?;

    Ok(OcspState {
        issuers,
        statuses: StatusMap::build(now, certificates),
        signer,
        signer_certificate,
        chain,
        key_path,
        loaded_at: now,
    })
}

fn signer_material(
    deps: &OcspDependencies,
    records: &[AuthorityRecord],
) -> Result<AuthorityMaterial, ChainkeeperError> {
    let record = records
        .iter()
        .find(|record| record.name == deps.ocsp_signer)
        .ok_or_else(|| {
            ChainkeeperError::not_found("OCSP signer authority", deps.ocsp_signer.as_str())
        })?;
    if record.kind != AuthorityKind::OcspSigner {
        return Err(ChainkeeperError::ocsp(format!(
            "authority {} is not an OCSP signer",
            deps.ocsp_signer
        )));
    }
    deps.store
        .load_authority(&deps.ocsp_signer)?
        .ok_or_else(|| {
            ChainkeeperError::not_found("OCSP signer authority", deps.ocsp_signer.as_str())
        })
}

fn validate_signer(
    signer_certificate: &X509,
    material: &AuthorityMaterial,
    name: &AuthorityName,
    signer: &dyn Signer,
    roots: &[X509],
    issuers: &IssuerIndex,
    now: OffsetDateTime,
) -> Result<(), ChainkeeperError> {
    use openssl::x509::X509ExtendedKeyUsage;

    let usage = signer_certificate.extended_key_usage();
    if usage != Some(X509ExtendedKeyUsage::OCSP_SIGN) {
        return Err(ChainkeeperError::ocsp(format!(
            "OCSP signer {name} does not assert only the OCSP signing usage"
        )));
    }

    let now_asn1 = Asn1Time::from_unix(now.unix_timestamp())
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot build OCSP time: {error}")))?;
    let ordering = signer_certificate
        .not_after()
        .compare(&now_asn1)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot compare validity: {error}")))?;
    if ordering != std::cmp::Ordering::Greater {
        return Err(ChainkeeperError::ocsp(format!(
            "OCSP signer {name} is expired"
        )));
    }

    let certificate_key = signer_certificate
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|error| {
            ChainkeeperError::ocsp(format!("cannot encode signer public key: {error}"))
        })?;
    let signer_key = signer.public_key_der()?;
    if certificate_key != signer_key {
        return Err(ChainkeeperError::ocsp(format!(
            "OCSP signer {name} public key does not match its certificate"
        )));
    }

    let certificate = rasn_certificate_from_pem(&material.cert_pem)?;
    let issuer_der = name_der(&certificate.tbs_certificate.issuer)?;
    if !issuers.is_intermediate_subject(&issuer_der) {
        return Err(ChainkeeperError::ocsp(format!(
            "OCSP signer {name} is not issued by an intermediate authority"
        )));
    }

    verify_chain(signer_certificate, &material.chain_pem, roots, name, now)
}

fn verify_chain(
    signer_certificate: &X509,
    chain_pem: &str,
    roots: &[X509],
    name: &AuthorityName,
    now: OffsetDateTime,
) -> Result<(), ChainkeeperError> {
    if roots.is_empty() {
        return Err(ChainkeeperError::ocsp(
            "no root authority is available to verify the OCSP signer",
        ));
    }

    let mut builder = X509StoreBuilder::new()
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot build trust store: {error}")))?;
    for root in roots {
        builder
            .add_cert(root.clone())
            .map_err(|error| ChainkeeperError::ocsp(format!("cannot add trust anchor: {error}")))?;
    }
    let mut parameters = openssl::x509::verify::X509VerifyParam::new().map_err(|error| {
        ChainkeeperError::ocsp(format!("cannot build verify parameters: {error}"))
    })?;
    parameters.set_time(now.unix_timestamp() as _);
    builder
        .set_param(&parameters)
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot set verify time: {error}")))?;
    let store = builder.build();

    let mut chain = Stack::new()
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot build chain: {error}")))?;
    for certificate in X509::stack_from_pem(chain_pem.as_bytes())
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot parse signer chain: {error}")))?
    {
        chain
            .push(certificate)
            .map_err(|error| ChainkeeperError::ocsp(format!("cannot extend chain: {error}")))?;
    }

    let mut context = X509StoreContext::new()
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot build verify context: {error}")))?;
    let (verified, detail) = context
        .init(&store, signer_certificate, &chain, |context| {
            let verified = context.verify_cert()?;
            let detail = if verified {
                String::new()
            } else {
                format!("{} at depth {}", context.error(), context.error_depth())
            };
            Ok((verified, detail))
        })
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot verify signer chain: {error}")))?;
    if !verified {
        return Err(ChainkeeperError::ocsp(format!(
            "OCSP signer {name} chain does not verify to a trusted root: {detail}"
        )));
    }
    Ok(())
}

fn chain_certificates(chain_pem: &str) -> Result<Vec<Certificate>, ChainkeeperError> {
    let certificates = X509::stack_from_pem(chain_pem.as_bytes())
        .map_err(|error| ChainkeeperError::ocsp(format!("cannot parse signer chain: {error}")))?;
    certificates
        .iter()
        .map(|certificate| {
            let der = certificate.to_der().map_err(|error| {
                ChainkeeperError::ocsp(format!("cannot encode signer chain: {error}"))
            })?;
            rasn::der::decode(&der)
                .map_err(|error| ChainkeeperError::ocsp(format!("cannot decode chain: {error}")))
        })
        .collect()
}

/// Maps a revocation reason to the ASN.1 representation used by OCSP.
#[must_use]
pub const fn crl_reason(reason: RevocationReason) -> rasn_pkix::CrlReason {
    match reason {
        RevocationReason::KeyCompromise => rasn_pkix::CrlReason::KeyCompromise,
        RevocationReason::CaCompromise => rasn_pkix::CrlReason::CaCompromise,
        RevocationReason::AffiliationChanged => rasn_pkix::CrlReason::AffiliationChanged,
        RevocationReason::Superseded => rasn_pkix::CrlReason::Superseded,
        RevocationReason::CessationOfOperation => rasn_pkix::CrlReason::CessationOfOperation,
        RevocationReason::CertificateHold => rasn_pkix::CrlReason::CertificateHold,
        RevocationReason::PrivilegeWithdrawn => rasn_pkix::CrlReason::PrivilegeWithdrawn,
        RevocationReason::AaCompromise => rasn_pkix::CrlReason::AaCompromise,
        _ => rasn_pkix::CrlReason::Unspecified,
    }
}
