//! Pure policy and profile validation.

use std::collections::BTreeSet;
use std::fmt;

use chainkeeper_core::{
    ChainkeeperError, CustomExtension, ErrorDetail, ErrorKind, IssueRequest, KeyAlgorithm,
    MAX_LEAF_VALIDITY_DAYS, Policy, Profile, San, SanType, SubjectName,
};

use crate::dns::{
    is_wildcard_dns, validate_dns_name, validate_email, validate_email_field, validate_ip,
    validate_uri,
};
use crate::oid::Oid;

/// Authority names a profile may reference in V1.
pub const DEFAULT_AUTHORITY_NAMES: [&str; 4] = ["tls", "smime", "codesign", "ocsp"];

/// Largest UTF-8 custom extension value, in bytes.
const MAX_UTF8_VALUE_BYTES: usize = 1024;

/// Largest decoded custom extension value, in bytes.
const MAX_HEX_VALUE_BYTES: usize = 4096;

fn invalid(field: &str, value: &str, reason: impl fmt::Display) -> ChainkeeperError {
    ChainkeeperError::invalid(field, value, reason)
}

const fn mapped_authority(name: &str) -> Option<&'static str> {
    match name.as_bytes() {
        b"tls-server" | b"tls-client" | b"mtls" => Some("tls"),
        b"smime" => Some("smime"),
        b"codesign" => Some("codesign"),
        b"ocsp" => Some("ocsp"),
        _ => None,
    }
}

const fn forbids_wildcard(profile_name: &str) -> bool {
    matches!(profile_name.as_bytes(), b"smime" | b"codesign")
}

const fn san_type_name(kind: SanType) -> &'static str {
    match kind {
        SanType::Dns => "dns",
        SanType::Ip => "ip",
        SanType::Email => "email",
        SanType::Uri => "uri",
        _ => "unknown",
    }
}

/// Validates a policy document, including its SAN suffix list.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Config`] when a limit is out of range, a list is
/// empty, or a SAN suffix is malformed.
pub fn validate_policy(policy: &Policy) -> Result<(), ChainkeeperError> {
    policy.validate()?;
    normalized_san_suffixes(policy)?;
    Ok(())
}

/// Returns the SAN suffixes of a policy lowercased and validated.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Config`] when a suffix is empty, starts with a
/// dot, contains invalid characters, or has a malformed label.
pub fn normalized_san_suffixes(policy: &Policy) -> Result<Vec<String>, ChainkeeperError> {
    policy
        .allowed_san_suffixes
        .iter()
        .map(|suffix| normalize_suffix(suffix))
        .collect()
}

fn normalize_suffix(suffix: &str) -> Result<String, ChainkeeperError> {
    let invalid_suffix = |reason: String| {
        ChainkeeperError::config(format!("invalid allowed_san_suffix {suffix:?}: {reason}"))
    };

    if suffix.is_empty() {
        return Err(invalid_suffix("must not be empty".to_owned()));
    }
    if suffix.trim() != suffix {
        return Err(invalid_suffix("must not contain whitespace".to_owned()));
    }
    if suffix.starts_with('.') {
        return Err(invalid_suffix(
            "must not start with a dot; write example.com, not .example.com".to_owned(),
        ));
    }
    if suffix.ends_with('.') {
        return Err(invalid_suffix("must not end with a dot".to_owned()));
    }
    let lower = suffix.to_ascii_lowercase();
    if lower.len() > 253 {
        return Err(invalid_suffix("must be at most 253 characters".to_owned()));
    }
    for label in lower.split('.') {
        if label.is_empty() {
            return Err(invalid_suffix("must not contain empty labels".to_owned()));
        }
        if label.len() > 63 {
            return Err(invalid_suffix(format!(
                "label {label:?} exceeds 63 characters"
            )));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid_suffix(format!(
                "label {label:?} must use letters, digits, and hyphens"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid_suffix(format!(
                "label {label:?} must not start or end with a hyphen"
            )));
        }
    }
    Ok(lower)
}

/// Validates profile self-consistency and V1 profile rules.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Profile`] when the profile version, validity,
/// key usage, extended key usage, algorithm, or authority mapping is invalid.
pub fn validate_profile_structure(profile: &Profile) -> Result<(), ChainkeeperError> {
    profile.validate()?;
    if profile.validity_days > MAX_LEAF_VALIDITY_DAYS {
        return Err(ChainkeeperError::from_detail(
            ErrorKind::Profile,
            ErrorDetail::new(format!(
                "profile {} validity_days {} exceeds the {MAX_LEAF_VALIDITY_DAYS} day limit",
                profile.name, profile.validity_days
            ))
            .with_object_id(profile.name.as_str()),
        ));
    }
    if !KeyAlgorithm::ALL.contains(&profile.algorithm) {
        return Err(ChainkeeperError::profile(format!(
            "profile {} algorithm {} is not supported",
            profile.name,
            profile.algorithm.as_str()
        )));
    }
    if profile.key_usage.is_empty() {
        return Err(ChainkeeperError::profile(format!(
            "profile {} must declare at least one key usage",
            profile.name
        )));
    }
    if profile.eku.is_empty() {
        return Err(ChainkeeperError::profile(format!(
            "profile {} must declare at least one extended key usage",
            profile.name
        )));
    }
    // `SanType` is a closed enum, so every deserialized value is known; the
    // check keeps programmatic profiles honest if the enum grows.
    if !profile.san_types.iter().all(|kind| {
        matches!(
            kind,
            SanType::Dns | SanType::Ip | SanType::Email | SanType::Uri
        )
    }) {
        return Err(ChainkeeperError::profile(format!(
            "profile {} declares an unknown SAN type",
            profile.name
        )));
    }
    if let Some(expected) = mapped_authority(profile.name.as_str())
        && profile.authority.as_str() != expected
    {
        return Err(ChainkeeperError::profile(format!(
            "profile {} must use authority {expected}, found {}",
            profile.name, profile.authority
        )));
    }
    if !DEFAULT_AUTHORITY_NAMES.contains(&profile.authority.as_str()) {
        return Err(ChainkeeperError::profile(format!(
            "profile {} authority {} is not one of {}",
            profile.name,
            profile.authority,
            DEFAULT_AUTHORITY_NAMES.join(", ")
        )));
    }
    Ok(())
}

/// Validates a profile against a policy's allow lists and limits.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Policy`] when the profile is not allowed, when
/// its algorithm is denied, or when its validity exceeds the policy maximum.
pub fn validate_profile_against_policy(
    policy: &Policy,
    profile: &Profile,
) -> Result<(), ChainkeeperError> {
    if !policy.permits_profile(&profile.name) {
        return Err(ChainkeeperError::policy(format!(
            "profile {} is not in policy allowed_profiles",
            profile.name
        )));
    }
    if !policy.permits_algorithm(profile.algorithm) {
        return Err(ChainkeeperError::policy(format!(
            "profile {} algorithm {} is not in policy allowed_algorithms",
            profile.name,
            profile.algorithm.as_str()
        )));
    }
    if profile.validity_days > policy.max_validity_days {
        return Err(ChainkeeperError::policy(format!(
            "profile {} validity_days {} exceeds policy max_validity_days {}",
            profile.name, profile.validity_days, policy.max_validity_days
        )));
    }
    Ok(())
}

/// Validates an issuance request against a policy and profile.
///
/// `issuer_remaining_days` is the authority lifetime left when the caller knows
/// it; requests may not outlive their issuer.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Policy`] or [`ChainkeeperError::Validation`]
/// for the first violated rule, in the order policy, profile, then request.
pub fn validate_issue_request(
    policy: &Policy,
    profile: &Profile,
    request: &IssueRequest,
    issuer_remaining_days: Option<u32>,
) -> Result<(), ChainkeeperError> {
    validate_policy(policy)?;
    validate_profile_structure(profile)?;
    validate_profile_against_policy(policy, profile)?;
    if request.profile != profile.name {
        return Err(ChainkeeperError::validation(format!(
            "request profile {} does not match resolved profile {}",
            request.profile, profile.name
        )));
    }
    validate_algorithm(policy, profile, request)?;
    validate_validity(policy, profile, request, issuer_remaining_days)?;
    validate_subject(&request.subject)?;
    validate_sans(policy, profile, request)?;
    validate_requested_extensions(policy, profile, request)?;
    validate_cn_matches_san(policy, request)?;
    Ok(())
}

fn validate_algorithm(
    policy: &Policy,
    profile: &Profile,
    request: &IssueRequest,
) -> Result<(), ChainkeeperError> {
    let algorithm = request.algorithm.unwrap_or(profile.algorithm);
    if !policy.permits_algorithm(algorithm) {
        return Err(ChainkeeperError::policy(format!(
            "requested algorithm {} is not in policy allowed_algorithms",
            algorithm.as_str()
        )));
    }
    Ok(())
}

fn validate_validity(
    policy: &Policy,
    profile: &Profile,
    request: &IssueRequest,
    issuer_remaining_days: Option<u32>,
) -> Result<(), ChainkeeperError> {
    let validity = request.validity_days.unwrap_or(profile.validity_days);
    if validity == 0 {
        return Err(ChainkeeperError::validation(
            "requested validity_days must be positive",
        ));
    }
    if validity > policy.max_validity_days {
        return Err(ChainkeeperError::policy(format!(
            "requested validity_days {validity} exceeds policy max_validity_days {}",
            policy.max_validity_days
        )));
    }
    if let Some(remaining) = issuer_remaining_days
        && validity > remaining
    {
        return Err(ChainkeeperError::policy(format!(
            "requested validity_days {validity} exceeds the issuing authority remaining lifetime of {remaining} days"
        )));
    }
    Ok(())
}

fn validate_subject(subject: &SubjectName) -> Result<(), ChainkeeperError> {
    if subject.cn.trim().is_empty() {
        return Err(ChainkeeperError::validation("subject cn must not be empty"));
    }
    if let Some(country) = &subject.country
        && (country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()))
    {
        return Err(invalid(
            "subject country",
            country,
            "must be exactly two uppercase ASCII letters",
        ));
    }
    if let Some(email) = &subject.email {
        validate_email_field("subject email", email)?;
    }
    Ok(())
}

fn validate_sans(
    policy: &Policy,
    profile: &Profile,
    request: &IssueRequest,
) -> Result<(), ChainkeeperError> {
    if request.sans.len() > policy.max_sans {
        return Err(ChainkeeperError::policy(format!(
            "request has {} subject alternative names, exceeding policy max_sans {}",
            request.sans.len(),
            policy.max_sans
        )));
    }
    if profile.san_required && request.sans.is_empty() {
        return Err(ChainkeeperError::validation(format!(
            "profile {} requires at least one subject alternative name",
            profile.name
        )));
    }
    let suffixes = normalized_san_suffixes(policy)?;
    for (index, san) in request.sans.iter().enumerate() {
        validate_san(policy, profile, index, san, &suffixes)?;
    }
    Ok(())
}

fn validate_san(
    policy: &Policy,
    profile: &Profile,
    index: usize,
    san: &San,
    suffixes: &[String],
) -> Result<(), ChainkeeperError> {
    if !profile.accepts_san_type(san.kind()) {
        return Err(ChainkeeperError::policy(format!(
            "subject alternative name {index} of type {} is not accepted by profile {}",
            san_type_name(san.kind()),
            profile.name
        )));
    }
    match san {
        San::Dns(value) => {
            validate_dns_name(value, policy.allow_wildcards)?;
            if is_wildcard_dns(value) && forbids_wildcard(profile.name.as_str()) {
                return Err(ChainkeeperError::policy(format!(
                    "profile {} does not allow wildcard DNS subject alternative name {value:?}",
                    profile.name
                )));
            }
            if !suffixes.is_empty() && !matches_allowed_suffix(value, suffixes) {
                return Err(ChainkeeperError::policy(format!(
                    "DNS subject alternative name {value:?} does not end with an allowed_san_suffix"
                )));
            }
        }
        San::Ip(value) => validate_ip(value)?,
        San::Email(value) => validate_email(value)?,
        San::Uri(value) => validate_uri(value)?,
    }
    Ok(())
}

fn matches_allowed_suffix(name: &str, suffixes: &[String]) -> bool {
    let host = name.strip_prefix("*.").unwrap_or(name).to_ascii_lowercase();
    suffixes
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

fn validate_requested_extensions(
    policy: &Policy,
    profile: &Profile,
    request: &IssueRequest,
) -> Result<(), ChainkeeperError> {
    if request.custom_extensions.is_empty() {
        return Ok(());
    }
    if !profile.allow_custom_oid {
        return Err(ChainkeeperError::policy(format!(
            "profile {} does not accept custom OID extensions",
            profile.name
        )));
    }
    validate_custom_extensions(policy, &request.custom_extensions)
}

fn validate_cn_matches_san(
    policy: &Policy,
    request: &IssueRequest,
) -> Result<(), ChainkeeperError> {
    if !policy.cn_must_match_san {
        return Ok(());
    }
    let cn = &request.subject.cn;
    let matched = request.sans.iter().any(|san| match san {
        San::Dns(value) | San::Email(value) => value == cn,
        San::Ip(_) | San::Uri(_) => false,
    });
    if !matched {
        return Err(ChainkeeperError::policy(format!(
            "subject cn {cn:?} must exactly match a DNS or email subject alternative name"
        )));
    }
    Ok(())
}

/// Validates a single custom extension against a policy.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Policy`] when custom OIDs or critical custom
/// extensions are disabled or the OID is reserved, and
/// [`ChainkeeperError::Validation`] when the OID or value encoding is invalid.
pub fn validate_custom_extension(
    policy: &Policy,
    extension: &CustomExtension,
) -> Result<(), ChainkeeperError> {
    validate_extension(policy, extension).map(|_oid| ())
}

/// Validates every custom extension in a request, rejecting duplicate OIDs.
///
/// # Errors
///
/// Returns the same errors as [`validate_custom_extension`], plus
/// [`ChainkeeperError::Policy`] when an OID repeats.
pub fn validate_custom_extensions(
    policy: &Policy,
    extensions: &[CustomExtension],
) -> Result<(), ChainkeeperError> {
    let mut seen = BTreeSet::new();
    for extension in extensions {
        let oid = validate_extension(policy, extension)?;
        if !seen.insert(oid.clone()) {
            return Err(ChainkeeperError::policy(format!(
                "custom extension OID {oid} is duplicated in one request"
            )));
        }
    }
    Ok(())
}

fn validate_extension(
    policy: &Policy,
    extension: &CustomExtension,
) -> Result<Oid, ChainkeeperError> {
    if !policy.allow_custom_oid {
        return Err(ChainkeeperError::policy(format!(
            "custom extension OID {:?} is rejected because policy allow_custom_oid is false",
            extension.oid
        )));
    }
    let oid = Oid::parse(&extension.oid)?;
    if oid.is_reserved() {
        return Err(ChainkeeperError::policy(format!(
            "custom extension OID {oid} is reserved and cannot be overridden"
        )));
    }
    if extension.critical && !policy.allow_critical_custom_oid {
        return Err(ChainkeeperError::policy(format!(
            "custom extension OID {oid} is critical but policy allow_critical_custom_oid is false"
        )));
    }
    match (&extension.value_utf8, &extension.value_hex) {
        (Some(_), Some(_)) | (None, None) => Err(invalid(
            "custom extension value",
            &extension.oid,
            "must set exactly one of value_utf8 and value_hex",
        )),
        (Some(value), None) => {
            if value.len() > MAX_UTF8_VALUE_BYTES {
                return Err(invalid(
                    "custom extension value_utf8",
                    &extension.oid,
                    format!(
                        "must be at most {MAX_UTF8_VALUE_BYTES} bytes, found {}",
                        value.len()
                    ),
                ));
            }
            Ok(oid)
        }
        (None, Some(hex)) => {
            if hex.len() % 2 != 0 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(invalid(
                    "custom extension value_hex",
                    &extension.oid,
                    "must be even-length hexadecimal",
                ));
            }
            let size = hex.len() / 2;
            if size > MAX_HEX_VALUE_BYTES {
                return Err(invalid(
                    "custom extension value_hex",
                    &extension.oid,
                    format!("must be at most {MAX_HEX_VALUE_BYTES} decoded bytes, found {size}"),
                ));
            }
            Ok(oid)
        }
    }
}
