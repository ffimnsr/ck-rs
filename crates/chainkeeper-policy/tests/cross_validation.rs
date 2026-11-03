//! Profile, policy, and authority cross-validation.

mod common;

use std::path::PathBuf;

use chainkeeper_core::{
    AuthorityConfig, AuthorityKind, AuthorityName, AuthorityRecord, KeyAlgorithm, KeyUsage, Policy,
};
use chainkeeper_policy::cross_validate;
use time::OffsetDateTime;

fn authority(name: &str) -> AuthorityRecord {
    let name = AuthorityName::new(name).expect("valid authority name");
    let (kind, parent) = if name.as_str() == "root" {
        (AuthorityKind::Root, None)
    } else {
        (
            AuthorityKind::Intermediate,
            Some(AuthorityName::new("root").expect("valid authority name")),
        )
    };
    let config = AuthorityConfig::new(
        name,
        kind,
        parent,
        KeyAlgorithm::EcdsaP256,
        3650,
        0,
        vec![KeyUsage::DigitalSignature],
        OffsetDateTime::UNIX_EPOCH,
    );
    AuthorityRecord::from_config(
        &config,
        PathBuf::from("cert.pem"),
        PathBuf::from("chain.pem"),
    )
}

fn default_authorities() -> Vec<AuthorityRecord> {
    ["root", "tls", "smime", "codesign", "ocsp"]
        .into_iter()
        .map(authority)
        .collect()
}

#[test]
fn matching_profiles_and_authorities_produce_no_findings() {
    let findings = cross_validate(
        &common::base_policy(),
        &chainkeeper_policy::default_profiles(),
        &default_authorities(),
    );
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn missing_authorities_are_reported() {
    let mut authorities = default_authorities();
    authorities.retain(|authority| authority.name.as_str() != "ocsp");
    let findings = cross_validate(
        &common::base_policy(),
        &chainkeeper_policy::default_profiles(),
        &authorities,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "POLICY_PROFILE_MISSING");
    assert_eq!(findings[0].object_id.as_deref(), Some("ocsp"));
    assert_eq!(findings[0].severity, chainkeeper_core::Severity::Error);
}

#[test]
fn denied_algorithms_are_reported() {
    let policy = Policy {
        allowed_algorithms: vec![KeyAlgorithm::EcdsaP256],
        ..common::base_policy()
    };
    let findings = cross_validate(
        &policy,
        &chainkeeper_policy::default_profiles(),
        &default_authorities(),
    );
    let codes: Vec<&str> = findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    assert_eq!(
        codes,
        vec!["POLICY_ALGORITHM_DENIED", "POLICY_ALGORITHM_DENIED"]
    );
    let ids: Vec<&str> = findings
        .iter()
        .filter_map(|finding| finding.object_id.as_deref())
        .collect();
    assert_eq!(ids, vec!["smime", "codesign"]);
}

#[test]
fn exceeded_validity_is_reported() {
    let policy = Policy {
        max_validity_days: 90,
        ..common::base_policy()
    };
    let findings = cross_validate(
        &policy,
        &chainkeeper_policy::default_profiles(),
        &default_authorities(),
    );
    assert_eq!(findings.len(), 5);
    for finding in &findings {
        assert_eq!(finding.code, "POLICY_VALIDITY_EXCEEDED");
        assert!(
            finding.message.contains("max_validity_days 90"),
            "{}",
            finding.message
        );
    }
}

#[test]
fn findings_are_deterministic_and_per_profile() {
    let policy = Policy {
        allowed_algorithms: vec![KeyAlgorithm::Ed25519],
        max_validity_days: 90,
        ..common::base_policy()
    };
    let mut profile = common::builtin("tls-server");
    profile.validity_days = 500;
    let findings = cross_validate(&policy, &[profile], &[]);
    let codes: Vec<&str> = findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    assert_eq!(
        codes,
        vec![
            "POLICY_PROFILE_MISSING",
            "POLICY_ALGORITHM_DENIED",
            "POLICY_VALIDITY_EXCEEDED",
        ]
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.object_id.as_deref() == Some("tls-server"))
    );
}
