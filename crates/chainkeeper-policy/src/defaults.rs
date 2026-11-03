//! Embedded default profiles and policy.

use chainkeeper_core::{ChainkeeperError, ErrorDetail, ErrorKind, Policy, Profile};

use crate::validate::validate_profile_structure;

/// Default policy YAML written by `ck init`.
pub const DEFAULT_POLICY_YAML: &str = include_str!("../policy.yaml");

/// Embedded built-in profile YAML files, keyed by file stem and profile name.
pub const BUILTIN_PROFILE_YAML: [(&str, &str); 6] = [
    ("tls-server", include_str!("../profiles/tls-server.yaml")),
    ("tls-client", include_str!("../profiles/tls-client.yaml")),
    ("mtls", include_str!("../profiles/mtls.yaml")),
    ("smime", include_str!("../profiles/smime.yaml")),
    ("codesign", include_str!("../profiles/codesign.yaml")),
    ("ocsp", include_str!("../profiles/ocsp.yaml")),
];

/// Returns every embedded profile YAML document with its file stem.
#[must_use]
pub const fn builtin_profile_yaml_files() -> &'static [(&'static str, &'static str)] {
    &BUILTIN_PROFILE_YAML
}

/// Returns the embedded YAML document for one profile.
#[must_use]
pub fn builtin_profile_yaml(name: &str) -> Option<&'static str> {
    BUILTIN_PROFILE_YAML
        .iter()
        .find(|(stem, _)| *stem == name)
        .map(|(_, yaml)| *yaml)
}

/// Parses and validates the embedded default policy.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Config`] when the embedded document is malformed.
pub fn load_default_policy() -> Result<Policy, ChainkeeperError> {
    let policy: Policy = serde_yaml_ng::from_str(DEFAULT_POLICY_YAML).map_err(|error| {
        ChainkeeperError::from_detail(
            ErrorKind::Config,
            ErrorDetail::new("embedded default policy is malformed").with_source(error),
        )
    })?;
    policy.validate()?;
    Ok(policy)
}

/// Parses and validates every embedded default profile.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Profile`] when an embedded document is malformed
/// or fails profile validation.
pub fn load_default_profiles() -> Result<Vec<Profile>, ChainkeeperError> {
    BUILTIN_PROFILE_YAML
        .iter()
        .map(|(stem, yaml)| {
            let profile: Profile = serde_yaml_ng::from_str(yaml).map_err(|error| {
                ChainkeeperError::from_detail(
                    ErrorKind::Profile,
                    ErrorDetail::new(format!("embedded profile {stem} is malformed"))
                        .with_source(error)
                        .with_object_id(*stem),
                )
            })?;
            if profile.name.as_str() != *stem {
                return Err(ChainkeeperError::from_detail(
                    ErrorKind::Profile,
                    ErrorDetail::new(format!(
                        "embedded profile {stem} declares name {}",
                        profile.name
                    ))
                    .with_object_id(*stem),
                ));
            }
            validate_profile_structure(&profile)?;
            Ok(profile)
        })
        .collect()
}

/// Returns the embedded default policy.
///
/// # Panics
///
/// Panics only when the embedded YAML is malformed, which is a build defect.
#[must_use]
pub fn default_policy() -> Policy {
    load_default_policy().expect("embedded default policy is valid")
}

/// Returns every embedded default profile in canonical order.
///
/// # Panics
///
/// Panics only when the embedded YAML is malformed, which is a build defect.
#[must_use]
pub fn default_profiles() -> Vec<Profile> {
    load_default_profiles().expect("embedded default profiles are valid")
}

#[cfg(test)]
mod tests {
    use super::{default_policy, default_profiles, load_default_policy, load_default_profiles};

    #[test]
    fn embedded_defaults_parse() {
        assert!(load_default_policy().is_ok());
        assert!(load_default_profiles().is_ok());
        assert_eq!(default_profiles().len(), 6);
        assert_eq!(default_policy().max_validity_days, 397);
    }
}
