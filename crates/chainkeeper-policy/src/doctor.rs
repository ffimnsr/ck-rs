//! Cross-validation between policy, profiles, and repository authorities.

use chainkeeper_core::{AuthorityRecord, DoctorFinding, Policy, Profile, Severity};

/// Compares profiles against a policy and the authorities present in a
/// repository.
///
/// Findings are emitted in profile order; each profile can produce a missing
/// authority, a denied algorithm, and an exceeded validity finding.
#[must_use]
pub fn cross_validate(
    policy: &Policy,
    profiles: &[Profile],
    authorities: &[AuthorityRecord],
) -> Vec<DoctorFinding> {
    let mut findings = Vec::new();
    for profile in profiles {
        if !authorities
            .iter()
            .any(|authority| authority.name == profile.authority)
        {
            findings.push(finding(
                "POLICY_PROFILE_MISSING",
                format!(
                    "profile {} references authority {} which is not in the repository",
                    profile.name, profile.authority
                ),
                profile.name.as_str(),
            ));
        }
        if !policy.permits_algorithm(profile.algorithm) {
            findings.push(finding(
                "POLICY_ALGORITHM_DENIED",
                format!(
                    "profile {} uses algorithm {} which policy allowed_algorithms denies",
                    profile.name,
                    profile.algorithm.as_str()
                ),
                profile.name.as_str(),
            ));
        }
        if profile.validity_days > policy.max_validity_days {
            findings.push(finding(
                "POLICY_VALIDITY_EXCEEDED",
                format!(
                    "profile {} validity_days {} exceeds policy max_validity_days {}",
                    profile.name, profile.validity_days, policy.max_validity_days
                ),
                profile.name.as_str(),
            ));
        }
    }
    findings
}

fn finding(code: &str, message: String, object_id: &str) -> DoctorFinding {
    DoctorFinding {
        code: code.to_owned(),
        severity: Severity::Error,
        message,
        object_id: Some(object_id.to_owned()),
    }
}
