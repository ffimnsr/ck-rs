#![allow(dead_code)]

//! Shared fixtures for the policy integration tests.

use chainkeeper_core::{
    ChainkeeperError, IssueRequest, Policy, PolicyEngine, Profile, ProfileName, ProfileRegistry,
    San, SubjectName,
};
use chainkeeper_policy::{DefaultProfileRegistry, PolicyValidator, default_policy};

/// Returns a built-in profile by name.
pub fn builtin(name: &str) -> Profile {
    let name = ProfileName::new(name).expect("built-in profile name is valid");
    DefaultProfileRegistry::defaults()
        .list()
        .into_iter()
        .find(|profile| profile.name == name)
        .expect("built-in profile exists")
}

/// Returns the parsed default policy.
pub fn base_policy() -> Policy {
    default_policy()
}

/// Returns an issuance request whose CN matches `cn` and whose only SAN is `cn`.
pub fn dns_request(profile: &str, cn: &str) -> IssueRequest {
    let request = IssueRequest::new(
        ProfileName::new(profile).expect("valid profile"),
        SubjectName::new(cn),
    );
    IssueRequest {
        sans: vec![San::Dns(cn.to_owned())],
        ..request
    }
}

/// Returns an issuance request with an explicit SAN list.
pub fn request_with(profile: &str, cn: &str, sans: Vec<San>) -> IssueRequest {
    let request = IssueRequest::new(
        ProfileName::new(profile).expect("valid profile"),
        SubjectName::new(cn),
    );
    IssueRequest { sans, ..request }
}

/// Runs the trait-level issuance validation.
pub fn validate(
    policy: &Policy,
    profile: &Profile,
    request: &IssueRequest,
) -> Result<(), ChainkeeperError> {
    PolicyValidator::new().validate_issue(policy, profile, request)
}
