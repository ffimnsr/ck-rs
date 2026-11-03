//! Policy engine implementation.

use chainkeeper_core::{
    ChainkeeperError, CustomExtension, IssueRequest, Policy, PolicyEngine, Profile,
};

use crate::validate::{
    validate_custom_extension, validate_issue_request, validate_profile_against_policy,
};

/// Extra issuance facts the policy layer cannot infer from a request alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IssueContext {
    /// Days left on the issuing authority certificate, when known.
    pub issuer_remaining_days: Option<u32>,
}

impl IssueContext {
    /// Context without issuer lifetime information.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            issuer_remaining_days: None,
        }
    }

    /// Context that clamps issuance validity to the issuer's remaining lifetime.
    #[must_use]
    pub const fn with_issuer_remaining_days(days: u32) -> Self {
        Self {
            issuer_remaining_days: Some(days),
        }
    }
}

/// Deterministic [`PolicyEngine`] implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolicyValidator;

impl PolicyValidator {
    /// Creates a validator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Validates an issuance request with issuer lifetime information.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`validate_issue_request`].
    pub fn validate_issue_with(
        policy: &Policy,
        profile: &Profile,
        request: &IssueRequest,
        context: IssueContext,
    ) -> Result<(), ChainkeeperError> {
        validate_issue_request(policy, profile, request, context.issuer_remaining_days)
    }
}

impl PolicyEngine for PolicyValidator {
    fn validate_issue(
        &self,
        policy: &Policy,
        profile: &Profile,
        request: &IssueRequest,
    ) -> Result<(), ChainkeeperError> {
        Self::validate_issue_with(policy, profile, request, IssueContext::new())
    }

    fn validate_custom_extension(
        &self,
        policy: &Policy,
        extension: &CustomExtension,
    ) -> Result<(), ChainkeeperError> {
        validate_custom_extension(policy, extension)
    }

    fn validate_profile(&self, policy: &Policy, profile: &Profile) -> Result<(), ChainkeeperError> {
        validate_profile_against_policy(policy, profile)
    }
}
