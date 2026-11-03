//! Commit message builders.
//!
//! Every application created commit uses one of these formats. The prefixes are
//! part of the product contract, so the constructors are the only supported way
//! to build a message.

use std::fmt;

use chainkeeper_core::{AuthorityName, ProfileName, RevocationReason, Serial, TenantId};

/// Validated commit message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitMessage(String);

impl CommitMessage {
    /// Initial repository commit.
    #[must_use]
    pub fn init(tenant: &TenantId) -> Self {
        Self(format!("feat(ck): initialize tenant {tenant}"))
    }

    /// Root authority creation.
    #[must_use]
    pub fn root(name: &AuthorityName) -> Self {
        Self(format!("feat(ck): create root authority {name}"))
    }

    /// Intermediate authority creation.
    #[must_use]
    pub fn intermediate(name: &AuthorityName) -> Self {
        Self(format!("feat(ck): create intermediate authority {name}"))
    }

    /// OCSP signer creation.
    #[must_use]
    pub fn ocsp_signer(name: &AuthorityName) -> Self {
        Self(format!("feat(ck): create ocsp signer {name}"))
    }

    /// Certificate issuance.
    #[must_use]
    pub fn issue(serial: &Serial, profile: &ProfileName) -> Self {
        Self(format!(
            "feat(ck): issue certificate {serial} profile {profile}"
        ))
    }

    /// Certificate revocation.
    #[must_use]
    pub fn revoke(serial: &Serial, reason: RevocationReason) -> Self {
        Self(format!(
            "feat(ck): revoke certificate {serial} reason {}",
            reason.as_str()
        ))
    }

    /// Certificate replacement.
    #[must_use]
    pub fn replace(old: &Serial, new: &Serial) -> Self {
        Self(format!("feat(ck): replace certificate {old} with {new}"))
    }

    /// CRL regeneration.
    #[must_use]
    pub fn crl(authority: &AuthorityName, number: u64) -> Self {
        Self(format!(
            "feat(ck): regenerate crl {authority} number {number}"
        ))
    }

    /// Publication of generated artifacts.
    #[must_use]
    pub fn publish(source_commit: &str) -> Self {
        Self(format!("chore(ck): publish artifacts from {source_commit}"))
    }

    /// Index rebuild.
    #[must_use]
    pub fn rebuild_index() -> Self {
        Self("chore(ck): rebuild index".to_owned())
    }

    /// Borrowed message text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the message, returning its text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for CommitMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}
