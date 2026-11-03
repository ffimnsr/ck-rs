//! Shared analysis categories and finding helpers.

use std::path::Path;

use chainkeeper_core::{AnalysisFinding, Severity};

/// Category of a repository path reported by `ck diff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChangeCategory {
    /// `certificates/`.
    Certificate,
    /// `revocations/`.
    Revocation,
    /// `crls/`.
    Crl,
    /// `policy/` and `profiles/`.
    Policy,
    /// `audit/`.
    Audit,
    /// `publish/`.
    Publish,
    /// Anything else.
    Other,
}

impl ChangeCategory {
    /// Stable string used in diagnostics and tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "certificates",
            Self::Revocation => "revocations",
            Self::Crl => "crls",
            Self::Policy => "policy",
            Self::Audit => "audit",
            Self::Publish => "publish",
            Self::Other => "other",
        }
    }
}

/// Classifies a repository-relative path.
#[must_use]
pub fn categorize(path: &Path) -> ChangeCategory {
    let first = path
        .components()
        .next()
        .map(|component| component.as_os_str().to_string_lossy().into_owned());
    match first.as_deref() {
        Some("certificates") => ChangeCategory::Certificate,
        Some("revocations") => ChangeCategory::Revocation,
        Some("crls") => ChangeCategory::Crl,
        Some("policy" | "profiles") => ChangeCategory::Policy,
        Some("audit") => ChangeCategory::Audit,
        Some("publish") => ChangeCategory::Publish,
        _ => ChangeCategory::Other,
    }
}

/// Builds an analysis finding.
#[must_use]
pub fn analysis_finding(
    code: &str,
    severity: Severity,
    message: impl Into<String>,
    object_id: Option<String>,
) -> AnalysisFinding {
    AnalysisFinding {
        code: code.to_owned(),
        severity,
        message: message.into(),
        object_id,
    }
}

/// Sorts findings by severity, object id, then code.
pub fn sort_analysis(findings: &mut [AnalysisFinding]) {
    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.object_id.cmp(&right.object_id))
            .then_with(|| left.code.cmp(&right.code))
    });
}
