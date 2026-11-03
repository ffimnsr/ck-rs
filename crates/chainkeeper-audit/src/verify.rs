//! Audit log verification.
//!
//! Verification is structural: sequence numbers must be contiguous from one,
//! every file must parse, and neither identifiers nor sequence numbers may
//! repeat. Audit files are not hash chained in V1, so an edit that keeps a file
//! internally valid is only detectable when it disturbs the sequence.

use std::collections::BTreeMap;
use std::path::Path;

use chainkeeper_core::ChainkeeperError;
use chainkeeper_core::{DoctorFinding, EventId, RepositoryPaths, Severity};

use crate::canonical::from_canonical_json;
use crate::file_log::event_paths;

/// Code reported when sequence numbers are missing or start above one.
pub const AUDIT_SEQ_GAP: &str = "AUDIT_SEQ_GAP";
/// Code reported when an identifier or sequence number repeats.
pub const AUDIT_DUPLICATE: &str = "AUDIT_DUPLICATE";
/// Code reported when a file cannot be read or parsed.
pub const AUDIT_INVALID: &str = "AUDIT_INVALID";

fn finding(code: &str, message: String, object_id: Option<String>) -> DoctorFinding {
    DoctorFinding {
        code: code.to_owned(),
        severity: Severity::Error,
        message,
        object_id,
    }
}

fn file_stem(path: &Path) -> Option<String> {
    path.file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
}

/// Inspects every audit file and reports structural problems.
///
/// # Errors
///
/// Returns [`ChainkeeperError::Audit`] when the audit directory cannot be read.
pub fn verify_events(paths: &RepositoryPaths) -> Result<Vec<DoctorFinding>, ChainkeeperError> {
    let mut findings = Vec::new();
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    let mut sequence: BTreeMap<u64, String> = BTreeMap::new();

    for path in event_paths(paths)? {
        let name = file_stem(&path).unwrap_or_else(|| path.display().to_string());

        let stem_id = EventId::new(name.clone());
        if stem_id.is_err() {
            findings.push(finding(
                AUDIT_INVALID,
                format!("audit file name {name:?} is not a canonical ULID"),
                Some(name.clone()),
            ));
        }

        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                findings.push(finding(
                    AUDIT_INVALID,
                    format!("could not read audit file {}: {error}", path.display()),
                    Some(name),
                ));
                continue;
            }
        };

        let event = match from_canonical_json(&bytes) {
            Ok(event) => event,
            Err(error) => {
                findings.push(finding(
                    AUDIT_INVALID,
                    format!("could not parse audit file {}: {error}", path.display()),
                    Some(name),
                ));
                continue;
            }
        };

        if event.id.as_str() != name {
            findings.push(finding(
                AUDIT_INVALID,
                format!(
                    "audit file {name:?} contains event id {}",
                    event.id.as_str()
                ),
                Some(name.clone()),
            ));
        }

        if let Some(existing) = ids.insert(event.id.to_string(), name.clone()) {
            findings.push(finding(
                AUDIT_DUPLICATE,
                format!(
                    "audit event id {} appears in both {existing} and {name}",
                    event.id.as_str()
                ),
                Some(event.id.to_string()),
            ));
        }

        if let Some(existing) = sequence.insert(event.seq, name.clone()) {
            findings.push(finding(
                AUDIT_DUPLICATE,
                format!(
                    "audit sequence number {} appears in both {existing} and {name}",
                    event.seq
                ),
                Some(event.seq.to_string()),
            ));
        }

        if event.seq == 0 {
            findings.push(finding(
                AUDIT_SEQ_GAP,
                "audit sequence numbers start at 1, found 0".to_owned(),
                Some("0".to_owned()),
            ));
        }
    }

    if let Some(maximum) = sequence.keys().next_back().copied() {
        for expected in 1..=maximum {
            if !sequence.contains_key(&expected) {
                findings.push(finding(
                    AUDIT_SEQ_GAP,
                    format!("missing audit sequence number {expected}"),
                    Some(expected.to_string()),
                ));
            }
        }
    }

    findings.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then_with(|| left.object_id.cmp(&right.object_id))
            .then_with(|| left.message.cmp(&right.message))
    });
    Ok(findings)
}
