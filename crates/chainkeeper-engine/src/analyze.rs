//! `ck analyze` reports.

use std::collections::BTreeMap;

use chainkeeper_core::{
    AnalysisFinding, AnalyzeKind, AnalyzeReport, AuthorityKind, CertificateRecord,
    ChainkeeperError, RevocationRecord, Severity,
};
use time::OffsetDateTime;

use crate::engine::Engine;
use crate::state::{analysis_finding, sort_analysis};

/// Runs `ck analyze <kind>`.
pub fn analyze(engine: &Engine, kind: AnalyzeKind) -> Result<AnalyzeReport, ChainkeeperError> {
    let now = engine.now();
    let certificates = engine.store.list_certificates()?;
    let mut findings = match kind {
        AnalyzeKind::Expirations => expirations(now, &certificates),
        AnalyzeKind::Revocations => revocations(&engine.store.list_revocations()?),
        AnalyzeKind::Intermediates => intermediates(now, &engine.store.list_authorities()?),
        AnalyzeKind::Algorithms => algorithms(&certificates),
        AnalyzeKind::Policy => policy(engine, now, &certificates)?,
        _ => Vec::new(),
    };
    sort_analysis(&mut findings);
    Ok(AnalyzeReport {
        kind,
        generated_at: now,
        findings,
    })
}

fn bucket(now: OffsetDateTime, record: &CertificateRecord) -> (&'static str, Severity) {
    if record.expires_at <= now {
        return ("EXPIRATIONS_EXPIRED", Severity::Error);
    }
    let days = (record.expires_at - now).whole_days();
    if days <= 30 {
        ("EXPIRATIONS_0_30", Severity::Warning)
    } else if days <= 60 {
        ("EXPIRATIONS_31_60", Severity::Info)
    } else if days <= 90 {
        ("EXPIRATIONS_61_90", Severity::Info)
    } else {
        ("EXPIRATIONS_91_PLUS", Severity::Info)
    }
}

fn expirations(now: OffsetDateTime, certificates: &[CertificateRecord]) -> Vec<AnalysisFinding> {
    let mut counts: BTreeMap<(String, String, &'static str), (Severity, usize)> = BTreeMap::new();
    for record in certificates {
        let (code, severity) = bucket(now, record);
        let key = (
            record.profile.to_string(),
            record.authority.to_string(),
            code,
        );
        let entry = counts.entry(key).or_insert((severity, 0));
        entry.1 += 1;
    }
    counts
        .into_iter()
        .map(|((profile, authority, code), (severity, count))| {
            analysis_finding(
                code,
                severity,
                format!("{count} certificate(s) in {profile} issued by {authority}"),
                Some(format!("{profile}/{authority}")),
            )
        })
        .collect()
}

fn revocations(records: &[RevocationRecord]) -> Vec<AnalysisFinding> {
    let mut by_reason: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_month: BTreeMap<String, usize> = BTreeMap::new();
    for record in records {
        *by_reason.entry(record.reason.as_str()).or_default() += 1;
        let month = format!(
            "{:04}-{:02}",
            record.revoked_at.year(),
            u8::from(record.revoked_at.month())
        );
        *by_month.entry(month).or_default() += 1;
    }
    let mut findings = Vec::new();
    for (reason, count) in by_reason {
        findings.push(analysis_finding(
            "REVOCATIONS_BY_REASON",
            Severity::Info,
            format!("{count} revocation(s) with reason {reason}"),
            Some(reason.to_owned()),
        ));
    }
    for (month, count) in by_month {
        findings.push(analysis_finding(
            "REVOCATIONS_BY_MONTH",
            Severity::Info,
            format!("{count} revocation(s) in {month}"),
            Some(month),
        ));
    }
    findings
}

fn intermediates(
    now: OffsetDateTime,
    authorities: &[chainkeeper_core::AuthorityRecord],
) -> Vec<AnalysisFinding> {
    let mut findings = Vec::new();
    for authority in authorities {
        if authority.kind != AuthorityKind::Intermediate {
            continue;
        }
        let expires_at = Engine::authority_expiry(authority);
        let remaining = expires_at - now;
        if remaining > time::Duration::days(90) {
            continue;
        }
        let severity = if remaining <= time::Duration::ZERO {
            Severity::Error
        } else {
            Severity::Warning
        };
        findings.push(analysis_finding(
            "INTERMEDIATE_EXPIRING",
            severity,
            format!(
                "intermediate {} expires in {} day(s); algorithm {}, path length {}, parent {}",
                authority.name,
                remaining.whole_days(),
                authority.algorithm,
                authority.path_len,
                authority
                    .parent
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), ToString::to_string),
            ),
            Some(authority.name.to_string()),
        ));
    }
    findings
}

fn algorithms(certificates: &[CertificateRecord]) -> Vec<AnalysisFinding> {
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for record in certificates {
        *counts
            .entry((record.algorithm.to_string(), record.profile.to_string()))
            .or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((algorithm, profile), count)| {
            analysis_finding(
                "ALGORITHM_COUNT",
                Severity::Info,
                format!("{count} certificate(s) use {algorithm} in profile {profile}"),
                Some(format!("{algorithm}/{profile}")),
            )
        })
        .collect()
}

fn policy(
    engine: &Engine,
    now: OffsetDateTime,
    certificates: &[CertificateRecord],
) -> Result<Vec<AnalysisFinding>, ChainkeeperError> {
    let policy = engine.load_policy()?;
    let mut findings = Vec::new();
    for record in certificates {
        let validity_days = (record.expires_at - record.issued_at).whole_days();
        if validity_days > i64::from(policy.max_validity_days) {
            findings.push(analysis_finding(
                "POLICY_VALIDITY_EXCEEDED",
                Severity::Error,
                format!(
                    "certificate {} is valid for {validity_days} day(s), policy allows {}",
                    record.serial, policy.max_validity_days
                ),
                Some(record.serial.to_string()),
            ));
        }
        if !policy.permits_algorithm(record.algorithm) {
            findings.push(analysis_finding(
                "POLICY_ALGORITHM_DISALLOWED",
                Severity::Error,
                format!(
                    "certificate {} uses disallowed algorithm {}",
                    record.serial, record.algorithm
                ),
                Some(record.serial.to_string()),
            ));
        }
        if !policy.permits_profile(&record.profile) {
            findings.push(analysis_finding(
                "POLICY_PROFILE_DISALLOWED",
                Severity::Error,
                format!(
                    "certificate {} uses disallowed profile {}",
                    record.serial, record.profile
                ),
                Some(record.serial.to_string()),
            ));
        }
        if !policy.allow_wildcards
            && record.sans.iter().any(
                |san| matches!(san, chainkeeper_core::San::Dns(value) if value.starts_with("*.")),
            )
        {
            findings.push(analysis_finding(
                "POLICY_WILDCARD_DISALLOWED",
                Severity::Error,
                format!("certificate {} uses a wildcard SAN", record.serial),
                Some(record.serial.to_string()),
            ));
        }
        let _ = now;
    }
    // Custom OIDs are not persisted in certificate metadata, so only the
    // request-time policy engine can reject them.
    Ok(findings)
}
