//! Index drift detection.
//!
//! Drift never mutates data. It compares canonical records with indexed rows
//! and reports stable finding codes the `ck doctor` command renders.

use std::collections::{BTreeMap, BTreeSet};

use chainkeeper_core::time_util::parse_timestamp;
use chainkeeper_core::{
    CONFIG_VERSION, CertificateRecord, ChainkeeperError, DoctorFinding, IndexRecords,
    RevocationReason, RevocationRecord, Severity,
};
use rusqlite::Connection;

use super::{SqliteIndex, all_certificates, index_error};

fn finding(code: &str, severity: Severity, message: String, object_id: &str) -> DoctorFinding {
    DoctorFinding {
        code: code.to_owned(),
        severity,
        message,
        object_id: Some(object_id.to_owned()),
    }
}

fn apply_revocations(certificates: &mut [CertificateRecord], revocations: &[RevocationRecord]) {
    let by_serial: BTreeMap<&str, &RevocationRecord> = revocations
        .iter()
        .map(|record| (record.serial.as_str(), record))
        .collect();
    for certificate in certificates {
        if let Some(revocation) = by_serial.get(certificate.serial.as_str()) {
            certificate.revoked_at = Some(revocation.revoked_at);
            certificate.revocation_reason = Some(revocation.reason);
        }
    }
}

fn indexed_revocations(connection: &Connection) -> Result<Vec<RevocationRecord>, ChainkeeperError> {
    let mut statement = connection
        .prepare(
            "SELECT serial, authority, reason, comment, revoked_at, crl_number
             FROM revocations ORDER BY serial ASC",
        )
        .map_err(|error| index_error(format!("could not prepare revocation scan: {error}")))?;
    let mut rows = statement
        .query([])
        .map_err(|error| index_error(format!("could not scan revocations: {error}")))?;
    let mut records = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| index_error(format!("could not scan revocations: {error}")))?
    {
        let reason: String = row
            .get(2)
            .map_err(|error| index_error(format!("revocation reason is unreadable: {error}")))?;
        let reason = RevocationReason::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == reason)
            .ok_or_else(|| index_error(format!("unknown revocation reason {reason:?}")))?;
        let comment: String = row
            .get(3)
            .map_err(|error| index_error(format!("revocation comment is unreadable: {error}")))?;
        records.push(RevocationRecord {
            version: CONFIG_VERSION,
            serial: serde_json::from_value(serde_json::Value::String(
                row.get::<_, String>(0)
                    .map_err(|error| index_error(format!("serial is unreadable: {error}")))?,
            ))
            .map_err(|error| index_error(format!("serial is invalid: {error}")))?,
            authority: serde_json::from_value(serde_json::Value::String(
                row.get::<_, String>(1)
                    .map_err(|error| index_error(format!("authority is unreadable: {error}")))?,
            ))
            .map_err(|error| index_error(format!("authority is invalid: {error}")))?,
            reason,
            comment: if comment.is_empty() {
                None
            } else {
                Some(comment)
            },
            revoked_at: parse_timestamp(
                &row.get::<_, String>(4)
                    .map_err(|error| index_error(format!("revoked_at is unreadable: {error}")))?,
            )
            .map_err(|error| index_error(format!("revoked_at is invalid: {error}")))?,
            crl_number: row
                .get::<_, Option<i64>>(5)
                .map_err(|error| index_error(format!("crl_number is unreadable: {error}")))?
                .unwrap_or(0)
                .cast_unsigned(),
        });
    }
    Ok(records)
}

fn normalize_comment(record: &RevocationRecord) -> Option<String> {
    record
        .comment
        .as_ref()
        .filter(|comment| !comment.is_empty())
        .cloned()
}

/// Projects a record onto the fields the index persists.
///
/// The schema stores only the common name and email of the subject, so the
/// remaining distinguished-name fields are ignored when comparing rows.
fn indexed_projection(record: &CertificateRecord) -> CertificateRecord {
    let mut projected = record.clone();
    projected.subject.organization = None;
    projected.subject.organizational_unit = None;
    projected.subject.country = None;
    projected.subject.state = None;
    projected.subject.locality = None;
    projected
}

fn compare_certificates(
    connection: &Connection,
    records: &IndexRecords,
) -> Result<Vec<DoctorFinding>, ChainkeeperError> {
    let mut findings = Vec::new();
    let mut filesystem = records.certificates.clone();
    apply_revocations(&mut filesystem, &records.revocations);
    let indexed = all_certificates(connection)?;

    let filesystem_map: BTreeMap<&str, &CertificateRecord> = filesystem
        .iter()
        .map(|record| (record.serial.as_str(), record))
        .collect();
    let indexed_map: BTreeMap<&str, &CertificateRecord> = indexed
        .iter()
        .map(|record| (record.serial.as_str(), record))
        .collect();

    for serial in filesystem_map.keys() {
        if !indexed_map.contains_key(serial) {
            findings.push(finding(
                "IDX_MISSING",
                Severity::Warning,
                format!("certificate {serial} is missing from the index"),
                serial,
            ));
        }
    }
    for (serial, record) in &indexed_map {
        let Some(on_disk) = filesystem_map.get(serial) else {
            findings.push(finding(
                "IDX_EXTRA",
                Severity::Warning,
                format!("certificate {serial} is indexed but not on disk"),
                serial,
            ));
            continue;
        };
        if *record != *on_disk && indexed_projection(record) != indexed_projection(on_disk) {
            findings.push(finding(
                "IDX_HASH_MISMATCH",
                Severity::Error,
                format!("certificate {serial} differs from the indexed copy"),
                serial,
            ));
        }
    }
    Ok(findings)
}

fn compare_revocations(
    connection: &Connection,
    records: &IndexRecords,
) -> Result<Vec<DoctorFinding>, ChainkeeperError> {
    let mut findings = Vec::new();
    let indexed = indexed_revocations(connection)?;
    let filesystem: BTreeMap<&str, &RevocationRecord> = records
        .revocations
        .iter()
        .map(|record| (record.serial.as_str(), record))
        .collect();
    let indexed_map: BTreeMap<&str, &RevocationRecord> = indexed
        .iter()
        .map(|record| (record.serial.as_str(), record))
        .collect();

    for serial in filesystem.keys() {
        if !indexed_map.contains_key(serial) {
            findings.push(finding(
                "IDX_MISSING",
                Severity::Warning,
                format!("revocation {serial} is missing from the index"),
                serial,
            ));
        }
    }
    for (serial, record) in &indexed_map {
        let Some(on_disk) = filesystem.get(serial) else {
            findings.push(finding(
                "IDX_EXTRA",
                Severity::Warning,
                format!("revocation {serial} is indexed but not on disk"),
                serial,
            ));
            continue;
        };
        let mut normalized = (*on_disk).clone();
        normalized.comment = normalize_comment(on_disk);
        if **record != normalized {
            findings.push(finding(
                "IDX_HASH_MISMATCH",
                Severity::Error,
                format!("revocation {serial} differs from the indexed copy"),
                serial,
            ));
        }
    }
    Ok(findings)
}

fn compare_authorities(
    connection: &Connection,
    records: &IndexRecords,
) -> Result<Vec<DoctorFinding>, ChainkeeperError> {
    let mut statement = connection
        .prepare("SELECT name FROM intermediates ORDER BY name ASC")
        .map_err(|error| index_error(format!("could not prepare authority scan: {error}")))?;
    let mut rows = statement
        .query([])
        .map_err(|error| index_error(format!("could not scan authorities: {error}")))?;
    let mut indexed = BTreeSet::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| index_error(format!("could not scan authorities: {error}")))?
    {
        indexed.insert(
            row.get::<_, String>(0)
                .map_err(|error| index_error(format!("authority name is unreadable: {error}")))?,
        );
    }

    let on_disk: BTreeSet<String> = records
        .authorities
        .iter()
        .map(|record| record.name.as_str().to_owned())
        .collect();
    let mut findings = Vec::new();
    for name in &on_disk {
        if !indexed.contains(name) {
            findings.push(finding(
                "IDX_MISSING",
                Severity::Warning,
                format!("authority {name} is missing from the index"),
                name,
            ));
        }
    }
    for name in &indexed {
        if !on_disk.contains(name) {
            findings.push(finding(
                "IDX_EXTRA",
                Severity::Warning,
                format!("authority {name} is indexed but not on disk"),
                name,
            ));
        }
    }
    Ok(findings)
}

fn compare_audit_events(
    connection: &Connection,
    records: &IndexRecords,
) -> Result<Vec<DoctorFinding>, ChainkeeperError> {
    let mut statement = connection
        .prepare("SELECT id FROM audit_events ORDER BY id ASC")
        .map_err(|error| index_error(format!("could not prepare audit scan: {error}")))?;
    let mut rows = statement
        .query([])
        .map_err(|error| index_error(format!("could not scan audit events: {error}")))?;
    let mut indexed = BTreeSet::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| index_error(format!("could not scan audit events: {error}")))?
    {
        indexed.insert(
            row.get::<_, String>(0)
                .map_err(|error| index_error(format!("audit id is unreadable: {error}")))?,
        );
    }

    let on_disk: BTreeSet<String> = records
        .audit_events
        .iter()
        .map(|event| event.id.as_str().to_owned())
        .collect();
    let mut findings = Vec::new();
    for id in &on_disk {
        if !indexed.contains(id) {
            findings.push(finding(
                "IDX_MISSING",
                Severity::Warning,
                format!("audit event {id} is missing from the index"),
                id,
            ));
        }
    }
    for id in &indexed {
        if !on_disk.contains(id) {
            findings.push(finding(
                "IDX_EXTRA",
                Severity::Warning,
                format!("audit event {id} is indexed but not on disk"),
                id,
            ));
        }
    }
    Ok(findings)
}

/// Compares records with the index.
pub fn compare(
    index: &SqliteIndex,
    records: &IndexRecords,
) -> Result<Vec<DoctorFinding>, ChainkeeperError> {
    let connection = index.lock();
    let mut findings = compare_certificates(&connection, records)?;
    findings.extend(compare_revocations(&connection, records)?);
    findings.extend(compare_authorities(&connection, records)?);
    findings.extend(compare_audit_events(&connection, records)?);
    findings
        .sort_by(|left, right| (&left.code, &left.object_id).cmp(&(&right.code, &right.object_id)));
    drop(connection);
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use chainkeeper_core::time_util::format_timestamp;

    #[test]
    fn timestamps_are_canonical() {
        assert!(format_timestamp(time::macros::datetime!(2024-01-01 00:00:00 UTC)).ends_with('Z'));
    }
}
