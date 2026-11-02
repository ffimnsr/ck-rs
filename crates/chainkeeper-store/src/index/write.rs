//! Index writes, rebuilds, and repair support.

use chainkeeper_core::time_util::format_timestamp;
use chainkeeper_core::{
    AuditEvent, AuthorityRecord, CertificateRecord, ChainkeeperError, IndexRecords, IndexReport,
    IndexedCrl, Profile, RevocationRecord,
};
use rusqlite::{Connection, OptionalExtension as _};

use super::schema::{self, SCHEMA_VERSION};
use super::{SqliteIndex, index_error, stats};
use crate::canonical;

fn insert_fts(
    connection: &Connection,
    id: i64,
    record: &CertificateRecord,
) -> Result<(), ChainkeeperError> {
    let sans = record
        .sans
        .iter()
        .map(chainkeeper_core::San::value)
        .collect::<Vec<_>>()
        .join(" ");
    let email = record.subject.email.as_deref();
    connection
        .execute(
            "INSERT INTO certificates_fts (rowid, serial, subject, sans, email, profile)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                id,
                record.serial.as_str(),
                record.subject.cn,
                sans,
                email,
                record.profile.as_str()
            ],
        )
        .map_err(|error| index_error(format!("could not index certificate FTS row: {error}")))?;
    Ok(())
}

/// Upserts one certificate inside an open transaction.
pub fn upsert_certificate_tx(
    connection: &Connection,
    now: time::OffsetDateTime,
    record: &CertificateRecord,
) -> Result<(), ChainkeeperError> {
    if record.issued_at >= record.expires_at {
        return Err(index_error(format!(
            "certificate {} has issued_at not before expires_at",
            record.serial
        )));
    }
    let sans = serde_json::to_string(&record.sans)
        .map_err(|error| index_error(format!("could not encode SANs: {error}")))?;
    let ekus = serde_json::to_string(&record.ekus)
        .map_err(|error| index_error(format!("could not encode EKUs: {error}")))?;
    let usages = serde_json::to_string(&record.key_usages)
        .map_err(|error| index_error(format!("could not encode key usages: {error}")))?;

    connection
        .execute(
            "INSERT INTO certificates (
                serial, subject, issuer, profile, authority, algorithm, status,
                issued_at, expires_at, path, sans_json, email, eku_json,
                key_usage_json, revoked_at, revocation_reason, replaces
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
             ON CONFLICT(serial) DO UPDATE SET
                subject = excluded.subject,
                issuer = excluded.issuer,
                profile = excluded.profile,
                authority = excluded.authority,
                algorithm = excluded.algorithm,
                status = excluded.status,
                issued_at = excluded.issued_at,
                expires_at = excluded.expires_at,
                path = excluded.path,
                sans_json = excluded.sans_json,
                email = excluded.email,
                eku_json = excluded.eku_json,
                key_usage_json = excluded.key_usage_json,
                revoked_at = excluded.revoked_at,
                revocation_reason = excluded.revocation_reason,
                replaces = excluded.replaces",
            rusqlite::params![
                record.serial.as_str(),
                record.subject.cn,
                record.issuer,
                record.profile.as_str(),
                record.authority.as_str(),
                record.algorithm.as_str(),
                record.status(now).as_str(),
                format_timestamp(record.issued_at),
                format_timestamp(record.expires_at),
                record.path.to_string_lossy(),
                sans,
                record.subject.email.as_deref(),
                ekus,
                usages,
                record.revoked_at.map(format_timestamp),
                record
                    .revocation_reason
                    .map(chainkeeper_core::RevocationReason::as_str),
                record
                    .replaces
                    .as_ref()
                    .map(chainkeeper_core::Serial::as_str),
            ],
        )
        .map_err(|error| index_error(format!("could not upsert certificate: {error}")))?;

    let id: i64 = connection
        .query_row(
            "SELECT id FROM certificates WHERE serial = ?1",
            [record.serial.as_str()],
            |row| row.get(0),
        )
        .map_err(|error| index_error(format!("could not resolve certificate id: {error}")))?;
    connection
        .execute("DELETE FROM certificates_fts WHERE rowid = ?1", [id])
        .map_err(|error| index_error(format!("could not clear certificate FTS row: {error}")))?;
    insert_fts(connection, id, record)
}

/// Upserts one revocation inside an open transaction.
pub fn upsert_revocation_tx(
    connection: &Connection,
    record: &RevocationRecord,
) -> Result<(), ChainkeeperError> {
    let certificate_id = connection
        .query_row(
            "SELECT id FROM certificates WHERE serial = ?1",
            [record.serial.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|error| index_error(format!("could not resolve certificate id: {error}")))?
        .ok_or_else(|| ChainkeeperError::not_found("certificate", record.serial.as_str()))?;

    connection
        .execute(
            "INSERT INTO revocations (
                certificate_id, serial, authority, reason, comment, revoked_at, crl_number
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(serial) DO UPDATE SET
                certificate_id = excluded.certificate_id,
                authority = excluded.authority,
                reason = excluded.reason,
                comment = excluded.comment,
                revoked_at = excluded.revoked_at,
                crl_number = excluded.crl_number",
            rusqlite::params![
                certificate_id,
                record.serial.as_str(),
                record.authority.as_str(),
                record.reason.as_str(),
                record.comment.as_deref().unwrap_or_default(),
                format_timestamp(record.revoked_at),
                i64::try_from(record.crl_number)
                    .map_err(|_| index_error("CRL number does not fit in SQLite INTEGER"))?,
            ],
        )
        .map_err(|error| index_error(format!("could not upsert revocation: {error}")))?;

    connection
        .execute(
            "UPDATE certificates SET revoked_at = ?1, revocation_reason = ?2, status = 'revoked'
             WHERE id = ?3",
            rusqlite::params![
                format_timestamp(record.revoked_at),
                record.reason.as_str(),
                certificate_id
            ],
        )
        .map_err(|error| index_error(format!("could not mark certificate revoked: {error}")))?;
    Ok(())
}

/// Upserts one authority inside an open transaction.
pub fn upsert_authority_tx(
    connection: &Connection,
    record: &AuthorityRecord,
) -> Result<(), ChainkeeperError> {
    let not_after = record.created_at + time::Duration::days(i64::from(record.validity_days));
    connection
        .execute(
            "INSERT INTO intermediates (name, kind, parent, algorithm, not_before, not_after, path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(name) DO UPDATE SET
                kind = excluded.kind,
                parent = excluded.parent,
                algorithm = excluded.algorithm,
                not_before = excluded.not_before,
                not_after = excluded.not_after,
                path = excluded.path",
            rusqlite::params![
                record.name.as_str(),
                record.kind.as_str(),
                record
                    .parent
                    .as_ref()
                    .map(chainkeeper_core::AuthorityName::as_str),
                record.algorithm.as_str(),
                format_timestamp(record.created_at),
                format_timestamp(not_after),
                record.cert_path.to_string_lossy(),
            ],
        )
        .map_err(|error| index_error(format!("could not upsert authority: {error}")))?;
    Ok(())
}

/// Upserts one audit event inside an open transaction.
pub fn upsert_audit_event_tx(
    connection: &Connection,
    event: &AuditEvent,
) -> Result<(), ChainkeeperError> {
    let details = serde_json::to_string(&event.details)
        .map_err(|error| index_error(format!("could not encode audit details: {error}")))?;
    connection
        .execute(
            "INSERT INTO audit_events (
                id, seq, timestamp, action, object_type, object_id, summary, path, actor, details_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
                seq = excluded.seq,
                timestamp = excluded.timestamp,
                action = excluded.action,
                object_type = excluded.object_type,
                object_id = excluded.object_id,
                summary = excluded.summary,
                path = excluded.path,
                actor = excluded.actor,
                details_json = excluded.details_json",
            rusqlite::params![
                event.id.as_str(),
                i64::try_from(event.seq)
                    .map_err(|_| index_error("audit sequence does not fit in SQLite INTEGER"))?,
                format_timestamp(event.timestamp),
                event.action.as_str(),
                event.object_type.as_str(),
                event.object_id.as_str(),
                event.summary.as_str(),
                format!("audit/events/{}.json", event.id),
                event.actor.as_str(),
                details,
            ],
        )
        .map_err(|error| index_error(format!("could not upsert audit event: {error}")))?;
    Ok(())
}

/// Upserts one profile inside an open transaction.
pub fn upsert_profile_tx(
    connection: &Connection,
    profile: &Profile,
) -> Result<(), ChainkeeperError> {
    let yaml = canonical::to_yaml(profile)?;
    let digest = canonical::sha256_hex(yaml.as_bytes());
    connection
        .execute(
            "INSERT INTO profiles (name, authority, algorithm, validity_days, yaml_sha256)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
                authority = excluded.authority,
                algorithm = excluded.algorithm,
                validity_days = excluded.validity_days,
                yaml_sha256 = excluded.yaml_sha256",
            rusqlite::params![
                profile.name.as_str(),
                profile.authority.as_str(),
                profile.algorithm.as_str(),
                i64::from(profile.validity_days),
                digest
            ],
        )
        .map_err(|error| index_error(format!("could not upsert profile: {error}")))?;
    Ok(())
}

/// Upserts one CRL inside an open transaction.
pub fn upsert_crl_tx(connection: &Connection, crl: &IndexedCrl) -> Result<(), ChainkeeperError> {
    connection
        .execute(
            "INSERT INTO crls (
                authority, crl_number, this_update, next_update, revoked_count, path, sha256
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(authority) DO UPDATE SET
                crl_number = excluded.crl_number,
                this_update = excluded.this_update,
                next_update = excluded.next_update,
                revoked_count = excluded.revoked_count,
                path = excluded.path,
                sha256 = excluded.sha256",
            rusqlite::params![
                crl.record.authority.as_str(),
                i64::try_from(crl.record.number)
                    .map_err(|_| index_error("CRL number does not fit in SQLite INTEGER"))?,
                format_timestamp(crl.record.this_update),
                format_timestamp(crl.record.next_update),
                i64::try_from(crl.record.revoked_serials.len())
                    .map_err(|_| index_error("CRL size does not fit in SQLite INTEGER"))?,
                crl.record.der_path.to_string_lossy(),
                crl.sha256,
            ],
        )
        .map_err(|error| index_error(format!("could not upsert CRL: {error}")))?;
    Ok(())
}

/// Rebuilds every mutable table from canonical records.
pub fn rebuild(
    index: &SqliteIndex,
    records: &IndexRecords,
) -> Result<IndexReport, ChainkeeperError> {
    let now = index.now();
    let mut connection = index.lock();
    let transaction = connection
        .transaction()
        .map_err(|error| index_error(format!("could not start rebuild: {error}")))?;

    for table in [
        "certificates_fts",
        "revocations",
        "certificates",
        "intermediates",
        "profiles",
        "audit_events",
        "crls",
    ] {
        transaction
            .execute(&format!("DELETE FROM {table}"), [])
            .map_err(|error| index_error(format!("could not clear {table}: {error}")))?;
    }

    for profile in &records.profiles {
        upsert_profile_tx(&transaction, profile)?;
    }
    for certificate in &records.certificates {
        upsert_certificate_tx(&transaction, now, certificate)?;
    }
    for revocation in &records.revocations {
        upsert_revocation_tx(&transaction, revocation)?;
    }
    for authority in &records.authorities {
        upsert_authority_tx(&transaction, authority)?;
    }
    for crl in &records.crls {
        upsert_crl_tx(&transaction, crl)?;
    }
    for event in &records.audit_events {
        upsert_audit_event_tx(&transaction, event)?;
    }

    schema::set_meta(&transaction, "rebuilt_at", &format_timestamp(now))?;
    let stats = stats::totals_from(&transaction)?;
    transaction
        .commit()
        .map_err(|error| index_error(format!("could not commit rebuild: {error}")))?;
    drop(connection);

    Ok(IndexReport {
        generated_at: now,
        schema_version: SCHEMA_VERSION,
        stats,
        moved: Vec::new(),
    })
}

/// Upserts a certificate and commits.
pub fn upsert_certificate(
    index: &SqliteIndex,
    record: &CertificateRecord,
) -> Result<(), ChainkeeperError> {
    let now = index.now();
    let mut connection = index.lock();
    let transaction = connection
        .transaction()
        .map_err(|error| index_error(format!("could not start upsert: {error}")))?;
    upsert_certificate_tx(&transaction, now, record)?;
    transaction
        .commit()
        .map_err(|error| index_error(format!("could not commit upsert: {error}")))?;
    drop(connection);
    Ok(())
}

/// Upserts a revocation and commits.
pub fn upsert_revocation(
    index: &SqliteIndex,
    record: &RevocationRecord,
) -> Result<(), ChainkeeperError> {
    let mut connection = index.lock();
    let transaction = connection
        .transaction()
        .map_err(|error| index_error(format!("could not start upsert: {error}")))?;
    upsert_revocation_tx(&transaction, record)?;
    transaction
        .commit()
        .map_err(|error| index_error(format!("could not commit upsert: {error}")))?;
    drop(connection);
    Ok(())
}

/// Upserts an authority and commits.
pub fn upsert_authority(
    index: &SqliteIndex,
    record: &AuthorityRecord,
) -> Result<(), ChainkeeperError> {
    let mut connection = index.lock();
    let transaction = connection
        .transaction()
        .map_err(|error| index_error(format!("could not start upsert: {error}")))?;
    upsert_authority_tx(&transaction, record)?;
    transaction
        .commit()
        .map_err(|error| index_error(format!("could not commit upsert: {error}")))?;
    drop(connection);
    Ok(())
}

/// Upserts an audit event and commits.
pub fn upsert_audit_event(index: &SqliteIndex, event: &AuditEvent) -> Result<(), ChainkeeperError> {
    let mut connection = index.lock();
    let transaction = connection
        .transaction()
        .map_err(|error| index_error(format!("could not start upsert: {error}")))?;
    upsert_audit_event_tx(&transaction, event)?;
    transaction
        .commit()
        .map_err(|error| index_error(format!("could not commit upsert: {error}")))?;
    drop(connection);
    Ok(())
}
