//! Search and audit queries.

use chainkeeper_core::time_util::format_timestamp;
use chainkeeper_core::{
    AuditEvent, AuditQuery, CertificateRecord, CertificateStatus, ChainkeeperError, SearchQuery,
};
use rusqlite::params_from_iter;
use rusqlite::types::Value;

use super::{
    CERTIFICATE_COLUMNS, SqliteIndex, audit_event_from_row, certificate_from_row, index_error,
};

/// Default number of search results.
pub const DEFAULT_SEARCH_LIMIT: usize = 50;

/// Maximum number of search results.
pub const MAX_SEARCH_LIMIT: usize = 1000;

/// Maximum accepted search offset.
pub const MAX_SEARCH_OFFSET: usize = 1_000_000;

/// Converts free text into an FTS5 prefix expression.
fn fts_expression(text: &str) -> Option<String> {
    let tokens: Vec<String> = text
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .map(|token| format!("\"{}\"*", token.replace('"', "\"\"")))
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" AND "))
    }
}

fn clamped_limit(limit: Option<usize>) -> usize {
    limit.map_or(DEFAULT_SEARCH_LIMIT, |value| value.min(MAX_SEARCH_LIMIT))
}

fn filters(query: &SearchQuery, now: time::OffsetDateTime) -> (String, Vec<Value>) {
    let mut sql = String::new();
    let mut values: Vec<Value> = Vec::new();

    if let Some(text) = query.text.as_deref().and_then(fts_expression) {
        sql.push_str(
            " AND c.id IN (SELECT rowid FROM certificates_fts WHERE certificates_fts MATCH ?)",
        );
        values.push(Value::Text(text));
    }
    if let Some(status) = query.status {
        sql.push_str(" AND c.status = ?");
        values.push(Value::Text(status.as_str().to_owned()));
    }
    if let Some(profile) = &query.profile {
        sql.push_str(" AND c.profile = ?");
        values.push(Value::Text(profile.as_str().to_owned()));
    }
    if let Some(authority) = &query.authority {
        sql.push_str(" AND c.authority = ?");
        values.push(Value::Text(authority.as_str().to_owned()));
    }
    if let Some(days) = query.expires_within_days {
        let cutoff = now + time::Duration::days(i64::from(days));
        sql.push_str(" AND c.expires_at <= ?");
        values.push(Value::Text(format_timestamp(cutoff)));
        if !query.include_expired && query.status != Some(CertificateStatus::Expired) {
            sql.push_str(" AND c.expires_at > ?");
            values.push(Value::Text(format_timestamp(now)));
        }
    }
    (sql, values)
}

/// Executes a search query.
pub fn search(
    index: &SqliteIndex,
    query: &SearchQuery,
) -> Result<Vec<CertificateRecord>, ChainkeeperError> {
    if query.offset > MAX_SEARCH_OFFSET {
        return Err(ChainkeeperError::validation(format!(
            "search offset {} exceeds the maximum of {MAX_SEARCH_OFFSET}",
            query.offset
        )));
    }

    let (filter_sql, mut values) = filters(query, index.now());
    let mut sql =
        format!("SELECT {CERTIFICATE_COLUMNS} FROM certificates c WHERE 1 = 1{filter_sql}");

    sql.push_str(" ORDER BY c.expires_at ASC, c.serial ASC LIMIT ? OFFSET ?");
    values.push(Value::Integer(
        i64::try_from(clamped_limit(query.limit))
            .map_err(|_| index_error("search limit does not fit in SQLite INTEGER"))?,
    ));
    values.push(Value::Integer(i64::try_from(query.offset).map_err(
        |_| index_error("search offset does not fit in SQLite INTEGER"),
    )?));

    let connection = index.lock();
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| index_error(format!("could not prepare search: {error}")))?;
    let mut rows = statement
        .query(params_from_iter(values.iter()))
        .map_err(|error| index_error(format!("could not execute search: {error}")))?;
    let mut records = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| index_error(format!("could not execute search: {error}")))?
    {
        records.push(certificate_from_row(row)?);
    }
    drop(rows);
    drop(statement);
    drop(connection);
    Ok(records)
}

/// Counts rows matching a search query.
pub fn count(index: &SqliteIndex, query: &SearchQuery) -> Result<u64, ChainkeeperError> {
    let (filter_sql, values) = filters(query, index.now());
    let sql = format!("SELECT COUNT(*) FROM certificates c WHERE 1 = 1{filter_sql}");
    let connection = index.lock();
    let total = connection
        .query_row(&sql, params_from_iter(values.iter()), |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|error| index_error(format!("could not count search results: {error}")))?;
    drop(connection);
    Ok(total.cast_unsigned())
}

/// Executes an audit query.
pub fn list_audit(
    index: &SqliteIndex,
    query: &AuditQuery,
) -> Result<Vec<AuditEvent>, ChainkeeperError> {
    let mut sql = String::from(
        "SELECT id, seq, timestamp, action, object_type, object_id, summary, actor, details_json
         FROM audit_events WHERE 1 = 1",
    );
    let mut values: Vec<Value> = Vec::new();

    if let Some(action) = query.action {
        sql.push_str(" AND action = ?");
        values.push(Value::Text(action.as_str().to_owned()));
    }
    if let Some(object_type) = &query.object_type {
        sql.push_str(" AND object_type = ?");
        values.push(Value::Text(object_type.clone()));
    }
    if let Some(object_id) = &query.object_id {
        sql.push_str(" AND object_id = ?");
        values.push(Value::Text(object_id.clone()));
    }
    if let Some(since) = query.since {
        sql.push_str(" AND timestamp >= ?");
        values.push(Value::Text(format_timestamp(since)));
    }
    if let Some(until) = query.until {
        sql.push_str(" AND timestamp <= ?");
        values.push(Value::Text(format_timestamp(until)));
    }

    sql.push_str(" ORDER BY seq ASC, id ASC LIMIT ?");
    values.push(Value::Integer(
        i64::try_from(clamped_limit(query.limit))
            .map_err(|_| index_error("audit limit does not fit in SQLite INTEGER"))?,
    ));

    let connection = index.lock();
    let mut statement = connection
        .prepare(&sql)
        .map_err(|error| index_error(format!("could not prepare audit query: {error}")))?;
    let mut rows = statement
        .query(params_from_iter(values.iter()))
        .map_err(|error| index_error(format!("could not execute audit query: {error}")))?;
    let mut events = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| index_error(format!("could not execute audit query: {error}")))?
    {
        events.push(audit_event_from_row(row)?);
    }
    drop(rows);
    drop(statement);
    drop(connection);
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::fts_expression;

    #[test]
    fn fts_expression_quotes_and_prefixes_tokens() {
        assert_eq!(
            fts_expression("leaf example"),
            Some("\"leaf\"* AND \"example\"*".to_owned())
        );
        assert_eq!(fts_expression("   "), None);
        assert_eq!(fts_expression("a\"b"), Some("\"a\"\"b\"*".to_owned()));
    }
}
