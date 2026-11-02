//! Index statistics.

use std::collections::BTreeMap;

use chainkeeper_core::{ChainkeeperError, IndexStats};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::{SqliteIndex, index_error};

/// Counts grouped by the certificate attributes used by analysis commands.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexBreakdown {
    /// Total rows per table.
    pub totals: IndexStats,
    /// Certificate counts by lifecycle status.
    pub by_status: BTreeMap<String, u64>,
    /// Certificate counts by profile.
    pub by_profile: BTreeMap<String, u64>,
    /// Certificate counts by issuing authority.
    pub by_authority: BTreeMap<String, u64>,
    /// Certificate counts by key algorithm.
    pub by_algorithm: BTreeMap<String, u64>,
}

fn count(connection: &Connection, table: &str) -> Result<u64, ChainkeeperError> {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get::<_, i64>(0)
        })
        .map(i64::cast_unsigned)
        .map_err(|error| index_error(format!("could not count {table}: {error}")))
}

/// Returns row counts per table.
pub fn totals_from(connection: &Connection) -> Result<IndexStats, ChainkeeperError> {
    Ok(IndexStats {
        certificates: count(connection, "certificates")?,
        revocations: count(connection, "revocations")?,
        authorities: count(connection, "intermediates")?,
        audit_events: count(connection, "audit_events")?,
    })
}

/// Returns row counts per table.
pub fn totals(index: &SqliteIndex) -> Result<IndexStats, ChainkeeperError> {
    let connection = index.lock();
    totals_from(&connection)
}

fn group(connection: &Connection, column: &str) -> Result<BTreeMap<String, u64>, ChainkeeperError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {column}, COUNT(*) FROM certificates GROUP BY {column} ORDER BY {column} ASC"
        ))
        .map_err(|error| index_error(format!("could not group by {column}: {error}")))?;
    let mut rows = statement
        .query([])
        .map_err(|error| index_error(format!("could not group by {column}: {error}")))?;
    let mut counts = BTreeMap::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| index_error(format!("could not group by {column}: {error}")))?
    {
        let value: String = row
            .get(0)
            .map_err(|error| index_error(format!("could not read {column}: {error}")))?;
        let total: i64 = row
            .get(1)
            .map_err(|error| index_error(format!("could not read count: {error}")))?;
        counts.insert(value, total.cast_unsigned());
    }
    Ok(counts)
}

/// Returns totals plus per-attribute counts.
pub fn breakdown(index: &SqliteIndex) -> Result<IndexBreakdown, ChainkeeperError> {
    let connection = index.lock();
    Ok(IndexBreakdown {
        totals: totals_from(&connection)?,
        by_status: group(&connection, "status")?,
        by_profile: group(&connection, "profile")?,
        by_authority: group(&connection, "authority")?,
        by_algorithm: group(&connection, "algorithm")?,
    })
}
