//! Index connection configuration and schema migrations.

use std::sync::LazyLock;
use std::time::Duration;

use chainkeeper_core::ChainkeeperError;
use rusqlite::{Connection, OptionalExtension as _};
use rusqlite_migration::{M, Migrations, SchemaVersion};

/// Schema version written by this crate.
pub const SCHEMA_VERSION: u32 = 1;

const INITIAL_SCHEMA: &str = include_str!("../../migrations/0001_initial.sql");

static MIGRATIONS: LazyLock<Migrations<'static>> =
    LazyLock::new(|| Migrations::new(vec![M::up(INITIAL_SCHEMA)]));

fn index_error(context: impl std::fmt::Display) -> ChainkeeperError {
    ChainkeeperError::index(context.to_string())
}

/// Applies connection scoped pragmas.
pub fn configure(connection: &Connection) -> Result<(), ChainkeeperError> {
    connection
        .pragma_update(None, "journal_mode", "WAL")
        .map_err(|error| index_error(format!("could not enable WAL: {error}")))?;
    connection
        .pragma_update(None, "synchronous", "NORMAL")
        .map_err(|error| index_error(format!("could not set synchronous=NORMAL: {error}")))?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| index_error(format!("could not enable foreign keys: {error}")))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|error| index_error(format!("could not set busy timeout: {error}")))?;
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, ChainkeeperError> {
    let found = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(true),
        )
        .optional()
        .map_err(|error| index_error(format!("could not inspect sqlite_master: {error}")))?;
    Ok(found.unwrap_or(false))
}

fn meta_value(connection: &Connection, key: &str) -> Result<Option<String>, ChainkeeperError> {
    connection
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|error| index_error(format!("could not read meta.{key}: {error}")))
}

/// Migrates the connection to [`SCHEMA_VERSION`].
pub fn migrate(connection: &mut Connection) -> Result<(), ChainkeeperError> {
    if table_exists(connection, "meta")?
        && let Some(raw) = meta_value(connection, "schema_version")?
    {
        let version = raw.parse::<u32>().map_err(|error| {
            index_error(format!(
                "meta.schema_version {raw:?} is not a number: {error}"
            ))
        })?;
        if version > SCHEMA_VERSION {
            return Err(index_error(format!(
                "index schema version {version} is newer than supported version {SCHEMA_VERSION}"
            )));
        }
    }

    match MIGRATIONS
        .current_version(connection)
        .map_err(|error| index_error(format!("could not read index version: {error}")))?
    {
        SchemaVersion::Outside(version) if usize::from(version) > SCHEMA_VERSION as usize => {
            return Err(index_error(format!(
                "index schema version {version} is newer than supported version {SCHEMA_VERSION}"
            )));
        }
        SchemaVersion::NoneSet | SchemaVersion::Inside(_) | SchemaVersion::Outside(_) => {}
    }

    MIGRATIONS
        .to_latest(connection)
        .map_err(|error| index_error(format!("could not migrate index: {error}")))?;
    connection
        .execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [SCHEMA_VERSION.to_string()],
        )
        .map_err(|error| index_error(format!("could not record schema version: {error}")))?;
    Ok(())
}

/// Reads the schema version stored in `meta`.
pub fn read_version(connection: &Connection) -> Result<u32, ChainkeeperError> {
    let Some(raw) = meta_value(connection, "schema_version")? else {
        return Ok(SCHEMA_VERSION);
    };
    raw.parse::<u32>()
        .map_err(|error| index_error(format!("meta.schema_version {raw:?} is invalid: {error}")))
}

/// Writes a meta value.
pub fn set_meta(connection: &Connection, key: &str, value: &str) -> Result<(), ChainkeeperError> {
    connection
        .execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [key, value],
        )
        .map_err(|error| index_error(format!("could not write meta.{key}: {error}")))?;
    Ok(())
}
