//! Output abstraction shared by human and JSON modes.

use std::io::Write;
use std::sync::Mutex;

use comfy_table::Table;
use comfy_table::presets::UTF8_FULL;
use serde_json::Value;

use crate::error::CliError;

/// Renderer used by every command handler.
pub trait Ui {
    /// Writes an informational line.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Operation`] when stdout fails.
    fn info(&self, message: &str) -> Result<(), CliError>;

    /// Writes a warning line.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Operation`] when stdout fails.
    fn warn(&self, message: &str) -> Result<(), CliError>;

    /// Writes an error line inside a report.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Operation`] when stdout fails.
    fn error(&self, message: &str) -> Result<(), CliError>;

    /// Writes a table.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Operation`] when stdout fails.
    fn table(&self, headers: &[&str], rows: &[Vec<String>]) -> Result<(), CliError>;

    /// Writes the single JSON document for a command.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Operation`] when serialization or stdout fails.
    fn json(&self, value: &Value) -> Result<(), CliError>;
}

/// Human readable renderer writing to stdout.
pub struct HumanUi {
    writer: Mutex<Box<dyn Write + Send>>,
    color: bool,
}

impl std::fmt::Debug for HumanUi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HumanUi")
            .field("color", &self.color)
            .finish_non_exhaustive()
    }
}

impl HumanUi {
    /// Creates a renderer for stdout.
    #[must_use]
    pub fn new(color: bool) -> Self {
        Self::with_writer(Box::new(std::io::stdout()), color)
    }

    /// Creates a renderer writing to `writer`.
    #[must_use]
    pub fn with_writer(writer: Box<dyn Write + Send>, color: bool) -> Self {
        Self {
            writer: Mutex::new(writer),
            color,
        }
    }

    /// Whether colour is enabled.
    #[must_use]
    pub const fn color(&self) -> bool {
        self.color
    }

    fn write_line(&self, line: &str) -> Result<(), CliError> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io_error("output writer is poisoned"))?;
        writeln!(writer, "{line}").map_err(|error| io_error(&error.to_string()))
    }
}

impl Ui for HumanUi {
    fn info(&self, message: &str) -> Result<(), CliError> {
        self.write_line(message)
    }

    fn warn(&self, message: &str) -> Result<(), CliError> {
        self.write_line(&format!("warning: {message}"))
    }

    fn error(&self, message: &str) -> Result<(), CliError> {
        self.write_line(&format!("error: {message}"))
    }

    fn table(&self, headers: &[&str], rows: &[Vec<String>]) -> Result<(), CliError> {
        let mut table = Table::new();
        table.load_style(UTF8_FULL);
        table.set_header(headers.iter().map(ToString::to_string).collect::<Vec<_>>());
        for row in rows {
            table.add_row(row.clone());
        }
        self.write_line(&table.to_string())
    }

    fn json(&self, value: &Value) -> Result<(), CliError> {
        let rendered = serde_json::to_string_pretty(value)
            .map_err(|error| io_error(&format!("could not encode JSON: {error}")))?;
        self.write_line(&rendered)
    }
}

/// Renderer that only emits the final JSON document.
pub struct JsonUi {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl std::fmt::Debug for JsonUi {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("JsonUi").finish_non_exhaustive()
    }
}

impl JsonUi {
    /// Creates a renderer for stdout.
    #[must_use]
    pub fn new() -> Self {
        Self {
            writer: Mutex::new(Box::new(std::io::stdout())),
        }
    }

    /// Creates a renderer writing to `writer`.
    #[must_use]
    pub fn with_writer(writer: Box<dyn Write + Send>) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

impl Default for JsonUi {
    fn default() -> Self {
        Self::new()
    }
}

impl Ui for JsonUi {
    fn info(&self, _message: &str) -> Result<(), CliError> {
        Ok(())
    }

    fn warn(&self, _message: &str) -> Result<(), CliError> {
        Ok(())
    }

    fn error(&self, _message: &str) -> Result<(), CliError> {
        Ok(())
    }

    fn table(&self, _headers: &[&str], _rows: &[Vec<String>]) -> Result<(), CliError> {
        Ok(())
    }

    fn json(&self, value: &Value) -> Result<(), CliError> {
        let rendered = serde_json::to_string_pretty(value)
            .map_err(|error| io_error(&format!("could not encode JSON: {error}")))?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io_error("output writer is poisoned"))?;
        writeln!(writer, "{rendered}").map_err(|error| io_error(&error.to_string()))
    }
}

/// Decides whether colour may be used.
#[must_use]
pub const fn color_enabled(no_color_flag: bool, env_no_color: bool, is_terminal: bool) -> bool {
    !no_color_flag && !env_no_color && is_terminal
}

fn io_error(message: &str) -> CliError {
    CliError::Operation(chainkeeper_core::ChainkeeperError::io_error(
        message.to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::color_enabled;

    #[test]
    fn color_requires_a_terminal_and_no_opt_out() {
        assert!(color_enabled(false, false, true));
        assert!(!color_enabled(true, false, true));
        assert!(!color_enabled(false, true, true));
        assert!(!color_enabled(false, false, false));
    }
}
