//! Interactive prompt isolation.
//!
//! Prompts are only constructed when stdin and stdout are terminals. Handlers
//! call these helpers through [`Prompter`] so tests can substitute a
//! non-interactive instance and prove no prompt ever blocks.

use std::io::IsTerminal as _;

use crate::error::CliError;

/// Prompt behaviour for one command invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prompter {
    interactive: bool,
    assume_yes: bool,
}

impl Prompter {
    /// Builds a prompter.
    #[must_use]
    pub const fn new(interactive: bool, assume_yes: bool) -> Self {
        Self {
            interactive,
            assume_yes,
        }
    }

    /// Creates a prompter for the current process.
    #[must_use]
    pub fn detect(assume_yes: bool) -> Self {
        Self::new(
            std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
            assume_yes,
        )
    }

    /// Whether prompts may be shown.
    #[must_use]
    pub const fn interactive(self) -> bool {
        self.interactive
    }

    /// Whether `--yes` was supplied.
    #[must_use]
    pub const fn assume_yes(self) -> bool {
        self.assume_yes
    }

    /// Asks for a required text value.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] when not interactive or the answer is empty.
    pub fn text(self, message: &str) -> Result<String, CliError> {
        if !self.interactive {
            return Err(CliError::usage(format!(
                "{message} is required; pass it explicitly when stdout is not a terminal"
            )));
        }
        let value = inquire::Text::new(message).prompt().map_err(prompt_error)?;
        if value.trim().is_empty() {
            return Err(CliError::usage(format!("{message} must not be empty")));
        }
        Ok(value)
    }

    /// Asks for an optional text value.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] when not interactive.
    pub fn optional_text(self, message: &str) -> Result<Option<String>, CliError> {
        if !self.interactive {
            return Ok(None);
        }
        inquire::Text::new(message)
            .prompt_skippable()
            .map_err(prompt_error)
    }

    /// Asks for confirmation.
    ///
    /// `--yes` and non-interactive invocations never prompt and return `true`;
    /// validation has already happened before this call.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Cancelled`] when the operator declines or interrupts.
    pub fn confirm(self, message: &str) -> Result<bool, CliError> {
        if self.assume_yes || !self.interactive {
            return Ok(true);
        }
        match inquire::Confirm::new(message).with_default(false).prompt() {
            Ok(true) => Ok(true),
            Ok(false) => Err(CliError::Cancelled),
            Err(error) => Err(prompt_error(error)),
        }
    }

    /// Selects one labelled value.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] when not interactive or the list is empty.
    pub fn select<T>(self, message: &str, mut items: Vec<(String, T)>) -> Result<T, CliError> {
        if !self.interactive {
            return Err(CliError::usage(format!(
                "interactive selection for {message} is unavailable; pass an explicit value"
            )));
        }
        if items.is_empty() {
            return Err(CliError::usage(format!(
                "no candidates are available for {message}"
            )));
        }
        let labels: Vec<String> = items.iter().map(|(label, _)| label.clone()).collect();
        let choice = inquire::Select::new(message, labels)
            .with_page_size(15)
            .prompt()
            .map_err(prompt_error)?;
        let index = items
            .iter()
            .position(|(label, _)| label == &choice)
            .ok_or_else(|| CliError::usage("selected item disappeared"))?;
        Ok(items.remove(index).1)
    }
}

fn prompt_error(error: inquire::InquireError) -> CliError {
    match error {
        inquire::InquireError::OperationCanceled | inquire::InquireError::OperationInterrupted => {
            CliError::Cancelled
        }
        other => CliError::usage(other.to_string()),
    }
}
