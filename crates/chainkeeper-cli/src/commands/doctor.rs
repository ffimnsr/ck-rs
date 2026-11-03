//! `ck doctor`.

use chainkeeper_core::Severity;

use crate::commands::Context;
use crate::error::CliError;

pub fn run(context: &Context<'_>) -> Result<u8, CliError> {
    let report = context.service.doctor()?;
    if context.json {
        let value = context.json_value(&report)?;
        context.ui.json(&value)?;
    } else {
        let errors: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::Error)
            .collect();
        let warnings: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::Warning)
            .collect();
        let healthy: Vec<_> = report
            .findings
            .iter()
            .filter(|finding| finding.severity == Severity::Info)
            .collect();

        context.ui.info("ERRORS:")?;
        if errors.is_empty() {
            context.ui.info("- none")?;
        } else {
            for finding in &errors {
                context
                    .ui
                    .error(&format!("{}: {}", finding.code, finding.message))?;
            }
        }
        context.ui.info("WARNINGS:")?;
        if warnings.is_empty() {
            context.ui.info("- none")?;
        } else {
            for finding in &warnings {
                context
                    .ui
                    .warn(&format!("{}: {}", finding.code, finding.message))?;
            }
        }
        context.ui.info("OK:")?;
        if healthy.is_empty() && errors.is_empty() && warnings.is_empty() {
            context.ui.info("- all checks passed")?;
        } else {
            for finding in &healthy {
                context
                    .ui
                    .info(&format!("{}: {}", finding.code, finding.message))?;
            }
        }
    }

    if report
        .findings
        .iter()
        .any(|finding| finding.severity == Severity::Error)
    {
        return Ok(3);
    }
    Ok(0)
}
