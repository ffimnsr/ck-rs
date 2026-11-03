//! `ck diff`.

use chainkeeper_core::DiffRequest;

use crate::cli::DiffArgs;
use crate::commands::Context;
use crate::error::CliError;

pub fn run(context: &Context<'_>, args: &DiffArgs) -> Result<u8, CliError> {
    let report = context.service.diff(&DiffRequest {
        from: args.since.clone(),
        to: None,
    })?;

    if context.json {
        let value = context.json_value(&report)?;
        context.ui.json(&value)?;
        return Ok(0);
    }

    context.ui.info(&format!(
        "from: {}",
        report.from.as_deref().unwrap_or("last publish")
    ))?;
    context
        .ui
        .info(&format!("to: {}", report.to.as_deref().unwrap_or("HEAD")))?;
    for (label, paths) in [
        ("ADDED", &report.added),
        ("MODIFIED", &report.modified),
        ("REMOVED", &report.removed),
    ] {
        context.ui.info(&format!("{label}:"))?;
        if paths.is_empty() {
            context.ui.info("- none")?;
        } else {
            for path in paths {
                context.ui.info(&format!("- {}", path.display()))?;
            }
        }
    }
    Ok(0)
}
