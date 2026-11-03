//! `ck init`.

use chainkeeper_core::{InitRequest, ProfileName, TenantId};

use crate::cli::InitArgs;
use crate::commands::Context;
use crate::error::CliError;

pub fn run(context: &Context<'_>, args: &InitArgs) -> Result<u8, CliError> {
    if args.force {
        return Err(CliError::usage(
            "--force is not supported; initialise an empty directory instead",
        ));
    }

    let tenant_text = match &args.tenant_id {
        Some(value) => value.clone(),
        None if context.prompt.interactive() => context.prompt.text("Tenant ID")?,
        None => {
            return Err(CliError::usage(
                "--tenant-id is required when stdout is not a terminal",
            ));
        }
    };
    let tenant_id =
        TenantId::new(tenant_text).map_err(|error| CliError::usage(error.to_string()))?;
    let display_name = args
        .display_name
        .clone()
        .unwrap_or_else(|| tenant_id.to_string());
    let profile = ProfileName::new(args.default_profile.clone())
        .map_err(|error| CliError::usage(error.to_string()))?;

    let report = context
        .service
        .init(&InitRequest::new(tenant_id, display_name, profile))?;

    if context.json {
        let value = context.json_value(&report)?;
        context.ui.json(&value)?;
        return Ok(0);
    }

    context.ui.info(&format!(
        "initialized tenant {} at {}",
        report.tenant_id,
        report.root.display()
    ))?;
    for path in &report.created_paths {
        context.ui.info(&format!("created {}", path.display()))?;
    }
    match &report.commit {
        Some(commit) => context.ui.info(&format!("commit {commit}"))?,
        None => context.ui.info("commit none (not committed)")?,
    }
    Ok(0)
}
