//! `ck publish`.

use chainkeeper_core::PublishOptions;
use chainkeeper_publish::{changed_paths, read_manifest};

use crate::cli::PublishArgs;
use crate::commands::Context;
use crate::error::CliError;

pub fn run(context: &Context<'_>, args: &PublishArgs) -> Result<u8, CliError> {
    let output_dir = context.repo.join("publish");
    let previous = if args.dry_run {
        None
    } else {
        read_manifest(&output_dir)?
    };

    let manifest = context.service.publish(&PublishOptions {
        output_dir,
        clean: false,
        dry_run: args.dry_run,
        no_commit: args.no_commit,
    })?;

    if context.json {
        let value = context.json_value(&manifest)?;
        context.ui.json(&value)?;
        return Ok(0);
    }

    context
        .ui
        .info(&format!("artifacts: {}", manifest.artifacts.len()))?;
    if let Some(previous) = &previous {
        let changed = changed_paths(previous, &manifest);
        context.ui.info(&format!(
            "changed: {} added, {} modified, {} removed",
            changed.added.len(),
            changed.modified.len(),
            changed.removed.len()
        ))?;
        for path in changed
            .added
            .iter()
            .chain(changed.modified.iter())
            .chain(changed.removed.iter())
        {
            context.ui.info(&format!("- {}", path.display()))?;
        }
    } else {
        context.ui.info("changed: initial publish")?;
    }
    context.ui.info(&format!(
        "commit: {}",
        manifest
            .source_commit
            .as_deref()
            .unwrap_or("none (not committed)")
    ))?;
    if args.dry_run {
        context.ui.info("dry run: destination not written")?;
    } else if args.no_commit {
        context
            .ui
            .info("no-commit: artifacts written without audit or commit")?;
    }
    Ok(0)
}
