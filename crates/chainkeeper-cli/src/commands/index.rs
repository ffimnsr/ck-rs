//! `ck index`.

use crate::cli::{IndexArgs, IndexCommand};
use crate::commands::Context;
use crate::error::CliError;
use crate::format::time_text;

pub fn run(context: &Context<'_>, args: &IndexArgs) -> Result<u8, CliError> {
    let report = match &args.command {
        IndexCommand::Rebuild(rebuild) if rebuild.repair => context.service.repair_index()?,
        IndexCommand::Rebuild(_) => context.service.rebuild_index()?,
    };

    if context.json {
        let value = context.json_value(&report)?;
        context.ui.json(&value)?;
        return Ok(0);
    }

    let rows = vec![
        vec!["generated_at".to_owned(), time_text(report.generated_at)],
        vec![
            "schema_version".to_owned(),
            report.schema_version.to_string(),
        ],
        vec![
            "certificates".to_owned(),
            report.stats.certificates.to_string(),
        ],
        vec![
            "revocations".to_owned(),
            report.stats.revocations.to_string(),
        ],
        vec![
            "authorities".to_owned(),
            report.stats.authorities.to_string(),
        ],
        vec![
            "audit_events".to_owned(),
            report.stats.audit_events.to_string(),
        ],
        vec![
            "moved".to_owned(),
            report
                .moved
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        ],
    ];
    context.ui.table(&["FIELD", "VALUE"], &rows)?;
    Ok(0)
}
