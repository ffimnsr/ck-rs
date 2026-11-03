//! `ck audit`.

use chainkeeper_core::{AuditAction, AuditQuery};

use crate::cli::{AuditArgs, parse_timestamp};
use crate::commands::Context;
use crate::error::CliError;
use crate::format::time_text;

pub fn run(context: &Context<'_>, args: &AuditArgs) -> Result<u8, CliError> {
    let query = AuditQuery {
        action: args.action.map(AuditAction::from),
        object_type: args.object_type.clone(),
        object_id: args.object_id.clone(),
        since: args
            .since
            .as_ref()
            .map(|value| parse_timestamp(value))
            .transpose()
            .map_err(CliError::usage)?,
        until: args
            .until
            .as_ref()
            .map(|value| parse_timestamp(value))
            .transpose()
            .map_err(CliError::usage)?,
        limit: Some(args.limit),
    };
    let events = context.service.audit(&query)?;

    if context.json {
        let value = context.json_value(&events)?;
        context.ui.json(&value)?;
        return Ok(0);
    }

    let rows: Vec<Vec<String>> = events
        .iter()
        .map(|event| {
            vec![
                event.seq.to_string(),
                time_text(event.timestamp),
                event.action.as_str().to_owned(),
                format!("{}/{}", event.object_type, event.object_id),
                event.summary.clone(),
            ]
        })
        .collect();
    context
        .ui
        .table(&["SEQ", "TIMESTAMP", "ACTION", "OBJECT", "SUMMARY"], &rows)?;
    context.ui.info(&format!("{} event(s)", events.len()))?;
    Ok(0)
}
