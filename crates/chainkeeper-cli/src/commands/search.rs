//! `ck search`.

use chainkeeper_core::{AuthorityName, CertificateStatus, ProfileName, SearchQuery};
use serde_json::json;

use crate::cli::{SearchArgs, parse_expiry};
use crate::commands::Context;
use crate::error::CliError;
use crate::format::{status_label, time_text};

pub fn run(context: &Context<'_>, args: &SearchArgs) -> Result<u8, CliError> {
    let query = SearchQuery {
        text: args.query.clone(),
        status: args.status.map(CertificateStatus::from),
        profile: args
            .profile
            .as_ref()
            .map(|profile| ProfileName::new(profile.clone()))
            .transpose()
            .map_err(|error| CliError::usage(error.to_string()))?,
        authority: args
            .issuer
            .as_ref()
            .map(|authority| AuthorityName::new(authority.clone()))
            .transpose()
            .map_err(|error| CliError::usage(error.to_string()))?,
        expires_within_days: args
            .expires
            .as_ref()
            .map(|value| parse_expiry(value))
            .transpose()
            .map_err(CliError::usage)?,
        include_expired: args.all,
        limit: Some(args.limit),
        offset: args.offset,
    };

    let items = context.service.search(&query)?;
    let total = context.service.count(&query)?;

    if context.json {
        let value = json!({
            "items": items,
            "total": total,
            "limit": args.limit,
            "offset": args.offset,
        });
        context.ui.json(&value)?;
        return Ok(0);
    }

    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|record| {
            vec![
                record.serial.to_string(),
                record.subject.cn.clone(),
                record.profile.to_string(),
                status_label(record.status(context.now)).to_owned(),
                time_text(record.expires_at),
                record.authority.to_string(),
            ]
        })
        .collect();
    context.ui.table(
        &["SERIAL", "CN", "PROFILE", "STATUS", "EXPIRES", "AUTHORITY"],
        &rows,
    )?;
    context
        .ui
        .info(&format!("{total} matching certificate(s)"))?;
    Ok(0)
}
