//! `ck revoke`.

use chainkeeper_core::{CertificateStatus, RevokeRequest, SearchQuery, Serial};

use crate::cli::RevokeArgs;
use crate::commands::Context;
use crate::error::CliError;
use crate::format::time_text;
use crate::selector::certificates;

pub fn run(context: &Context<'_>, args: &RevokeArgs) -> Result<u8, CliError> {
    let serial = match &args.serial {
        Some(serial) => {
            Serial::new(serial.clone()).map_err(|error| CliError::usage(error.to_string()))?
        }
        None if context.prompt.interactive() => {
            let active = context.service.search(&SearchQuery {
                status: Some(CertificateStatus::Active),
                limit: Some(1000),
                ..SearchQuery::default()
            })?;
            let record = certificates().select(
                context.prompt,
                "Certificate to revoke",
                &active,
                |record| {
                    format!(
                        "{} {} {} (expires {})",
                        record.serial,
                        record.subject.cn,
                        record.profile,
                        time_text(record.expires_at)
                    )
                },
            )?;
            record.serial
        }
        None => {
            return Err(CliError::usage(
                "--serial is required when stdout is not a terminal",
            ));
        }
    };

    context.prompt.confirm(&format!(
        "Revoke certificate {serial} for reason {}?",
        chainkeeper_core::RevocationReason::from(args.reason)
    ))?;

    let report = context.service.revoke(&RevokeRequest {
        serial,
        reason: args.reason.into(),
        comment: args.comment.clone(),
    })?;

    if context.json {
        let value = context.json_value(&report)?;
        context.ui.json(&value)?;
        return Ok(0);
    }

    let rows = vec![
        vec!["serial".to_owned(), report.revocation.serial.to_string()],
        vec!["reason".to_owned(), report.revocation.reason.to_string()],
        vec![
            "crl_number".to_owned(),
            report.revocation.crl_number.to_string(),
        ],
        vec![
            "revoked_at".to_owned(),
            time_text(report.revocation.revoked_at),
        ],
        vec![
            "commit".to_owned(),
            report.commit.unwrap_or_else(|| "none".to_owned()),
        ],
    ];
    context.ui.table(&["FIELD", "VALUE"], &rows)?;
    Ok(0)
}
