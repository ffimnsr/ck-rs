//! `ck inspect`.

use std::path::Path;

use chainkeeper_core::{CertificateStatus, ChainkeeperError, SearchQuery, Serial};
use chainkeeper_store::parse_certificate_pem;

use crate::cli::InspectArgs;
use crate::commands::Context;
use crate::error::CliError;
use crate::format::{enum_text, fingerprint, status_label, time_text};
use crate::selector::certificates;

pub fn run(context: &Context<'_>, args: &InspectArgs) -> Result<u8, CliError> {
    let serial = match (&args.serial, &args.file) {
        (Some(serial), _) => {
            Serial::new(serial.clone()).map_err(|error| CliError::usage(error.to_string()))?
        }
        (None, Some(path)) => serial_from_file(path)?,
        (None, None) if context.prompt.interactive() => {
            let items = context.service.search(&SearchQuery {
                limit: Some(100),
                ..SearchQuery::default()
            })?;
            certificates()
                .select(context.prompt, "Certificate", &items, |record| {
                    format!("{} {} {}", record.serial, record.subject.cn, record.profile)
                })?
                .serial
        }
        (None, None) => {
            return Err(CliError::usage(
                "--serial or --file is required when stdout is not a terminal",
            ));
        }
    };

    let report = context.service.inspect(&serial)?;

    if context.json {
        let value = context.json_value(&report)?;
        context.ui.json(&value)?;
        return Ok(0);
    }

    let record = &report.certificate;
    let mut rows = vec![
        vec!["serial".to_owned(), record.serial.to_string()],
        vec!["subject".to_owned(), record.subject.cn.clone()],
        vec!["issuer".to_owned(), record.issuer.clone()],
        vec!["profile".to_owned(), record.profile.to_string()],
        vec!["authority".to_owned(), record.authority.to_string()],
        vec!["algorithm".to_owned(), record.algorithm.as_str().to_owned()],
        vec!["status".to_owned(), status_label(report.status).to_owned()],
        vec!["issued_at".to_owned(), time_text(record.issued_at)],
        vec!["expires_at".to_owned(), time_text(record.expires_at)],
        vec![
            "revoked_at".to_owned(),
            record
                .revoked_at
                .map_or_else(|| "none".to_owned(), time_text),
        ],
        vec![
            "revocation_reason".to_owned(),
            record
                .revocation_reason
                .map_or_else(|| "none".to_owned(), |reason| reason.to_string()),
        ],
        vec![
            "sans".to_owned(),
            record
                .sans
                .iter()
                .map(|san| format!("{}:{}", enum_text(&san.kind()), san.value()))
                .collect::<Vec<_>>()
                .join(", "),
        ],
        vec![
            "ekus".to_owned(),
            record
                .ekus
                .iter()
                .map(enum_text)
                .collect::<Vec<_>>()
                .join(", "),
        ],
        vec![
            "key_usages".to_owned(),
            record
                .key_usages
                .iter()
                .map(enum_text)
                .collect::<Vec<_>>()
                .join(", "),
        ],
        vec!["path".to_owned(), record.path.display().to_string()],
    ];
    rows.push(vec![
        "fingerprint".to_owned(),
        report
            .cert_pem
            .as_deref()
            .and_then(fingerprint)
            .unwrap_or_else(|| "unknown".to_owned()),
    ]);
    context.ui.table(&["FIELD", "VALUE"], &rows)?;
    if report.status == CertificateStatus::Active {
        // The status is already rendered above; this keeps the branch explicit.
    }
    Ok(0)
}

fn serial_from_file(path: &Path) -> Result<Serial, CliError> {
    let pem = std::fs::read_to_string(path).map_err(|error| {
        CliError::Operation(ChainkeeperError::io_error(format!(
            "could not read certificate {}: {error}",
            path.display()
        )))
    })?;
    let parsed = parse_certificate_pem(&pem, path)?;
    Ok(parsed.serial)
}
