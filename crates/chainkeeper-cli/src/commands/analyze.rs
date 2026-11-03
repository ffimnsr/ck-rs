//! `ck analyze`.

use chainkeeper_core::{AnalyzeKind, Severity};

use crate::cli::{AnalyzeArgs, AnalyzeCommand};
use crate::commands::Context;
use crate::error::CliError;

pub fn run(context: &Context<'_>, args: &AnalyzeArgs) -> Result<u8, CliError> {
    let kind = match args.command {
        AnalyzeCommand::Expirations => AnalyzeKind::Expirations,
        AnalyzeCommand::Revocations => AnalyzeKind::Revocations,
        AnalyzeCommand::Intermediates => AnalyzeKind::Intermediates,
        AnalyzeCommand::Algorithms => AnalyzeKind::Algorithms,
        AnalyzeCommand::Policy => AnalyzeKind::Policy,
    };
    let report = context.service.analyze(kind)?;
    if context.json {
        let value = context.json_value(&report)?;
        context.ui.json(&value)?;
        return Ok(0);
    }

    context
        .ui
        .info(&format!("analysis: {}", report.kind.kind_to_string()))?;
    for (label, severity) in [
        ("ERROR", Severity::Error),
        ("WARNING", Severity::Warning),
        ("INFO", Severity::Info),
    ] {
        let findings: Vec<Vec<String>> = report
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .map(|finding| {
                vec![
                    finding.code.clone(),
                    finding.message.clone(),
                    finding.object_id.clone().unwrap_or_else(|| "-".to_owned()),
                ]
            })
            .collect();
        context.ui.info(&format!("{label}:"))?;
        if findings.is_empty() {
            context.ui.info("- none")?;
        } else {
            context
                .ui
                .table(&["CODE", "MESSAGE", "OBJECT"], &findings)?;
        }
    }
    Ok(0)
}

trait AnalyzeKindText {
    fn kind_to_string(self) -> &'static str;
}

impl AnalyzeKindText for AnalyzeKind {
    fn kind_to_string(self) -> &'static str {
        match self {
            Self::Expirations => "expirations",
            Self::Revocations => "revocations",
            Self::Intermediates => "intermediates",
            Self::Algorithms => "algorithms",
            Self::Policy => "policy",
            _ => "unknown",
        }
    }
}
