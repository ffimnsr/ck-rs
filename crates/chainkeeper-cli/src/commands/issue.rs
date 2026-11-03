//! `ck issue`.

use std::path::PathBuf;

use chainkeeper_core::{
    IssueReport, IssueRequest, KeyAlgorithm, Profile, ProfileName, San, Serial, SubjectName,
    builtin_profile, builtin_profile_names,
};

use crate::cli::{IssueArgs, parse_custom_extension};
use crate::commands::Context;
use crate::error::CliError;
use crate::format::{fingerprint, time_text};

pub fn run(context: &Context<'_>, args: &IssueArgs) -> Result<u8, CliError> {
    let profile = resolve_profile(context, args)?;
    let definition = builtin_profile(&profile)
        .ok_or_else(|| CliError::usage(format!("unknown profile {profile}")))?;
    let cn = resolve_cn(context, args)?;
    let sans = resolve_sans(context, args, &profile, &definition)?;
    let request = IssueRequest {
        profile,
        subject: subject(args, cn),
        sans,
        custom_extensions: resolve_extensions(args)?,
        algorithm: args.algorithm.map(KeyAlgorithm::from),
        validity_days: args.validity_days,
        csr_pem: resolve_csr(args)?,
        key_out: args.key_out.clone(),
        replaces: resolve_replaces(args)?,
    };

    if request.csr_pem.is_none() {
        context
            .prompt
            .confirm("Write generated private key material?")?;
    }

    emit(context, &context.service.issue(&request)?)
}

fn resolve_profile(context: &Context<'_>, args: &IssueArgs) -> Result<ProfileName, CliError> {
    match &args.profile {
        Some(profile) => {
            ProfileName::new(profile.clone()).map_err(|error| CliError::usage(error.to_string()))
        }
        None if context.prompt.interactive() => context.prompt.select(
            "Profile",
            builtin_profile_names()
                .into_iter()
                .map(|name| (name.to_string(), name))
                .collect(),
        ),
        None => Err(CliError::usage(
            "--profile is required when stdout is not a terminal",
        )),
    }
}

fn resolve_cn(context: &Context<'_>, args: &IssueArgs) -> Result<String, CliError> {
    match &args.cn {
        Some(cn) => Ok(cn.clone()),
        None if context.prompt.interactive() => context.prompt.text("Common name"),
        None => Err(CliError::usage(
            "--cn is required when stdout is not a terminal",
        )),
    }
}

fn resolve_sans(
    context: &Context<'_>,
    args: &IssueArgs,
    profile: &ProfileName,
    definition: &Profile,
) -> Result<Vec<San>, CliError> {
    let mut sans = Vec::new();
    sans.extend(args.dns.iter().cloned().map(San::Dns));
    sans.extend(args.ip.iter().cloned().map(San::Ip));
    sans.extend(args.email.iter().cloned().map(San::Email));
    sans.extend(args.uri.iter().cloned().map(San::Uri));

    if !definition.san_required || !sans.is_empty() {
        return Ok(sans);
    }
    if !context.prompt.interactive() {
        return Err(CliError::usage(format!(
            "profile {profile} requires at least one subject alternative name"
        )));
    }
    if let Some(value) = context
        .prompt
        .optional_text("DNS subject alternative names (comma separated)")?
    {
        sans.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| San::Dns(value.to_owned())),
        );
    }
    Ok(sans)
}

fn resolve_extensions(
    args: &IssueArgs,
) -> Result<Vec<chainkeeper_core::CustomExtension>, CliError> {
    let mut extensions = Vec::new();
    for value in &args.custom_oid {
        extensions.push(parse_custom_extension(value, false).map_err(CliError::usage)?);
    }
    for value in &args.custom_oid_hex {
        extensions.push(parse_custom_extension(value, true).map_err(CliError::usage)?);
    }
    Ok(extensions)
}

fn resolve_csr(args: &IssueArgs) -> Result<Option<String>, CliError> {
    args.csr.as_ref().map_or(Ok(None), |path| {
        std::fs::read_to_string(path).map(Some).map_err(|error| {
            CliError::Operation(chainkeeper_core::ChainkeeperError::io_error(format!(
                "could not read CSR {}: {error}",
                path.display()
            )))
        })
    })
}

fn resolve_replaces(args: &IssueArgs) -> Result<Option<Serial>, CliError> {
    args.replaces
        .as_ref()
        .map(|serial| Serial::new(serial.clone()))
        .transpose()
        .map_err(|error| CliError::usage(error.to_string()))
}

fn subject(args: &IssueArgs, cn: String) -> SubjectName {
    let mut subject = SubjectName::new(cn);
    subject.organization.clone_from(&args.org);
    subject.organizational_unit.clone_from(&args.ou);
    subject.country.clone_from(&args.country);
    subject.state.clone_from(&args.state);
    subject.locality.clone_from(&args.locality);
    subject
}

fn emit(context: &Context<'_>, report: &IssueReport) -> Result<u8, CliError> {
    if context.json {
        let value = context.json_value(report)?;
        context.ui.json(&value)?;
        return Ok(0);
    }

    let cert_pem = read_certificate(context, &report.cert_path);
    let fingerprint = cert_pem
        .as_deref()
        .and_then(fingerprint)
        .unwrap_or_else(|| "unknown".to_owned());
    let rows = vec![
        vec!["serial".to_owned(), report.certificate.serial.to_string()],
        vec!["subject".to_owned(), report.certificate.subject.cn.clone()],
        vec!["profile".to_owned(), report.certificate.profile.to_string()],
        vec![
            "expires_at".to_owned(),
            time_text(report.certificate.expires_at),
        ],
        vec![
            "cert_path".to_owned(),
            report.cert_path.display().to_string(),
        ],
        vec![
            "key_path".to_owned(),
            report
                .key_path
                .as_ref()
                .map_or_else(|| "none".to_owned(), |path| path.display().to_string()),
        ],
        vec!["fingerprint".to_owned(), fingerprint],
    ];
    context.ui.table(&["FIELD", "VALUE"], &rows)?;
    Ok(0)
}

fn read_certificate(context: &Context<'_>, path: &std::path::Path) -> Option<String> {
    let absolute: PathBuf = if path.is_absolute() {
        path.to_path_buf()
    } else {
        context.repo.join(path)
    };
    std::fs::read_to_string(absolute).ok()
}
