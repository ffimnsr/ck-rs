//! Clap command and flag definitions.

use std::path::PathBuf;

use chainkeeper_core::{
    AuditAction, CertificateStatus, CustomExtension, KeyAlgorithm, RevocationReason,
};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;

/// Global command line options.
#[derive(Debug, Parser)]
#[command(name = "ck", about = "Chainkeeper PKI command line interface")]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    /// Path to the repository root. Defaults to the current directory.
    #[arg(long, global = true, value_name = "PATH", default_value = ".")]
    pub repo: PathBuf,

    /// Emit a single JSON document on stdout.
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable coloured output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Suppress confirmation prompts.
    #[arg(long, global = true)]
    pub yes: bool,

    /// Increase diagnostic verbosity.
    #[arg(long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress informational diagnostics.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Builds the clap command with the runtime version string.
    #[must_use]
    pub fn command() -> clap::Command {
        <Self as CommandFactory>::command().version(crate::version_string())
    }

    /// Parses `args` with the runtime version string applied.
    ///
    /// # Errors
    ///
    /// Returns the clap error, including help and version output.
    pub fn parse_from(
        args: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>,
    ) -> Result<Self, clap::Error> {
        let matches = Self::command().try_get_matches_from(args)?;
        Self::from_arg_matches(&matches)
    }
}

/// Top level commands.
#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Initialise a repository.
    Init(InitArgs),
    /// Manage the root authority.
    Root(RootArgs),
    /// Manage intermediate authorities.
    Intermediate(IntermediateArgs),
    /// Manage the dedicated OCSP signer.
    #[command(name = "ocsp-signer")]
    OcspSigner(OcspSignerArgs),
    /// Issue a certificate.
    Issue(IssueArgs),
    /// Revoke a certificate.
    Revoke(RevokeArgs),
    /// Inspect a certificate.
    Inspect(InspectArgs),
    /// Search certificates.
    Search(SearchArgs),
    /// Render the trust hierarchy.
    Tree,
    /// Run repository analysis.
    Analyze(AnalyzeArgs),
    /// List audit events.
    Audit(AuditArgs),
    /// Run health diagnostics.
    Doctor,
    /// Compare repository states.
    Diff(DiffArgs),
    /// Publish repository artifacts.
    Publish(PublishArgs),
    /// Manage the disposable index.
    Index(IndexArgs),
}

/// `ck init`.
#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Tenant identifier.
    #[arg(long, value_name = "ID")]
    pub tenant_id: Option<String>,
    /// Human readable tenant name.
    #[arg(long, value_name = "NAME")]
    pub display_name: Option<String>,
    /// Default profile for the repository.
    #[arg(long, default_value = "tls-server")]
    pub default_profile: String,
    /// Reinitialise an existing directory. Not supported in V1.
    #[arg(long)]
    pub force: bool,
}

/// `ck root ...`.
#[derive(Debug, clap::Args)]
pub struct RootArgs {
    /// Root subcommand.
    #[command(subcommand)]
    pub command: RootCommand,
}

/// Root subcommands.
#[derive(Debug, Subcommand)]
pub enum RootCommand {
    /// Create the root authority.
    Create(RootCreateArgs),
}

/// `ck root create`.
#[derive(Debug, clap::Args)]
pub struct RootCreateArgs {
    /// Root common name.
    #[arg(long, value_name = "CN")]
    pub cn: Option<String>,
    /// Root key algorithm.
    #[arg(long, value_enum, default_value = "ecdsa-p256")]
    pub algorithm: AlgorithmArg,
    /// Root validity in days.
    #[arg(long, default_value_t = 7300)]
    pub validity_days: u32,
    /// Organisation name.
    #[arg(long, value_name = "ORG")]
    pub org: Option<String>,
    /// Two letter country code.
    #[arg(long, value_name = "CC")]
    pub country: Option<String>,
}

/// `ck intermediate ...`.
#[derive(Debug, clap::Args)]
pub struct IntermediateArgs {
    /// Intermediate subcommand.
    #[command(subcommand)]
    pub command: IntermediateCommand,
}

/// Intermediate subcommands.
#[derive(Debug, Subcommand)]
pub enum IntermediateCommand {
    /// Create an intermediate authority.
    Create(IntermediateCreateArgs),
    /// Inspect one intermediate authority.
    Inspect(IntermediateInspectArgs),
}

/// `ck intermediate create`.
#[derive(Debug, clap::Args)]
pub struct IntermediateCreateArgs {
    /// Intermediate name: tls, smime, codesign, or ocsp.
    #[arg(long, value_name = "NAME")]
    pub name: String,
    /// Parent authority.
    #[arg(long, default_value = "root")]
    pub parent: String,
    /// Intermediate key algorithm.
    #[arg(long, value_enum, default_value = "ecdsa-p256")]
    pub algorithm: AlgorithmArg,
    /// Validity in days.
    #[arg(long, default_value_t = 3650)]
    pub validity_days: u32,
    /// Common name. Defaults to the authority name.
    #[arg(long, value_name = "CN")]
    pub cn: Option<String>,
}

/// `ck intermediate inspect`.
#[derive(Debug, clap::Args)]
pub struct IntermediateInspectArgs {
    /// Intermediate name. Prompts when omitted.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,
}

/// `ck ocsp-signer ...`.
#[derive(Debug, clap::Args)]
pub struct OcspSignerArgs {
    /// OCSP signer subcommand.
    #[command(subcommand)]
    pub command: OcspSignerCommand,
}

/// OCSP signer subcommands.
#[derive(Debug, Subcommand)]
pub enum OcspSignerCommand {
    /// Create the dedicated OCSP signer.
    Create(OcspSignerCreateArgs),
}

/// `ck ocsp-signer create`.
#[derive(Debug, clap::Args)]
pub struct OcspSignerCreateArgs {
    /// Signer common name.
    #[arg(long, value_name = "CN")]
    pub cn: Option<String>,
    /// Validity in days.
    #[arg(long, default_value_t = 90)]
    pub validity_days: u32,
}

/// `ck issue`.
#[derive(Debug, clap::Args)]
pub struct IssueArgs {
    /// Certificate profile.
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,
    /// Subject common name.
    #[arg(long, value_name = "CN")]
    pub cn: Option<String>,
    /// DNS subject alternative name. Repeatable.
    #[arg(long, value_name = "NAME")]
    pub dns: Vec<String>,
    /// IP subject alternative name. Repeatable.
    #[arg(long, value_name = "ADDR")]
    pub ip: Vec<String>,
    /// Email subject alternative name. Repeatable.
    #[arg(long, value_name = "ADDR")]
    pub email: Vec<String>,
    /// URI subject alternative name. Repeatable.
    #[arg(long, value_name = "URI")]
    pub uri: Vec<String>,
    /// Organisation name.
    #[arg(long, value_name = "ORG")]
    pub org: Option<String>,
    /// Organisational unit.
    #[arg(long, value_name = "OU")]
    pub ou: Option<String>,
    /// Two letter country code.
    #[arg(long, value_name = "CC")]
    pub country: Option<String>,
    /// State or province.
    #[arg(long, value_name = "STATE")]
    pub state: Option<String>,
    /// Locality.
    #[arg(long, value_name = "LOCALITY")]
    pub locality: Option<String>,
    /// Key algorithm override.
    #[arg(long, value_enum)]
    pub algorithm: Option<AlgorithmArg>,
    /// Validity override in days.
    #[arg(long, value_name = "DAYS")]
    pub validity_days: Option<u32>,
    /// Custom UTF-8 extension as OID:true|false:VALUE. Repeatable.
    #[arg(long, value_name = "OID:CRITICAL:VALUE")]
    pub custom_oid: Vec<String>,
    /// Custom hexadecimal extension as OID:true|false:HEX. Repeatable.
    #[arg(long, value_name = "OID:CRITICAL:HEX")]
    pub custom_oid_hex: Vec<String>,
    /// PEM encoded certificate signing request.
    #[arg(long, value_name = "PATH")]
    pub csr: Option<PathBuf>,
    /// Destination for the generated private key.
    #[arg(long, value_name = "PATH")]
    pub key_out: Option<PathBuf>,
    /// Serial of the certificate this one replaces.
    #[arg(long, value_name = "SERIAL")]
    pub replaces: Option<String>,
}

/// `ck revoke`.
#[derive(Debug, clap::Args)]
pub struct RevokeArgs {
    /// Serial to revoke. Prompts when omitted.
    #[arg(long, value_name = "SERIAL")]
    pub serial: Option<String>,
    /// Revocation reason.
    #[arg(long, value_enum, default_value = "unspecified")]
    pub reason: ReasonArg,
    /// Operator comment.
    #[arg(long, value_name = "TEXT")]
    pub comment: Option<String>,
}

/// `ck inspect`.
#[derive(Debug, clap::Args)]
pub struct InspectArgs {
    /// Certificate serial. Prompts when neither serial nor file is supplied.
    #[arg(long, value_name = "SERIAL", conflicts_with = "file")]
    pub serial: Option<String>,
    /// PEM certificate file.
    #[arg(long, value_name = "PATH")]
    pub file: Option<PathBuf>,
}

/// `ck search`.
#[derive(Debug, clap::Args)]
pub struct SearchArgs {
    /// Free text query.
    #[arg(long, value_name = "TEXT")]
    pub query: Option<String>,
    /// Lifecycle status filter.
    #[arg(long, value_enum)]
    pub status: Option<StatusArg>,
    /// Profile filter.
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,
    /// Issuing authority filter.
    #[arg(long, value_name = "AUTHORITY")]
    pub issuer: Option<String>,
    /// Expiry window such as 30d or 12h.
    #[arg(long, value_name = "WINDOW")]
    pub expires: Option<String>,
    /// Include expired certificates.
    #[arg(long)]
    pub all: bool,
    /// Maximum number of results.
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
    /// Number of matching rows to skip.
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
}

/// `ck analyze`.
#[derive(Debug, clap::Args)]
pub struct AnalyzeArgs {
    /// Analysis to run.
    #[command(subcommand)]
    pub command: AnalyzeCommand,
}

/// Analysis subcommands.
#[derive(Debug, Subcommand)]
pub enum AnalyzeCommand {
    /// Certificates approaching expiry.
    Expirations,
    /// Revocation statistics.
    Revocations,
    /// Intermediate authority health.
    Intermediates,
    /// Algorithm distribution.
    Algorithms,
    /// Policy compliance.
    Policy,
}

/// `ck audit`.
#[derive(Debug, clap::Args)]
pub struct AuditArgs {
    /// Action filter.
    #[arg(long, value_enum)]
    pub action: Option<AuditActionArg>,
    /// Object type filter.
    #[arg(long, value_name = "TYPE")]
    pub object_type: Option<String>,
    /// Object identifier filter.
    #[arg(long, value_name = "ID")]
    pub object_id: Option<String>,
    /// Lower timestamp bound, RFC 3339 or YYYY-MM-DD.
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,
    /// Upper timestamp bound, RFC 3339 or YYYY-MM-DD.
    #[arg(long, value_name = "TIME")]
    pub until: Option<String>,
    /// Maximum number of events.
    #[arg(long, default_value_t = 100)]
    pub limit: usize,
}

/// `ck diff`.
#[derive(Debug, clap::Args)]
pub struct DiffArgs {
    /// Start revision. Defaults to the last published commit.
    #[arg(long, value_name = "REV")]
    pub since: Option<String>,
}

/// `ck publish`.
#[derive(Debug, clap::Args)]
pub struct PublishArgs {
    /// Build into a temporary directory without writing the repository.
    #[arg(long)]
    pub dry_run: bool,
    /// Write artifacts without auditing or committing.
    #[arg(long)]
    pub no_commit: bool,
}

/// `ck index`.
#[derive(Debug, clap::Args)]
pub struct IndexArgs {
    /// Index subcommand.
    #[command(subcommand)]
    pub command: IndexCommand,
}

/// Index subcommands.
#[derive(Debug, Subcommand)]
pub enum IndexCommand {
    /// Rebuild the index.
    Rebuild(IndexRebuildArgs),
}

/// `ck index rebuild`.
#[derive(Debug, clap::Args)]
pub struct IndexRebuildArgs {
    /// Move misplaced canonical records before rebuilding.
    #[arg(long)]
    pub repair: bool,
}

/// Key algorithm accepted by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AlgorithmArg {
    /// RSA 3072.
    #[value(name = "rsa3072")]
    Rsa3072,
    /// ECDSA P-256.
    #[value(name = "ecdsa-p256")]
    EcdsaP256,
    /// Ed25519.
    #[value(name = "ed25519")]
    Ed25519,
}

impl From<AlgorithmArg> for KeyAlgorithm {
    fn from(value: AlgorithmArg) -> Self {
        match value {
            AlgorithmArg::Rsa3072 => Self::Rsa3072,
            AlgorithmArg::EcdsaP256 => Self::EcdsaP256,
            AlgorithmArg::Ed25519 => Self::Ed25519,
        }
    }
}

/// Revocation reason accepted by the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReasonArg {
    /// Reason not specified.
    #[value(name = "unspecified")]
    Unspecified,
    /// Key compromised.
    #[value(name = "keyCompromise")]
    KeyCompromise,
    /// CA key compromised.
    #[value(name = "caCompromise")]
    CaCompromise,
    /// Affiliation changed.
    #[value(name = "affiliationChanged")]
    AffiliationChanged,
    /// Superseded.
    #[value(name = "superseded")]
    Superseded,
    /// Cessation of operation.
    #[value(name = "cessationOfOperation")]
    CessationOfOperation,
    /// Certificate hold.
    #[value(name = "certificateHold")]
    CertificateHold,
    /// Privileges withdrawn.
    #[value(name = "privilegeWithdrawn")]
    PrivilegeWithdrawn,
    /// Attribute authority compromised.
    #[value(name = "aaCompromise")]
    AaCompromise,
}

impl From<ReasonArg> for RevocationReason {
    fn from(value: ReasonArg) -> Self {
        match value {
            ReasonArg::Unspecified => Self::Unspecified,
            ReasonArg::KeyCompromise => Self::KeyCompromise,
            ReasonArg::CaCompromise => Self::CaCompromise,
            ReasonArg::AffiliationChanged => Self::AffiliationChanged,
            ReasonArg::Superseded => Self::Superseded,
            ReasonArg::CessationOfOperation => Self::CessationOfOperation,
            ReasonArg::CertificateHold => Self::CertificateHold,
            ReasonArg::PrivilegeWithdrawn => Self::PrivilegeWithdrawn,
            ReasonArg::AaCompromise => Self::AaCompromise,
        }
    }
}

/// Certificate status filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StatusArg {
    /// Active certificates.
    Active,
    /// Revoked certificates.
    Revoked,
    /// Expired certificates.
    Expired,
}

impl From<StatusArg> for CertificateStatus {
    fn from(value: StatusArg) -> Self {
        match value {
            StatusArg::Active => Self::Active,
            StatusArg::Revoked => Self::Revoked,
            StatusArg::Expired => Self::Expired,
        }
    }
}

/// Audit action filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AuditActionArg {
    /// Repository initialised.
    #[value(name = "REPO_INITIALIZED")]
    RepoInitialized,
    /// Root created.
    #[value(name = "ROOT_CREATED")]
    RootCreated,
    /// Intermediate created.
    #[value(name = "INTERMEDIATE_CREATED")]
    IntermediateCreated,
    /// OCSP signer created.
    #[value(name = "OCSP_SIGNER_CREATED")]
    OcspSignerCreated,
    /// Certificate issued.
    #[value(name = "CERT_ISSUED")]
    CertIssued,
    /// Certificate revoked.
    #[value(name = "CERT_REVOKED")]
    CertRevoked,
    /// Certificate replaced.
    #[value(name = "CERT_REPLACED")]
    CertReplaced,
    /// CRL generated.
    #[value(name = "CRL_GENERATED")]
    CrlGenerated,
    /// Publication completed.
    #[value(name = "PUBLISH_COMPLETED")]
    PublishCompleted,
    /// Policy updated.
    #[value(name = "POLICY_UPDATED")]
    PolicyUpdated,
    /// Profile updated.
    #[value(name = "PROFILE_UPDATED")]
    ProfileUpdated,
    /// Index rebuilt.
    #[value(name = "INDEX_REBUILT")]
    IndexRebuilt,
}

impl From<AuditActionArg> for AuditAction {
    fn from(value: AuditActionArg) -> Self {
        match value {
            AuditActionArg::RepoInitialized => Self::RepoInitialized,
            AuditActionArg::RootCreated => Self::RootCreated,
            AuditActionArg::IntermediateCreated => Self::IntermediateCreated,
            AuditActionArg::OcspSignerCreated => Self::OcspSignerCreated,
            AuditActionArg::CertIssued => Self::CertIssued,
            AuditActionArg::CertRevoked => Self::CertRevoked,
            AuditActionArg::CertReplaced => Self::CertReplaced,
            AuditActionArg::CrlGenerated => Self::CrlGenerated,
            AuditActionArg::PublishCompleted => Self::PublishCompleted,
            AuditActionArg::PolicyUpdated => Self::PolicyUpdated,
            AuditActionArg::ProfileUpdated => Self::ProfileUpdated,
            AuditActionArg::IndexRebuilt => Self::IndexRebuilt,
        }
    }
}

/// Parses `Nd` or `Nh` into whole days, rounding hours up.
///
/// # Errors
///
/// Returns a message suitable for clap when the value is malformed.
pub fn parse_expiry(value: &str) -> Result<u32, String> {
    let (number, suffix) = value.split_at(value.len().saturating_sub(1));
    let amount: u32 = number
        .parse()
        .map_err(|_| format!("expiry window {value:?} must be a number followed by d or h"))?;
    match suffix {
        "d" if amount <= 36_500 => Ok(amount),
        "h" if amount <= 36_500 * 24 => Ok(amount.div_ceil(24)),
        "d" | "h" => Err(format!("expiry window {value:?} is too large")),
        _ => Err(format!("expiry window {value:?} must end with d or h")),
    }
}

/// Parses an RFC 3339 timestamp or a `YYYY-MM-DD` date at midnight UTC.
///
/// # Errors
///
/// Returns a message suitable for clap when the value is malformed.
pub fn parse_timestamp(value: &str) -> Result<OffsetDateTime, String> {
    if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
        return Ok(timestamp);
    }
    let date = time::Date::parse(value, format_description!("[year]-[month]-[day]"))
        .map_err(|_| format!("timestamp {value:?} must be RFC 3339 or YYYY-MM-DD"))?;
    Ok(date.midnight().assume_utc())
}

/// Parses a repeated `--custom-oid` value.
///
/// # Errors
///
/// Returns a message suitable for clap when the OID, criticality, or value is
/// malformed.
pub fn parse_custom_extension(value: &str, hexadecimal: bool) -> Result<CustomExtension, String> {
    let mut parts = value.splitn(3, ':');
    let oid = parts
        .next()
        .filter(|oid| !oid.is_empty())
        .ok_or_else(|| "custom extension must be OID:true|false:VALUE".to_owned())?;
    let critical = parts
        .next()
        .ok_or_else(|| "custom extension must be OID:true|false:VALUE".to_owned())?;
    let critical = match critical.to_ascii_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => return Err("custom extension criticality must be true or false".to_owned()),
    };
    let payload = parts
        .next()
        .ok_or_else(|| "custom extension must be OID:true|false:VALUE".to_owned())?;
    let extension = CustomExtension {
        oid: oid.to_owned(),
        critical,
        value_utf8: (!hexadecimal).then(|| payload.to_owned()),
        value_hex: hexadecimal.then(|| payload.to_owned()),
    };
    extension.validate().map_err(|error| error.to_string())?;
    Ok(extension)
}

#[cfg(test)]
mod tests {
    use super::{
        AlgorithmArg, Cli, ReasonArg, StatusArg, parse_custom_extension, parse_expiry,
        parse_timestamp,
    };
    use chainkeeper_core::{CertificateStatus, KeyAlgorithm, RevocationReason};

    #[test]
    fn every_command_and_subcommand_supports_help() {
        fn walk(path: &mut Vec<String>, command: &clap::Command) {
            let mut args = vec!["ck".to_owned()];
            args.extend(path.iter().cloned());
            args.push("--help".to_owned());
            let error = Cli::command()
                .try_get_matches_from(args)
                .expect_err("help exits with a display error");
            assert_eq!(error.exit_code(), 0, "{path:?}");
            for subcommand in command.get_subcommands() {
                path.push(subcommand.get_name().to_owned());
                walk(path, subcommand);
                path.pop();
            }
        }

        let root_error = Cli::command()
            .try_get_matches_from(["ck", "--help"])
            .expect_err("help exits with a display error");
        assert_eq!(root_error.exit_code(), 0);

        let root = Cli::command();
        for subcommand in root.get_subcommands() {
            let mut path = vec![subcommand.get_name().to_owned()];
            walk(&mut path, subcommand);
        }
    }

    #[test]
    fn version_contains_commit_and_target() {
        let rendered = crate::version_string();
        assert!(rendered.contains(env!("CARGO_PKG_VERSION")));
        assert!(rendered.contains("commit"));
        let error = Cli::command()
            .try_get_matches_from(["ck", "--version"])
            .expect_err("version exits with a display error");
        assert_eq!(error.exit_code(), 0);
    }

    #[test]
    fn unknown_commands_exit_two() {
        let error = Cli::command()
            .try_get_matches_from(["ck", "not-a-command"])
            .expect_err("unknown command");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn algorithm_and_reason_parsers_cover_every_value() {
        assert_eq!(
            KeyAlgorithm::from(AlgorithmArg::Rsa3072),
            KeyAlgorithm::Rsa3072
        );
        assert_eq!(
            RevocationReason::from(ReasonArg::AaCompromise),
            RevocationReason::AaCompromise
        );
        assert_eq!(
            CertificateStatus::from(StatusArg::Expired),
            CertificateStatus::Expired
        );
    }

    #[test]
    fn expiry_windows_accept_days_and_hours() {
        assert_eq!(parse_expiry("30d").expect("days"), 30);
        assert_eq!(parse_expiry("25h").expect("hours"), 2);
        assert!(parse_expiry("30").is_err());
        assert!(parse_expiry("30m").is_err());
        assert!(parse_expiry("-1d").is_err());
    }

    #[test]
    fn timestamps_accept_rfc3339_and_dates() {
        assert_eq!(
            parse_timestamp("2024-05-01T12:00:00Z")
                .expect("timestamp")
                .unix_timestamp(),
            1_714_564_800
        );
        assert_eq!(
            parse_timestamp("2024-05-01")
                .expect("date")
                .unix_timestamp(),
            1_714_521_600
        );
        assert!(parse_timestamp("yesterday").is_err());
    }

    #[test]
    fn custom_extensions_parse_utf8_and_hex() {
        let utf8 = parse_custom_extension("1.2.3.4:true:value", false).expect("utf8");
        assert!(utf8.critical);
        assert_eq!(utf8.value_utf8.as_deref(), Some("value"));

        let hex = parse_custom_extension("1.2.3.4:false:00ff", true).expect("hex");
        assert_eq!(hex.value_hex.as_deref(), Some("00ff"));

        assert!(parse_custom_extension("1.2.3.4:maybe:value", false).is_err());
        assert!(parse_custom_extension("1.2.3.4:true:0", true).is_err());
    }
}
