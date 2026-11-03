//! Command dispatch and process-level error handling.

use std::io::IsTerminal as _;

use chainkeeper_core::ChainkeeperService;
use time::OffsetDateTime;

use crate::cli::{Cli, Command};
use crate::commands::{self, Context};
use crate::error::CliError;
use crate::prompt::Prompter;
use crate::service::{self, OpenMode};
use crate::ui::{HumanUi, JsonUi, Ui, color_enabled};

/// Runs a parsed command, printing failures to stderr.
#[must_use]
pub fn run(cli: &Cli) -> u8 {
    match execute(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{}", error.message());
            error.exit_code()
        }
    }
}

fn execute(cli: &Cli) -> Result<u8, CliError> {
    let mode = if matches!(&cli.command, Command::Init(_)) {
        OpenMode::Init
    } else {
        OpenMode::Normal
    };
    let service = service::open(&cli.repo, mode)?;
    let color = color_enabled(
        cli.no_color,
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    );
    let ui: Box<dyn Ui> = if cli.json {
        Box::new(JsonUi::new())
    } else {
        Box::new(HumanUi::new(color))
    };
    let code = dispatch(
        cli,
        service.as_ref(),
        ui.as_ref(),
        Prompter::detect(cli.yes),
        OffsetDateTime::now_utc(),
    )?;
    if mode == OpenMode::Init && code == 0 {
        service::finalize_init(&service)?;
    }
    Ok(code)
}

/// Runs a parsed command against an injected service.
///
/// # Errors
///
/// Returns [`CliError`] when the command is rejected or the operation fails.
pub fn dispatch(
    cli: &Cli,
    service: &dyn ChainkeeperService,
    ui: &dyn Ui,
    prompt: Prompter,
    now: OffsetDateTime,
) -> Result<u8, CliError> {
    let context = Context {
        service,
        ui,
        prompt,
        repo: &cli.repo,
        now,
        json: cli.json,
    };

    match &cli.command {
        Command::Init(args) => commands::init(&context, args),
        Command::Root(args) => match &args.command {
            crate::cli::RootCommand::Create(create) => commands::root(&context, create),
        },
        Command::Intermediate(args) => match &args.command {
            crate::cli::IntermediateCommand::Create(create) => {
                commands::intermediate(&context, create)
            }
            crate::cli::IntermediateCommand::Inspect(inspect) => {
                commands::intermediate_inspect(&context, inspect)
            }
        },
        Command::OcspSigner(args) => match &args.command {
            crate::cli::OcspSignerCommand::Create(create) => {
                commands::ocsp_signer(&context, create)
            }
        },
        Command::Issue(args) => commands::issue(&context, args),
        Command::Revoke(args) => commands::revoke(&context, args),
        Command::Inspect(args) => commands::inspect(&context, args),
        Command::Search(args) => commands::search(&context, args),
        Command::Tree => commands::tree(&context),
        Command::Analyze(args) => commands::analyze(&context, args),
        Command::Audit(args) => commands::audit(&context, args),
        Command::Doctor => commands::doctor(&context),
        Command::Diff(args) => commands::diff(&context, args),
        Command::Publish(args) => commands::publish(&context, args),
        Command::Index(args) => commands::index(&context, args),
    }
}
