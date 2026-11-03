//! `ck` command line entry point.

use std::process::ExitCode;

use chainkeeper_cli::Cli;
use chainkeeper_core::init_tracing_with_default;

fn main() -> ExitCode {
    let cli = match Cli::parse_from(std::env::args_os()) {
        Ok(cli) => cli,
        Err(error) => {
            let code = u8::try_from(error.exit_code()).unwrap_or(2);
            let _ = error.print();
            return ExitCode::from(code);
        }
    };

    let filter = if cli.quiet {
        "error"
    } else if cli.verbose > 0 {
        "debug"
    } else {
        "info"
    };
    if let Err(error) = init_tracing_with_default(filter) {
        eprintln!("{error}");
        return ExitCode::from(1);
    }

    ExitCode::from(chainkeeper_cli::run(&cli))
}
