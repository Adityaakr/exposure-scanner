//! `exposure`: which companies have a channel to your data, through which
//! apps, with proof.
//!
//! This binary wires the pipeline together and does nothing else:
//!
//! ```text
//! built-in signed rule pack ─▶ verify ─▶ matchers
//! paths ─▶ collect (reads files) ─▶ evidence ─▶ derive ─▶ claims ─▶ render ─▶ report
//! ```
//!
//! It links no network code at all. `cargo deny` bans the crates that could
//! open a socket, and CI audits the built binary's imported symbols.

mod args;
mod commands;

use std::io::Write as _;
use std::process::ExitCode;

use args::Command;

/// Exit status for a command line the program does not understand.
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let command = match args::parse(lexopt::Parser::from_env()) {
        Ok(command) => command,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "exposure: {message}\n\n{}", args::USAGE);
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let outcome = match command {
        Command::Help => commands::print(args::USAGE),
        Command::Version => commands::print(concat!("exposure ", env!("CARGO_PKG_VERSION"), "\n")),
        Command::Scan(scan) => commands::scan(&scan),
        Command::Report(report) => commands::report(&report),
        Command::RulesShow => commands::rules_show(),
        Command::RulesVerify(verify) => commands::rules_verify(&verify),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "exposure: {message}");
            ExitCode::FAILURE
        }
    }
}
