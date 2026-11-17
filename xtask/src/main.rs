//! Developer tooling for the exposure scanner: `cargo xtask <command>`.
//!
//! Nothing here ships. The scanner itself may not read the environment, run
//! a process or open a socket; this crate does all three on purpose, to
//! build the rule pack and to prove the scanner's guarantees from outside.
#![allow(clippy::print_stdout, clippy::print_stderr, reason = "a command-line tool for developers")]

mod bench;
mod fixtures;
mod guard;
mod key;
mod net;
mod pack;
mod symbols;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Errors are messages for a developer's terminal.
type Result<T> = std::result::Result<T, String>;

const USAGE: &str = "\
usage: cargo xtask <command>

rule pack
  pack compile            compile rules/core into rules/dist/core.pack.json
  pack sign --key FILE    sign the compiled pack with a minisign secret key
  pack check              verify the committed pack is fresh, reproducible and signed
  key generate --dir DIR  create a rule-pack signing key outside the repository

fixtures
  fixtures fetch --dir DIR  download the real apps pinned in tests/fixtures/real-apps.txt

guarantees
  guardrails              prove the guardrails bite: banned crates and APIs are refused
  no-network [--strict]   prove a scan opens no socket (--strict: no check may be skipped)
  audit-symbols FILE      list socket functions a binary imports
  netprobe                control program: exits 0 if it can open a socket, 3 if blocked

speed
  bench [--strict] [PATH...]  time a scan at 1, 2, 4 and 8 threads and measure its peak
                          memory; gates: 3x at 8 threads, under 200 MB, one report.
                          Without a PATH: the apps installed on this machine.
                          --strict: no gate may be skipped
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = match args.as_slice() {
        ["pack", "compile"] => pack::compile_to_dist(),
        ["pack", "sign", "--key", key] => pack::sign(Path::new(key)),
        ["pack", "check"] => pack::check(),
        ["key", "generate", "--dir", dir] => key::generate(Path::new(dir)),
        ["fixtures", "fetch", "--dir", dir] => fixtures::fetch(Path::new(dir)),
        ["guardrails"] => guard::run(),
        ["no-network"] => net::run(false),
        ["no-network", "--strict"] => net::run(true),
        ["audit-symbols", file] => symbols::report(Path::new(file)),
        ["netprobe"] => return net::probe(),
        ["bench", rest @ ..] => bench::run_all(rest),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The repository root: the parent of this crate's directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// The cargo that is running this xtask, so nested builds use the pinned
/// toolchain.
fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| String::from("cargo"))
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn read_text(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).map_err(|error| format!("cannot write {}: {error}", path.display()))
}
