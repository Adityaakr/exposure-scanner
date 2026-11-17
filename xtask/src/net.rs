//! The no-network test: proof from outside that a scan opens no socket.
//!
//! Design report, section 7 property 4, four independent checks:
//!
//! 1. `cargo deny` bans the crates that could open one (run separately).
//! 2. The built binary imports no socket function ([`crate::symbols`]).
//! 3. Linux: the scan runs inside a network namespace with no interfaces.
//! 4. Linux: `strace` sees no network system call. macOS: the scan runs under
//!    a sandbox profile that denies all network access.
//!
//! Every dynamic check is paired with a **control**: a tiny program that does
//! open a socket ([`probe`]) is run the same way and must be caught. A
//! sandbox that blocks nothing, or a tracer that records nothing, therefore
//! fails the test instead of passing it.

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Output};

use crate::{Result, cargo, repo_root, symbols};

/// Exit status of [`probe`] when it could not use the network.
const BLOCKED: u8 = 3;

/// `netprobe`: the control program. Opens a listening socket on the loopback
/// interface and connects to it. Exits 0 if that worked and 3 if anything
/// stopped it.
pub(crate) fn probe() -> ExitCode {
    // The listener must stay open until the connection is made.
    let attempt = TcpListener::bind("127.0.0.1:0").and_then(|listener| {
        let stream = TcpStream::connect(listener.local_addr()?)?;
        Ok((listener, stream))
    });
    match attempt {
        Ok(_) => {
            println!("netprobe: opened a socket");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("netprobe: blocked: {error}");
            ExitCode::from(BLOCKED)
        }
    }
}

enum Outcome {
    Passed(String),
    Skipped(String),
    Failed(String),
}

struct Checks(Vec<(&'static str, Outcome)>);

impl Checks {
    fn record(&mut self, name: &'static str, outcome: Outcome) {
        let (mark, detail) = match &outcome {
            Outcome::Passed(detail) => ("ok  ", detail),
            Outcome::Skipped(detail) => ("skip", detail),
            Outcome::Failed(detail) => ("FAIL", detail),
        };
        println!("{mark}  {name}: {detail}");
        self.0.push((name, outcome));
    }
}

fn output(command: &mut Command) -> Result<Output> {
    command.output().map_err(|error| format!("cannot run {:?}: {error}", command.get_program()))
}

fn works(program: &str, args: &[&str]) -> bool {
    Command::new(program).args(args).output().is_ok_and(|output| output.status.success())
}

/// A command line that runs `program` with `args` behind `wrapper`.
fn wrapped(wrapper: &[&str], program: &Path, args: &[&str]) -> Command {
    let mut words = wrapper.iter().copied();
    let mut command = match words.next() {
        Some(first) => {
            let mut command = Command::new(first);
            command.args(words).arg(program);
            command
        }
        None => Command::new(program),
    };
    command.args(args);
    command
}

/// `no-network [--strict]`
pub(crate) fn run(strict: bool) -> Result<()> {
    let root = repo_root();
    let build = Command::new(cargo())
        .args(["build", "--release", "--locked", "--package", "exposure"])
        .current_dir(&root)
        .status()
        .map_err(|error| format!("cannot run cargo: {error}"))?;
    if !build.success() {
        return Err(String::from("the release build failed"));
    }
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let exposure = target.join("release/exposure");
    // The folder of committed fixtures, so that every collector reads
    // something: the bundles under `macos/`, one of them an Electron app
    // with an archive, and the package under `android/`.
    let fixture = root.join("tests/fixtures");
    let fixture = fixture.to_str().ok_or("the repository path is not UTF-8")?;
    let scan = ["scan", fixture, "--threads", "2"];
    let me = std::env::current_exe()
        .map_err(|error| format!("cannot find the xtask binary: {error}"))?;

    // What an unrestricted scan prints. Every restricted run must print the
    // same bytes: the scanner neither needs the network nor notices its loss.
    let baseline = output(Command::new(&exposure).args(scan))?;
    if !baseline.status.success() || baseline.stdout.is_empty() {
        return Err(format!(
            "the plain scan failed: {}",
            String::from_utf8_lossy(&baseline.stderr)
        ));
    }
    // The control must be able to reach the network when nothing stops it.
    if !output(Command::new(&me).arg("netprobe"))?.status.success() {
        return Err(String::from(
            "the control probe cannot open a loopback socket even unrestricted, so it proves nothing here",
        ));
    }

    let mut checks = Checks(Vec::new());
    checks.record("imported symbols", symbol_check(&exposure, &me));

    if cfg!(target_os = "macos") {
        let sandbox = ["sandbox-exec", "-p", "(version 1)(allow default)(deny network*)"];
        let outcome =
            if works("sandbox-exec", &["-p", "(version 1)(allow default)", "/usr/bin/true"]) {
                restricted_run(&sandbox, &exposure, &scan, &me, &baseline.stdout)
            } else {
                Outcome::Skipped(String::from("sandbox-exec is not available"))
            };
        checks.record("sandbox that denies the network", outcome);
    }
    if cfg!(target_os = "linux") {
        // Unprivileged user namespaces are restricted on some distributions
        // (Ubuntu 24.04), so fall back to sudo where it needs no password.
        let unprivileged = ["unshare", "--map-root-user", "--net"];
        let with_sudo = ["sudo", "-n", "unshare", "--net"];
        let outcome = if works("unshare", &["--map-root-user", "--net", "true"]) {
            restricted_run(&unprivileged, &exposure, &scan, &me, &baseline.stdout)
        } else if works("sudo", &["-n", "unshare", "--net", "true"]) {
            restricted_run(&with_sudo, &exposure, &scan, &me, &baseline.stdout)
        } else {
            Outcome::Skipped(String::from(
                "cannot create a network namespace (no unshare, or no privilege)",
            ))
        };
        checks.record("network namespace with no interfaces", outcome);

        let outcome = if works("strace", &["-V"]) {
            strace_check(&target.join("no-network"), &exposure, &scan, &me, &baseline.stdout)
        } else {
            Outcome::Skipped(String::from("strace is not installed"))
        };
        checks.record("system-call trace", outcome);
    }

    let failed =
        checks.0.iter().filter(|(_, outcome)| matches!(outcome, Outcome::Failed(_))).count();
    let skipped: Vec<&str> = checks
        .0
        .iter()
        .filter(|(_, outcome)| matches!(outcome, Outcome::Skipped(_)))
        .map(|(name, _)| *name)
        .collect();
    if failed > 0 {
        return Err(format!("{failed} no-network check(s) failed"));
    }
    if strict && !skipped.is_empty() {
        return Err(format!("--strict: these checks could not run: {}", skipped.join(", ")));
    }
    let _ = std::io::stdout().flush();
    Ok(())
}

fn symbol_check(exposure: &Path, control: &Path) -> Outcome {
    // Control: this xtask binary links `std::net`, and the audit must see it.
    match symbols::audit(control) {
        Ok(audit) if audit.network.is_empty() => {
            return Outcome::Failed(String::from(
                "the audit sees no socket import in the control program",
            ));
        }
        Ok(_) => {}
        Err(error) => return Outcome::Failed(error),
    }
    match symbols::audit(exposure) {
        Ok(audit) if audit.network.is_empty() => Outcome::Passed(format!(
            "{} imports, none can open a socket (control: caught)",
            audit.imports
        )),
        Ok(audit) => Outcome::Failed(format!("exposure imports {}", audit.network.join(", "))),
        Err(error) => Outcome::Failed(error),
    }
}

/// Runs the control and then the scan behind `wrapper`. The control must be
/// blocked; the scan must succeed and print exactly the baseline.
fn restricted_run(
    wrapper: &[&str],
    exposure: &Path,
    scan: &[&str],
    control: &Path,
    baseline: &[u8],
) -> Outcome {
    match output(&mut wrapped(wrapper, control, &["netprobe"])) {
        Ok(probe) if probe.status.code() == Some(i32::from(BLOCKED)) => {}
        Ok(probe) => {
            return Outcome::Failed(format!(
                "the control probe was not blocked (exit {:?}): {}",
                probe.status.code(),
                String::from_utf8_lossy(&probe.stdout).trim()
            ));
        }
        Err(error) => return Outcome::Failed(error),
    }
    match output(&mut wrapped(wrapper, exposure, scan)) {
        Ok(run) if run.status.success() && run.stdout == baseline => {
            Outcome::Passed(String::from("scan succeeded with identical output (control: blocked)"))
        }
        Ok(run) if run.status.success() => {
            Outcome::Failed(String::from("the scan printed a different report without a network"))
        }
        Ok(run) => Outcome::Failed(format!(
            "the scan failed without a network: {}",
            String::from_utf8_lossy(&run.stderr).trim()
        )),
        Err(error) => Outcome::Failed(error),
    }
}

/// The network system calls in an `strace -f -e trace=network` log: every
/// line that is a call, as opposed to an exit or signal notice.
fn network_calls(log: &str) -> Vec<&str> {
    log.lines()
        .map(|line| {
            // With -f each line starts with a process id.
            line.trim_start_matches(|c: char| c.is_ascii_digit() || c == ' ')
        })
        .filter(|line| !line.is_empty() && !line.starts_with("+++") && !line.starts_with("---"))
        .collect()
}

fn strace_check(
    dir: &Path,
    exposure: &Path,
    scan: &[&str],
    control: &Path,
    baseline: &[u8],
) -> Outcome {
    if let Err(error) = std::fs::create_dir_all(dir) {
        return Outcome::Failed(format!("cannot create {}: {error}", dir.display()));
    }
    let trace = |program: &Path, args: &[&str], name: &str| -> Result<(Output, String)> {
        let log = dir.join(name);
        let log_text = log.to_str().ok_or("the target path is not UTF-8")?;
        let wrapper = ["strace", "-f", "-e", "trace=network", "-o", log_text];
        let run = output(&mut wrapped(&wrapper, program, args))?;
        let log = std::fs::read_to_string(&log)
            .map_err(|error| format!("cannot read {}: {error}", log.display()))?;
        Ok((run, log))
    };
    match trace(control, &["netprobe"], "control.strace") {
        Ok((_, log)) if network_calls(&log).iter().any(|call| call.starts_with("socket(")) => {}
        Ok(_) => {
            return Outcome::Failed(String::from(
                "strace recorded no socket call for the control probe",
            ));
        }
        Err(error) => return Outcome::Failed(error),
    }
    match trace(exposure, scan, "scan.strace") {
        Ok((run, _)) if !run.status.success() => Outcome::Failed(format!(
            "the traced scan failed: {}",
            String::from_utf8_lossy(&run.stderr).trim()
        )),
        Ok((run, _)) if run.stdout != baseline => {
            Outcome::Failed(String::from("the traced scan printed a different report"))
        }
        Ok((_, log)) => {
            let calls = network_calls(&log);
            if calls.is_empty() {
                Outcome::Passed(String::from(
                    "scan succeeded with identical output and 0 network system calls (control: caught)",
                ))
            } else {
                Outcome::Failed(format!(
                    "the scan made network system calls: {}",
                    calls.join(" | ")
                ))
            }
        }
        Err(error) => Outcome::Failed(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_and_signal_notices_are_not_calls() {
        let clean = "12345 +++ exited with 0 +++\n12346 --- SIGCHLD {si_signo=SIGCHLD} ---\n+++ exited with 0 +++\n";
        assert!(network_calls(clean).is_empty());
        assert!(network_calls("").is_empty());
    }

    #[test]
    fn network_calls_are_found_with_and_without_a_process_id() {
        let log = "4242 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3\n\
                   connect(3, {sa_family=AF_INET}, 16) = 0\n\
                   4242 +++ exited with 0 +++\n";
        let calls = network_calls(log);
        assert_eq!(calls.len(), 2);
        assert!(calls[0].starts_with("socket("));
        assert!(calls[1].starts_with("connect("));
    }
}
