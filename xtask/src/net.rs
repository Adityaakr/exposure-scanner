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
//!
//! Every dynamic check runs the scan three times ([`Scans`]): without the
//! results cache, with an empty one, which reads every app and stores what
//! it found, and with the cache that run left, which reads none. So what is
//! proven of the scan is proven of it however much the cache spares it.

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

/// The scans a dynamic check runs, and what each has to print.
struct Scans<'a> {
    /// The arguments of a scan that keeps no cache.
    plain: &'a [&'a str],
    /// The arguments of the same scan with its cache.
    cached: &'a [&'a str],
    /// A home folder for the scans, which holds the cache, that this
    /// program may empty.
    home: &'a Path,
    /// What an unrestricted scan without a cache printed: the report.
    baseline: &'a [u8],
}

impl Scans<'_> {
    /// Sets `command` up to run as a user whose home folder is the scans'.
    fn at_home<'c>(&self, command: &'c mut Command) -> &'c mut Command {
        command.env("HOME", self.home).env_remove("XDG_CACHE_HOME")
    }

    /// Runs the three scans with `run`, which says what is wrong with a run
    /// that it does not accept. Each must succeed and print the baseline.
    /// The two with a cache must have read every app and none, or, where
    /// they ran `as_root`, have said that root keeps no cache.
    fn each(
        &self,
        as_root: bool,
        mut run: impl FnMut(&str, &[&str]) -> Result<Output>,
    ) -> Result<()> {
        // The folder is made here, by whoever runs the test, so that it can
        // be removed again whoever the scan itself ran as.
        let _ = std::fs::remove_dir_all(self.home);
        std::fs::create_dir_all(self.home)
            .map_err(|error| format!("cannot create {}: {error}", self.home.display()))?;
        let (empty, full) = if as_root {
            ("cache: not used when run as root", "cache: not used when run as root")
        } else {
            ("cache: 0 apps unchanged", ", 0 apps read")
        };
        let scans = [
            ("without a cache", self.plain, None),
            ("with an empty cache", self.cached, Some(empty)),
            ("with a full cache", self.cached, Some(full)),
        ];
        let mut outcome = Ok(());
        for (name, args, said) in scans {
            outcome = run(name, args).and_then(|run| {
                let summary = String::from_utf8_lossy(&run.stderr);
                if !run.status.success() {
                    Err(format!("the scan {name} failed: {}", summary.trim()))
                } else if run.stdout != self.baseline {
                    Err(format!("the scan {name} printed a different report"))
                } else if said.is_some_and(|said| !summary.contains(said)) {
                    Err(format!("the scan {name} did not use it as expected: {}", summary.trim()))
                } else {
                    Ok(())
                }
            });
            if outcome.is_err() {
                break;
            }
        }
        std::fs::remove_dir_all(self.home)
            .map_err(|error| format!("cannot remove {}: {error}", self.home.display()))?;
        outcome
    }
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
    // The committed fixtures, so that every collector reads something: the
    // folder of bundles, one of them an Electron app with an archive, the
    // package, and the browser extensions, a folder of them and an add-on.
    let bundles = root.join("tests/fixtures/macos");
    let package = root.join("tests/fixtures/android/Skeleton.apk");
    let extensions = root.join("tests/fixtures/browser/Extensions");
    let addon = root.join("tests/fixtures/browser/addon@example.org.xpi");
    let utf8 = |path: &'_ PathBuf| path.to_str().map(String::from);
    let paths = [&bundles, &package, &extensions, &addon]
        .map(utf8)
        .into_iter()
        .collect::<Option<Vec<String>>>()
        .ok_or("the repository path is not UTF-8")?;
    let home = target.join("no-network/home");
    let mut cached: Vec<&str> = vec!["scan"];
    cached.extend(paths.iter().map(String::as_str));
    cached.extend(["--threads", "2"]);
    let mut plain = cached.clone();
    plain.insert(1, "--no-cache");
    let me = std::env::current_exe()
        .map_err(|error| format!("cannot find the xtask binary: {error}"))?;

    // What an unrestricted scan prints. Every restricted run must print the
    // same bytes: the scanner neither needs the network nor notices its loss.
    let baseline = output(Command::new(&exposure).args(&plain))?;
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

    let scans = Scans { plain: &plain, cached: &cached, home: &home, baseline: &baseline.stdout };

    let mut checks = Checks(Vec::new());
    checks.record("imported symbols", symbol_check(&exposure, &me));

    if cfg!(target_os = "macos") {
        let sandbox = ["sandbox-exec", "-p", "(version 1)(allow default)(deny network*)"];
        let outcome =
            if works("sandbox-exec", &["-p", "(version 1)(allow default)", "/usr/bin/true"]) {
                restricted_run(&sandbox, false, &exposure, &scans, &me)
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
            restricted_run(&unprivileged, true, &exposure, &scans, &me)
        } else if works("sudo", &["-n", "unshare", "--net", "true"]) {
            restricted_run(&with_sudo, true, &exposure, &scans, &me)
        } else {
            Outcome::Skipped(String::from(
                "cannot create a network namespace (no unshare, or no privilege)",
            ))
        };
        checks.record("network namespace with no interfaces", outcome);

        let outcome = if works("strace", &["-V"]) {
            strace_check(&target.join("no-network"), &exposure, &scans, &me)
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

/// Runs the control and then the scans behind `wrapper`, which runs them
/// `as_root` or not. The control must be blocked; every scan must succeed
/// and print exactly the baseline.
fn restricted_run(
    wrapper: &[&str],
    as_root: bool,
    exposure: &Path,
    scans: &Scans<'_>,
    control: &Path,
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
    match scans
        .each(as_root, |_, scan| output(scans.at_home(&mut wrapped(wrapper, exposure, scan))))
    {
        Ok(()) => Outcome::Passed(String::from(
            "3 scans (no cache, empty cache, full cache) succeeded with identical output \
             (control: blocked)",
        )),
        Err(error) => Outcome::Failed(format!("without a network, {error}")),
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

fn strace_check(dir: &Path, exposure: &Path, scans: &Scans<'_>, control: &Path) -> Outcome {
    if let Err(error) = std::fs::create_dir_all(dir) {
        return Outcome::Failed(format!("cannot create {}: {error}", dir.display()));
    }
    let trace = |program: &Path, args: &[&str], name: &str| -> Result<(Output, String)> {
        let log = dir.join(name);
        let log_text = log.to_str().ok_or("the target path is not UTF-8")?;
        let wrapper = ["strace", "-f", "-e", "trace=network", "-o", log_text];
        let run = output(scans.at_home(&mut wrapped(&wrapper, program, args)))?;
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
    let traced = scans.each(false, |name, scan| {
        let (run, log) = trace(exposure, scan, "scan.strace")?;
        let calls = network_calls(&log);
        if run.status.success() && !calls.is_empty() {
            return Err(format!(
                "the scan {name} made network system calls: {}",
                calls.join(" | ")
            ));
        }
        Ok(run)
    });
    match traced {
        Ok(()) => Outcome::Passed(String::from(
            "3 scans (no cache, empty cache, full cache) succeeded with identical output and 0 \
             network system calls (control: caught)",
        )),
        Err(error) => Outcome::Failed(format!("traced, {error}")),
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
