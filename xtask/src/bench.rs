//! The scan benchmark: how the scan scales with threads, and how much
//! memory it takes.
//!
//! Design report, section 6.5, three of its gates:
//!
//! | Benchmark | Method | Gate |
//! |---|---|---|
//! | Scaling | 1, 2, 4, 8 threads on a size-sorted list | At least 3x at 8 threads |
//! | Memory | Peak resident size during the scan | Under 200 MB |
//! | Determinism | The report of every run | One report |
//!
//! The scaling gate is the one that catches the splitting trap (section 6.2
//! decision 5): if the largest files of the queue are handed to one thread,
//! eight threads are barely faster than one.
//!
//! What is measured is the `exposure` binary itself, from outside, as a user
//! runs it: the release build, one process per run. Time is wall-clock time
//! of the whole process, and memory is what the operating system accounts to
//! it, read with `/usr/bin/time`. One run that is not measured goes first,
//! so that every measured run reads from the page cache: this benchmark is
//! about the schedule, not about the disk.
//!
//! The scanner has no clock and takes no measurements of itself; all of that
//! is here, in tooling that never ships.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use xs_model::Report;
use xs_model::record::Record;

use crate::{Result, cargo, repo_root};

/// The thread counts of the scaling benchmark.
const THREADS: [usize; 4] = [1, 2, 4, 8];
/// How many times each thread count is run. The fastest run counts: noise
/// from the rest of the machine only ever adds time.
const RUNS: usize = 3;
/// The scaling gate: the scan at eight threads is at least this many
/// hundredths as fast as at one.
const MIN_SPEEDUP_HUNDREDTHS: u128 = 300;
/// The memory gate: peak resident size, in bytes.
const MAX_PEAK_BYTES: u64 = 200_000_000;
/// The least a scan has to read for its scaling to mean anything. Below
/// this, starting the process and the threads is most of the time.
const MIN_SCALING_BYTES: u64 = 1 << 30;
/// Where both systems keep the tool that reports a process's peak memory.
const TIME: &str = "/usr/bin/time";

/// One measured run.
struct Run {
    elapsed: Duration,
    peak_bytes: u64,
    report: Vec<u8>,
}

/// What a scan covered, from its report.
struct Load {
    apps: u64,
    files: u64,
    bytes: u64,
}

/// The peak resident size in what `/usr/bin/time` wrote, in bytes.
///
/// macOS (`-l`) writes a line `<bytes>  maximum resident set size` among
/// others. GNU time is asked for the one number (`-f %M`), in kibibytes.
fn peak_bytes(usage: &str) -> Option<u64> {
    if cfg!(target_os = "macos") {
        let line = usage.lines().find(|line| line.ends_with("maximum resident set size"))?;
        line.split_whitespace().next()?.parse().ok()
    } else {
        // A run that fails makes GNU time put a notice before the number.
        usage.lines().last()?.trim().parse::<u64>().ok()?.checked_mul(1024)
    }
}

/// Runs one scan of `paths` at `threads` threads and measures it. Files it
/// needs are written into `dir`.
fn run(exposure: &Path, paths: &[String], threads: usize, dir: &Path) -> Result<Run> {
    let usage = dir.join("usage.txt");
    let report = dir.join("report.json");
    let mut command = Command::new(TIME);
    if cfg!(target_os = "macos") {
        command.arg("-l");
    } else {
        command.args(["-f", "%M"]);
    }
    command.arg("-o").arg(&usage).arg(exposure).arg("scan");
    command.arg("--threads").arg(threads.to_string()).arg("--json").arg(&report);
    command.arg("--").args(paths);

    let started = Instant::now();
    let output = command.output().map_err(|error| {
        format!("cannot run {TIME}, which measures memory (on Linux: the `time` package): {error}")
    })?;
    let elapsed = started.elapsed();
    if !output.status.success() {
        return Err(format!("the scan failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let peak_bytes = peak_bytes(&crate::read_text(&usage)?)
        .ok_or_else(|| format!("cannot find the peak memory in what {TIME} wrote"))?;
    Ok(Run { elapsed, peak_bytes, report: crate::read(&report)? })
}

/// What the scan behind `report` covered.
fn load(report: &[u8]) -> Result<Load> {
    let report: Report = serde_json::from_slice(report)
        .map_err(|error| format!("the scan wrote a report that does not parse: {error}"))?;
    let mut load = Load { apps: 0, files: 0, bytes: 0 };
    for (_, record) in report.evidence.iter() {
        if let Record::Artifact(artifact) = record {
            load.apps += 1;
            load.files += artifact.facts.files_scanned;
            load.bytes += artifact.facts.bytes_scanned;
        }
    }
    Ok(load)
}

/// `value` hundredths, written with two decimals.
fn hundredths(value: u128) -> String {
    format!("{}.{:02}", value / 100, value % 100)
}

/// How many hundredths as fast `this` is as `base`.
fn speedup(base: Duration, this: Duration) -> u128 {
    base.as_micros().saturating_mul(100) / this.as_micros().max(1)
}

/// `bench [--strict] [PATH...]`
pub(crate) fn run_all(args: &[&str]) -> Result<()> {
    let strict = args.first() == Some(&"--strict");
    let paths: Vec<String> =
        args.iter().skip(usize::from(strict)).map(|path| (*path).to_owned()).collect();
    if let Some(option) = paths.iter().find(|path| path.starts_with("--")) {
        return Err(format!("bench does not know the option {option}"));
    }

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

    // Reports name the apps of this machine. They stay in a folder only its
    // owner can read, which is removed when the benchmark ends.
    let dir = std::env::temp_dir().join(format!("exposure-bench-{}", std::process::id()));
    let made = fs::create_dir(&dir);
    #[cfg(unix)]
    let made = made.and_then(|()| {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
    });
    made.map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    let outcome = measure(&exposure, &paths, &dir, strict);
    let _ = fs::remove_dir_all(&dir);
    outcome
}

fn measure(exposure: &Path, paths: &[String], dir: &Path, strict: bool) -> Result<()> {
    // Not measured: it fills the page cache, and says what the load is.
    let first = run(exposure, paths, THREADS[THREADS.len() - 1], dir)?;
    let load = load(&first.report)?;
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let megabytes = |bytes: u64| bytes / 1_000_000;
    println!(
        "scan of {}: {} apps, {} files, {} MB read; {cores} cores; fastest of {RUNS} runs, page cache warm",
        if paths.is_empty() { "the installed apps" } else { "the given paths" },
        load.apps,
        load.files,
        megabytes(load.bytes),
    );
    println!("threads  seconds  speed-up    MB/s  peak memory");

    let mut same_report = true;
    let mut peak = first.peak_bytes;
    let mut fastest: Vec<Duration> = Vec::new();
    for threads in THREADS {
        let mut best: Option<Run> = None;
        for _ in 0..RUNS {
            let this = run(exposure, paths, threads, dir)?;
            same_report &= this.report == first.report;
            peak = peak.max(this.peak_bytes);
            if best.as_ref().is_none_or(|best| this.elapsed < best.elapsed) {
                best = Some(this);
            }
        }
        let Some(best) = best else { continue };
        let base = fastest.first().copied().unwrap_or(best.elapsed);
        let rate = u128::from(load.bytes) / best.elapsed.as_micros().max(1);
        println!(
            "{threads:>7}  {:>7}  {:>7}x  {rate:>6}  {:>8} MB",
            hundredths(best.elapsed.as_millis() / 10),
            hundredths(speedup(base, best.elapsed)),
            megabytes(best.peak_bytes),
        );
        fastest.push(best.elapsed);
    }

    let mut failed = Vec::new();
    let mut skipped = Vec::new();
    let mut check = |name: &'static str, passed: Option<bool>, detail: String| {
        let mark = match passed {
            Some(true) => "ok  ",
            Some(false) => "FAIL",
            None => "skip",
        };
        println!("{mark}  {name}: {detail}");
        match passed {
            Some(true) => {}
            Some(false) => failed.push(name),
            None => skipped.push(name),
        }
    };

    let gained = match (fastest.first(), fastest.last()) {
        (Some(base), Some(most)) => speedup(*base, *most),
        _ => 0,
    };
    let most = THREADS[THREADS.len() - 1];
    let gate = hundredths(MIN_SPEEDUP_HUNDREDTHS);
    if cores < most {
        let detail = format!("needs {most} cores to mean anything, and this machine has {cores}");
        check("scaling", None, detail);
    } else if load.bytes < MIN_SCALING_BYTES {
        let least = megabytes(MIN_SCALING_BYTES);
        let detail = format!("needs a scan that reads at least {least} MB to mean anything");
        check("scaling", None, detail);
    } else {
        let detail = format!("{}x at {most} threads (gate: at least {gate}x)", hundredths(gained));
        check("scaling", Some(gained >= MIN_SPEEDUP_HUNDREDTHS), detail);
    }
    check(
        "memory",
        Some(peak < MAX_PEAK_BYTES),
        format!(
            "{} MB at most in any run (gate: under {} MB)",
            megabytes(peak),
            megabytes(MAX_PEAK_BYTES)
        ),
    );
    check(
        "determinism",
        Some(same_report),
        format!(
            "{} runs at {} thread counts, {}",
            1 + RUNS * THREADS.len(),
            THREADS.len(),
            if same_report { "one report, byte for byte" } else { "and their reports differ" }
        ),
    );

    if !failed.is_empty() {
        return Err(format!("these benchmark gates failed: {}", failed.join(", ")));
    }
    if strict && !skipped.is_empty() {
        return Err(format!("--strict: these gates could not be checked: {}", skipped.join(", ")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peak_memory_is_read_from_what_the_time_tool_writes() {
        let usage = if cfg!(target_os = "macos") {
            "        0.85 real         3.91 user         1.80 sys\n            \
             43565056  maximum resident set size\n                   \
             0  average shared memory size\n            \
             42000000  peak memory footprint\n"
        } else {
            "42544\n"
        };
        assert_eq!(peak_bytes(usage), Some(43_565_056));
        assert_eq!(peak_bytes(""), None);
        assert_eq!(peak_bytes("no numbers here\n"), None);
    }

    #[test]
    fn speed_up_is_counted_in_hundredths_without_fractions() {
        let seconds = Duration::from_millis;
        assert_eq!(speedup(seconds(6470), seconds(1350)), 479);
        assert_eq!(speedup(seconds(1000), seconds(1000)), 100);
        assert_eq!(speedup(seconds(1000), seconds(2000)), 50);
        assert_eq!(speedup(seconds(1000), Duration::ZERO), 100_000_000);
        assert_eq!(hundredths(479), "4.79");
        assert_eq!(hundredths(300), "3.00");
        assert_eq!(hundredths(5), "0.05");
        assert_eq!(hundredths(12_345), "123.45");
    }
}
