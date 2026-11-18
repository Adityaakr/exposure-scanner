//! The scan benchmark: how the scan scales with threads, how much memory it
//! takes, and how long it takes when nothing has changed.
//!
//! Design report, section 6.5, five of its gates:
//!
//! | Benchmark | Method | Gate |
//! |---|---|---|
//! | Cold scan | Empty results cache, page cache dropped where that needs no password | Under 60 s |
//! | Scaling | 1, 2, 4, 8 threads on a size-sorted list | At least 3x at 8 threads |
//! | Memory | Peak resident size during the scan | Under 200 MB |
//! | Warm scan | Populated cache, no changes | Under 5 s |
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
//! The cold scan is the first scan a person runs: the results cache is
//! empty, so every app is read. Before it, the operating system is asked to
//! drop its page cache (`sudo -n purge` on macOS, `drop_caches` on Linux),
//! so the files come from the disk; where `sudo` would ask for a password
//! that is skipped and said, and the scan reads from the page cache.
//!
//! The scaling runs keep no results cache, or all but the first would read
//! nothing. The warm scan is measured after them: one run fills a cache in
//! a folder of the benchmark's own, never the user's, and the runs after it
//! find every app unchanged. The scan keeps its cache in the user's cache
//! folder and takes no option for another, so those runs are given a home
//! folder of the benchmark's own. Its `Applications` leads to the user's,
//! and so does its `Library/Application Support`, where the browsers keep
//! their profiles, so that a scan of the installed apps covers the same apps
//! and the same extensions. Its `Library/Caches` is its own.
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
/// The warm-scan gate: a scan that finds nothing changed takes less.
const MAX_WARM: Duration = Duration::from_secs(5);
/// The cold-scan gate: a scan with an empty results cache takes less.
const MAX_COLD: Duration = Duration::from_secs(60);
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
    /// What the scan told the terminal.
    summary: String,
}

/// How many apps a scan did not read, since its cache held them unchanged,
/// and how many it read: from the line of its summary that says so. `None`
/// if the scan did not use a cache.
fn cache_use(summary: &str) -> Option<(u64, u64)> {
    let said = summary.lines().find_map(|line| line.strip_prefix("exposure: cache: "))?;
    let (unchanged, read) = said.split_once(", ")?;
    let count = |text: &str| text.split(' ').next()?.parse::<u64>().ok();
    Some((count(unchanged)?, count(read)?))
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

/// Runs one scan of `paths` at `threads` threads and measures it, with the
/// results cache of the user whose home folder is `home`, or without one.
/// Files it needs are written into `dir`.
fn run(
    exposure: &Path,
    paths: &[String],
    threads: usize,
    home: Option<&Path>,
    dir: &Path,
) -> Result<Run> {
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
    match home {
        Some(home) => command.env("HOME", home).env_remove("XDG_CACHE_HOME"),
        None => command.arg("--no-cache"),
    };
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
    let summary = String::from_utf8_lossy(&output.stderr).into_owned();
    Ok(Run { elapsed, peak_bytes, report: crate::read(&report)?, summary })
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
    let most = THREADS[THREADS.len() - 1];
    let first = run(exposure, paths, most, None, dir)?;
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
            let this = run(exposure, paths, threads, None, dir)?;
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

    // The warm scan: one run fills the cache, the next ones find it full.
    let home = dir.join("home");
    fs::create_dir(&home).map_err(|error| format!("cannot create {}: {error}", home.display()))?;
    #[cfg(unix)]
    if let Some(apps) = std::env::home_dir().map(|home| home.join("Applications"))
        && apps.is_dir()
    {
        std::os::unix::fs::symlink(&apps, home.join("Applications"))
            .map_err(|error| format!("cannot link {}: {error}", apps.display()))?;
    }
    #[cfg(unix)]
    if let Some(support) = std::env::home_dir().map(|home| home.join("Library/Application Support"))
        && support.is_dir()
    {
        let library = home.join("Library");
        fs::create_dir(&library)
            .and_then(|()| {
                std::os::unix::fs::symlink(&support, library.join("Application Support"))
            })
            .map_err(|error| format!("cannot link {}: {error}", support.display()))?;
    }
    let disk_cold = drop_page_cache();
    let filled = run(exposure, paths, most, Some(&home), dir)?;
    same_report &= filled.report == first.report;
    peak = peak.max(filled.peak_bytes);
    let mut warm: Option<Run> = None;
    for _ in 0..RUNS {
        let this = run(exposure, paths, most, Some(&home), dir)?;
        same_report &= this.report == first.report;
        peak = peak.max(this.peak_bytes);
        if warm.as_ref().is_none_or(|warm| this.elapsed < warm.elapsed) {
            warm = Some(this);
        }
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
    let seconds = |elapsed: Duration| hundredths(elapsed.as_millis() / 10);
    check(
        "cold scan",
        Some(filled.elapsed < MAX_COLD),
        format!(
            "{} s with an empty results cache, {} (gate: under {} s)",
            seconds(filled.elapsed),
            if disk_cold {
                "the page cache dropped first"
            } else {
                "from the page cache: dropping it needs sudo without a password"
            },
            MAX_COLD.as_secs()
        ),
    );
    match warm.as_ref().map(|warm| (warm.elapsed, cache_use(&warm.summary))) {
        // A scan that read every app again is not a warm scan, however long
        // it took: there is nothing here to hold against the gate.
        None | Some((_, None | Some((0, _)))) => {
            let said = warm.as_ref().and_then(|warm| warm.summary.lines().last());
            let detail = format!(
                "the cache spared the scan nothing, so there is no warm scan to time: {}",
                said.unwrap_or("the scan said nothing")
            );
            check("warm scan", None, detail);
        }
        Some((elapsed, Some((unchanged, read)))) => {
            let detail = format!(
                "{} s with {unchanged} of {} apps unchanged and not read, against {} s to read \
                 them all and fill the cache (gate: under {} s)",
                seconds(elapsed),
                unchanged + read,
                seconds(filled.elapsed),
                MAX_WARM.as_secs()
            );
            check("warm scan", Some(elapsed < MAX_WARM), detail);
        }
    }
    check(
        "determinism",
        Some(same_report),
        format!(
            "{} runs at {} thread counts, with the cache off, empty and full, {}",
            2 + RUNS * (THREADS.len() + 1),
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

/// Asks the operating system to drop its page cache, so the next scan
/// reads from the disk, and says whether it did. Never asks for a password.
fn drop_page_cache() -> bool {
    let mut command = Command::new("sudo");
    command.arg("-n");
    if cfg!(target_os = "macos") {
        command.arg("purge");
    } else {
        command.args(["sh", "-c", "sync && echo 3 > /proc/sys/vm/drop_caches"]);
    }
    command
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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
    fn what_the_cache_spared_a_scan_is_read_from_its_summary() {
        let summary = |cache: &str| {
            format!(
                "exposure: scanned 16 apps (11658 files, 6813162633 bytes): 19 claims, 2 coverage \
                 notes\nexposure: scope: the paths given and nothing else\n{cache}"
            )
        };
        let used = "exposure: cache: 15 apps unchanged since an earlier scan and not read again, \
                    1 app read\n";
        assert_eq!(cache_use(&summary(used)), Some((15, 1)));
        let cold = "exposure: cache: 0 apps unchanged since an earlier scan and not read again, \
                    16 apps read\n";
        assert_eq!(cache_use(&summary(cold)), Some((0, 16)));
        assert_eq!(cache_use(&summary("")), None);
        assert_eq!(cache_use(&summary("exposure: cache: not used: cannot use /x: denied\n")), None);
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
