//! Collection: the front half of the pipeline, and the only crate that opens
//! files.
//!
//! ```text
//! discover ─▶ plan ─▶ read (one pass: hash + match) ─▶ records ─▶ evidence set
//! (stat)      (stat,   one task per file,              (pure)
//!             small    largest first
//!             reads)
//! ```
//!
//! One collector walks a macOS application bundle ([`macos`]). Inside a
//! bundle, the code of an Electron app (asar archives and loose scripts) is
//! read by a part of its own. Another reads an Android package, a single
//! file, in a pass of its own ([`android`]).
//!
//! Besides what an app ships, both say what it may access: the permissions
//! it asks for in its property list and its code signature, or in its
//! Android manifest. Nothing here reads which of them the user allowed;
//! that is in the system's own permission store, outside the artifact, and
//! needs a privilege a scan of app files does not have.
//!
//! Everything here is read-only. Nothing is extracted, executed or written,
//! and symbolic links inside an artifact are never followed, so a hostile
//! bundle cannot point the scanner at files outside itself.
//!
//! **One schedule for the whole scan** (design report, section 6.2). The
//! files of every bundle and every package go into one list, largest first,
//! and each is one task ([`schedule`]). The few files that hold most of the
//! bytes therefore start at once on separate threads, whichever artifacts
//! they belong to. A file is read once, in windows of 1 MiB ([`read`]), so
//! what a scan holds in memory does not grow with the size of what it reads.
//!
//! **One artifact cannot fail the scan.** What cannot be read, of an
//! artifact or of a file in it, becomes a `coverage` record that says so,
//! and every other artifact is scanned as if it had not been there.
//!
//! **Determinism while parallel** (design report, section 6.4). A file's
//! result is a function of its bytes and the rule pack alone. Results are
//! gathered in input order and enter an [`EvidenceSet`], which is keyed by
//! content hash, so neither thread timing nor the order of the paths given
//! can reach the output. Records hold paths relative to the artifact only;
//! where the artifact sits on disk is not recorded anywhere.

mod access;
pub mod android;
pub mod discover;
mod electron;
pub mod macos;
pub mod read;
pub mod schedule;

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use xs_match::Matchers;
use xs_model::EvidenceSet;
use xs_model::evidence::EvidenceError;
use xs_model::record::Record;

use crate::discover::Artifacts;
pub use crate::discover::ScanScope;
use crate::schedule::{Job, Pool};

/// How to run a scan.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanOptions {
    /// Number of worker threads; zero means one per available core.
    pub threads: usize,
}

/// What a scan produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Every record the collectors emitted.
    pub evidence: EvidenceSet,
    /// Totals for the progress line. Not part of any report.
    pub stats: ScanStats,
    /// Where apps were looked for, and where they were deliberately not.
    /// It is not evidence: no record holds it.
    pub scope: ScanScope,
}

/// Totals of one scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Artifacts scanned. One that could not be read at all is not among
    /// them; a `coverage` record stands for it.
    pub artifacts: u64,
    /// Files read and hashed.
    pub files: u64,
    /// Bytes read and hashed.
    pub bytes: u64,
}

/// Why a scan could not run. Problems with a single artifact are not errors;
/// they become `coverage` records and the scan carries on.
#[derive(Debug)]
pub enum ScanError {
    /// No path was given, and this build does not know where the system it
    /// runs on keeps installed apps.
    NoInstalledApps,
    /// A path given on the command line does not exist or cannot be read.
    Path {
        /// The path as given.
        path: PathBuf,
        /// What the operating system said.
        error: std::io::Error,
    },
    /// A path given on the command line is not something this build can scan.
    Unsupported(PathBuf),
    /// The worker threads could not be started.
    Threads(String),
    /// A collector produced a record that breaks the evidence format. This is
    /// a bug in the scanner, reported rather than hidden.
    Evidence(EvidenceError),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInstalledApps => f.write_str(
                "no PATH was given, and installed apps are only looked for on macOS; name the \
                 apps or the folders to scan",
            ),
            Self::Path { path, error } => write!(f, "cannot read {}: {error}", path.display()),
            Self::Unsupported(path) => write!(
                f,
                "{} is not a macOS application bundle, an Android package (.apk) or a folder of \
                 them; other artifact kinds are not supported yet",
                path.display()
            ),
            Self::Threads(message) => write!(f, "cannot start worker threads: {message}"),
            Self::Evidence(error) => {
                write!(f, "internal error: a collector emitted a bad record: {error}")
            }
        }
    }
}

impl std::error::Error for ScanError {}

impl From<EvidenceError> for ScanError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}

/// Scans the artifacts found at `paths` and returns the evidence.
///
/// Each path is a macOS application bundle, an Android package (a file
/// named `.apk`) or a folder that holds either; see [`discover::artifacts`].
/// With no path at all, the apps installed on this machine are scanned; see
/// [`discover::installed`]. A path replaces those folders: when any is
/// given, only what the paths name is scanned. Which of the two a scan was
/// is its [`ScanScope`]. Giving the same artifact twice, directly or
/// through a symbolic link, scans it once.
///
/// # Errors
///
/// Fails if a path does not exist or is not scannable, if no path is given
/// on a system whose installed apps this build cannot find, or if the worker
/// threads cannot be started. Nothing that happens once reading has begun
/// fails the scan: an artifact, or a file inside one, that is unreadable or
/// malformed is reported in a `coverage` record.
pub fn scan(
    paths: &[PathBuf],
    matchers: &Matchers<'_>,
    options: ScanOptions,
) -> Result<ScanOutcome, ScanError> {
    let (scope, found) = if paths.is_empty() {
        (ScanScope::Installed, discover::installed()?)
    } else {
        (ScanScope::Given, discover::artifacts(paths)?)
    };
    let pool = Pool::new(options.threads).map_err(ScanError::Threads)?;
    let (records, stats) = collect(&found, matchers, &pool);

    let mut evidence = EvidenceSet::new();
    for record in records {
        evidence.insert(record)?;
    }
    Ok(ScanOutcome { evidence, stats, scope })
}

/// One read of the scan: a file of a bundle, or a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Work {
    /// The file at place `file` of the plan of bundle number `bundle`.
    File { bundle: usize, file: usize },
    /// The package at this place in the list of packages found.
    Package(usize),
}

/// What one read produced.
enum Done {
    File(macos::FileRead),
    Package(android::Package),
}

/// Reads `found` on `pool` and returns the records with the scan's totals.
///
/// Three steps: every bundle is listed, which only looks at names and
/// sizes; every file to read, of whatever artifact, is read as a task of
/// its own, largest first; and what was read is turned into records, one
/// artifact at a time, which touches no file.
fn collect(found: &Artifacts, matchers: &Matchers<'_>, pool: &Pool) -> (Vec<Record>, ScanStats) {
    // Listing is stat-bound and independent per bundle.
    let plans: Vec<macos::Plan> = pool.map(&found.bundles, |root| macos::plan(root));

    let mut jobs: Vec<Job<Work>> = Vec::new();
    for (bundle, plan) in plans.iter().enumerate() {
        let files = plan.sizes().enumerate();
        jobs.extend(files.map(|(file, size)| Job { size, work: Work::File { bundle, file } }));
    }
    for (index, path) in found.packages.iter().enumerate() {
        // A package that cannot even be measured is found out when it is
        // read; where it stands in the queue until then does not matter.
        let size = std::fs::metadata(path).map_or(0, |metadata| metadata.len());
        jobs.push(Job { size, work: Work::Package(index) });
    }
    let done = pool.largest_first(&mut jobs, |work| match *work {
        Work::File { bundle, file } => {
            plans.get(bundle).map(|plan| Done::File(macos::read(plan, file, matchers)))
        }
        Work::Package(index) => {
            found.packages.get(index).map(|path| Done::Package(android::read(path, matchers)))
        }
    });

    let mut stats = ScanStats::default();
    let mut records = Vec::new();
    let mut per_bundle: Vec<Vec<(usize, macos::FileRead)>> =
        plans.iter().map(|_| Vec::new()).collect();
    // Packages that were not read are told apart by name alone, so those
    // that share one are counted in one record.
    let mut unread: BTreeMap<String, u32> = BTreeMap::new();
    for (job, done) in jobs.iter().zip(done) {
        match (job.work, done) {
            (Work::File { bundle, file }, Some(Done::File(result))) => {
                if let Some(results) = per_bundle.get_mut(bundle) {
                    results.push((file, result));
                }
            }
            (
                Work::Package(_),
                Some(Done::Package(android::Package::Scanned { records: scanned, bytes })),
            ) => {
                stats.artifacts += 1;
                stats.files += 1;
                stats.bytes += bytes;
                records.extend(scanned);
            }
            (Work::Package(index), Some(Done::Package(android::Package::Unread))) => {
                if let Some(path) = found.packages.get(index) {
                    let count = unread.entry(android::unread_name(path)).or_insert(0);
                    *count = count.saturating_add(1);
                }
            }
            // A job names a place in the lists it was made from, and a read
            // gives back the kind of result its job asks for.
            (Work::File { .. } | Work::Package(_), _) => {}
        }
    }
    for (plan, results) in plans.into_iter().zip(per_bundle) {
        let (finished, files, bytes) = macos::finish(plan, results, matchers);
        stats.artifacts += 1;
        stats.files += files;
        stats.bytes += bytes;
        records.extend(finished);
    }
    for (name, count) in unread {
        records.push(android::unread(name, count));
    }
    (records, stats)
}
