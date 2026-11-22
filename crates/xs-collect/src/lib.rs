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
//! file, in a pass of its own ([`android`]). A third reads the manifest of
//! a browser extension ([`browser`]).
//!
//! Besides what an app ships, both say what it may access: the permissions
//! it asks for in its property list and its code signature, or in its
//! Android manifest. Nothing here reads which of them the user allowed;
//! that is in the system's own permission store, outside the artifact, and
//! needs a privilege a scan of app files does not have.
//!
//! Everything here is read-only towards what is scanned. Nothing is
//! extracted, executed or changed, and symbolic links inside an artifact are
//! never followed, so a hostile bundle cannot point the scanner at files
//! outside itself. The one thing written is the scanner's own cache, when
//! the scan is given a folder to keep it in.
//!
//! **One schedule for the whole scan** (design report, section 6.2). The
//! files of every bundle and every package go into one list, largest first,
//! and each is one task ([`schedule`]). The few files that hold most of the
//! bytes therefore start at once on separate threads, whichever artifacts
//! they belong to. A file is read once, in windows of 1 MiB ([`read`]), so
//! what a scan holds in memory does not grow with the size of what it reads.
//!
//! **An artifact that has not changed is not read again** ([`cache`]). Its
//! listing, which reads no content, is compared with the one its stored
//! records were made from. Only the artifacts that differ go into the
//! schedule, and a scan with the cache gives the same report as one without.
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
pub mod browser;
pub mod cache;
pub mod discover;
mod electron;
pub mod macos;
pub mod read;
pub mod schedule;

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use xs_match::Matchers;
use xs_model::EvidenceSet;
use xs_model::evidence::EvidenceError;
pub use xs_model::report::ScanScope;

pub use crate::cache::CacheError;
use crate::cache::{Cache, Collected, Kind, Slot, State};
use crate::discover::Artifacts;
use crate::schedule::{Job, Pool};

/// How to run a scan.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanOptions<'a> {
    /// Number of worker threads; zero means one per available core.
    pub threads: usize,
    /// The folder to keep the results cache in, which is created if it is
    /// not there; see [`cache`] and [`cache::default_dir`]. Without one,
    /// every artifact is read and nothing is written anywhere.
    pub cache: Option<&'a Path>,
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
    /// Why the cache the scan was given could not be used, in which case
    /// every artifact was read. `None` if it was used, or if none was given.
    pub cache_failure: Option<CacheError>,
}

/// Totals of one scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Apps scanned. One that could not be read at all is not among them; a
    /// `coverage` record stands for it.
    pub artifacts: u64,
    /// Browser extensions read, counted like apps.
    pub extensions: u64,
    /// Files read and hashed: in this scan, or for an artifact that has not
    /// changed, in the scan its stored result is from.
    pub files: u64,
    /// Bytes read and hashed, counted like the files.
    pub bytes: u64,
    /// How many of the artifacts were not read, because they have not
    /// changed since the result the cache holds for them was made.
    pub reused: u64,
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
                "{} is not a macOS application bundle, an Android package (.apk or .aab), a browser \
                 extension (a Firefox .xpi file, or a Chromium <id>/<version> folder) or a \
                 folder of them; other artifact kinds are not supported yet",
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
/// named `.apk`, or an app bundle named `.aab`), a browser extension or a folder that holds any of them;
/// see [`discover::artifacts`]. With no path at all, the apps and the
/// browser extensions installed on this machine are scanned; see
/// [`discover::installed`]. A path replaces those folders: when any is
/// given, only what the paths name is scanned. Which of the two a scan was
/// is its [`ScanScope`]. Giving the same artifact twice, directly or
/// through a symbolic link, scans it once.
///
/// With a folder for the [`cache`], an artifact that has not changed since
/// it was last read is not read again, and what is read is stored there. A
/// cache that cannot be used does not fail the scan: the outcome says why,
/// and every artifact is read.
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
    options: ScanOptions<'_>,
) -> Result<ScanOutcome, ScanError> {
    let (scope, found) = if paths.is_empty() {
        (ScanScope::Installed, discover::installed()?)
    } else {
        (ScanScope::Given, discover::artifacts(paths)?)
    };
    let pool = Pool::new(options.threads).map_err(ScanError::Threads)?;
    let (cache, cache_failure) = match options.cache.map(|dir| Cache::open(dir, matchers)) {
        Some(Ok(cache)) => (Some(cache), None),
        Some(Err(error)) => (None, Some(error)),
        None => (None, None),
    };
    let (evidence, stats) = collect(&found, matchers, &pool, cache.as_ref())?;
    Ok(ScanOutcome { evidence, stats, scope, cache_failure })
}

/// An artifact once it is listed, which reads none of its content.
enum Listed<'c, T> {
    /// It has not changed since this result was stored: it is not read.
    Stored(Collected),
    /// It is to be read: what its kind needs for that, and where its result
    /// is to be stored when there is a cache.
    Fresh(T, Option<Slot<'c>>),
}

impl<'c, T> Listed<'c, T> {
    /// The stored result of an artifact in the state `slot` is for, or else
    /// `fresh`, to read it with.
    fn new(fresh: T, slot: Option<Slot<'c>>) -> Self {
        match slot.as_ref().and_then(Slot::load) {
            Some(stored) => Self::Stored(stored),
            None => Self::Fresh(fresh, slot),
        }
    }
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

/// Reads `found` on `pool` and returns the evidence with the scan's totals.
///
/// Four steps. Every artifact is listed, which only looks at names, sizes
/// and times, and one that `cache` holds in the state listed is done with.
/// Every file to read of the others, of whatever artifact, is read as a
/// task of its own, largest first. What was read is turned into records,
/// one artifact at a time, which touches no file. And the records of each
/// artifact that was read are stored in `cache`.
///
/// # Errors
///
/// Fails if a collector made a record that breaks the evidence format.
fn collect<'c>(
    found: &Artifacts,
    matchers: &Matchers<'_>,
    pool: &Pool,
    cache: Option<&'c Cache>,
) -> Result<(EvidenceSet, ScanStats), EvidenceError> {
    // Listing is stat-bound and independent per artifact.
    let bundles: Vec<Listed<'c, macos::Plan>> = pool.map_io(&found.bundles, |root| {
        let plan = macos::plan(root);
        let slot = cache.map(|cache| cache.slot(Kind::Bundle, root, plan.state()));
        Listed::new(plan, slot)
    });
    let packages: Vec<Listed<'c, u64>> = pool.map_io(&found.packages, |path| {
        // A package that cannot even be measured is found out when it is
        // read; where it stands in the queue until then does not matter.
        let metadata = fs::metadata(path).ok();
        let size = metadata.as_ref().map_or(0, fs::Metadata::len);
        let state = metadata.as_ref().map(State::of_file);
        let slot = cache.zip(state).map(|(cache, state)| cache.slot(Kind::Package, path, state));
        Listed::new(size, slot)
    });

    let mut jobs: Vec<Job<Work>> = Vec::new();
    for (bundle, listed) in bundles.iter().enumerate() {
        if let Listed::Fresh(plan, _) = listed {
            let files = plan.sizes().enumerate();
            jobs.extend(files.map(|(file, size)| Job { size, work: Work::File { bundle, file } }));
        }
    }
    for (index, listed) in packages.iter().enumerate() {
        if let Listed::Fresh(size, _) = listed {
            jobs.push(Job { size: *size, work: Work::Package(index) });
        }
    }
    let done = pool.largest_first(&mut jobs, |work| match *work {
        Work::File { bundle, file } => match bundles.get(bundle) {
            Some(Listed::Fresh(plan, _)) => Some(Done::File(macos::read(plan, file, matchers))),
            _ => None,
        },
        Work::Package(index) => {
            found.packages.get(index).map(|path| Done::Package(android::read(path, matchers)))
        }
    });

    let mut per_bundle: Vec<Vec<(usize, macos::FileRead)>> =
        bundles.iter().map(|_| Vec::new()).collect();
    let mut per_package: Vec<Option<android::Package>> = packages.iter().map(|_| None).collect();
    for (job, done) in jobs.iter().zip(done) {
        match (job.work, done) {
            (Work::File { bundle, file }, Some(Done::File(result))) => {
                if let Some(results) = per_bundle.get_mut(bundle) {
                    results.push((file, result));
                }
            }
            (Work::Package(index), Some(Done::Package(package))) => {
                if let Some(read) = per_package.get_mut(index) {
                    *read = Some(package);
                }
            }
            // A job names a place in the lists it was made from, and a read
            // gives back the kind of result its job asks for.
            (Work::File { .. } | Work::Package(_), _) => {}
        }
    }

    let mut stats = ScanStats::default();
    // Every artifact with a result, and where to store it if it is new.
    let mut artifacts: Vec<(Collected, Option<Slot<'c>>)> = Vec::new();
    for (listed, results) in bundles.into_iter().zip(per_bundle) {
        match listed {
            Listed::Stored(stored) => {
                stats.reused += 1;
                artifacts.push((stored, None));
            }
            Listed::Fresh(plan, slot) => {
                let (records, files, bytes) = macos::finish(plan, results, matchers);
                artifacts.push((Collected::new(records, files, bytes)?, slot));
            }
        }
    }
    // Packages that were not read are told apart by name alone, so those
    // that share one are counted in one record.
    let mut unread: BTreeMap<String, u32> = BTreeMap::new();
    for ((listed, read), path) in packages.into_iter().zip(per_package).zip(&found.packages) {
        match (listed, read) {
            (Listed::Stored(stored), _) => {
                stats.reused += 1;
                artifacts.push((stored, None));
            }
            (Listed::Fresh(_, slot), Some(android::Package::Scanned { records, bytes })) => {
                artifacts.push((Collected::new(records, 1, bytes)?, slot));
            }
            (Listed::Fresh(..), Some(android::Package::Unread)) => {
                let count = unread.entry(android::unread_name(path)).or_insert(0);
                *count = count.saturating_add(1);
            }
            // Every package that is to be read has a job.
            (Listed::Fresh(..), None) => {}
        }
    }
    if cache.is_some() {
        // One small file per artifact that was read, each on its own.
        pool.map_io(&artifacts, |(result, slot)| {
            slot.as_ref().is_some_and(|slot| slot.store(result))
        });
    }

    let mut evidence = EvidenceSet::new();
    for (result, _) in artifacts {
        stats.artifacts += 1;
        stats.files += result.files;
        stats.bytes += result.bytes;
        evidence.merge(result.evidence);
    }
    for (name, count) in unread {
        evidence.insert(android::unread(name, count))?;
    }
    extensions(found, &mut evidence, &mut stats)?;
    Ok((evidence, stats))
}

/// Reads the browser extensions of `found`, one after the other, and adds
/// their records and totals.
///
/// A manifest is a few kilobytes, so there is nothing to gain from the
/// pool, and reading one add-on archive at a time bounds what is held in
/// memory to one of them. For the same reason they are not kept in the
/// cache: every scan reads them again.
///
/// # Errors
///
/// Fails if the collector made a record that breaks the evidence format.
fn extensions(
    found: &Artifacts,
    evidence: &mut EvidenceSet,
    stats: &mut ScanStats,
) -> Result<(), EvidenceError> {
    // Extensions that were not read and cannot be told apart are counted
    // in one record.
    let mut unread: BTreeMap<browser::Unread, u32> = BTreeMap::new();
    for extension in &found.extensions {
        match browser::read(extension) {
            browser::Outcome::Scanned { records: read, files, bytes } => {
                stats.extensions += 1;
                stats.files += files;
                stats.bytes += bytes;
                for record in read {
                    evidence.insert(record)?;
                }
            }
            browser::Outcome::Unread(extension) => {
                let count = unread.entry(extension).or_insert(0);
                *count = count.saturating_add(1);
            }
        }
    }
    for (extension, count) in unread {
        evidence.insert(browser::unread(extension, count))?;
    }
    for (&(browser, reason), &count) in &found.unlisted {
        evidence.insert(browser::unlisted(browser, reason, count))?;
    }
    Ok(())
}
