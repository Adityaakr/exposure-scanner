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
//! Everything here is read-only. Nothing is extracted, executed or written,
//! and symbolic links inside an artifact are never followed, so a hostile
//! bundle cannot point the scanner at files outside itself.
//!
//! **Determinism while parallel** (design report, section 6.4). A file's
//! result is a function of its bytes and the rule pack alone. Results are
//! gathered in input order and enter an [`EvidenceSet`], which is keyed by
//! content hash, so neither thread timing nor the order of the paths given
//! can reach the output. Records hold paths relative to the artifact only;
//! where the artifact sits on disk is not recorded anywhere.

pub mod android;
pub mod discover;
mod electron;
pub mod macos;
pub mod read;
pub mod schedule;

use std::fmt;
use std::path::PathBuf;

use xs_match::Matchers;
use xs_model::EvidenceSet;
use xs_model::evidence::EvidenceError;

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
}

/// Totals of one scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Artifacts scanned.
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
            Self::Path { path, error } => write!(f, "cannot read {}: {error}", path.display()),
            Self::Unsupported(path) => write!(
                f,
                "{} is not a macOS application bundle, a folder of them or an Android package \
                 (.apk); other artifact kinds are not supported yet",
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
/// Each path is a macOS application bundle, a folder that holds bundles, or
/// an Android package (a file named `.apk`). A folder is not searched for
/// packages. Giving the same artifact twice, directly or through a symbolic
/// link, scans it once.
///
/// # Errors
///
/// Fails if a path does not exist or is not scannable, if an Android
/// package cannot be read to its end or changes while it is read, or if the
/// worker threads cannot be started. Unreadable or malformed files inside
/// an artifact do not fail the scan.
pub fn scan(
    paths: &[PathBuf],
    matchers: &Matchers<'_>,
    options: ScanOptions,
) -> Result<ScanOutcome, ScanError> {
    let found = discover::artifacts(paths)?;
    let pool = schedule::Pool::new(options.threads).map_err(ScanError::Threads)?;
    let (mut records, mut stats) = macos::collect(&found.bundles, matchers, &pool);
    let (package_records, package_stats) = android::collect(&found.packages, matchers, &pool)?;
    records.extend(package_records);
    stats.artifacts += package_stats.artifacts;
    stats.files += package_stats.files;
    stats.bytes += package_stats.bytes;

    let mut evidence = EvidenceSet::new();
    for record in records {
        evidence.insert(record)?;
    }
    Ok(ScanOutcome { evidence, stats })
}
