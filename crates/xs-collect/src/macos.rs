//! The macOS application bundle collector.
//!
//! It establishes a bundle's identity and gathers every kind of witness a
//! bundle offers (design report, section 5.1):
//!
//! * `Contents/Info.plist` gives the app id, version and name, and the
//!   address of the update feed, of which only the host is kept.
//! * The folder names under `Contents/Frameworks` are matched against the
//!   rule pack's `apple_framework` tokens.
//! * Every Mach-O file in the bundle is read in one pass that hashes it, so
//!   that two builds which share an app id and version are still two
//!   subjects, and searches it where the file itself says to look (the
//!   `binary` module does this): the libraries its load commands name
//!   (`macho_dylib`), its Objective-C class names (`macho_objc_class`),
//!   literals in its data (`macho_token`) and in an embedded script
//!   (`content_literal`).
//! * The code of an Electron app, its asar archives and loose scripts, is
//!   read by the `electron` module (build plan, task 7), which says what it
//!   draws from them. Its findings are records about the same bundle.
//! * The code signature of the main executable names the Apple Team ID,
//!   says whether the app asks for the App Sandbox, and holds its
//!   entitlements.
//! * What the app may access is what it asks for in two places: the usage
//!   descriptions of `Contents/Info.plist`, each with the purpose it states
//!   (`usage_description`), and the entitlements of the main executable
//!   (`entitlement`). These are access edges, graded `requested`. Whether
//!   the user allowed any of it is in the system's permission store, which
//!   is not part of the bundle and is not read.
//! * Every `PrivacyInfo.xcprivacy` file declares tracking domains
//!   (`privacy_manifest`).
//!
//! An SDK that is linked statically leaves no framework folder; its class
//! names in the main executable are what finds it. An encrypted binary is
//! reported as such instead of being searched as if it were readable.
//!
//! Every limit is a fixed budget, so a hostile bundle costs a bounded amount
//! of work and memory and gives the same result on every run: [`MAX_DEPTH`]
//! folders deep, [`MAX_ENTRIES`] directory entries of any kind,
//! [`MAX_FILE_BYTES`] per file read, [`MAX_LOCATED_GAPS`] coverage records
//! that name a place, and the property list parser's own budgets. What a
//! budget cuts off becomes an `over_budget` coverage record.
//!
//! The work is split in three so that the scan can schedule reading per
//! file across all artifacts at once (design report, section 6.2):
//!
//! 1. **plan** (per bundle): list the files, read the small property list.
//! 2. **read** (per file): one pass for hash and matches.
//! 3. **finish** (per bundle, pure): turn what was read into records.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use std::collections::BTreeSet;

use xs_formats::{Budget, FormatError, host, info_plist, macho, privacy_manifest};
use xs_match::{ContentMatcher as _, Finding, HitAcc, Matchers};
use xs_model::digest::BundleManifest;
use xs_model::record::{
    ArtifactRecord, Collector, CoverageReason, CoverageRecord, CoverageStatus, EdgeRecord,
    EdgeType, Facts, ObjectKind, ObjectRef, Platform, Proof, Record, Region, Scope, Subject,
    SubjectKind, V1, declared,
};
use xs_model::{MatcherKind, RelPath, Sha256Digest, canon, text};

use self::binary::{Binary, BinaryFindings};
use crate::access::Asked;
use crate::cache::{Listing, Seen, State};
use crate::electron;
use crate::read::{self, OnePass, Sink, WINDOW};

mod binary;

/// Deepest folder nesting the collector follows inside a bundle.
pub const MAX_DEPTH: u32 = 64;
/// Most directory entries the collector lists in one bundle. Files, folders,
/// links and everything else count alike, each once, in the folder that
/// holds it. A folder that holds more entries than are left of this budget
/// is not listed at all and is reported as over budget; nothing is drawn
/// from it. So every list the collector keeps per entry (a folder's listing,
/// the folders still to visit, the files to read, the framework names) holds
/// at most this many items.
pub const MAX_ENTRIES: usize = 1_000_000;
/// Most coverage records of one bundle that name a place inside it. Past
/// this, the records with the greatest paths are folded into one record per
/// status and reason that names no place and counts them.
pub const MAX_LOCATED_GAPS: usize = 1000;
/// Largest file the collector reads: 2 GiB. The budget applies to the files
/// it would read: those whose first bytes say Mach-O, and the archives and
/// loose scripts of an Electron app. A larger one is not read past its first
/// bytes; it is reported with its size, and the bundle digest covers that
/// size instead of a content hash. A file the collector
/// has no reason to read is ignored whatever its size. The largest file seen
/// in a real app was 485 MB.
pub const MAX_FILE_BYTES: u64 = 2 << 30;

const CONTENTS: &str = "Contents";
const INFO_PLIST: &str = "Contents/Info.plist";
const FRAMEWORKS: &str = "Contents/Frameworks";
/// The folder that holds the main executable, which `CFBundleExecutable`
/// names.
const MAIN_FOLDER: &str = "Contents/MacOS";
/// The file name Apple fixes for a privacy manifest, wherever it sits.
const PRIVACY_MANIFEST: &str = "PrivacyInfo.xcprivacy";

/// Frameworks that are an embedded browser engine. Their binaries hold the
/// names of ad and analytics hosts as data, so they are `runtime` files and
/// content matchers do not run on them (design report, section 5.2 control
/// 1: 65 of 71 `doubleclick.net` hits on real bundles sat in a browser
/// engine). Table matchers still do.
pub const RUNTIME_FRAMEWORKS: [&str; 3] = [
    "Chromium Embedded Framework.framework",
    "Electron Framework.framework",
    "QtWebEngineCore.framework",
];

/// What kind of code a Mach-O file is, and whose declaration a privacy
/// manifest is, from where the file sits in the bundle.
///
/// A file inside a browser-engine framework is `runtime`. Any other file
/// below a folder named `Frameworks` or `node_modules` is a `dependency`:
/// that is where a bundle keeps the libraries and the packages it ships.
/// Everything else, the main executable, helpers, plug-ins and extensions,
/// is the app's own code.
fn binary_scope(path: &RelPath) -> Scope {
    let mut folders = path.as_str().split('/');
    folders.next_back();
    let mut scope = Scope::AppCode;
    for folder in folders {
        if RUNTIME_FRAMEWORKS.contains(&folder) {
            return Scope::Runtime;
        }
        if folder == "Frameworks" || folder == electron::NODE_MODULES {
            scope = Scope::Dependency;
        }
    }
    scope
}

/// Whether `path` is a privacy manifest, going by its file name.
fn is_privacy_manifest(path: &RelPath) -> bool {
    path.as_str().rsplit('/').next() == Some(PRIVACY_MANIFEST)
}

/// A gap at a known place, keyed so that equal gaps add up and ordered by
/// path. The last part is the size of a file over the byte budget.
type LocatedGap = (RelPath, CoverageStatus, CoverageReason, Option<u64>);

/// What the collector could not cover.
///
/// At most [`MAX_LOCATED_GAPS`] gaps keep their place: the ones with the
/// least keys, whatever order they were found in. The rest are counted
/// under their status and reason alone.
#[derive(Default)]
struct Gaps {
    located: BTreeMap<LocatedGap, u32>,
    unlocated: BTreeMap<(CoverageStatus, CoverageReason), u32>,
}

impl Gaps {
    /// Records `count` things that were not covered. Zero records nothing.
    fn add(
        &mut self,
        status: CoverageStatus,
        reason: CoverageReason,
        location: Option<RelPath>,
        bytes: Option<u64>,
        count: u32,
    ) {
        if count == 0 {
            return;
        }
        let mut fold = |status, reason, count: u32| {
            let total = self.unlocated.entry((status, reason)).or_insert(0);
            *total = total.saturating_add(count);
        };
        let Some(path) = location else { return fold(status, reason, count) };
        let total = self.located.entry((path, status, reason, bytes)).or_insert(0);
        *total = total.saturating_add(count);
        if self.located.len() > MAX_LOCATED_GAPS
            && let Some(((_, status, reason, _), count)) = self.located.pop_last()
        {
            fold(status, reason, count);
        }
    }

    fn skipped(&mut self, reason: CoverageReason, location: Option<RelPath>) {
        self.add(CoverageStatus::Skipped, reason, location, None, 1);
    }

    fn unrecognized(&mut self, reason: CoverageReason, location: Option<RelPath>) {
        self.add(CoverageStatus::Unrecognized, reason, location, None, 1);
    }
}

/// What is known about a bundle before its files are read.
pub(crate) struct Plan {
    root: PathBuf,
    /// The bundle folder's own name, used as the app id only when the
    /// property list gives none.
    folder_name: String,
    info: Option<info_plist::BundleInfo>,
    manifest: BundleManifest,
    /// Names of the real folders under `Contents/Frameworks`, sorted.
    frameworks: Vec<String>,
    /// Regular files to consider, with their sizes.
    files: Vec<(RelPath, u64)>,
    /// Everything the listing saw, for the results cache: what tells this
    /// state of the bundle from another without reading it.
    listing: Listing,
    gaps: Gaps,
    files_read: u64,
    bytes_read: u64,
}

impl Plan {
    /// The sizes of the files to consider, as the listing saw them. A file's
    /// place in this list is what `read` and `finish` know it by.
    pub(crate) fn sizes(&self) -> impl Iterator<Item = u64> + '_ {
        self.files.iter().map(|(_, size)| *size)
    }

    /// The state the bundle was listed in, as far as the file system tells
    /// it without any file being read: every name and every kind of entry
    /// the listing saw, and of each regular file what [`Listing::file`]
    /// adds. Whatever the collector goes by when it lists is in it, so a
    /// bundle in the same state is read into the same records.
    pub(crate) fn state(&self) -> State {
        self.listing.state()
    }

    /// Sets aside a file of `bytes` bytes, which is over [`MAX_FILE_BYTES`].
    ///
    /// The digest covers the exact size. The record carries it only up to
    /// the largest integer canonical JSON can hold, so that a file of any
    /// size the file system allows still yields a record.
    fn over_budget(&mut self, path: RelPath, bytes: u64) {
        self.manifest.over_budget(path.clone(), bytes);
        self.gaps.add(
            CoverageStatus::Skipped,
            CoverageReason::OverBudget,
            Some(path),
            Some(bytes.min(canon::MAX_SAFE_INTEGER)),
            1,
        );
    }
}

/// What reading one file of a bundle produced, for `finish` to take in.
///
/// A scan holds one of these per file it listed until the last file is
/// read, and most files of a bundle are not ones the collector reads. So
/// such a file costs a word here, and only a file that was read has a
/// result behind it.
pub(crate) struct FileRead(Option<Box<FileResult>>);

/// What reading one file produced.
enum FileResult {
    /// Not a kind of file the collector reads. It cost one small read.
    NotCandidate,
    /// A Mach-O file, read to the end.
    Binary {
        /// SHA-256 of the whole file.
        sha256: Sha256Digest,
        /// Its length.
        bytes: u64,
        /// What was found in it.
        found: BinaryFindings,
    },
    /// A privacy manifest, read whole.
    Manifest {
        /// SHA-256 of the whole file.
        sha256: Sha256Digest,
        /// Its length.
        bytes: u64,
        /// The tracking domains it declares, as written.
        declared: Result<Vec<String>, FormatError>,
    },
    /// A loose script of an Electron app, read to the end and searched.
    Script(OnePass),
    /// An asar archive, read to the end and searched.
    Archive(electron::ArchiveScan),
    /// A file the collector reads, but larger than the byte budget: its size.
    OverBudget(u64),
    /// The file system refused.
    Failed,
}

/// Lists the bundle at `root` and reads its property list.
///
/// A bundle that cannot be listed is not an error: it yields a plan with no
/// files, and the record that says so.
pub(crate) fn plan(root: &Path) -> Plan {
    plan_within(root, MAX_ENTRIES)
}

/// Reads one file of a planned bundle, the one at place `file` of
/// [`Plan::sizes`]: one pass for its hash and for what is found in it.
pub(crate) fn read(plan: &Plan, file: usize, matchers: &Matchers<'_>) -> FileRead {
    let result = match plan.files.get(file) {
        Some((path, _)) => {
            read_file(&plan.root.join(path.as_str()), path, matchers, MAX_FILE_BYTES)
        }
        None => FileResult::Failed,
    };
    FileRead(match result {
        FileResult::NotCandidate => None,
        result => Some(Box::new(result)),
    })
}

fn rel(path: &str) -> Option<RelPath> {
    RelPath::new(path).ok()
}

/// Lists a bundle, at most `max_entries` directory entries of it, and reads
/// its property list.
fn plan_within(root: &Path, max_entries: usize) -> Plan {
    let folder_name =
        root.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let mut plan = Plan {
        root: root.to_path_buf(),
        folder_name,
        info: None,
        manifest: BundleManifest::new(),
        frameworks: Vec::new(),
        files: Vec::new(),
        listing: Listing::new(),
        gaps: Gaps::default(),
        files_read: 0,
        bytes_read: 0,
    };
    walk(&mut plan, max_entries);
    plan
}

/// Reads the property list. Called when the walk lists it, so that a link
/// named `Contents` cannot stand another bundle in for this one.
fn read_info_plist(plan: &mut Plan) {
    let location = rel(INFO_PLIST);
    let path = plan.root.join(INFO_PLIST);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            plan.listing.note(Seen::Refused);
            return if error.kind() == io::ErrorKind::NotFound {
                plan.gaps.unrecognized(CoverageReason::ParseError, location)
            } else {
                plan.gaps.skipped(CoverageReason::Unreadable, location)
            };
        }
    };
    if !metadata.is_file() {
        // A link or a folder where the property list belongs.
        plan.listing.note(Seen::Other);
        return plan.gaps.unrecognized(CoverageReason::ParseError, location);
    }
    plan.listing.file(&metadata);
    let limit = info_plist::MAX_BYTES as u64;
    if metadata.len() > limit {
        return plan.gaps.skipped(CoverageReason::OverBudget, location);
    }
    let mut bytes = Vec::new();
    // One byte past the limit, so a file that grew since the stat is noticed.
    let read = File::open(&path).and_then(|file| file.take(limit + 1).read_to_end(&mut bytes));
    if read.is_err() {
        return plan.gaps.skipped(CoverageReason::Unreadable, location);
    }
    if bytes.len() as u64 > limit {
        return plan.gaps.skipped(CoverageReason::OverBudget, location);
    }

    if let Some(location) = location.clone() {
        plan.manifest.file(location, Sha256Digest::of(&bytes));
    }
    plan.files_read += 1;
    plan.bytes_read += bytes.len() as u64;
    match info_plist::parse(&bytes) {
        Ok(info) => plan.info = Some(info),
        Err(FormatError::OverBudget(Budget::Bytes | Budget::Items | Budget::Depth)) => {
            plan.gaps.skipped(CoverageReason::OverBudget, location);
        }
        Err(FormatError::Malformed) => plan.gaps.unrecognized(CoverageReason::ParseError, location),
    }
}

/// Lists the bundle without following symbolic links: the regular files to
/// read, and the names of the real folders under `Contents/Frameworks`.
///
/// Only folders count as frameworks: a file or a symbolic link with a
/// framework's name is not one, and `Contents/Frameworks` itself must be a
/// real folder. That listing enters the bundle digest, because evidence is
/// drawn from it.
///
/// The layout names (`Contents`, and `Frameworks` and `Info.plist` in it)
/// are taken exactly as the listing spells them, never as a path for the
/// file system to resolve, so a bundle gives the same evidence on a volume
/// that ignores letter case as on one that does not. A name that differs
/// from one of them only in case is reported, and what sits there is not
/// treated as that part of the layout.
///
/// Every entry of every folder listed counts against `max_entries`. A folder
/// with more entries than are left of that budget is skipped whole and
/// reported as over budget, and nothing is drawn from it. The order of the
/// visit is fixed: a folder's own entries in name order, then its sub-folders
/// in name order, each to its full depth. Both rules look only at names and
/// counts, so the budget cuts at the same place whatever order the file
/// system returns entries in.
fn walk(plan: &mut Plan, max_entries: usize) {
    let mut left = max_entries;
    // Depth-first with an explicit stack: nesting is bounded by the budget,
    // not by the call stack.
    let mut pending: Vec<(PathBuf, Option<RelPath>, u32)> = vec![(plan.root.clone(), None, 0)];
    while let Some((dir, dir_rel, depth)) = pending.pop() {
        let listed_as = dir_rel.as_ref().map_or("", RelPath::as_str);
        plan.listing.name(Seen::Listed, listed_as.as_bytes());
        let Ok(entries) = fs::read_dir(&dir) else {
            plan.listing.note(Seen::Refused);
            plan.gaps.skipped(CoverageReason::Unreadable, dir_rel);
            continue;
        };
        let mut listed = Vec::new();
        let mut over_budget = false;
        let mut complete = true;
        for entry in entries {
            match entry {
                Ok(_) if listed.len() >= left => {
                    over_budget = true;
                    break;
                }
                Ok(entry) => listed.push((entry.file_name(), entry.file_type())),
                Err(_) => {
                    complete = false;
                    plan.listing.note(Seen::Refused);
                    plan.gaps.skipped(CoverageReason::Unreadable, dir_rel.clone());
                }
            }
        }
        if over_budget {
            plan.listing.note(Seen::OverBudget);
            plan.gaps.skipped(CoverageReason::OverBudget, dir_rel);
            continue;
        }
        left -= listed.len();
        listed.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        // The property list is missing only if a whole listing shows that
        // it, or the folder that holds it, is not there. A folder that could
        // not be listed has its own record and says nothing about the file.
        let holds = |leaf: &str| listed.iter().any(|(name, _)| name == leaf);
        let plist_missing = match dir_rel.as_ref().map(RelPath::as_str) {
            None => !holds(CONTENTS),
            Some(CONTENTS) => !holds("Info.plist"),
            Some(_) => false,
        };
        if complete && plist_missing {
            plan.gaps.unrecognized(CoverageReason::ParseError, rel(INFO_PLIST));
        }
        let frameworks = dir_rel.as_ref().is_some_and(|dir| dir.as_str() == FRAMEWORKS);
        let mut folders = Vec::new();
        for (name, kind) in listed {
            let seen = match &kind {
                Ok(kind) if kind.is_dir() => Seen::Folder,
                Ok(kind) if kind.is_file() => Seen::File,
                Ok(kind) if kind.is_symlink() => Seen::Link,
                Ok(_) => Seen::Other,
                Err(_) => Seen::Refused,
            };
            plan.listing.name(seen, name.as_encoded_bytes());
            let path = name.to_str().and_then(|name| match &dir_rel {
                Some(parent) => parent.join(name).ok().map(|path| (name, path)),
                None => rel(name).map(|path| (name, path)),
            });
            let Some((name, path)) = path else {
                // The name is not UTF-8, holds a control character or makes
                // the path too long. It cannot be stored, so only counted.
                plan.gaps.skipped(CoverageReason::Unreadable, None);
                continue;
            };
            let miscased = [CONTENTS, FRAMEWORKS, INFO_PLIST].iter().any(|expected| {
                let (parent, leaf) = match expected.rsplit_once('/') {
                    Some((parent, leaf)) => (Some(parent), leaf),
                    None => (None, *expected),
                };
                dir_rel.as_ref().map(RelPath::as_str) == parent
                    && name != leaf
                    && name.eq_ignore_ascii_case(leaf)
            });
            if miscased {
                plan.gaps.skipped(CoverageReason::UnexpectedCase, Some(path.clone()));
            }
            let Ok(kind) = kind else {
                plan.gaps.skipped(CoverageReason::Unreadable, Some(path));
                continue;
            };
            if path.as_str() == INFO_PLIST {
                read_info_plist(plan);
                if !kind.is_dir() {
                    continue;
                }
            }
            if kind.is_dir() {
                if frameworks {
                    plan.frameworks.push(name.to_string());
                }
                if depth + 1 >= MAX_DEPTH {
                    plan.gaps.skipped(CoverageReason::OverBudget, Some(path));
                } else {
                    folders.push((dir.join(name), Some(path), depth + 1));
                }
                continue;
            }
            if path.as_str() == CONTENTS {
                // A link or a file where the contents folder belongs.
                plan.gaps.unrecognized(CoverageReason::ParseError, Some(path.clone()));
            }
            if path.as_str() == FRAMEWORKS {
                // A link or a file where the frameworks folder belongs.
                plan.gaps.unrecognized(CoverageReason::ParseError, Some(path.clone()));
            }
            if kind.is_symlink() {
                // Never followed. Its target, if inside the bundle, is
                // reached by its real path.
            } else if kind.is_file() {
                match fs::symlink_metadata(dir.join(name)) {
                    Ok(metadata) if metadata.is_file() => {
                        plan.listing.file(&metadata);
                        plan.files.push((path, metadata.len()));
                    }
                    _ => {
                        plan.listing.note(Seen::Refused);
                        plan.gaps.skipped(CoverageReason::Unreadable, Some(path));
                    }
                }
            } else {
                // A socket, pipe or device node. Not app content.
                plan.gaps.skipped(CoverageReason::UnsupportedFormat, Some(path));
            }
        }
        if let Some(location) = dir_rel.filter(|_| frameworks) {
            plan.manifest.listing(location, plan.frameworks.iter().map(String::as_str));
        }
        // The stack gives back the last folder first.
        pending.extend(folders.into_iter().rev());
    }
    // The visit goes folder by folder, which is not path order.
    plan.files.sort_unstable();
}

thread_local! {
    /// One read buffer per worker thread, reused for every file.
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Reads a privacy manifest whole. It is a small property list; one over
/// the property-list budget is set aside with its size, like a Mach-O file
/// over its budget.
fn read_manifest(path: &Path) -> FileResult {
    let limit = privacy_manifest::MAX_BYTES as u64;
    let Ok(file) = File::open(path) else { return FileResult::Failed };
    let size = |read: u64| file.metadata().map_or(read, |metadata| metadata.len().max(read));
    match file.metadata() {
        Ok(metadata) if metadata.len() > limit => return FileResult::OverBudget(metadata.len()),
        Ok(_) => {}
        Err(_) => return FileResult::Failed,
    }
    let mut bytes = Vec::new();
    // One byte past the limit, so a file that grew since the stat is noticed.
    if (&file).take(limit + 1).read_to_end(&mut bytes).is_err() {
        return FileResult::Failed;
    }
    if bytes.len() as u64 > limit {
        return FileResult::OverBudget(size(bytes.len() as u64));
    }
    FileResult::Manifest {
        sha256: Sha256Digest::of(&bytes),
        bytes: bytes.len() as u64,
        declared: privacy_manifest::parse(&bytes).map(|manifest| manifest.tracking_domains),
    }
}

/// A [`Sink`] that searches a whole file as one stream of script text.
struct ScriptSearch<'m> {
    content: &'m xs_match::ContentEngine,
    hits: HitAcc,
}

impl Sink for ScriptSearch<'_> {
    fn overlap(&self) -> usize {
        self.content.overlap()
    }

    fn window(&mut self, view: &[u8], carry: usize, last: bool) {
        self.content.scan(view, carry, last, &mut self.hits);
    }
}

/// Reads one file of a bundle, `location` being its path inside it, the way
/// its place in the bundle calls for.
///
/// A privacy manifest is read whole. An asar archive and a loose script of
/// an Electron app are read by their path (see [`electron`]). Any other
/// file is read in a single pass if its first bytes say it is a Mach-O
/// file, and given up on after one small read otherwise.
///
/// A Mach-O file larger than `budget` is set aside after that one small
/// read. One that grows while it is being read stops one byte past `budget`
/// and is reported the same way, so the read is bounded in every case.
fn read_file(path: &Path, location: &RelPath, matchers: &Matchers<'_>, budget: u64) -> FileResult {
    if is_privacy_manifest(location) {
        return read_manifest(path);
    }
    match electron::classify(location.as_str()) {
        electron::FileKind::Archive { dependency } => {
            match electron::read_archive(path, dependency, matchers, budget) {
                electron::ArchiveRead::Scanned(scan) => FileResult::Archive(scan),
                electron::ArchiveRead::OverBudget(bytes) => FileResult::OverBudget(bytes),
                electron::ArchiveRead::Failed => FileResult::Failed,
            }
        }
        electron::FileKind::Script { scope, .. } => {
            let content = matchers.content(MatcherKind::ContentLiteral, scope);
            let search = ScriptSearch { content, hits: HitAcc::new() };
            read_matching(
                path,
                search,
                budget,
                |_| true,
                |search, sha256, bytes| {
                    FileResult::Script(OnePass { sha256, bytes, hits: search.hits })
                },
            )
        }
        electron::FileKind::Other => {
            let binary = Binary::new(matchers, binary_scope(location));
            let is_macho = |head: &[u8]| macho::sniff(head).is_some();
            read_matching(path, binary, budget, is_macho, |binary, sha256, bytes| {
                FileResult::Binary { sha256, bytes, found: binary.finish() }
            })
        }
    }
}

/// Reads one file into `sink` in a single pass if `candidate` says so of
/// its first bytes, within `budget` as [`read_file`] describes. A file read
/// to the end is what `done` makes of the sink, the file's hash and its
/// length.
fn read_matching<S: Sink>(
    path: &Path,
    mut sink: S,
    budget: u64,
    candidate: impl Fn(&[u8]) -> bool,
    done: impl FnOnce(S, Sha256Digest, u64) -> FileResult,
) -> FileResult {
    let Ok(file) = File::open(path) else { return FileResult::Failed };
    let mut bounded = (&file).take(budget.saturating_add(1));
    SCRATCH.with_borrow_mut(|buf| {
        let needed = read::buffer_len_for(sink.overlap(), WINDOW);
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        let mut oversize = None;
        let wanted = |head: &[u8]| {
            if !candidate(head) {
                return false;
            }
            match file.metadata() {
                Ok(metadata) if metadata.len() > budget => {
                    oversize = Some(metadata.len());
                    false
                }
                _ => true,
            }
        };
        match read::pass(&mut bounded, buf, WINDOW, &mut sink, wanted) {
            Ok(Some((_, bytes))) if bytes > budget => match file.metadata() {
                Ok(metadata) => FileResult::OverBudget(metadata.len().max(bytes)),
                Err(_) => FileResult::Failed,
            },
            Ok(Some((sha256, bytes))) => done(sink, sha256, bytes),
            Ok(None) => oversize.map_or(FileResult::NotCandidate, FileResult::OverBudget),
            Err(_) => FileResult::Failed,
        }
    })
}

/// An edge to the SDK of the rule whose token was found.
fn sdk_edge(
    subject: &Subject,
    finding: Finding<'_>,
    location: &RelPath,
    region: Region,
    scope: Scope,
) -> Record {
    Record::Edge(EdgeRecord {
        v: V1,
        collector: Collector::MacosBundle,
        subject: subject.clone(),
        edge: EdgeType::Channel,
        grade: finding.matcher.grade(),
        object: ObjectRef { kind: ObjectKind::Sdk, id: finding.rule.id.clone() },
        rule: finding.rule.id.clone(),
        proof: Proof {
            matcher: finding.matcher,
            token: finding.token.lit.clone(),
            count: finding.count,
            example: finding.example,
            location: location.clone(),
            region,
            scope,
            max_sdk: None,
        },
    })
}

/// Hosts a property list declares under one key, and what they are
/// evidence of.
struct Declaration<'a> {
    /// The kind of witness: which declaration this is.
    matcher: MatcherKind,
    /// The built-in rule the host edges name.
    rule: &'static str,
    /// The key of the property list that holds the hosts.
    key: &'static str,
    /// The property list.
    location: &'a RelPath,
    /// Whose declaration it is.
    scope: Scope,
}

impl Declaration<'_> {
    /// The records for `hosts`: an edge to each host as itself.
    ///
    /// A host is shown whether or not a rule knows it. Who owns it is not
    /// decided here.
    fn records(&self, hosts: &BTreeSet<String>, subject: &Subject, records: &mut Vec<Record>) {
        for host in hosts {
            records.push(Record::Edge(EdgeRecord {
                v: V1,
                collector: Collector::MacosBundle,
                subject: subject.clone(),
                edge: EdgeType::Channel,
                grade: self.matcher.grade(),
                object: ObjectRef { kind: ObjectKind::Host, id: host.clone() },
                rule: self.rule.into(),
                proof: Proof {
                    matcher: self.matcher,
                    token: self.key.into(),
                    count: 1,
                    example: None,
                    location: self.location.clone(),
                    region: Region::PropertyList,
                    scope: self.scope,
                    max_sdk: None,
                },
            }));
        }
    }
}

/// The host a declaration names, in the one spelling a record stores.
fn declared_host(text: &str, reduce: impl Fn(&str) -> Option<String>) -> Option<String> {
    reduce(text).filter(|host| text::is_host(host))
}

/// Turns a plan and what was read into records, with the number of files
/// and of bytes that were read. Pure.
///
/// `results` pairs a file's place in [`Plan::sizes`] with what `read` made
/// of it, in any order.
pub(crate) fn finish(
    mut plan: Plan,
    results: Vec<(usize, FileRead)>,
    matchers: &Matchers<'_>,
) -> (Vec<Record>, u64, u64) {
    // The code of an Electron app: its archives and loose scripts.
    let mut code = electron::Roots::default();
    for (path, _) in &plan.files {
        code.listed(path, matchers);
    }
    let mut binaries: Vec<(RelPath, BinaryFindings)> = Vec::new();
    let mut manifests: Vec<(RelPath, Result<Vec<String>, FormatError>)> = Vec::new();
    for (file, FileRead(result)) in results {
        let (Some((path, _)), Some(result)) = (plan.files.get(file), result) else { continue };
        let path = path.clone();
        match *result {
            FileResult::NotCandidate => {}
            FileResult::Binary { sha256, bytes, found } => {
                plan.manifest.file(path.clone(), sha256);
                plan.files_read += 1;
                plan.bytes_read += bytes;
                binaries.push((path, found));
            }
            FileResult::Script(pass) => {
                plan.manifest.file(path.clone(), pass.sha256);
                plan.files_read += 1;
                plan.bytes_read += pass.bytes;
                code.script(&path, &pass.hits, matchers);
            }
            FileResult::Archive(scan) => {
                plan.manifest.file(path.clone(), scan.sha256);
                plan.files_read += 1;
                plan.bytes_read += scan.bytes;
                code.archive(&path, scan);
            }
            FileResult::Manifest { sha256, bytes, declared } => {
                plan.manifest.file(path.clone(), sha256);
                plan.files_read += 1;
                plan.bytes_read += bytes;
                manifests.push((path, declared));
            }
            FileResult::OverBudget(bytes) => plan.over_budget(path, bytes),
            FileResult::Failed => plan.gaps.skipped(CoverageReason::Unreadable, Some(path)),
        }
    }
    // Before the digest is taken: the listings evidence is drawn from enter
    // the manifest here.
    let (code_edges, code_gaps) = code.finish(matchers, &mut plan.manifest);
    for (location, status, reason, items) in code_gaps {
        plan.gaps.add(status, reason, location, None, items);
    }
    // Results arrive largest file first. Records are a set, but the lists
    // below are walked in path order so that nothing depends on sizes.
    binaries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
    manifests.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

    // A value the property list declares but leaves empty is no value, so
    // each one is cleaned and checked before the next is considered.
    let stated = |value: Option<String>, max_bytes: usize| {
        value.map(|value| text::clean(&value, max_bytes)).filter(|value| !value.is_empty())
    };
    let parsed = plan.info.is_some();
    let info = plan.info.unwrap_or_default();
    let id = match stated(info.identifier, text::MAX_ID_BYTES) {
        Some(id) => id,
        None => {
            // No usable app id: fall back to the folder's name so that the
            // bundle's findings still have a subject. A property list that
            // could not be read already left its own coverage record; one
            // that parsed but names no id is reported here.
            if parsed {
                plan.gaps.unrecognized(CoverageReason::ParseError, rel(INFO_PLIST));
            }
            let name = text::clean(&plan.folder_name, text::MAX_ID_BYTES);
            if name.is_empty() { String::from("unnamed.app") } else { name }
        }
    };
    let version = stated(info.short_version, text::MAX_VERSION_BYTES)
        .or_else(|| stated(info.build_version, text::MAX_VERSION_BYTES));
    let subject = Subject {
        kind: SubjectKind::App,
        platform: Platform::Macos,
        id,
        version,
        digest: plan.manifest.digest(),
    };

    let mut records = Vec::new();

    // The Team ID is the one the main executable's signature names. A
    // universal file whose images name different teams names none.
    let declared_main =
        info.executable.as_deref().and_then(|name| rel(MAIN_FOLDER)?.join(name).ok());
    let main =
        declared_main.as_ref().and_then(|path| binaries.iter().find(|(binary, _)| binary == path));
    // The main executable the property list names was not read as a Mach-O
    // file: it is a link, which is never followed, a script, or not there.
    // Then its signature was not looked at, and what it asks for is not
    // known. A file that was set aside already has its record.
    if let (None, Some(path)) = (main, declared_main)
        && !plan.gaps.located.keys().any(|(place, ..)| *place == path)
    {
        plan.gaps.skipped(CoverageReason::UnsupportedFormat, Some(path));
    }
    let team_id = match main {
        Some((path, found)) if found.team_ids.len() > 1 => {
            plan.gaps.unrecognized(CoverageReason::ParseError, Some(path.clone()));
            None
        }
        Some((_, found)) => found.team_ids.first().cloned(),
        None => None,
    };
    // What the main executable's signature asks for. The entitlements of a
    // helper or a library are its own and say nothing about the app.
    let sandbox = main.and_then(|(_, found)| found.sandbox());
    if let Some((location, found)) = main {
        records.extend(found.entitlements.iter().filter_map(|(key, &count)| {
            Asked {
                collector: Collector::MacosBundle,
                matcher: MatcherKind::Entitlement,
                key,
                count,
                purpose: None,
                location,
                region: Region::Entitlements,
                max_sdk: None,
            }
            .edge(&subject)
        }));
    }
    // What the property list asks for, each with the purpose it states. A
    // usage description under a key this build has no permission for was
    // read and not understood.
    if let Some(location) = rel(INFO_PLIST) {
        let mut unknown: u32 = 0;
        for (key, purpose) in &info.usage_descriptions {
            let asked = Asked {
                collector: Collector::MacosBundle,
                matcher: MatcherKind::UsageDescription,
                key,
                count: 1,
                purpose: Some(purpose),
                location: &location,
                region: Region::PropertyList,
                max_sdk: None,
            };
            match asked.edge(&subject) {
                Some(record) => records.push(record),
                None => unknown = unknown.saturating_add(1),
            }
        }
        let gaps = [
            (CoverageStatus::Unrecognized, CoverageReason::UnrecognizedRecord, unknown),
            (CoverageStatus::Skipped, CoverageReason::OverBudget, info.usage_descriptions_dropped),
        ];
        for (status, reason, count) in gaps {
            plan.gaps.add(status, reason, Some(location.clone()), None, count);
        }
    }
    let name = stated(info.display_name, text::MAX_NAME_BYTES)
        .or_else(|| stated(info.name, text::MAX_NAME_BYTES));
    records.push(Record::Artifact(ArtifactRecord {
        v: V1,
        collector: Collector::MacosBundle,
        subject: subject.clone(),
        facts: Facts {
            name,
            team_id,
            sandbox,
            files_scanned: plan.files_read,
            bytes_scanned: plan.bytes_read,
            ..Facts::default()
        },
    }));

    if let Some(location) = rel(FRAMEWORKS) {
        // The folder listing is one table: every name is matched, then the
        // hits are judged together.
        let scope = Scope::Dependency;
        let mut hits = HitAcc::new();
        for folder in &plan.frameworks {
            matchers.match_value(MatcherKind::AppleFramework, scope, folder.as_bytes(), &mut hits);
        }
        for finding in matchers.judge(&hits).edges {
            records.push(sdk_edge(&subject, finding, &location, Region::DirEntries, scope));
        }
    }

    for (path, found) in binaries {
        // What the file is by where it sits. That is also what a script it
        // carries is; the file around a script is the script's runtime.
        let placed = binary_scope(&path);
        let file_scope = if found.has_script { Scope::Runtime } else { placed };
        // The hits of one file are judged together, whatever part of the
        // file each came from.
        for finding in matchers.judge(&found.hits).edges {
            let (region, scope) = match finding.matcher {
                MatcherKind::MachoObjcClass => (Region::ObjcClassname, file_scope),
                MatcherKind::MachoDylib => (Region::LoadCommands, file_scope),
                MatcherKind::ContentLiteral => (Region::EmbeddedScript, placed),
                _ => (Region::NonCode, file_scope),
            };
            records.push(sdk_edge(&subject, finding, &path, region, scope));
        }
        let gaps = [
            (CoverageStatus::Skipped, CoverageReason::EncryptedBinary, found.encrypted),
            (CoverageStatus::Unrecognized, CoverageReason::ParseError, found.malformed),
            (CoverageStatus::Skipped, CoverageReason::OverBudget, found.over_budget),
            (CoverageStatus::Skipped, CoverageReason::UnsupportedFormat, found.unsupported),
        ];
        for (status, reason, count) in gaps {
            plan.gaps.add(status, reason, Some(path.clone()), None, count);
        }
    }

    for (path, listed) in manifests {
        let listed = match listed {
            Ok(listed) => listed,
            Err(FormatError::OverBudget(Budget::Bytes | Budget::Items | Budget::Depth)) => {
                plan.gaps.skipped(CoverageReason::OverBudget, Some(path));
                continue;
            }
            Err(FormatError::Malformed) => {
                plan.gaps.unrecognized(CoverageReason::ParseError, Some(path));
                continue;
            }
        };
        let mut hosts = BTreeSet::new();
        let mut not_hosts: u32 = 0;
        for entry in listed {
            match declared_host(&entry, host::of_name) {
                Some(host) => {
                    hosts.insert(host);
                }
                None => not_hosts = not_hosts.saturating_add(1),
            }
        }
        // An entry that is not a host name was read and not understood.
        plan.gaps.add(
            CoverageStatus::Unrecognized,
            CoverageReason::ParseError,
            Some(path.clone()),
            None,
            not_hosts,
        );
        let scope = binary_scope(&path);
        // The listed hosts are one table: every one is matched, then the
        // hits are judged together.
        let mut hits = HitAcc::new();
        for host in &hosts {
            matchers.match_value(MatcherKind::PrivacyManifest, scope, host.as_bytes(), &mut hits);
        }
        for finding in matchers.judge(&hits).edges {
            records.push(sdk_edge(&subject, finding, &path, Region::PropertyList, scope));
        }
        Declaration {
            matcher: MatcherKind::PrivacyManifest,
            rule: declared::TRACKING_DOMAIN,
            key: privacy_manifest::TRACKING_DOMAINS_KEY,
            location: &path,
            scope,
        }
        .records(&hosts, &subject, &mut records);
    }

    // An address that is left empty declares nothing. One that is there and
    // cannot be reduced to a host was read and not understood.
    let feed = info.feed_url.filter(|address| !address.trim().is_empty());
    if let (Some(address), Some(location)) = (feed, rel(INFO_PLIST)) {
        match declared_host(&address, host::of_url) {
            Some(host) => Declaration {
                matcher: MatcherKind::UpdateFeed,
                rule: declared::UPDATE_FEED,
                key: info_plist::FEED_URL_KEY,
                location: &location,
                scope: Scope::AppCode,
            }
            .records(&BTreeSet::from([host]), &subject, &mut records),
            None => plan.gaps.unrecognized(CoverageReason::ParseError, Some(location)),
        }
    }

    for found in code_edges {
        records.push(Record::Edge(EdgeRecord {
            v: V1,
            collector: Collector::ElectronApp,
            subject: subject.clone(),
            edge: EdgeType::Channel,
            grade: found.proof.matcher.grade(),
            object: ObjectRef { kind: ObjectKind::Sdk, id: found.rule.clone() },
            rule: found.rule,
            proof: found.proof,
        }));
    }

    let located =
        plan.gaps.located.into_iter().map(|((path, status, reason, bytes), count)| {
            (status, reason, Some(path), bytes, count)
        });
    let unlocated = plan
        .gaps
        .unlocated
        .into_iter()
        .map(|((status, reason), count)| (status, reason, None, None, count));
    for (status, reason, location, bytes, count) in located.chain(unlocated) {
        records.push(Record::Coverage(CoverageRecord {
            v: V1,
            collector: Collector::MacosBundle,
            subject: subject.clone(),
            status,
            reason,
            location,
            bytes,
            count,
        }));
    }
    (records, plan.files_read, plan.bytes_read)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use xs_model::Pack;
    use xs_model::matcher::Boundary;
    use xs_model::pack::{Category, Layer, LoadedLayer, Rule, Token};

    use super::*;

    /// A pack with one rule, `sdk/sample`, that holds `tokens`.
    pub(super) fn pack_with(tokens: &[(MatcherKind, &str, Boundary)]) -> Pack {
        let mut matchers: BTreeMap<MatcherKind, Vec<Token>> = BTreeMap::new();
        for &(matcher, literal, at) in tokens {
            matchers.entry(matcher).or_default().push(Token { lit: literal.into(), at });
        }
        pack(vec![Rule {
            id: "sdk/sample".into(),
            name: "Sample".into(),
            entity: None,
            category: "component".into(),
            sources: vec![],
            notes: vec![],
            matchers,
            min_distinct: BTreeMap::new(),
        }])
    }

    fn location(path: &str) -> RelPath {
        RelPath::new(path).unwrap()
    }

    /// Design report, section 5.2 control 1, for Mach-O files: the scope
    /// follows from where a file sits and from nothing else.
    #[test]
    fn a_binary_s_scope_follows_from_where_it_sits() {
        for (path, scope) in [
            ("Contents/MacOS/Example", Scope::AppCode),
            ("Contents/PlugIns/Share.appex/Contents/MacOS/Share", Scope::AppCode),
            ("Contents/Library/LoginItems/Helper.app/Contents/MacOS/Helper", Scope::AppCode),
            ("Contents/Resources/tool", Scope::AppCode),
            ("Wrapper/Example.app/Example", Scope::AppCode),
            ("Contents/Frameworks/Sentry.framework/Versions/A/Sentry", Scope::Dependency),
            ("Contents/Frameworks/libswiftCore.dylib", Scope::Dependency),
            (
                "Contents/Frameworks/Sparkle.framework/Versions/B/Updater.app/Contents/MacOS/Updater",
                Scope::Dependency,
            ),
            ("Contents/PlugIns/Share.appex/Contents/Frameworks/X.framework/X", Scope::Dependency),
            (
                "Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework",
                Scope::Runtime,
            ),
            (
                "Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/libffmpeg.dylib",
                Scope::Runtime,
            ),
            (
                "Contents/Frameworks/Chromium Embedded Framework.framework/Chromium Embedded Framework",
                Scope::Runtime,
            ),
            // A file that is merely named like one is not inside one.
            ("Contents/MacOS/Electron Framework.framework", Scope::AppCode),
            ("Contents/MacOS/Frameworks", Scope::AppCode),
            (
                "Contents/Resources/app.asar.unpacked/node_modules/keytar/build/Release/keytar.node",
                Scope::Dependency,
            ),
            ("Contents/Resources/app/node_modules/a/node_modules/b/b.node", Scope::Dependency),
            (
                "Contents/Frameworks/Electron Framework.framework/Resources/node_modules/x/x.node",
                Scope::Runtime,
            ),
            ("Contents/Resources/my_node_modules/x.node", Scope::AppCode),
            ("Contents/MacOS/node_modules", Scope::AppCode),
        ] {
            assert_eq!(binary_scope(&location(path)), scope, "{path}");
        }
        assert!(is_privacy_manifest(&location("Contents/Resources/PrivacyInfo.xcprivacy")));
        assert!(is_privacy_manifest(&location("PrivacyInfo.xcprivacy")));
        assert!(!is_privacy_manifest(&location("Contents/Resources/privacyinfo.xcprivacy")));
        assert!(!is_privacy_manifest(&location("PrivacyInfo.xcprivacy/Info.plist")));
    }

    /// The byte budget binds on the open file, whatever size the walk saw.
    /// The oracle is the file's length as written here.
    #[test]
    fn a_file_over_the_budget_when_read_is_set_aside_with_its_size() {
        let pack = pack(Vec::new());
        let matchers = Matchers::build(&pack).unwrap();
        let at = location("Contents/MacOS/Example");
        let read = |path: &Path, budget| read_file(path, &at, &matchers, budget);

        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];
        bytes.resize(100, 0);
        file.write_all(&bytes).unwrap();

        let whole = Sha256Digest::of(&bytes);
        assert!(matches!(
            read(file.path(), 100),
            FileResult::Binary { sha256, bytes: 100, found }
                // One image, with nothing in it.
                if sha256 == whole
                    && found == BinaryFindings { images: 1, ..BinaryFindings::default() }
        ));
        for budget in [99, 50, 16] {
            assert!(
                matches!(read(file.path(), budget), FileResult::OverBudget(100)),
                "budget {budget}"
            );
        }
        // A file the collector has no reason to read is not over any budget.
        let mut other = tempfile::NamedTempFile::new().unwrap();
        other.write_all(&[b'x'; 100]).unwrap();
        assert!(matches!(read(other.path(), 50), FileResult::NotCandidate));

        // A privacy manifest is read whole, whatever its first bytes are,
        // and one over the property-list budget is set aside with its size.
        let manifest = location("Contents/Resources/PrivacyInfo.xcprivacy");
        let document = b"<plist version=\"1.0\"><dict><key>NSPrivacyTrackingDomains</key>\
            <array><string>tracker.example.net</string></array></dict></plist>";
        let mut other = tempfile::NamedTempFile::new().unwrap();
        other.write_all(document).unwrap();
        assert!(matches!(
            read_file(other.path(), &manifest, &matchers, 50),
            FileResult::Manifest { sha256, bytes, declared: Ok(listed) }
                if sha256 == Sha256Digest::of(document)
                    && bytes == document.len() as u64
                    && listed == ["tracker.example.net"]
        ));
        let oversized = privacy_manifest::MAX_BYTES as u64 + 1;
        other.as_file().set_len(oversized).unwrap();
        assert!(matches!(
            read_file(other.path(), &manifest, &matchers, 50),
            FileResult::OverBudget(size) if size == oversized
        ));
    }

    fn pack(rules: Vec<Rule>) -> Pack {
        let layer = Layer {
            format: V1,
            layer: "core".into(),
            version: 1,
            license: "CC-BY-4.0".into(),
            categories: vec![Category {
                id: "component".into(),
                name: "Component".into(),
                headline: false,
            }],
            entities: vec![],
            rules,
        };
        Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
    }

    /// Makes `names` under a fresh folder in the given order. A name ending
    /// in `/` is an empty folder; any other is a one-byte file.
    fn tree(names: &[&str], order: impl Iterator<Item = usize>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for index in order {
            let path = dir.path().join(names[index]);
            if names[index].ends_with('/') {
                fs::create_dir_all(path).unwrap();
            } else {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"x").unwrap();
            }
        }
        dir
    }

    /// The files a plan lists and the folders it skipped as over budget.
    fn listed(plan: &Plan) -> (Vec<String>, Vec<String>) {
        let files = plan.files.iter().map(|(path, _)| path.as_str().to_string()).collect();
        let mut skipped: Vec<String> = plan
            .gaps
            .located
            .keys()
            .filter(|(_, status, reason, _)| {
                (*status, *reason) == (CoverageStatus::Skipped, CoverageReason::OverBudget)
            })
            .map(|(path, ..)| path.as_str().to_string())
            .collect();
        let whole = (CoverageStatus::Skipped, CoverageReason::OverBudget);
        if plan.gaps.unlocated.contains_key(&whole) {
            skipped.push("<root>".to_string());
        }
        (files, skipped)
    }

    fn expect(files: &[&str], skipped: &[&str]) -> (Vec<String>, Vec<String>) {
        let owned = |list: &[&str]| list.iter().map(|item| (*item).to_string()).collect();
        (owned(files), owned(skipped))
    }

    /// Every limit is a deterministic budget (design report, C3): the same
    /// bundle must lose the same files to the entry budget on every file
    /// system, and a listing must never be held beyond the budget. The
    /// expected lists follow from the documented rules alone: every entry
    /// counts once, a folder's entries come by name and then its sub-folders
    /// by name, and a folder with more entries than are left of the budget
    /// is skipped whole.
    #[test]
    fn the_entry_budget_cuts_at_the_same_place_whatever_order_files_were_made_in() {
        // Entries: 4 at the top, 3 in `a`, 1 in `a/sub`, 2 in `b`, 2 in `c`.
        let names = ["a/1", "a/2", "a/sub/1", "b/1", "b/2", "c/1", "c/2", "top"];
        let forward: Vec<usize> = (0..names.len()).collect();
        let backward: Vec<usize> = forward.iter().rev().copied().collect();
        let shuffled = vec![5, 2, 7, 0, 4, 1, 6, 3];
        for order in [forward, backward, shuffled] {
            let dir = tree(&names, order.iter().copied());
            let under = |max_entries| listed(&plan_within(dir.path(), max_entries));
            // Everything fits.
            assert_eq!(under(12), expect(&names, &[]), "{order:?}");
            // One entry is left when `c` is reached, and it holds two.
            assert_eq!(
                under(11),
                expect(&["a/1", "a/2", "a/sub/1", "b/1", "b/2", "top"], &["c"]),
                "{order:?}"
            );
            // The top, `a` and `a/sub` use up all eight.
            assert_eq!(
                under(8),
                expect(&["a/1", "a/2", "a/sub/1", "top"], &["b", "c"]),
                "{order:?}"
            );
            // The bundle's own folder holds four entries.
            assert_eq!(under(3), expect(&[], &["<root>"]), "{order:?}");
        }
    }

    /// A coverage record must say what happened. `unrecognized` means the
    /// input was read and not understood; a property list inside a folder
    /// that was never listed was not read, and the folder's own record
    /// already says so.
    #[test]
    fn a_contents_folder_that_was_not_listed_does_not_make_the_property_list_damaged() {
        use std::os::unix::fs::PermissionsExt as _;

        let gaps = |plan: &Plan| -> Vec<(String, CoverageStatus, CoverageReason)> {
            assert!(plan.gaps.unlocated.is_empty());
            plan.gaps
                .located
                .keys()
                .map(|(path, status, reason, _)| (path.as_str().to_string(), *status, *reason))
                .collect()
        };
        let names = ["Contents/Info.plist", "Contents/a", "Contents/b"];
        let dir = tree(&names, 0..names.len());

        // Listed in full, the file is found: no record about it missing.
        let listed = plan_within(dir.path(), 4);
        assert!(!gaps(&listed).iter().any(|(path, ..)| path == "Contents"), "{:?}", gaps(&listed));
        assert_eq!(listed.files_read, 1);

        // One entry at the top leaves one, and `Contents` holds three.
        assert_eq!(
            gaps(&plan_within(dir.path(), 2)),
            [("Contents".to_string(), CoverageStatus::Skipped, CoverageReason::OverBudget)]
        );

        // A folder that is there but may not be listed.
        let contents = dir.path().join("Contents");
        fs::set_permissions(&contents, fs::Permissions::from_mode(0o000)).unwrap();
        let unreadable = fs::read_dir(&contents).is_err();
        let found = gaps(&plan_within(dir.path(), 4));
        fs::set_permissions(&contents, fs::Permissions::from_mode(0o755)).unwrap();
        // Running as root, permissions do not bind and there is nothing to test.
        if unreadable {
            assert_eq!(
                found,
                [("Contents".to_string(), CoverageStatus::Skipped, CoverageReason::Unreadable)]
            );
        }

        // A listing that completes without the file is what "missing" means.
        fs::remove_file(contents.join("Info.plist")).unwrap();
        assert_eq!(
            gaps(&plan_within(dir.path(), 4)),
            [(
                "Contents/Info.plist".to_string(),
                CoverageStatus::Unrecognized,
                CoverageReason::ParseError
            )]
        );
    }

    /// Folders cost memory like files do, so they count against the same
    /// budget: a tree of nothing but folders stops at the limit.
    #[test]
    fn folders_count_against_the_entry_budget() {
        let names: Vec<String> = (0..10)
            .flat_map(|outer| (0..10).map(move |inner| format!("f{outer}/d{inner}/")))
            .collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        for reversed in [false, true] {
            let order: Vec<usize> = (0..names.len()).collect();
            let dir = if reversed {
                tree(&names, order.into_iter().rev())
            } else {
                tree(&names, order.into_iter())
            };
            // 10 entries at the top, 10 in `f0` and 10 in `f1` leave 5.
            assert_eq!(
                listed(&plan_within(dir.path(), 35)),
                expect(&[], &["f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9"]),
                "reversed: {reversed}"
            );
            assert_eq!(listed(&plan_within(dir.path(), 110)), expect(&[], &[]));
        }
    }

    /// Evidence is drawn from the `Contents/Frameworks` listing, so that
    /// listing obeys the budget like any other: over it, the folder is
    /// reported and yields no edge and no digest entry.
    #[test]
    fn a_frameworks_folder_over_the_entry_budget_yields_no_evidence() {
        let sentry = Rule {
            id: "sdk/sentry".into(),
            name: "Sentry".into(),
            entity: None,
            category: "component".into(),
            sources: vec![],
            notes: vec![],
            matchers: BTreeMap::from([(
                MatcherKind::AppleFramework,
                vec![Token { lit: "Sentry.framework".into(), at: Boundary::Exact }],
            )]),
            min_distinct: BTreeMap::new(),
        };
        let pack = pack(vec![sentry]);
        let matchers = Matchers::build(&pack).unwrap();
        let frameworks = [
            "Contents/Frameworks/A.framework/",
            "Contents/Frameworks/B.framework/",
            "Contents/Frameworks/Sentry.framework/",
        ];
        let dir = tree(&frameworks, 0..frameworks.len());
        let without = tree(&["Contents/"], 0..1);
        let records = |root: &Path, max_entries| {
            finish(plan_within(root, max_entries), Vec::new(), &matchers).0
        };
        let edges = |records: &[Record]| {
            records.iter().filter(|record| matches!(record, Record::Edge(_))).count()
        };
        let digest = |records: &[Record]| records.first().map(|record| record.subject().digest);

        // One entry at the top, one in `Contents`, three frameworks.
        let within = records(dir.path(), 5);
        assert_eq!(edges(&within), 1);
        assert_ne!(digest(&within), digest(&records(without.path(), 5)));

        let over = records(dir.path(), 4);
        assert_eq!(edges(&over), 0);
        assert_eq!(digest(&over), digest(&records(without.path(), 4)));
        let reported: Vec<&str> = over
            .iter()
            .filter_map(|record| match record {
                Record::Coverage(gap) if gap.reason == CoverageReason::OverBudget => {
                    gap.location.as_ref().map(RelPath::as_str)
                }
                _ => None,
            })
            .collect();
        assert_eq!(reported, ["Contents/Frameworks"]);
    }

    /// A hostile tree must not produce an unbounded report. The gaps that
    /// keep their place are the least by path, whatever order they were
    /// found in; the rest are counted, not dropped.
    #[test]
    fn gaps_past_the_cap_are_folded_into_one_count_whatever_order_they_came_in() {
        let total = MAX_LOCATED_GAPS + 500;
        let path = |index: usize| RelPath::new(&format!("d/{index:05}")).unwrap();
        let collect = |order: &mut dyn Iterator<Item = usize>| {
            let mut gaps = Gaps::default();
            for index in order {
                gaps.skipped(CoverageReason::OverBudget, Some(path(index)));
            }
            // The same place twice is one gap that counts two.
            gaps.skipped(CoverageReason::OverBudget, Some(path(0)));
            gaps.unrecognized(CoverageReason::ParseError, Some(path(total)));
            (gaps.located, gaps.unlocated)
        };
        let (located, unlocated) = collect(&mut (0..total));
        assert_eq!(collect(&mut (0..total).rev()), (located.clone(), unlocated.clone()));
        assert_eq!(
            collect(&mut (0..total).map(|i| i * 7 % total)),
            (located.clone(), unlocated.clone())
        );

        let kept: Vec<&str> = located.keys().map(|(path, ..)| path.as_str()).collect();
        let least: Vec<String> = (0..MAX_LOCATED_GAPS).map(|i| format!("d/{i:05}")).collect();
        assert_eq!(kept, least);
        assert_eq!(located.values().sum::<u32>(), 1001);
        assert_eq!(
            unlocated,
            BTreeMap::from([
                ((CoverageStatus::Skipped, CoverageReason::OverBudget), 500),
                ((CoverageStatus::Unrecognized, CoverageReason::ParseError), 1),
            ])
        );
    }

    /// A problem inside a bundle never fails the scan, so every record the
    /// collector emits must have an id. Canonical JSON holds integers up to
    /// 2^53 - 1 (RFC 7493, section 2.2); a file system can report more.
    #[test]
    fn an_over_budget_file_of_any_size_yields_a_record_with_an_id() {
        let pack = pack(Vec::new());
        let matchers = Matchers::build(&pack).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let records_for = |bytes: u64| {
            let mut plan = plan_within(dir.path(), MAX_ENTRIES);
            plan.over_budget(RelPath::new("Contents/MacOS/Huge").unwrap(), bytes);
            finish(plan, Vec::new(), &matchers).0
        };

        for bytes in [(1 << 53) - 1, 1 << 53, u64::MAX] {
            let records = records_for(bytes);
            let sizes: Vec<Option<u64>> = records
                .iter()
                .filter_map(|record| match record {
                    Record::Coverage(gap) if gap.reason == CoverageReason::OverBudget => {
                        Some(gap.bytes)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(sizes, [Some(9_007_199_254_740_991)], "{bytes} bytes");
            for record in &records {
                assert!(record.id().is_ok(), "{bytes} bytes: {record:?}");
            }
        }
        // The digest still tells two such files apart by their exact sizes.
        let digest = |bytes| records_for(bytes).first().map(|record| record.subject().digest);
        assert_ne!(digest(u64::MAX), digest(u64::MAX - 1));
    }
}
