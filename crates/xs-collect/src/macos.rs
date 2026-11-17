//! The macOS application bundle collector.
//!
//! This is the walking skeleton of the collector (build plan, task 4). It
//! establishes a bundle's identity and matches one kind of witness:
//!
//! * `Contents/Info.plist` gives the app id, version and name.
//! * The folder names under `Contents/Frameworks` are matched against the
//!   rule pack's `apple_framework` tokens.
//! * Every Mach-O file in the bundle is hashed in one pass, so that two
//!   builds which share an app id and version are still two subjects.
//!
//! Every limit is a fixed budget, so a hostile bundle costs a bounded amount
//! of work and gives the same result on every run: [`MAX_DEPTH`] folders
//! deep, [`MAX_FILES`] files, [`MAX_FILE_BYTES`] per file, and the property
//! list parser's own budgets. What a budget cuts off becomes an
//! `over_budget` coverage record.
//!
//! Mach-O sections, Objective-C class names, load commands, the code
//! signature and privacy manifests are task 6.
//!
//! The work is split in three so that reading can be scheduled per file
//! across all bundles at once (design report, section 6.2):
//!
//! 1. **plan** (per bundle): list the files, read the small property list.
//! 2. **read** (per file, largest first): one pass for hash and matches.
//! 3. **finish** (per bundle, pure): turn what was read into records.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use xs_formats::{Budget, FormatError, info_plist, macho};
use xs_match::{ContentMatcher, Matchers, NoContent};
use xs_model::digest::BundleManifest;
use xs_model::record::{
    ArtifactRecord, Collector, CoverageReason, CoverageRecord, CoverageStatus, EdgeRecord,
    EdgeType, Facts, ObjectKind, ObjectRef, Platform, Proof, Record, Region, Scope, Subject,
    SubjectKind, V1,
};
use xs_model::{MatcherKind, RelPath, Sha256Digest, text};

use crate::ScanStats;
use crate::read::{self, OnePass, WINDOW};
use crate::schedule::Pool;

/// Deepest folder nesting the collector follows inside a bundle.
pub const MAX_DEPTH: u32 = 64;
/// Most files the collector considers in one bundle.
pub const MAX_FILES: usize = 1_000_000;
/// Largest file the collector reads: 2 GiB. A larger file is not opened; it
/// is reported with its size, and the bundle digest covers that size instead
/// of a content hash. The largest file seen in a real app was 485 MB.
pub const MAX_FILE_BYTES: u64 = 2 << 30;

const CONTENTS: &str = "Contents";
const INFO_PLIST: &str = "Contents/Info.plist";
const FRAMEWORKS: &str = "Contents/Frameworks";

/// Something the collector could not cover, keyed so that equal gaps add up.
/// The last part is the size of a file over the byte budget.
type GapKey = (CoverageStatus, CoverageReason, Option<RelPath>, Option<u64>);

#[derive(Default)]
struct Gaps(BTreeMap<GapKey, u32>);

impl Gaps {
    fn add(&mut self, key: GapKey) {
        let count = self.0.entry(key).or_insert(0);
        *count = count.saturating_add(1);
    }

    fn skipped(&mut self, reason: CoverageReason, location: Option<RelPath>) {
        self.add((CoverageStatus::Skipped, reason, location, None));
    }

    fn unrecognized(&mut self, reason: CoverageReason, location: Option<RelPath>) {
        self.add((CoverageStatus::Unrecognized, reason, location, None));
    }
}

/// What is known about a bundle before its files are read.
struct Plan {
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
    gaps: Gaps,
    files_read: u64,
    bytes_read: u64,
}

impl Plan {
    /// Sets aside a file of `bytes` bytes, which is over [`MAX_FILE_BYTES`].
    fn over_budget(&mut self, path: RelPath, bytes: u64) {
        self.manifest.over_budget(path.clone(), bytes);
        self.gaps.add((
            CoverageStatus::Skipped,
            CoverageReason::OverBudget,
            Some(path),
            Some(bytes),
        ));
    }
}

/// One file to read: which bundle, which file in its plan, and how large.
struct Job {
    bundle: usize,
    file: usize,
    size: u64,
}

/// What reading one file produced.
enum FileResult {
    /// Not a kind of file the collector reads. It cost one small read.
    NotCandidate,
    /// Read to the end.
    Read(OnePass),
    /// Larger than the byte budget by the time it was read: its size.
    OverBudget(u64),
    /// The file system refused.
    Failed,
}

/// Scans `bundles` and returns their records with the scan's totals.
///
/// A problem inside a bundle never fails the scan; it becomes a `coverage`
/// record.
pub fn collect(
    bundles: &[PathBuf],
    matchers: &Matchers<'_>,
    pool: &Pool,
) -> (Vec<Record>, ScanStats) {
    // Listing is stat-bound and independent per bundle.
    let plans: Vec<Plan> = pool.map(bundles, |root| plan(root));

    // One task per file across all bundles, largest first, so the few files
    // that hold most of the bytes start at once on separate threads.
    let mut jobs: Vec<Job> = plans
        .iter()
        .enumerate()
        .flat_map(|(bundle, plan)| {
            plan.files.iter().enumerate().map(move |(file, (_, size))| Job {
                bundle,
                file,
                size: *size,
            })
        })
        .collect();
    jobs.sort_by(|a, b| {
        b.size.cmp(&a.size).then(a.bundle.cmp(&b.bundle)).then(a.file.cmp(&b.file))
    });

    // The content engine arrives with task 5; until then no content tokens
    // are searched for, and the pass hashes only.
    let content = NoContent;
    let results: Vec<FileResult> = pool.map(&jobs, |job| {
        let found = plans.get(job.bundle).and_then(|plan| Some((plan, plan.files.get(job.file)?)));
        match found {
            Some((plan, (path, _))) => {
                read_file(&plan.root.join(path.as_str()), &content, MAX_FILE_BYTES)
            }
            None => FileResult::Failed,
        }
    });

    let mut per_bundle: Vec<Vec<(usize, FileResult)>> = plans.iter().map(|_| Vec::new()).collect();
    for (job, result) in jobs.iter().zip(results) {
        if let Some(list) = per_bundle.get_mut(job.bundle) {
            list.push((job.file, result));
        }
    }

    let mut records = Vec::new();
    let mut stats = ScanStats::default();
    for (plan, results) in plans.into_iter().zip(per_bundle) {
        let (bundle_records, files, bytes) = finish(plan, results, matchers);
        stats.artifacts += 1;
        stats.files += files;
        stats.bytes += bytes;
        records.extend(bundle_records);
    }
    (records, stats)
}

fn rel(path: &str) -> Option<RelPath> {
    RelPath::new(path).ok()
}

/// Lists a bundle and reads its property list.
fn plan(root: &Path) -> Plan {
    let folder_name =
        root.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let mut plan = Plan {
        root: root.to_path_buf(),
        folder_name,
        info: None,
        manifest: BundleManifest::new(),
        frameworks: Vec::new(),
        files: Vec::new(),
        gaps: Gaps::default(),
        files_read: 0,
        bytes_read: 0,
    };
    // `walk` never follows a link. The two reads below go by fixed paths, so
    // every folder on those paths must be a real one, or a link named
    // `Contents` would stand another bundle in for this one.
    if replaced(&plan.root.join(CONTENTS)) {
        plan.gaps.unrecognized(CoverageReason::ParseError, rel(CONTENTS));
    } else {
        read_info_plist(&mut plan);
        list_frameworks(&mut plan);
    }
    walk(&mut plan);
    plan
}

/// Whether something other than a real folder (a symbolic link, a file) sits
/// where a folder belongs. A missing folder is not a replaced one.
fn replaced(dir: &Path) -> bool {
    fs::symlink_metadata(dir).is_ok_and(|metadata| !metadata.is_dir())
}

fn read_info_plist(plan: &mut Plan) {
    let location = rel(INFO_PLIST);
    let path = plan.root.join(INFO_PLIST);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return plan.gaps.unrecognized(CoverageReason::ParseError, location);
        }
        Err(_) => return plan.gaps.skipped(CoverageReason::Unreadable, location),
    };
    if !metadata.is_file() {
        // A link or a folder where the property list belongs.
        return plan.gaps.unrecognized(CoverageReason::ParseError, location);
    }
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

/// Records the names of the real folders under `Contents/Frameworks`.
///
/// Only folders count: a file or a symbolic link with a framework's name is
/// not a framework, and `Contents/Frameworks` itself must be a real folder.
/// The listing enters the bundle digest, because evidence is
/// drawn from it.
fn list_frameworks(plan: &mut Plan) {
    let Some(location) = rel(FRAMEWORKS) else { return };
    let path = plan.root.join(FRAMEWORKS);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return plan.gaps.unrecognized(CoverageReason::ParseError, Some(location)),
        Err(_) => return,
    }
    let Ok(entries) = fs::read_dir(&path) else {
        return plan.gaps.skipped(CoverageReason::Unreadable, Some(location));
    };
    for entry in entries {
        let Ok(entry) = entry else {
            plan.gaps.skipped(CoverageReason::Unreadable, Some(location.clone()));
            continue;
        };
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        // A name that cannot be stored cannot be reported; `walk` counts it.
        if let Some(name) = entry.file_name().to_str().filter(|name| location.join(name).is_ok()) {
            plan.frameworks.push(name.to_string());
        }
    }
    plan.frameworks.sort_unstable();
    plan.manifest.listing(location, plan.frameworks.iter().map(String::as_str));
}

/// Lists every regular file in the bundle, without following symbolic links.
fn walk(plan: &mut Plan) {
    // Depth-first with an explicit stack: nesting is bounded by the budget,
    // not by the call stack.
    let mut pending: Vec<(PathBuf, Option<RelPath>, u32)> = vec![(plan.root.clone(), None, 0)];
    while let Some((dir, dir_rel, depth)) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            plan.gaps.skipped(CoverageReason::Unreadable, dir_rel);
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                plan.gaps.skipped(CoverageReason::Unreadable, dir_rel.clone());
                continue;
            };
            let name = entry.file_name();
            let path = name.to_str().and_then(|name| match &dir_rel {
                Some(parent) => parent.join(name).ok(),
                None => rel(name),
            });
            let Some(path) = path else {
                // The name is not UTF-8, holds a control character or makes
                // the path too long. It cannot be stored, so only counted.
                plan.gaps.skipped(CoverageReason::Unreadable, None);
                continue;
            };
            let Ok(kind) = entry.file_type() else {
                plan.gaps.skipped(CoverageReason::Unreadable, Some(path));
                continue;
            };
            if kind.is_symlink() {
                // Never followed. Its target, if inside the bundle, is
                // reached by its real path.
            } else if kind.is_dir() {
                if depth + 1 >= MAX_DEPTH {
                    plan.gaps.skipped(CoverageReason::OverBudget, Some(path));
                } else {
                    pending.push((entry.path(), Some(path), depth + 1));
                }
            } else if kind.is_file() {
                if path.as_str() == INFO_PLIST {
                    continue; // Already read.
                }
                if plan.files.len() >= MAX_FILES {
                    // Stop listing. What was listed so far is still scanned.
                    plan.gaps.skipped(CoverageReason::OverBudget, None);
                    pending.clear();
                    break;
                }
                match entry.metadata() {
                    Ok(metadata) if metadata.len() > MAX_FILE_BYTES => {
                        plan.over_budget(path, metadata.len());
                    }
                    Ok(metadata) => plan.files.push((path, metadata.len())),
                    Err(_) => plan.gaps.skipped(CoverageReason::Unreadable, Some(path)),
                }
            } else {
                // A socket, pipe or device node. Not app content.
                plan.gaps.skipped(CoverageReason::UnsupportedFormat, Some(path));
            }
        }
    }
    // Directory order is whatever the file system returns; fix it.
    plan.files.sort_unstable();
}

thread_local! {
    /// One read buffer per worker thread, reused for every file.
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Reads one file in a single pass if its first bytes say it is a Mach-O
/// file, and gives up after one small read otherwise.
///
/// Never reads more than one byte past `budget`. The walk already set aside
/// the files that were larger when it listed them; one that has grown since
/// stops here and is reported the same way.
fn read_file<M: ContentMatcher + ?Sized>(path: &Path, content: &M, budget: u64) -> FileResult {
    let Ok(file) = File::open(path) else { return FileResult::Failed };
    let mut bounded = (&file).take(budget.saturating_add(1));
    SCRATCH.with_borrow_mut(|buf| {
        let needed = read::buffer_len(content, WINDOW);
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        let sniff = |head: &[u8]| macho::sniff(head).is_some();
        match read::one_pass(&mut bounded, buf, WINDOW, content, sniff) {
            Ok(Some(pass)) if pass.bytes > budget => match file.metadata() {
                Ok(metadata) => FileResult::OverBudget(metadata.len().max(pass.bytes)),
                Err(_) => FileResult::Failed,
            },
            Ok(Some(pass)) => FileResult::Read(pass),
            Ok(None) => FileResult::NotCandidate,
            Err(_) => FileResult::Failed,
        }
    })
}

/// Turns a plan and what was read into records. Pure.
fn finish(
    mut plan: Plan,
    results: Vec<(usize, FileResult)>,
    matchers: &Matchers<'_>,
) -> (Vec<Record>, u64, u64) {
    for (file, result) in results {
        let Some((path, _)) = plan.files.get(file) else { continue };
        match result {
            FileResult::NotCandidate => {}
            FileResult::Read(pass) => {
                plan.manifest.file(path.clone(), pass.sha256);
                plan.files_read += 1;
                plan.bytes_read += pass.bytes;
            }
            FileResult::OverBudget(bytes) => {
                let path = path.clone();
                plan.over_budget(path, bytes);
            }
            FileResult::Failed => plan.gaps.skipped(CoverageReason::Unreadable, Some(path.clone())),
        }
    }

    // A value the property list declares but leaves empty is no value, so
    // each one is cleaned and checked before the next is considered.
    let declared = |value: Option<String>, max_bytes: usize| {
        value.map(|value| text::clean(&value, max_bytes)).filter(|value| !value.is_empty())
    };
    let parsed = plan.info.is_some();
    let info = plan.info.unwrap_or_default();
    let id = match declared(info.identifier, text::MAX_ID_BYTES) {
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
    let version = declared(info.short_version, text::MAX_VERSION_BYTES)
        .or_else(|| declared(info.build_version, text::MAX_VERSION_BYTES));
    let subject = Subject {
        kind: SubjectKind::App,
        platform: Platform::Macos,
        id,
        version,
        digest: plan.manifest.digest(),
    };

    let mut records = Vec::new();
    let name = declared(info.display_name, text::MAX_NAME_BYTES)
        .or_else(|| declared(info.name, text::MAX_NAME_BYTES));
    records.push(Record::Artifact(ArtifactRecord {
        v: V1,
        collector: Collector::MacosBundle,
        subject: subject.clone(),
        facts: Facts { name, files_scanned: plan.files_read, bytes_scanned: plan.bytes_read },
    }));

    if let Some(location) = rel(FRAMEWORKS) {
        let table = matchers.exact(MatcherKind::AppleFramework);
        for folder in &plan.frameworks {
            for hit in table.lookup(folder) {
                records.push(Record::Edge(EdgeRecord {
                    v: V1,
                    collector: Collector::MacosBundle,
                    subject: subject.clone(),
                    edge: EdgeType::Channel,
                    grade: MatcherKind::AppleFramework.grade(),
                    object: ObjectRef { kind: ObjectKind::Sdk, id: hit.rule.id.clone() },
                    rule: hit.rule.id.clone(),
                    proof: Proof {
                        matcher: MatcherKind::AppleFramework,
                        token: hit.token.lit.clone(),
                        count: 1,
                        example: Some(text::clean(folder, text::MAX_EXAMPLE_BYTES)),
                        location: location.clone(),
                        region: Region::DirEntries,
                        scope: Scope::Dependency,
                    },
                }));
            }
        }
    }

    for ((status, reason, location, bytes), count) in plan.gaps.0 {
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

    use super::*;

    /// The byte budget must bind on what is actually read, not only on the
    /// size the walk saw: a file can grow between the two. The oracle is the
    /// file's length as written here.
    #[test]
    fn a_file_over_the_budget_when_read_is_set_aside_with_its_size() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];
        bytes.resize(100, 0);
        file.write_all(&bytes).unwrap();

        let whole = Sha256Digest::of(&bytes);
        assert!(matches!(
            read_file(file.path(), &NoContent, 100),
            FileResult::Read(pass) if pass.bytes == 100 && pass.sha256 == whole
        ));
        for budget in [99, 50, 16] {
            assert!(
                matches!(read_file(file.path(), &NoContent, budget), FileResult::OverBudget(100)),
                "budget {budget}"
            );
        }
        // A file that is not a candidate is still told apart by its head.
        let mut other = tempfile::NamedTempFile::new().unwrap();
        other.write_all(&[b'x'; 100]).unwrap();
        assert!(matches!(read_file(other.path(), &NoContent, 50), FileResult::NotCandidate));
    }
}
