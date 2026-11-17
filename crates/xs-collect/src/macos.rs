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
//! of work and memory and gives the same result on every run: [`MAX_DEPTH`]
//! folders deep, [`MAX_ENTRIES`] directory entries of any kind,
//! [`MAX_FILE_BYTES`] per file read, [`MAX_LOCATED_GAPS`] coverage records
//! that name a place, and the property list parser's own budgets. What a
//! budget cuts off becomes an `over_budget` coverage record.
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
use xs_model::{MatcherKind, RelPath, Sha256Digest, canon, text};

use crate::ScanStats;
use crate::read::{self, OnePass, WINDOW};
use crate::schedule::Pool;

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
/// it would read, those whose first bytes say Mach-O. A larger one is not
/// read past those first bytes; it is reported with its size, and the bundle
/// digest covers that size instead of a content hash. A file the collector
/// has no reason to read is ignored whatever its size. The largest file seen
/// in a real app was 485 MB.
pub const MAX_FILE_BYTES: u64 = 2 << 30;

const CONTENTS: &str = "Contents";
const INFO_PLIST: &str = "Contents/Info.plist";
const FRAMEWORKS: &str = "Contents/Frameworks";

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
    fn add(
        &mut self,
        status: CoverageStatus,
        reason: CoverageReason,
        location: Option<RelPath>,
        bytes: Option<u64>,
    ) {
        let mut fold = |status, reason, count: u32| {
            let total = self.unlocated.entry((status, reason)).or_insert(0);
            *total = total.saturating_add(count);
        };
        let Some(path) = location else { return fold(status, reason, 1) };
        let count = self.located.entry((path, status, reason, bytes)).or_insert(0);
        *count = count.saturating_add(1);
        if self.located.len() > MAX_LOCATED_GAPS
            && let Some(((_, status, reason, _), count)) = self.located.pop_last()
        {
            fold(status, reason, count);
        }
    }

    fn skipped(&mut self, reason: CoverageReason, location: Option<RelPath>) {
        self.add(CoverageStatus::Skipped, reason, location, None);
    }

    fn unrecognized(&mut self, reason: CoverageReason, location: Option<RelPath>) {
        self.add(CoverageStatus::Unrecognized, reason, location, None);
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
        );
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
    /// A file the collector reads, but larger than the byte budget: its size.
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
    let plans: Vec<Plan> = pool.map(bundles, |root| plan(root, MAX_ENTRIES));

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

/// Lists a bundle, at most `max_entries` directory entries of it, and reads
/// its property list.
fn plan(root: &Path, max_entries: usize) -> Plan {
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
    // `walk` never follows a link. The property list is read by a fixed
    // path, so the folder on that path must be a real one, or a link named
    // `Contents` would stand another bundle in for this one.
    if replaced(&plan.root.join(CONTENTS)) {
        plan.gaps.unrecognized(CoverageReason::ParseError, rel(CONTENTS));
    } else {
        read_info_plist(&mut plan);
    }
    walk(&mut plan, max_entries);
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

/// Lists the bundle without following symbolic links: the regular files to
/// read, and the names of the real folders under `Contents/Frameworks`.
///
/// Only folders count as frameworks: a file or a symbolic link with a
/// framework's name is not one, and `Contents/Frameworks` itself must be a
/// real folder. That listing enters the bundle digest, because evidence is
/// drawn from it.
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
        let Ok(entries) = fs::read_dir(&dir) else {
            plan.gaps.skipped(CoverageReason::Unreadable, dir_rel);
            continue;
        };
        let mut listed = Vec::new();
        let mut over_budget = false;
        for entry in entries {
            match entry {
                Ok(_) if listed.len() >= left => {
                    over_budget = true;
                    break;
                }
                Ok(entry) => listed.push((entry.file_name(), entry.file_type())),
                Err(_) => plan.gaps.skipped(CoverageReason::Unreadable, dir_rel.clone()),
            }
        }
        if over_budget {
            plan.gaps.skipped(CoverageReason::OverBudget, dir_rel);
            continue;
        }
        left -= listed.len();
        listed.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        let frameworks = dir_rel.as_ref().is_some_and(|dir| dir.as_str() == FRAMEWORKS);
        let mut folders = Vec::new();
        for (name, kind) in listed {
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
            let Ok(kind) = kind else {
                plan.gaps.skipped(CoverageReason::Unreadable, Some(path));
                continue;
            };
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
            if path.as_str() == FRAMEWORKS {
                // A link or a file where the frameworks folder belongs.
                plan.gaps.unrecognized(CoverageReason::ParseError, Some(path.clone()));
            }
            if kind.is_symlink() {
                // Never followed. Its target, if inside the bundle, is
                // reached by its real path.
            } else if kind.is_file() {
                if path.as_str() == INFO_PLIST {
                    continue; // Already read.
                }
                match fs::symlink_metadata(dir.join(name)) {
                    Ok(metadata) if metadata.is_file() => plan.files.push((path, metadata.len())),
                    _ => plan.gaps.skipped(CoverageReason::Unreadable, Some(path)),
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

/// Reads one file in a single pass if its first bytes say it is a Mach-O
/// file, and gives up after one small read otherwise.
///
/// A Mach-O file larger than `budget` is set aside after that one small
/// read. One that grows while it is being read stops one byte past `budget`
/// and is reported the same way, so the read is bounded in every case.
fn read_file<M: ContentMatcher + ?Sized>(path: &Path, content: &M, budget: u64) -> FileResult {
    let Ok(file) = File::open(path) else { return FileResult::Failed };
    let mut bounded = (&file).take(budget.saturating_add(1));
    SCRATCH.with_borrow_mut(|buf| {
        let needed = read::buffer_len(content, WINDOW);
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        let mut oversize = None;
        let wanted = |head: &[u8]| {
            if macho::sniff(head).is_none() {
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
        match read::one_pass(&mut bounded, buf, WINDOW, content, wanted) {
            Ok(Some(pass)) if pass.bytes > budget => match file.metadata() {
                Ok(metadata) => FileResult::OverBudget(metadata.len().max(pass.bytes)),
                Err(_) => FileResult::Failed,
            },
            Ok(Some(pass)) => FileResult::Read(pass),
            Ok(None) => oversize.map_or(FileResult::NotCandidate, FileResult::OverBudget),
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

    /// The byte budget binds on the open file, whatever size the walk saw.
    /// The oracle is the file's length as written here.
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
        // A file the collector has no reason to read is not over any budget.
        let mut other = tempfile::NamedTempFile::new().unwrap();
        other.write_all(&[b'x'; 100]).unwrap();
        assert!(matches!(read_file(other.path(), &NoContent, 50), FileResult::NotCandidate));
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
            let under = |max_entries| listed(&plan(dir.path(), max_entries));
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
                listed(&plan(dir.path(), 35)),
                expect(&[], &["f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9"]),
                "reversed: {reversed}"
            );
            assert_eq!(listed(&plan(dir.path(), 110)), expect(&[], &[]));
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
        let matchers = Matchers::build(&pack);
        let frameworks = [
            "Contents/Frameworks/A.framework/",
            "Contents/Frameworks/B.framework/",
            "Contents/Frameworks/Sentry.framework/",
        ];
        let dir = tree(&frameworks, 0..frameworks.len());
        let without = tree(&["Contents/"], 0..1);
        let records =
            |root: &Path, max_entries| finish(plan(root, max_entries), Vec::new(), &matchers).0;
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
        let matchers = Matchers::build(&pack);
        let dir = tempfile::tempdir().unwrap();
        let records_for = |bytes: u64| {
            let mut plan = plan(dir.path(), MAX_ENTRIES);
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
