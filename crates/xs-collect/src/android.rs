//! The Android package collector.
//!
//! An APK is a zip archive. Four tables inside it say which SDKs the app
//! ships, and each is an independent witness that survives a different
//! obstacle (design report, section 5.1):
//!
//! | Witness | Table | Still there when |
//! |---|---|---|
//! | `manifest_component` | component and `meta-data` names in `AndroidManifest.xml` | the code is fully obfuscated: the build keeps every class the manifest names |
//! | `android_class_prefix` | classes defined in the `class_defs` table of each `classes*.dex` | entry classes keep their names |
//! | `dex_string` | the `string_ids` table of each `classes*.dex` | the code is fully obfuscated: string constants are not renamed |
//! | `apk_file` | the names of the archive's entries | the code is fully obfuscated: files an SDK ships are not renamed |
//!
//! # One pass, and evidence only from the bytes that were hashed
//!
//! A package's identity is the SHA-256 of its file, so the file is read
//! once from start to end for the hash (design report, section 6.2). A zip
//! archive keeps its table of contents at the end, though, and the entries
//! worth reading are somewhere in the middle. So:
//!
//! 1. The last bytes are read first: the end record, then the central
//!    directory it points at. The directory names the entries to read (the
//!    manifest and the DEX files) and says where each one starts.
//! 2. The one pass over the file feeds the hash and copies out those
//!    entries as they go by. An entry is inflated and parsed as soon as the
//!    pass has gone over it, and its bytes are let go, so one entry is held
//!    in memory at a time, not the code of the whole app.
//! 3. The same pass compares what step 1 read with the bytes it now sees at
//!    those offsets. If they differ, the file changed while it was being
//!    read: the entries that were read and the hash may be of different
//!    versions, so the package has no identity to report under, and the
//!    scan fails as it does for a file that cannot be read.
//!
//! Every byte evidence is drawn from is therefore a byte the digest covers:
//! equal digests give equal evidence, which is what lets anyone holding the
//! same file reproduce a `contains` record (project spec, "Evidence
//! format").
//!
//! # Budgets
//!
//! Every limit is a count, so a hostile package costs a bounded amount of
//! work and memory and gives the same result on every run: the zip reader's
//! own limits on the directory, [`MAX_ENTRY_BYTES`] for one entry,
//! [`MAX_INFLATED_BYTES`] for all entries read from one package,
//! [`MAX_DEX_FILES`] DEX files, and the limits of the manifest and DEX
//! readers. What a budget cuts off becomes an `over_budget` coverage record.
//! Two entries that share bytes of the archive are not both read, so the
//! entries held at one time cannot add up either. Nothing is extracted to
//! disk and nothing is executed.
//!
//! # What is not read
//!
//! Only the DEX files Android itself loads from a package are read: the
//! root entries `classes.dex`, `classes2.dex` and so on. A `.dex` file
//! anywhere else is counted in a coverage record. Native libraries are
//! matched by name only, resources are not parsed (so an app's display name
//! is known only when the manifest states it as text), and split packages
//! are scanned one file at a time.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use xs_formats::dex::{self, Dex};
use xs_formats::zip::{self, Entry};
use xs_formats::{Budget, FormatError, ReadError, android_manifest};
use xs_match::{Finding, HitAcc, Matchers};
use xs_model::record::{
    ArtifactRecord, Collector, CoverageReason, CoverageRecord, CoverageStatus, EdgeRecord,
    EdgeType, Facts, ObjectKind, ObjectRef, Platform, Proof, Record, Region, Scope, Subject,
    SubjectKind, V1,
};
use xs_model::{MatcherKind, RelPath, Sha256Digest, Sha256Stream, SubjectDigest, text};

use crate::read::WINDOW;
use crate::schedule::Pool;
use crate::{ScanError, ScanStats};

/// Most DEX files read from one package. Android loads `classes.dex`,
/// `classes2.dex` and so on; the largest apps ship around a hundred.
pub const MAX_DEX_FILES: usize = 1000;
/// Largest entry the collector reads, stored or inflated: 256 MiB (design
/// report, section 4.8). A DEX file is rarely over 16 MiB.
pub const MAX_ENTRY_BYTES: u64 = 256 << 20;
/// Most bytes the collector reads out of one package, over all its entries:
/// 1 GiB (design report, section 4.8).
pub const MAX_INFLATED_BYTES: u64 = 1 << 30;

const MANIFEST: &str = "AndroidManifest.xml";
/// The app id of a package whose manifest does not give one. A constant,
/// not the file's name: evidence must depend on the bytes of the artifact
/// and on nothing else. The digest still tells two such packages apart.
const UNIDENTIFIED: &str = "unidentified.apk";
/// Everything in a package is the app's own: one archive, one signature.
/// The DEX files do hold the code of libraries next to the app's, but a
/// DEX file cannot be split into the two.
const SCOPE: Scope = Scope::AppCode;

/// Something the collector could not cover, at a known entry.
struct Gap {
    status: CoverageStatus,
    reason: CoverageReason,
    location: RelPath,
    /// The size of an entry over a byte budget: the larger of its stored
    /// and its inflated size, as the directory declares them.
    bytes: Option<u64>,
}

/// What the collector could not cover in one package.
///
/// A gap keeps its place only if it is about an entry the collector reads,
/// and there are at most [`MAX_DEX_FILES`] of those plus the manifest. All
/// other gaps are counted by status and reason, so a hostile archive of
/// sixty thousand entries cannot turn into sixty thousand records.
#[derive(Default)]
struct Gaps {
    located: Vec<Gap>,
    counted: BTreeMap<(CoverageStatus, CoverageReason), u32>,
}

impl Gaps {
    fn count(&mut self, status: CoverageStatus, reason: CoverageReason) {
        let total = self.counted.entry((status, reason)).or_insert(0);
        *total = total.saturating_add(1);
    }

    fn at(&mut self, location: &RelPath, (status, reason): (CoverageStatus, CoverageReason)) {
        self.located.push(Gap { status, reason, location: location.clone(), bytes: None });
    }

    fn over_budget(&mut self, location: &RelPath, bytes: u64) {
        self.located.push(Gap {
            status: CoverageStatus::Skipped,
            reason: CoverageReason::OverBudget,
            location: location.clone(),
            bytes: Some(bytes),
        });
    }
}

/// How a reader's refusal is reported: input that was read and not
/// understood is `unrecognized`; input that was not read, or not to its
/// end, is `skipped`.
const fn coverage_of(error: ReadError) -> (CoverageStatus, CoverageReason) {
    match error {
        ReadError::Format(FormatError::Malformed) => {
            (CoverageStatus::Unrecognized, CoverageReason::ParseError)
        }
        ReadError::Format(FormatError::OverBudget(
            Budget::Bytes | Budget::Items | Budget::Depth,
        )) => (CoverageStatus::Skipped, CoverageReason::OverBudget),
        ReadError::Unsupported => (CoverageStatus::Skipped, CoverageReason::UnsupportedFormat),
    }
}

/// What the collector reads an entry as.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Manifest,
    Dex,
}

impl Kind {
    /// The most bytes an entry of this kind may hold.
    const fn budget(self) -> u64 {
        match self {
            Self::Manifest => android_manifest::MAX_BYTES as u64,
            Self::Dex => MAX_ENTRY_BYTES,
        }
    }
}

/// The number in the name of a DEX file Android loads from a package: 1 for
/// `classes.dex`, N for `classesN.dex` with N from 2 up, written without
/// leading zeros.
fn dex_number(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("classes")?.strip_suffix(".dex")?;
    if digits.is_empty() {
        return Some(1);
    }
    if digits.starts_with('0') || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().filter(|number| *number >= 2)
}

/// What reading one entry gave.
enum Content {
    Manifest(android_manifest::Manifest),
    /// The hits in the class table and the string table of a DEX file.
    Dex(HitAcc),
}

/// One entry the pass copies out of the archive as it goes by.
struct Capture<'a> {
    entry: Entry<'a>,
    name: RelPath,
    kind: Kind,
    /// The archive from the entry's local header on, as far as it has been
    /// read. Empty again once the entry has been read from it.
    bytes: Vec<u8>,
    /// How many bytes are wanted. Until the fixed part of the local header
    /// has been read this is the length of that part; the header then says
    /// how long its name and extra field are.
    wanted: usize,
    header_read: bool,
    /// What the entry held, once the pass has gone over all of it.
    outcome: Option<Result<Content, ReadError>>,
}

impl<'a> Capture<'a> {
    fn new(entry: Entry<'a>, name: RelPath, kind: Kind) -> Self {
        Self {
            entry,
            name,
            kind,
            bytes: Vec::new(),
            wanted: zip::LOCAL_HEADER_BYTES,
            header_read: false,
            outcome: None,
        }
    }

    /// The least this entry takes up in the archive, from its local header
    /// to the end of its data. The header's extra field, which only the
    /// header itself gives the length of, comes on top.
    fn least_extent(&self) -> std::ops::Range<u64> {
        let start = u64::from(self.entry.offset);
        let length = (zip::LOCAL_HEADER_BYTES as u64)
            .saturating_add(self.entry.name.len() as u64)
            .saturating_add(u64::from(self.entry.compressed_bytes));
        start..start.saturating_add(length)
    }

    /// Takes what `window`, the bytes of the file from `offset` on, holds of
    /// this entry, and reads the entry once all of it is there. Windows
    /// arrive in file order and without gaps.
    fn feed(&mut self, offset: u64, window: &[u8], matchers: &Matchers<'_>) {
        while self.outcome.is_none() {
            let missing = self.wanted.saturating_sub(self.bytes.len());
            // Where the next missing byte is, relative to the window.
            let next = u64::from(self.entry.offset)
                .saturating_add(self.bytes.len() as u64)
                .checked_sub(offset)
                .and_then(|next| usize::try_from(next).ok());
            let available = next.and_then(|next| window.get(next..)).unwrap_or_default();
            let take = missing.min(available.len());
            self.bytes.extend_from_slice(available.get(..take).unwrap_or_default());

            if !self.header_read && self.bytes.len() >= zip::LOCAL_HEADER_BYTES {
                self.header_read = true;
                // A header that is not one ends the capture here: reading
                // the entry then fails, and that is reported.
                if let Ok(data_offset) = zip::data_offset(&self.bytes) {
                    let data_bytes =
                        usize::try_from(self.entry.compressed_bytes).unwrap_or(usize::MAX);
                    self.wanted = data_offset.saturating_add(data_bytes);
                }
                // The same window may hold the rest of the entry.
                continue;
            }
            if self.bytes.len() < self.wanted {
                return;
            }
            self.read(matchers);
        }
    }

    /// Reads the entry from what was copied of it, and lets the copy go.
    fn read(&mut self, matchers: &Matchers<'_>) {
        let local = std::mem::take(&mut self.bytes);
        self.outcome = Some(self.content(&local, matchers));
    }

    /// Inflates the entry and parses it. Evidence comes only from a table
    /// that was read whole: a file that fails part of the way through
    /// yields its error and nothing else.
    fn content(&self, local: &[u8], matchers: &Matchers<'_>) -> Result<Content, ReadError> {
        let data = zip::data(&self.entry, local)?;
        let budget = usize::try_from(self.kind.budget()).unwrap_or(usize::MAX);
        let content = zip::content(&self.entry, data, budget)?;
        Ok(match self.kind {
            Kind::Manifest => Content::Manifest(android_manifest::parse(&content)?),
            Kind::Dex => Content::Dex(dex_hits(&content, matchers)?),
        })
    }

    /// The entry's name and what it held. An entry the pass never went over
    /// all of, because the file ends before the entry does, is read from
    /// what there is, which fails.
    fn finish(mut self, matchers: &Matchers<'_>) -> (RelPath, Result<Content, ReadError>) {
        if self.outcome.is_none() {
            self.read(matchers);
        }
        (self.name, self.outcome.unwrap_or(Err(ReadError::Format(FormatError::Malformed))))
    }
}

/// Bytes read before the pass, to be compared with what the pass sees at
/// the same place.
struct Expected<'a> {
    offset: u64,
    bytes: &'a [u8],
}

impl Expected<'_> {
    /// Whether `window`, the bytes of the file from `offset` on, agrees
    /// with these bytes wherever the two overlap.
    fn agrees_with(&self, offset: u64, window: &[u8]) -> bool {
        // The overlap, as a range of this region and a range of the window.
        let (skip_here, skip_window) = if offset >= self.offset {
            (offset.saturating_sub(self.offset), 0)
        } else {
            (0, self.offset.saturating_sub(offset))
        };
        let (Ok(skip_here), Ok(skip_window)) =
            (usize::try_from(skip_here), usize::try_from(skip_window))
        else {
            return true;
        };
        let here = self.bytes.get(skip_here..).unwrap_or_default();
        let there = window.get(skip_window..).unwrap_or_default();
        let overlap = here.len().min(there.len());
        here.get(..overlap) == there.get(..overlap)
    }
}

/// Reads exactly `length` bytes at `offset`.
fn read_at(reader: &mut (impl Read + Seek), offset: u64, length: usize) -> io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    reader.take(length as u64).read_to_end(&mut bytes)?;
    if bytes.len() == length {
        Ok(bytes)
    } else {
        Err(io::Error::from(io::ErrorKind::UnexpectedEof))
    }
}

/// Reads `reader` from its start to its end in windows, at most `limit`
/// bytes, and shows every window to `each` with its offset. Returns the
/// hash and the length of what was read.
fn pass(
    reader: &mut (impl Read + Seek),
    limit: u64,
    buffer: &mut [u8],
    mut each: impl FnMut(u64, &[u8]),
) -> io::Result<(Sha256Digest, u64)> {
    reader.seek(SeekFrom::Start(0))?;
    let mut bounded = reader.take(limit);
    let mut hasher = Sha256Stream::new();
    let mut offset: u64 = 0;
    loop {
        match bounded.read(buffer) {
            Ok(0) => return Ok((hasher.finish(), offset)),
            Ok(count) => {
                let window = buffer.get(..count).unwrap_or_default();
                hasher.update(window);
                each(offset, window);
                offset = offset.saturating_add(count as u64);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// What reading one package produced.
struct Scanned {
    records: Vec<Record>,
    bytes: u64,
}

/// Scans the packages at `paths` and returns their records with the scan's
/// totals.
///
/// A problem inside a package never fails the scan; it becomes a `coverage`
/// record.
///
/// # Errors
///
/// Fails if a package cannot be opened or read to its end, or changes while
/// it is read. Its digest is its identity, so without one there is no
/// subject to report anything about, and saying nothing would pass for
/// "nothing found".
pub fn collect(
    paths: &[PathBuf],
    matchers: &Matchers<'_>,
    pool: &Pool,
) -> Result<(Vec<Record>, ScanStats), ScanError> {
    let fail = |path: &Path, error| ScanError::Path { path: path.to_path_buf(), error };
    // One task per package, largest first.
    let mut jobs: Vec<(u64, &Path)> = Vec::with_capacity(paths.len());
    for path in paths {
        let size = std::fs::metadata(path).map_err(|error| fail(path, error))?.len();
        jobs.push((size, path));
    }
    jobs.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));

    let results = pool.map(&jobs, |(_, path)| scan_file(path, matchers));
    let mut records = Vec::new();
    let mut stats = ScanStats::default();
    for ((_, path), result) in jobs.iter().zip(results) {
        let scanned = result.map_err(|error| fail(path, error))?;
        stats.artifacts += 1;
        stats.files += 1;
        stats.bytes += scanned.bytes;
        records.extend(scanned.records);
    }
    Ok((records, stats))
}

thread_local! {
    /// One read buffer per worker thread, reused for every package.
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn scan_file(path: &Path, matchers: &Matchers<'_>) -> io::Result<Scanned> {
    let mut file = File::open(path)?;
    let file_bytes = file.metadata()?.len();
    scan_with_scratch(&mut file, file_bytes, matchers)
}

fn scan_with_scratch(
    reader: &mut (impl Read + Seek),
    file_bytes: u64,
    matchers: &Matchers<'_>,
) -> io::Result<Scanned> {
    SCRATCH.with_borrow_mut(|buffer| {
        if buffer.len() < WINDOW {
            buffer.resize(WINDOW, 0);
        }
        scan_package(reader, file_bytes, buffer, matchers)
    })
}

/// Scans one package read from `reader`, which holds `file_bytes` bytes,
/// and returns its records: what [`collect`] does for each file.
///
/// For a caller that holds a package somewhere other than in a file of its
/// own, such as a test or a fuzz target with the bytes in memory.
///
/// # Errors
///
/// Passes on the first error of `reader`, and fails if it does not hold
/// exactly `file_bytes` bytes or gives other bytes on the second read of a
/// place than on the first.
pub fn scan_reader(
    reader: &mut (impl Read + Seek),
    file_bytes: u64,
    matchers: &Matchers<'_>,
) -> io::Result<Vec<Record>> {
    scan_with_scratch(reader, file_bytes, matchers).map(|scanned| scanned.records)
}

/// Reads one package from `reader`, which holds `file_bytes` bytes, and
/// turns it into records.
fn scan_package(
    reader: &mut (impl Read + Seek),
    file_bytes: u64,
    buffer: &mut [u8],
    matchers: &Matchers<'_>,
) -> io::Result<Scanned> {
    // The end of the file first: the end record, then the directory.
    let tail_bytes = usize::try_from(file_bytes).unwrap_or(usize::MAX).min(zip::MAX_TAIL_BYTES);
    let tail_offset = file_bytes.saturating_sub(tail_bytes as u64);
    let tail = read_at(reader, tail_offset, tail_bytes)?;
    let end = zip::locate(&tail, file_bytes);
    let directory = match &end {
        Ok(end) => read_at(reader, end.directory_offset, end.directory_bytes)?,
        Err(_) => Vec::new(),
    };
    let entries = end.and_then(|end| Ok((zip::directory(&directory, &end)?, end)));

    let mut gaps = Gaps::default();
    let mut names = HitAcc::new();
    let mut captures = Vec::new();
    let mut expected = vec![Expected { offset: tail_offset, bytes: &tail }];
    match &entries {
        Ok((entries, end)) => {
            expected.push(Expected { offset: end.directory_offset, bytes: &directory });
            captures = plan(entries, matchers, &mut names, &mut gaps);
        }
        Err(error) => {
            let (status, reason) = coverage_of(*error);
            gaps.count(status, reason);
        }
    }

    // The one pass: hash everything, copy out and read the wanted entries,
    // and check that the end of the file still is what the plan was made
    // from. One byte more than the file held is allowed, so that growth is
    // noticed.
    let mut unchanged = true;
    let (sha256, bytes) = pass(reader, file_bytes.saturating_add(1), buffer, |offset, window| {
        for capture in &mut captures {
            capture.feed(offset, window, matchers);
        }
        unchanged &= expected.iter().all(|region| region.agrees_with(offset, window));
    })?;

    if !unchanged || bytes != file_bytes {
        // The directory, the entries and the hash may each be of a
        // different version of the file. There is nothing to report that
        // would be true of any one of them.
        return Err(io::Error::other("the package changed while it was being read"));
    }
    let entries = captures.into_iter().map(|capture| capture.finish(matchers)).collect();
    let digest = SubjectDigest::Sha256(sha256);
    Ok(Scanned { records: records(digest, bytes, entries, &names, gaps, matchers), bytes })
}

/// Decides what to read from an archive, from its directory alone.
///
/// Matches every entry name against the `apk_file` tokens, and picks the
/// manifest and the DEX files Android would load, in the order they are
/// then read: the manifest, then the DEX files by number. The byte budgets
/// are applied here, to the sizes the directory declares, so the same
/// archive loses the same entries on every run.
fn plan<'a>(
    entries: &[Entry<'a>],
    matchers: &Matchers<'_>,
    names: &mut HitAcc,
    gaps: &mut Gaps,
) -> Vec<Capture<'a>> {
    let mut manifest = None;
    let mut dex_files: Vec<(u32, RelPath, Entry<'a>)> = Vec::new();
    for entry in entries {
        if entry.is_directory() {
            continue;
        }
        // A proof points at an entry by its name, so a name a record cannot
        // hold (not UTF-8, absolute, with `..`, `//` or a control character)
        // is only counted, as a name that was read and not understood.
        let name = std::str::from_utf8(entry.name).ok().and_then(|name| {
            let path = RelPath::new(name).ok()?;
            Some((name, path))
        });
        let Some((name, path)) = name else {
            gaps.count(CoverageStatus::Unrecognized, CoverageReason::ParseError);
            continue;
        };
        matchers.match_value(MatcherKind::ApkFile, SCOPE, entry.name, names);
        if name == MANIFEST {
            manifest = Some((path, *entry));
        } else if let Some(number) = dex_number(name) {
            dex_files.push((number, path, *entry));
        } else if name.ends_with(".dex") {
            // Code that Android does not load from the package by itself.
            gaps.count(CoverageStatus::Skipped, CoverageReason::UnsupportedFormat);
        }
    }
    dex_files.sort_by_key(|(number, ..)| *number);
    for _ in dex_files.iter().skip(MAX_DEX_FILES) {
        gaps.count(CoverageStatus::Skipped, CoverageReason::OverBudget);
    }
    dex_files.truncate(MAX_DEX_FILES);

    let wanted = manifest
        .into_iter()
        .map(|(path, entry)| (Kind::Manifest, path, entry))
        .chain(dex_files.into_iter().map(|(_, path, entry)| (Kind::Dex, path, entry)));
    let mut captures = Vec::new();
    let mut total: u64 = 0;
    for (kind, path, entry) in wanted {
        // Both sizes are held in memory while an entry is inflated, so the
        // larger of the two is what the entry costs, and what is reported.
        let cost = u64::from(entry.bytes).max(u64::from(entry.compressed_bytes));
        if cost > kind.budget() || total.saturating_add(cost) > MAX_INFLATED_BYTES {
            gaps.over_budget(&path, cost);
            continue;
        }
        total = total.saturating_add(cost);
        captures.push(Capture::new(entry, path, kind));
    }

    // In a well-formed archive no two entries share a byte. Of two that do,
    // the one that starts later is not read: its bytes belong to the other,
    // and reading both would hold both in memory at once. Entries that
    // start at the same place keep their reading order, so the first one
    // read is the one that stays.
    let mut order: Vec<usize> = (0..captures.len()).collect();
    order.sort_by_key(|&index| captures.get(index).map(|capture| capture.entry.offset));
    let mut taken_until = 0;
    let mut shared = BTreeSet::new();
    for index in order {
        let Some(extent) = captures.get(index).map(Capture::least_extent) else { continue };
        if extent.start < taken_until {
            shared.insert(index);
        } else {
            taken_until = extent.end;
        }
    }
    let mut index = 0;
    captures.retain(|capture| {
        let keep = !shared.contains(&index);
        if !keep {
            gaps.at(&capture.name, (CoverageStatus::Unrecognized, CoverageReason::ParseError));
        }
        index += 1;
        keep
    });

    if manifest_missing(&captures, gaps) {
        // Android does not install a package without a manifest.
        if let Ok(location) = RelPath::new(MANIFEST) {
            gaps.at(&location, (CoverageStatus::Unrecognized, CoverageReason::ParseError));
        }
    }
    captures
}

/// Whether the archive has no manifest at all: none to read, and none set
/// aside as over budget.
fn manifest_missing(captures: &[Capture<'_>], gaps: &Gaps) -> bool {
    !captures.iter().any(|capture| capture.kind == Kind::Manifest)
        && !gaps.located.iter().any(|gap| gap.location.as_str() == MANIFEST)
}

/// The hits of one DEX file: its class table and its string table.
fn dex_hits(bytes: &[u8], matchers: &Matchers<'_>) -> Result<HitAcc, ReadError> {
    let dex = Dex::parse(bytes)?;
    let mut hits = HitAcc::new();
    let mut name = Vec::new();
    for descriptor in dex.class_descriptors() {
        if dex::class_name(descriptor?, &mut name) {
            matchers.match_value(MatcherKind::AndroidClassPrefix, SCOPE, &name, &mut hits);
        }
    }
    for string in dex.strings() {
        matchers.match_value(MatcherKind::DexString, SCOPE, string?, &mut hits);
    }
    Ok(hits)
}

/// Turns what was read of one package into records. Pure.
fn records(
    digest: SubjectDigest,
    bytes: u64,
    entries: Vec<(RelPath, Result<Content, ReadError>)>,
    names: &HitAcc,
    mut gaps: Gaps,
    matchers: &Matchers<'_>,
) -> Vec<Record> {
    let mut manifest = None;
    let mut dex_files: Vec<(RelPath, HitAcc)> = Vec::new();
    for (name, content) in entries {
        match content {
            Ok(Content::Manifest(parsed)) => manifest = Some((name, parsed)),
            Ok(Content::Dex(hits)) => dex_files.push((name, hits)),
            Err(error) => gaps.at(&name, coverage_of(error)),
        }
    }

    // A value the manifest declares but leaves empty is no value.
    let declared = |value: Option<&String>, max_bytes: usize| {
        value.map(|value| text::clean(value, max_bytes)).filter(|value| !value.is_empty())
    };
    let parsed = manifest.as_ref().map(|(_, parsed)| parsed);
    let id = declared(parsed.and_then(|m| m.package.as_ref()), text::MAX_ID_BYTES);
    if let (None, Some((location, _))) = (&id, &manifest) {
        // A manifest that parsed but names no package. One that could not
        // be read already left its own coverage record.
        gaps.at(location, (CoverageStatus::Unrecognized, CoverageReason::ParseError));
    }
    let version = declared(parsed.and_then(|m| m.version_name.as_ref()), text::MAX_VERSION_BYTES);
    let subject = Subject {
        kind: SubjectKind::App,
        platform: Platform::Android,
        id: id.unwrap_or_else(|| String::from(UNIDENTIFIED)),
        version,
        digest,
    };

    let mut records = vec![Record::Artifact(ArtifactRecord {
        v: V1,
        collector: Collector::AndroidApk,
        subject: subject.clone(),
        facts: Facts {
            name: declared(parsed.and_then(|m| m.label.as_ref()), text::MAX_NAME_BYTES),
            team_id: None,
            files_scanned: 1,
            bytes_scanned: bytes,
        },
    })];
    let mut edge = |collector, finding: Finding<'_>, location: &RelPath, region| {
        records.push(Record::Edge(EdgeRecord {
            v: V1,
            collector,
            subject: subject.clone(),
            edge: EdgeType::Channel,
            grade: finding.matcher.grade(),
            object: ObjectRef { kind: ObjectKind::Sdk, id: finding.rule.id.clone() },
            rule: finding.rule.id.clone(),
            proof: Proof {
                matcher: finding.matcher,
                token: finding.token.lit.clone(),
                count: finding.count,
                // A name from a table is an identifier and may be shown. A
                // string constant is file content, which a record never
                // copies: it could hold a URL with a path, or anything else.
                example: finding.example.filter(|_| !finding.matcher.is_content()),
                location: location.clone(),
                region,
                scope: SCOPE,
            },
        }));
    };

    // The manifest: one table.
    if let Some((location, parsed)) = &manifest {
        let mut hits = HitAcc::new();
        for component in &parsed.components {
            let name = component.name.as_bytes();
            matchers.match_value(MatcherKind::ManifestComponent, SCOPE, name, &mut hits);
        }
        for finding in matchers.judge(&hits).edges {
            edge(Collector::AndroidManifest, finding, location, Region::Components);
        }
    }

    // The entry names: one table. An `apk_file` token is a whole entry
    // name, so the entry that matched is the place of the hit.
    for finding in matchers.judge(names).edges {
        if let Ok(location) = RelPath::new(&finding.token.lit) {
            edge(Collector::AndroidApk, finding, &location, Region::ZipEntries);
        }
    }

    // The DEX files. Where the build cuts the code into `classesN.dex` is
    // an accident of a format limit, so the controls that look at a whole
    // haystack (the breadth guard and the distinct-token minimum) judge the
    // files of one package together. Each record still names the file its
    // hit is in, with that file's count.
    let mut whole = HitAcc::new();
    for (_, hits) in &dex_files {
        whole.merge(hits);
    }
    let token_of = |finding: &Finding<'_>| {
        (finding.rule.id.clone(), finding.matcher, finding.token.lit.clone())
    };
    let evidence: BTreeSet<_> = matchers.judge(&whole).edges.iter().map(token_of).collect();
    for (location, hits) in &dex_files {
        let verdict = matchers.judge(hits);
        let found =
            verdict.edges.into_iter().chain(verdict.mentions.into_iter().map(|m| m.finding));
        for finding in found.filter(|finding| evidence.contains(&token_of(finding))) {
            let region = match finding.matcher {
                MatcherKind::DexString => Region::StringIds,
                _ => Region::ClassDefs,
            };
            edge(Collector::AndroidDex, finding, location, region);
        }
    }

    let coverage = |status, reason, location, bytes, count| {
        Record::Coverage(CoverageRecord {
            v: V1,
            collector: Collector::AndroidApk,
            subject: subject.clone(),
            status,
            reason,
            location,
            bytes,
            count,
        })
    };
    let located = gaps
        .located
        .into_iter()
        .map(|gap| coverage(gap.status, gap.reason, Some(gap.location), gap.bytes, 1));
    let counted = gaps
        .counted
        .into_iter()
        .map(|((status, reason), count)| coverage(status, reason, None, None, count));
    let coverage: Vec<Record> = located.chain(counted).collect();
    records.extend(coverage);
    records
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use xs_formats::testkit::{self, DexBuilder, ZipBuilder};
    use xs_model::Pack;
    use xs_model::matcher::Boundary;
    use xs_model::pack::{Category, Entity, Layer, LoadedLayer, Rule, Token};

    use super::*;

    fn rule(id: &str, entity: &str, tokens: &[(MatcherKind, &str, Boundary)]) -> Rule {
        let mut matchers: BTreeMap<MatcherKind, Vec<Token>> = BTreeMap::new();
        for &(kind, lit, at) in tokens {
            matchers.entry(kind).or_default().push(Token { lit: lit.into(), at });
        }
        Rule {
            id: id.into(),
            name: id.into(),
            entity: Some(entity.into()),
            category: "analytics".into(),
            sources: vec![],
            notes: vec![],
            matchers,
            min_distinct: BTreeMap::new(),
        }
    }

    fn pack_of(entities: &[&str], rules: Vec<Rule>) -> Pack {
        let layer = Layer {
            format: V1,
            layer: "core".into(),
            version: 1,
            license: "CC-BY-4.0".into(),
            categories: vec![Category {
                id: "analytics".into(),
                name: "Analytics".into(),
                headline: true,
            }],
            entities: entities
                .iter()
                .map(|id| Entity {
                    id: (*id).into(),
                    name: (*id).into(),
                    parent: None,
                    website: "https://example.com/".into(),
                    team_ids: Vec::new(),
                    app_ids: Vec::new(),
                    domains: Vec::new(),
                    sources: vec!["https://example.com/".into()],
                })
                .collect(),
            rules,
        };
        Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
    }

    /// A pack with one SDK that every Android witness can find.
    fn tracker_pack() -> Pack {
        pack_of(
            &["acme"],
            vec![rule(
                "sdk/tracker",
                "acme",
                &[
                    (
                        MatcherKind::ManifestComponent,
                        "com.acme.tracker.UploadService",
                        Boundary::Exact,
                    ),
                    (MatcherKind::AndroidClassPrefix, "com.acme.tracker.", Boundary::Prefix),
                    (MatcherKind::DexString, "collect.acme.example", Boundary::Host),
                    (MatcherKind::ApkFile, "acme-tracker.properties", Boundary::Exact),
                ],
            )],
        )
    }

    fn tracker_manifest() -> Vec<u8> {
        testkit::manifest(
            "com.example.app",
            "1.2.3",
            &[("activity", ".Main"), ("service", "com.acme.tracker.UploadService")],
        )
    }

    fn tracker_dex() -> Vec<u8> {
        DexBuilder::new()
            .class("com.example.app.Main")
            .class("com.acme.tracker.Tracker")
            .class("com.acme.tracker.UploadService")
            .referenced_type("Lcom/acme/tracker/NotDefinedHere;")
            .string("https://collect.acme.example/v1/batch?key=secret")
            .finish()
    }

    /// A package that ships the tracker in every way a rule can see.
    fn tracker_apk() -> Vec<u8> {
        ZipBuilder::new()
            .deflated(MANIFEST, &tracker_manifest())
            .deflated("classes.dex", &tracker_dex())
            .stored("acme-tracker.properties", b"version=1.0\n")
            .stored("res/", b"")
            .deflated("res/layout/main.xml", b"<layout/>")
            .finish()
    }

    /// Scans a package held in memory, read `step` bytes at a time.
    fn scan_with(apk: &[u8], pack: &Pack, step: usize) -> Vec<Record> {
        let matchers = Matchers::build(pack).unwrap();
        let mut buffer = vec![0; step];
        let scanned =
            scan_package(&mut Cursor::new(apk), apk.len() as u64, &mut buffer, &matchers).unwrap();
        assert_eq!(scanned.bytes, apk.len() as u64);
        for record in &scanned.records {
            record.validate().unwrap();
            assert!(record.id().is_ok());
            assert_eq!(record.subject().digest, SubjectDigest::Sha256(Sha256Digest::of(apk)));
        }
        scanned.records
    }

    fn scan(apk: &[u8], pack: &Pack) -> Vec<Record> {
        scan_with(apk, pack, 4096)
    }

    /// `collector matcher token count example where region` of every edge,
    /// sorted.
    fn edges(records: &[Record]) -> Vec<String> {
        let mut edges: Vec<String> = records
            .iter()
            .filter_map(|record| match record {
                Record::Edge(edge) => Some(format!(
                    "{:?} {} {} {} {:?} {} {:?}",
                    edge.collector,
                    edge.proof.matcher,
                    edge.proof.token,
                    edge.proof.count,
                    edge.proof.example,
                    edge.proof.location,
                    edge.proof.region,
                )),
                _ => None,
            })
            .collect();
        edges.sort();
        edges
    }

    /// `status reason where bytes count` of every coverage record, sorted.
    fn coverage(records: &[Record]) -> Vec<String> {
        let mut gaps: Vec<String> = records
            .iter()
            .filter_map(|record| match record {
                Record::Coverage(gap) => Some(format!(
                    "{:?} {:?} {} {:?} {}",
                    gap.status,
                    gap.reason,
                    gap.location.as_ref().map_or("-", RelPath::as_str),
                    gap.bytes,
                    gap.count
                )),
                _ => None,
            })
            .collect();
        gaps.sort();
        gaps
    }

    fn artifact(records: &[Record]) -> &ArtifactRecord {
        let artifacts: Vec<&ArtifactRecord> = records
            .iter()
            .filter_map(|record| match record {
                Record::Artifact(artifact) => Some(artifact),
                _ => None,
            })
            .collect();
        assert_eq!(artifacts.len(), 1, "one artifact record per package");
        artifacts[0]
    }

    #[test]
    fn every_witness_finds_the_sdk_and_says_where() {
        let apk = tracker_apk();
        let records = scan(&apk, &tracker_pack());

        let artifact = artifact(&records);
        assert_eq!(artifact.collector, Collector::AndroidApk);
        assert_eq!(artifact.subject.id, "com.example.app");
        assert_eq!(artifact.subject.version.as_deref(), Some("1.2.3"));
        assert_eq!(artifact.subject.platform, Platform::Android);
        assert_eq!(artifact.facts.files_scanned, 1);
        assert_eq!(artifact.facts.bytes_scanned, apk.len() as u64);

        assert_eq!(
            edges(&records),
            [
                "AndroidApk apk_file acme-tracker.properties 1 Some(\"acme-tracker.properties\") \
                 acme-tracker.properties ZipEntries",
                "AndroidDex android_class_prefix com.acme.tracker. 2 \
                 Some(\"com.acme.tracker.Tracker\") classes.dex ClassDefs",
                // The string is a URL with a path and a key. None of it is
                // copied into the record.
                "AndroidDex dex_string collect.acme.example 1 None classes.dex StringIds",
                "AndroidManifest manifest_component com.acme.tracker.UploadService 1 \
                 Some(\"com.acme.tracker.UploadService\") AndroidManifest.xml Components",
            ]
        );
        assert_eq!(coverage(&records), [] as [&str; 0]);
        assert!(!format!("{records:?}").contains("secret"));
    }

    /// Design report, section 6.4 rule 4: where the windows of the pass fall
    /// cannot change the result.
    #[test]
    fn the_records_do_not_depend_on_how_the_file_is_cut_into_windows() {
        let apk = tracker_apk();
        let pack = tracker_pack();
        let reference = scan_with(&apk, &pack, apk.len() + 1);
        assert_eq!(edges(&reference).len(), 4);
        for step in [1, 2, 7, 29, 30, 31, 64, 1000, apk.len()] {
            assert_eq!(scan_with(&apk, &pack, step), reference, "step {step}");
        }
    }

    #[test]
    fn a_package_without_the_sdk_yields_its_identity_and_nothing_else() {
        let apk = ZipBuilder::new()
            .deflated(
                MANIFEST,
                &testkit::manifest("org.example.clean", "7", &[("activity", ".Main")]),
            )
            .deflated(
                "classes.dex",
                &DexBuilder::new()
                    .class("org.example.clean.Main")
                    // Names that only resemble the tracker's.
                    .class("com.acme.trackers.Other")
                    .class("org.example.com.acme.tracker.Copy")
                    .referenced_type("Lcom/acme/tracker/Tracker;")
                    .string("collect.acme.example.evil.test")
                    .string("xcollect.acme.example")
                    .finish(),
            )
            .stored("assets/acme-tracker.properties", b"not at the root")
            .finish();
        let records = scan(&apk, &tracker_pack());
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(artifact(&records).subject.id, "org.example.clean");
    }

    /// Two builds that share an app id and a version are two subjects.
    #[test]
    fn the_file_hash_is_the_identity() {
        let pack = tracker_pack();
        let one = tracker_apk();
        let other = ZipBuilder::new()
            .deflated(MANIFEST, &tracker_manifest())
            .deflated("classes.dex", &tracker_dex())
            .finish();
        let (first, second) = (scan(&one, &pack), scan(&other, &pack));
        assert_eq!(artifact(&first).subject.id, artifact(&second).subject.id);
        assert_ne!(artifact(&first).subject.digest, artifact(&second).subject.digest);
    }

    #[test]
    fn hits_in_several_dex_files_are_reported_per_file() {
        let apk = ZipBuilder::new()
            .deflated(MANIFEST, &testkit::manifest("com.example.app", "1", &[]))
            .stored("classes.dex", &DexBuilder::new().class("com.example.app.Main").finish())
            .deflated("classes2.dex", &DexBuilder::new().class("com.acme.tracker.A").finish())
            .stored_padded(
                "classes3.dex",
                &DexBuilder::new()
                    .class("com.acme.tracker.B")
                    .class("com.acme.tracker.C")
                    .string("collect.acme.example")
                    .finish(),
                3,
            )
            .finish();
        assert_eq!(
            edges(&scan(&apk, &tracker_pack())),
            [
                "AndroidDex android_class_prefix com.acme.tracker. 1 \
                 Some(\"com.acme.tracker.A\") classes2.dex ClassDefs",
                "AndroidDex android_class_prefix com.acme.tracker. 2 \
                 Some(\"com.acme.tracker.B\") classes3.dex ClassDefs",
                "AndroidDex dex_string collect.acme.example 1 None classes3.dex StringIds",
            ]
        );
    }

    /// A rule that asks for two different tokens.
    fn two_token_pack() -> Pack {
        let mut rule = rule(
            "sdk/tracker",
            "acme",
            &[
                (MatcherKind::DexString, "collect.acme.example", Boundary::Host),
                (MatcherKind::DexString, "config.acme.example", Boundary::Host),
            ],
        );
        rule.min_distinct.insert(MatcherKind::DexString, 2);
        pack_of(&["acme"], vec![rule])
    }

    fn apk_with_strings(dex_files: &[&[&str]]) -> Vec<u8> {
        let mut zip =
            ZipBuilder::new().deflated(MANIFEST, &testkit::manifest("com.example.app", "1", &[]));
        for (index, strings) in dex_files.iter().enumerate() {
            let mut dex = DexBuilder::new();
            for string in *strings {
                dex = dex.string(string);
            }
            let name = if index == 0 {
                String::from("classes.dex")
            } else {
                format!("classes{}.dex", index + 1)
            };
            zip = zip.deflated(&name, &dex.finish());
        }
        zip.finish()
    }

    /// Where the build cuts the code into DEX files is an accident, so a
    /// minimum of distinct tokens is counted over the package.
    #[test]
    fn the_distinct_token_minimum_is_counted_over_all_dex_files() {
        let pack = two_token_pack();
        let split = apk_with_strings(&[&["collect.acme.example"], &["config.acme.example"]]);
        assert_eq!(
            edges(&scan(&split, &pack)),
            [
                "AndroidDex dex_string collect.acme.example 1 None classes.dex StringIds",
                "AndroidDex dex_string config.acme.example 1 None classes2.dex StringIds",
            ]
        );
        // One token alone is below the minimum, however often it occurs.
        let alone = apk_with_strings(&[&["collect.acme.example"], &["a collect.acme.example b"]]);
        assert!(edges(&scan(&alone, &pack)).is_empty());
    }

    /// Design report, section 5.2 control 4, for a package: a string table
    /// that names eight companies is a list, however it is spread over DEX
    /// files. Class names say what the code is made of and stay evidence.
    #[test]
    fn the_breadth_guard_looks_at_the_strings_of_the_whole_package() {
        let hosts: Vec<String> = (0..8).map(|n| format!("collect.vendor-{n}.example")).collect();
        let entities: Vec<String> = (0..8).map(|n| format!("vendor-{n}")).collect();
        let mut rules: Vec<Rule> = (0..8)
            .map(|n| {
                rule(
                    &format!("sdk/vendor-{n}"),
                    &entities[n],
                    &[(MatcherKind::DexString, hosts[n].as_str(), Boundary::Host)],
                )
            })
            .collect();
        rules.push(rule(
            "sdk/vendor-code",
            "vendor-0",
            &[(MatcherKind::AndroidClassPrefix, "com.vendor.", Boundary::Prefix)],
        ));
        let entity_ids: Vec<&str> = entities.iter().map(String::as_str).collect();
        let pack = pack_of(&entity_ids, rules);
        let names = |range: std::ops::Range<usize>| -> Vec<&str> {
            hosts[range].iter().map(String::as_str).collect()
        };

        // Seven companies: every string is evidence.
        let seven = apk_with_strings(&[&names(0..4)[..], &names(4..7)[..]]);
        assert_eq!(edges(&scan(&seven, &pack)).len(), 7);

        // Eight, four in each file: none is.
        let (first, second) = (names(0..4), names(4..8));
        let eight = ZipBuilder::new()
            .deflated(MANIFEST, &testkit::manifest("com.example.app", "1", &[]))
            .deflated("classes.dex", &{
                let mut dex = DexBuilder::new().class("com.vendor.Sdk");
                for name in &first {
                    dex = dex.string(name);
                }
                dex.finish()
            })
            .deflated("classes2.dex", &{
                let mut dex = DexBuilder::new();
                for name in &second {
                    dex = dex.string(name);
                }
                dex.finish()
            })
            .finish();
        assert_eq!(
            edges(&scan(&eight, &pack)),
            ["AndroidDex android_class_prefix com.vendor. 1 Some(\"com.vendor.Sdk\") classes.dex \
              ClassDefs"]
        );
    }

    #[test]
    fn the_dex_files_android_loads_are_told_from_the_rest_by_name() {
        for (name, number) in [
            ("classes.dex", Some(1)),
            ("classes2.dex", Some(2)),
            ("classes10.dex", Some(10)),
            ("classes4294967295.dex", Some(u32::MAX)),
            ("classes1.dex", None),
            ("classes0.dex", None),
            ("classes02.dex", None),
            ("classes4294967296.dex", None),
            ("classes-2.dex", None),
            ("classes2.DEX", None),
            ("Classes.dex", None),
            ("assets/classes.dex", None),
            ("classes.dex/x", None),
        ] {
            assert_eq!(dex_number(name), number, "{name}");
        }
    }

    #[test]
    fn dex_files_android_does_not_load_are_counted_not_read() {
        let tracker = tracker_dex();
        let apk = ZipBuilder::new()
            .deflated(MANIFEST, &testkit::manifest("com.example.app", "1", &[]))
            .deflated("classes.dex", &DexBuilder::new().class("com.example.app.Main").finish())
            .deflated("assets/payload.dex", &tracker)
            .deflated("classes1.dex", &tracker)
            .finish();
        let records = scan(&apk, &tracker_pack());
        assert!(edges(&records).is_empty());
        assert_eq!(coverage(&records), ["Skipped UnsupportedFormat - None 2"]);
    }

    #[test]
    fn a_package_without_a_manifest_is_reported_and_still_scanned() {
        let apk = ZipBuilder::new().deflated("classes.dex", &tracker_dex()).finish();
        let records = scan(&apk, &tracker_pack());
        let artifact = artifact(&records);
        assert_eq!(artifact.subject.id, UNIDENTIFIED);
        assert_eq!(artifact.subject.version, None);
        assert_eq!(edges(&records).len(), 2);
        assert_eq!(coverage(&records), ["Unrecognized ParseError AndroidManifest.xml None 1"]);
    }

    #[test]
    fn a_manifest_that_does_not_parse_or_names_no_package_is_reported() {
        let pack = tracker_pack();
        let damaged = ZipBuilder::new().stored(MANIFEST, b"<manifest/>").finish();
        let records = scan(&damaged, &pack);
        assert_eq!(artifact(&records).subject.id, UNIDENTIFIED);
        assert_eq!(coverage(&records), ["Unrecognized ParseError AndroidManifest.xml None 1"]);

        let nameless = testkit::AxmlBuilder::new()
            .start(
                "manifest",
                &[testkit::Attr::int(testkit::ANDROID_VERSION_CODE, "versionCode", 42)],
            )
            .end()
            .finish();
        let records = scan(&ZipBuilder::new().stored(MANIFEST, &nameless).finish(), &pack);
        let artifact = artifact(&records);
        assert_eq!(artifact.subject.id, UNIDENTIFIED);
        // The build number is not a version name and does not stand in.
        assert_eq!(artifact.subject.version, None);
        assert_eq!(coverage(&records), ["Unrecognized ParseError AndroidManifest.xml None 1"]);
    }

    #[test]
    fn hostile_text_in_the_manifest_is_cleaned_before_it_enters_a_record() {
        let manifest = testkit::AxmlBuilder::new()
            .start(
                "manifest",
                &[
                    testkit::Attr::plain("package", "com.example\u{202e}evil\n"),
                    testkit::Attr::android(
                        testkit::ANDROID_VERSION_NAME,
                        "versionName",
                        &"9".repeat(500),
                    ),
                ],
            )
            .start(
                "application",
                &[testkit::Attr::android(testkit::ANDROID_LABEL, "label", "A\u{7}pp")],
            )
            .end()
            .end()
            .finish();
        let records =
            scan(&ZipBuilder::new().deflated(MANIFEST, &manifest).finish(), &tracker_pack());
        let artifact = artifact(&records);
        assert_eq!(artifact.subject.id, "com.example\u{fffd}evil\u{fffd}");
        assert_eq!(
            artifact.subject.version.as_ref().map(String::len),
            Some(text::MAX_VERSION_BYTES)
        );
        assert_eq!(artifact.facts.name.as_deref(), Some("A\u{fffd}pp"));
    }

    #[test]
    fn a_damaged_dex_file_yields_a_coverage_record_and_no_evidence() {
        let pack = tracker_pack();
        let manifest = testkit::manifest("com.example.app", "1", &[]);
        let good = tracker_dex();

        // A class definition that points past the type table. The classes
        // before it were read, and still nothing is drawn from the file.
        let mut dangling = good.clone();
        let class_defs = u32::from_le_bytes(dangling[0x64..0x68].try_into().unwrap()) as usize;
        dangling[class_defs + 64..class_defs + 68].copy_from_slice(&9999u32.to_le_bytes());
        // A file of a version this build cannot read.
        let mut container = good.clone();
        container[4..7].copy_from_slice(b"041");

        for (dex, expected) in [
            (&dangling[..], "Unrecognized ParseError classes2.dex None 1"),
            (&b"not a dex file"[..], "Unrecognized ParseError classes2.dex None 1"),
            (&container[..], "Skipped UnsupportedFormat classes2.dex None 1"),
        ] {
            let apk = ZipBuilder::new()
                .deflated(MANIFEST, &manifest)
                .deflated("classes.dex", &good)
                .deflated("classes2.dex", dex)
                .finish();
            let records = scan(&apk, &pack);
            assert_eq!(coverage(&records), [expected]);
            // The sound file is still evidence.
            let edges = edges(&records);
            assert_eq!(edges.len(), 2, "{edges:?}");
            assert!(edges.iter().all(|edge| edge.contains(" classes.dex ")), "{edges:?}");
        }
    }

    #[test]
    fn entries_the_collector_cannot_inflate_are_reported_by_reason() {
        let pack = tracker_pack();
        let dex = tracker_dex();
        let deflated = miniz_dex(&dex);
        let size = dex.len() as u32;
        for (entry, expected) in [
            // Encrypted.
            (
                ZipBuilder::new().raw("classes.dex", 8, 1, &deflated, size),
                "Skipped UnsupportedFormat",
            ),
            // A compression method Android has no reader for either.
            (
                ZipBuilder::new().raw("classes.dex", 93, 0, &deflated, size),
                "Skipped UnsupportedFormat",
            ),
            // A stream that is cut short.
            (
                ZipBuilder::new().raw("classes.dex", 8, 0, &deflated[..deflated.len() / 2], size),
                "Unrecognized ParseError",
            ),
            // A stream that inflates to more than the entry declares.
            (
                ZipBuilder::new().raw("classes.dex", 8, 0, &deflated, size - 1),
                "Unrecognized ParseError",
            ),
            // A stored entry whose two sizes disagree.
            (ZipBuilder::new().raw("classes.dex", 0, 0, &dex, size - 1), "Unrecognized ParseError"),
        ] {
            let apk = entry.deflated(MANIFEST, &tracker_manifest()).finish();
            let records = scan(&apk, &pack);
            assert_eq!(coverage(&records), [format!("{expected} classes.dex None 1")]);
            // The manifest is still read.
            assert_eq!(edges(&records).len(), 1);
        }
    }

    /// The bytes of `content` as a raw DEFLATE stream, through a zip entry.
    fn miniz_dex(content: &[u8]) -> Vec<u8> {
        let archive = ZipBuilder::new().deflated("x", content).finish();
        let end = zip::locate(&archive, archive.len() as u64).unwrap();
        let start = end.directory_offset as usize;
        let entries = zip::directory(&archive[start..start + end.directory_bytes], &end).unwrap();
        zip::data(&entries[0], &archive).unwrap().to_vec()
    }

    /// The inflate budget (design report, section 4.8). The sizes are what
    /// the directory declares, so nothing is read or inflated to find out.
    #[test]
    fn entries_over_a_byte_budget_are_set_aside_with_their_declared_size() {
        let pack = tracker_pack();
        let small = tracker_dex();
        let entry_budget = MAX_ENTRY_BYTES as u32;
        let manifest_budget = android_manifest::MAX_BYTES as u32;

        // One entry over the per-entry budget, by its inflated size and by
        // its stored size.
        let apk = ZipBuilder::new()
            .raw(MANIFEST, 8, 0, b"", manifest_budget + 1)
            .deflated("classes.dex", &small)
            .raw("classes2.dex", 8, 0, b"tiny", entry_budget + 1)
            .raw("classes3.dex", 8, 0, b"tiny", entry_budget)
            .finish();
        let records = scan(&apk, &pack);
        assert_eq!(
            coverage(&records),
            [
                format!("Skipped OverBudget AndroidManifest.xml Some({}) 1", manifest_budget + 1),
                format!("Skipped OverBudget classes2.dex Some({}) 1", entry_budget + 1),
                // Within budget as declared, so it was read, and it is not
                // what it declares.
                String::from("Unrecognized ParseError classes3.dex None 1"),
            ]
        );
        assert_eq!(edges(&records).len(), 2, "the sound DEX file is still evidence");

        // The package budget is on the sum, in reading order: with the
        // manifest, three entries of 256 MiB fit in 1 GiB and the fourth
        // does not. A small file after it still fits, and is read.
        let mut zip = ZipBuilder::new().deflated(MANIFEST, &tracker_manifest());
        for name in ["classes.dex", "classes2.dex", "classes3.dex", "classes4.dex"] {
            zip = zip.raw(name, 8, 0, b"tiny", entry_budget);
        }
        let records = scan(&zip.deflated("classes5.dex", &small).finish(), &pack);
        assert_eq!(
            coverage(&records),
            [
                format!("Skipped OverBudget classes4.dex Some({entry_budget}) 1"),
                String::from("Unrecognized ParseError classes.dex None 1"),
                String::from("Unrecognized ParseError classes2.dex None 1"),
                String::from("Unrecognized ParseError classes3.dex None 1"),
            ]
        );
        assert_eq!(edges(&records).len(), 3, "the manifest and the last DEX file");
    }

    /// Sets where the directory says the local header of `name` is.
    fn move_entry(apk: &mut [u8], name: &str, offset: u32) {
        let end = zip::locate(apk, apk.len() as u64).unwrap();
        let mut at = end.directory_offset as usize;
        for _ in 0..end.entries {
            let length = |field: usize| {
                usize::from(u16::from_le_bytes([apk[at + field], apk[at + field + 1]]))
            };
            let (name_bytes, skip) = (length(28), length(30) + length(32));
            if &apk[at + 46..at + 46 + name_bytes] == name.as_bytes() {
                apk[at + 42..at + 46].copy_from_slice(&offset.to_le_bytes());
                return;
            }
            at += 46 + name_bytes + skip;
        }
        panic!("no entry named {name}");
    }

    fn offset_of(apk: &[u8], name: &str) -> u32 {
        let end = zip::locate(apk, apk.len() as u64).unwrap();
        let start = end.directory_offset as usize;
        let entries = zip::directory(&apk[start..start + end.directory_bytes], &end).unwrap();
        entries.iter().find(|entry| entry.name == name.as_bytes()).unwrap().offset
    }

    /// In a well-formed archive entries do not share bytes. Reading two
    /// that do would hold both in memory at once, so the one that starts
    /// later is refused, which also keeps a hostile directory from pointing
    /// a thousand entries at the same megabytes.
    #[test]
    fn of_two_entries_that_share_bytes_only_the_first_is_read() {
        let pack = tracker_pack();
        let apk = ZipBuilder::new()
            .deflated(MANIFEST, &tracker_manifest())
            .stored("classes.dex", &tracker_dex())
            .stored("classes2.dex", &tracker_dex())
            .stored("classes3.dex", &tracker_dex())
            .finish();
        let sound = scan(&apk, &pack);
        assert_eq!(coverage(&sound), [] as [&str; 0]);
        assert_eq!(edges(&sound).len(), 7);

        // The second DEX file is said to start inside the first, and the
        // third exactly where the first does.
        let first = offset_of(&apk, "classes.dex");
        let mut sharing = apk.clone();
        move_entry(&mut sharing, "classes2.dex", first + 40);
        move_entry(&mut sharing, "classes3.dex", first);
        let records = scan(&sharing, &pack);
        assert_eq!(
            coverage(&records),
            [
                "Unrecognized ParseError classes2.dex None 1",
                "Unrecognized ParseError classes3.dex None 1",
            ]
        );
        let edges = edges(&records);
        assert_eq!(edges.len(), 3, "{edges:?}");
        assert!(edges.iter().all(|edge| !edge.contains("classes2") && !edge.contains("classes3")));

        // Which of two is first is decided by where they start, not by
        // their names: here the manifest is said to start inside a DEX file.
        let mut sharing = apk.clone();
        move_entry(&mut sharing, MANIFEST, first + 40);
        let records = scan(&sharing, &pack);
        assert_eq!(coverage(&records), ["Unrecognized ParseError AndroidManifest.xml None 1"]);
        assert_eq!(artifact(&records).subject.id, UNIDENTIFIED);
        assert_eq!(edges_of(&records, "classes").len(), 6);
    }

    fn edges_of(records: &[Record], file_prefix: &str) -> Vec<String> {
        edges(records)
            .into_iter()
            .filter(|edge| edge.contains(&format!(" {file_prefix}")))
            .collect()
    }

    /// An entry is read as soon as the pass has gone over it. One whose
    /// data would run past the end of the file never is whole, and is read
    /// from what there is, which fails.
    #[test]
    fn an_entry_that_runs_past_the_end_of_the_file_is_reported() {
        let apk = ZipBuilder::new()
            .deflated(MANIFEST, &tracker_manifest())
            .stored("classes.dex", &tracker_dex())
            .finish();
        // The directory gives the entry four megabytes more than the
        // archive has for it, stored and inflated alike.
        let mut cut = apk.clone();
        let end = zip::locate(&apk, apk.len() as u64).unwrap();
        let sizes = end.directory_offset as usize + 46 + MANIFEST.len() + 20;
        let long = (tracker_dex().len() as u32 + 4_000_000).to_le_bytes();
        cut[sizes..sizes + 4].copy_from_slice(&long);
        cut[sizes + 4..sizes + 8].copy_from_slice(&long);
        let records = scan(&cut, &tracker_pack());
        assert_eq!(coverage(&records), ["Unrecognized ParseError classes.dex None 1"]);
        assert_eq!(edges(&records).len(), 1, "the manifest was read");
    }

    #[test]
    fn dex_files_past_the_count_budget_are_counted() {
        let dex = DexBuilder::new().finish();
        let mut zip = ZipBuilder::new().deflated(MANIFEST, &tracker_manifest());
        for number in 1..=MAX_DEX_FILES + 3 {
            let name = if number == 1 {
                String::from("classes.dex")
            } else {
                format!("classes{number}.dex")
            };
            zip = zip.stored(&name, &dex);
        }
        let records = scan(&zip.finish(), &tracker_pack());
        assert_eq!(coverage(&records), ["Skipped OverBudget - None 3"]);
    }

    #[test]
    fn entry_names_a_record_cannot_hold_are_counted() {
        let apk = ZipBuilder::new()
            .deflated(MANIFEST, &tracker_manifest())
            .stored("../../etc/passwd", b"x")
            .stored("/absolute", b"x")
            .stored("a//b", b"x")
            .stored("bell\u{7}", b"x")
            .stored("fine/name.txt", b"x")
            .finish();
        let records = scan(&apk, &tracker_pack());
        assert_eq!(coverage(&records), ["Unrecognized ParseError - None 4"]);
    }

    #[test]
    fn what_is_not_a_package_yields_a_coverage_record_under_its_own_hash() {
        let pack = tracker_pack();
        for (bytes, expected) in [
            (&b""[..], "Unrecognized ParseError - None 1"),
            (
                &b"just some text in a file named like a package"[..],
                "Unrecognized ParseError - None 1",
            ),
        ] {
            let records = scan(bytes, &pack);
            assert_eq!(records.len(), 2);
            assert_eq!(artifact(&records).subject.id, UNIDENTIFIED);
            assert_eq!(coverage(&records), [expected]);
        }

        // An archive with the 64-bit extension.
        let mut zip64 = tracker_apk();
        let at = zip64.len() - zip::END_RECORD_BYTES + 10;
        zip64[at..at + 2].copy_from_slice(&[0xff, 0xff]);
        let records = scan(&zip64, &pack);
        assert_eq!(coverage(&records), ["Skipped UnsupportedFormat - None 1"]);
        assert!(edges(&records).is_empty());

        // An archive with the same entry twice, which Android refuses.
        let twice = ZipBuilder::new()
            .deflated("classes.dex", &tracker_dex())
            .deflated("classes.dex", &DexBuilder::new().finish())
            .finish();
        let records = scan(&twice, &pack);
        assert_eq!(coverage(&records), ["Unrecognized ParseError - None 1"]);
        assert!(edges(&records).is_empty());
    }

    /// A reader over a file that is replaced, in place, after a number of
    /// reads.
    struct Changing<'a> {
        before: &'a [u8],
        after: &'a [u8],
        position: usize,
        reads_left: usize,
    }

    impl Read for Changing<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let file = if self.reads_left > 0 { self.before } else { self.after };
            self.reads_left = self.reads_left.saturating_sub(1);
            let rest = file.get(self.position..).unwrap_or_default();
            let count = rest.len().min(buffer.len());
            buffer[..count].copy_from_slice(&rest[..count]);
            self.position += count;
            Ok(count)
        }
    }

    impl Seek for Changing<'_> {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            let SeekFrom::Start(offset) = to else { return Err(io::ErrorKind::Unsupported.into()) };
            self.position = offset as usize;
            Ok(offset)
        }
    }

    /// Evidence comes only from bytes the digest covers. If the end of the
    /// file is not what the plan was made from, the package changed under
    /// the scanner, and the scan of it fails. There is no moment at which a
    /// replacement gives a mix of the two files.
    #[test]
    fn a_package_that_changes_while_it_is_read_fails_the_scan() {
        let pack = tracker_pack();
        let matchers = Matchers::build(&pack).unwrap();
        let before = tracker_apk();
        // The same length, another directory: the tracker's file is renamed
        // and its DEX file is given another name, so a plan made from this
        // directory reads other entries.
        let after: Vec<u8> = {
            let mut bytes = before.clone();
            let at = bytes.windows(4).rposition(|window| window == b"acme").unwrap();
            bytes[at..at + 4].copy_from_slice(b"ACME");
            let at = bytes.windows(11).rposition(|window| window == b"classes.dex").unwrap();
            bytes[at..at + 11].copy_from_slice(b"classes.bin");
            bytes
        };
        assert_eq!(before.len(), after.len());

        let run = |reads_left: usize| {
            let mut reader = Changing { before: &before, after: &after, position: 0, reads_left };
            let mut buffer = vec![0; 64];
            scan_package(&mut reader, before.len() as u64, &mut buffer, &matchers)
                .map(|scanned| scanned.records)
                .map_err(|error| error.to_string())
        };

        // Never replaced, and replaced before the first read.
        let stable = run(usize::MAX).unwrap();
        assert_eq!(edges(&stable).len(), 4);
        let replaced = run(0).unwrap();
        assert_eq!(edges(&replaced).len(), 1, "only the manifest's edge is left");
        let digest_after = SubjectDigest::Sha256(Sha256Digest::of(&after));
        assert_eq!(artifact(&replaced).subject.digest, digest_after);

        // Replaced after any number of reads: the result is one file or the
        // other, whole, or the scan of the package fails.
        let mut failed = 0;
        for reads_left in 1..200 {
            match run(reads_left) {
                Ok(records) => assert!(
                    records == stable || records == replaced,
                    "a mix of two files after {reads_left} reads"
                ),
                Err(error) => {
                    failed += 1;
                    assert_eq!(error, "the package changed while it was being read");
                }
            }
        }
        assert!(failed > 10, "the replacement was noticed {failed} times");

        // A file that grew, or shrank, is noticed too.
        let mut grown = before.clone();
        grown.extend_from_slice(b"more");
        let mut buffer = vec![0; 64];
        let outcome =
            scan_package(&mut Cursor::new(&grown), before.len() as u64, &mut buffer, &matchers);
        assert!(outcome.is_err());
    }

    #[test]
    fn read_errors_fail_the_scan_of_the_package() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        }
        impl Seek for Failing {
            fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
                Ok(0)
            }
        }
        let pack = tracker_pack();
        let matchers = Matchers::build(&pack).unwrap();
        let mut buffer = vec![0; 64];
        let error = scan_package(&mut Failing, 100, &mut buffer, &matchers).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        // A file shorter than its size says.
        let error =
            scan_package(&mut Cursor::new(b"short"), 100, &mut buffer, &matchers).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_region_agrees_with_a_window_wherever_they_overlap() {
        let region = Expected { offset: 10, bytes: b"0123456789" };
        // No overlap at all.
        assert!(region.agrees_with(0, b"abcdefghij"));
        assert!(region.agrees_with(20, b"abc"));
        // The window starts before, inside, and covers the region.
        assert!(region.agrees_with(8, b"xx0123"));
        assert!(!region.agrees_with(8, b"xx0193"));
        assert!(region.agrees_with(15, b"56789 and more"));
        assert!(!region.agrees_with(15, b"56780"));
        assert!(region.agrees_with(0, b"..........0123456789.........."));
        assert!(!region.agrees_with(0, b"..........012345678X.........."));
        assert!(region.agrees_with(19, b"9"));
        assert!(!region.agrees_with(19, b"8"));
    }

    /// Scanning files on disk: one task per package, results in a set.
    #[test]
    fn packages_on_disk_are_scanned_and_an_unreadable_one_fails_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        let clean = ZipBuilder::new()
            .deflated(MANIFEST, &testkit::manifest("org.example.clean", "1", &[]))
            .finish();
        std::fs::write(dir.path().join("tracker.apk"), tracker_apk()).unwrap();
        std::fs::write(dir.path().join("clean.apk"), &clean).unwrap();
        let paths = [dir.path().join("clean.apk"), dir.path().join("tracker.apk")];

        let pack = tracker_pack();
        let matchers = Matchers::build(&pack).unwrap();
        let pool = Pool::new(2).unwrap();
        let (records, stats) = collect(&paths, &matchers, &pool).unwrap();
        assert_eq!(stats.artifacts, 2);
        assert_eq!(stats.files, 2);
        assert_eq!(stats.bytes, (clean.len() + tracker_apk().len()) as u64);
        assert_eq!(edges(&records).len(), 4);
        assert_eq!(records.len(), 6);

        let missing = [dir.path().join("clean.apk"), dir.path().join("gone.apk")];
        assert!(matches!(
            collect(&missing, &matchers, &pool),
            Err(ScanError::Path { path, .. }) if path.ends_with("gone.apk")
        ));
    }
}
