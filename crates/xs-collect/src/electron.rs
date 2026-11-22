//! The code of an Electron app inside a bundle (build plan, task 7).
//!
//! An Electron app is a browser engine plus the app's own scripts. The
//! scripts sit in one of two kinds of **code root**:
//!
//! * an **asar archive**, any file named `*.asar`, such as
//!   `Contents/Resources/app.asar`;
//! * a **loose folder**: `Contents/Resources/app`, which Electron runs in
//!   place of an archive, or a `*.asar.unpacked` folder, which holds the
//!   files an archive names but does not contain.
//!
//! Two kinds of witness are drawn from a code root (design report, 5.1):
//!
//! * `npm_package`: the root's file table lists
//!   `node_modules/<package>/package.json`. A table lookup, high confidence,
//!   and gone as soon as the app is bundled into one script. The table is
//!   the header of an archive, or the folder listing of
//!   `Contents/Resources/app`, which has no header. A `*.asar.unpacked`
//!   folder has no table of its own: the header of its archive already
//!   lists what it holds, so a package is reported once.
//! * `content_literal`: a script holds a literal the SDK cannot work
//!   without. This is the witness that survives bundling and minification.
//!
//! # Scope
//!
//! Which files are searched, and as what, is decided by path alone (section
//! 5.2, controls 1 and 7):
//!
//! | File | Scope | Searched |
//! |---|---|---|
//! | `.js`, `.cjs`, `.mjs` outside `node_modules` | `app_code` | yes |
//! | `.js`, `.cjs`, `.mjs` under a `node_modules` folder | `dependency` | yes |
//! | anything else | | no |
//!
//! Scripts only. A page is not searched, the app's own or a dependency's:
//! a link or a sentence in it names a company without the app talking to
//! it, and dependencies ship demo pages and documentation. Bitwarden
//! desktop 2026.10.4 carries an analytics snippet in
//! `node_modules/lunr/index.html`, the demo page of a search library.
//! Source maps are not searched for a like reason: a `.map` beside a
//! bundle repeats the source of every dependency. V8 bytecode (`.jsc`)
//! cannot be searched for literals at all, so each such file is reported as
//! a gap instead of passing for clean.
//!
//! # One file at a time
//!
//! Every searched file is judged on its own, as its own stream: a literal
//! cannot straddle two files of an archive, the start and the end of a file
//! are boundaries, and the breadth guard (control 4) sees one file, so a
//! filter list inside an app is held back without silencing the app's real
//! scripts.
//!
//! # What a record says
//!
//! The findings of the files of one root are gathered into one record per
//! token and scope: `where` is the root, `count` is the number of files the
//! token was found in, and `example` is the smallest path among them inside
//! the root. A hostile archive of a million scripts therefore yields a
//! handful of records, and the record still names a file a person can open
//! and search. A bundle may hold any number of roots, so the edges of one
//! bundle are capped as well: [`MAX_EDGES`] are kept, those of the roots
//! with the least paths, and the rest are counted in one gap.
//!
//! What could not be read or understood is handed to the bundle collector
//! as gaps. It owns the bundle's coverage records and their cap, so they
//! carry its name.
//!
//! # Reading an archive
//!
//! An archive is read front to back exactly once (section 6.2). The same
//! bytes feed the hash of the whole file, which enters the bundle digest,
//! and the search of each script at the place the header gives for it.
//! Nothing is extracted, and no entry is trusted: an entry that overlaps
//! one already read, or that reaches past the end of the archive, is
//! counted as a gap and not searched, so no byte is searched twice and the
//! work is bounded by the size of the file.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use xs_formats::{FormatError, asar};
use xs_match::{ContentMatcher, HitAcc, Matchers};
use xs_model::digest::BundleManifest;
use xs_model::record::{CoverageReason, CoverageStatus, Proof, Region, Scope};
use xs_model::{MatcherKind, RelPath, Sha256Digest, Sha256Stream, text};

use crate::read::{self, WINDOW, read_full};

/// The folder npm installs packages into.
pub(crate) const NODE_MODULES: &str = "node_modules";
/// The file every npm package has at its top.
const PACKAGE_JSON: &str = "package.json";
/// The folder Electron runs when there is no archive.
const LOOSE_APP: &str = "Contents/Resources/app";
/// How the name of an archive ends.
const ARCHIVE_SUFFIX: &str = ".asar";
/// How the name of the folder beside an archive ends.
const UNPACKED_SUFFIX: &str = ".asar.unpacked";

/// Most edges the code roots of one bundle yield. Past this, the edges of
/// the roots with the greatest paths are counted in one gap and not kept,
/// so a hostile bundle of many small archives cannot make a report large.
pub(crate) const MAX_EDGES: usize = 1000;

/// What a file is, going by the end of its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Code {
    /// JavaScript the runtime loads as is.
    Script,
    /// V8 bytecode. Its literals are not contiguous bytes.
    Bytecode,
    /// Not code.
    Other,
}

fn code_of(name: &str) -> Code {
    let Some((_, extension)) = name.rsplit_once('.') else { return Code::Other };
    let is = |wanted: &str| extension.eq_ignore_ascii_case(wanted);
    if is("js") || is("cjs") || is("mjs") {
        Code::Script
    } else if is("jsc") {
        Code::Bytecode
    } else {
        Code::Other
    }
}

/// Whether the content of a file is searched. See the table in the module
/// documentation.
const fn searched(code: Code, scope: Scope) -> bool {
    matches!((code, scope), (Code::Script, Scope::AppCode | Scope::Dependency))
}

/// Whether one of the folders in `folders`, a path, is `node_modules`.
fn in_dependency(folders: &str) -> bool {
    folders.split('/').any(|folder| folder == NODE_MODULES)
}

/// Splits a path into the folders that lead to a file and the file's name.
fn split_name(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

/// The loose code folder a bundle path lies in, and the path inside it.
fn loose_root(path: &str) -> Option<(&str, &str)> {
    if let Some(inner) = path.strip_prefix(LOOSE_APP).and_then(|rest| rest.strip_prefix('/')) {
        return Some((LOOSE_APP, inner));
    }
    // The outermost folder whose name ends the way an unpacked folder's does.
    let marker = path.match_indices(UNPACKED_SUFFIX).find_map(|(at, _)| {
        let end = at.checked_add(UNPACKED_SUFFIX.len())?;
        path.get(end..)?.starts_with('/').then_some(end)
    })?;
    let (root, rest) = path.split_at_checked(marker)?;
    Some((root, rest.strip_prefix('/')?))
}

/// The npm package whose `package.json` is at `path`, a path inside a code
/// root: `node_modules/<name>/package.json` or
/// `node_modules/@<scope>/<name>/package.json`, at any depth.
fn npm_package(path: &str) -> Option<&str> {
    let folder = path.strip_suffix(PACKAGE_JSON)?.strip_suffix('/')?;
    let (above, name) = folder.rsplit_once('/')?;
    let (further, parent) = split_name(above);
    if parent == NODE_MODULES {
        // `node_modules/@scope` is a folder of packages, not a package.
        return (!name.starts_with('@')).then_some(name);
    }
    if parent.starts_with('@') && split_name(further).1 == NODE_MODULES {
        // `@scope/name`, which is contiguous in the path.
        let start =
            folder.len().checked_sub(parent.len().checked_add(name.len())?.checked_add(1)?)?;
        return folder.get(start..);
    }
    None
}

/// How the collector treats one regular file of a bundle, by its path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileKind<'a> {
    /// An asar archive.
    Archive {
        /// Whether the archive itself sits under a `node_modules` folder, so
        /// that everything in it is a dependency.
        dependency: bool,
    },
    /// A file of a loose code folder whose content is searched.
    Script {
        /// The loose code folder.
        root: &'a str,
        /// The file's path inside it.
        inner: &'a str,
        /// What kind of code it is.
        scope: Scope,
    },
    /// A file this module draws nothing from by reading it.
    Other,
}

/// Classifies a regular file by its path inside the bundle.
pub(crate) fn classify(path: &str) -> FileKind<'_> {
    let (folders, name) = split_name(path);
    let dependency = in_dependency(folders);
    // Case matters: this is the name Electron itself looks for.
    if name.ends_with(ARCHIVE_SUFFIX) {
        return FileKind::Archive { dependency };
    }
    let Some((root, inner)) = loose_root(path) else { return FileKind::Other };
    let scope = if dependency { Scope::Dependency } else { Scope::AppCode };
    if searched(code_of(name), scope) {
        FileKind::Script { root, inner, scope }
    } else {
        FileKind::Other
    }
}

/// Records in `packages` the rule tokens that name the npm package whose
/// `package.json` is at `path`, a path inside a code root. The path is what
/// a record shows as the example.
fn note_package(matchers: &Matchers<'_>, path: &str, packages: &mut HitAcc) {
    let Some(package) = npm_package(path) else { return };
    let mut named = HitAcc::new();
    matchers.match_value(
        MatcherKind::NpmPackage,
        Scope::Dependency,
        package.as_bytes(),
        &mut named,
    );
    for (pattern, _) in named.iter() {
        packages.hit_value(pattern, path.as_bytes());
    }
}

/// What the files of one code root say, by path inside the root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Tables {
    /// The npm packages the file table lists.
    packages: HitAcc,
    /// The app's own files whose content is evidence.
    app_code: HitAcc,
    /// The dependency files whose content is evidence.
    dependency: HitAcc,
}

impl Tables {
    fn content(&mut self, scope: Scope) -> Option<&mut HitAcc> {
        match scope {
            Scope::AppCode => Some(&mut self.app_code),
            Scope::Dependency => Some(&mut self.dependency),
            Scope::Runtime | Scope::Resource => None,
        }
    }

    /// Records that the content of the file at `path` supports `verdict`'s
    /// edges. Mentions are dropped here: a hit that a control held back must
    /// never become an edge.
    fn file(&mut self, scope: Scope, path: &str, verdict: &xs_match::Verdict<'_>) {
        let Some(table) = self.content(scope) else { return };
        for edge in &verdict.edges {
            table.hit_value(edge.pattern, path.as_bytes());
        }
    }
}

/// What could not be learned from a code root: how many items, by status
/// and reason.
type Gaps = BTreeMap<(CoverageStatus, CoverageReason), u32>;

fn add_gap(gaps: &mut Gaps, status: CoverageStatus, reason: CoverageReason, count: usize) {
    if count == 0 {
        return;
    }
    let total = gaps.entry((status, reason)).or_insert(0);
    *total = total.saturating_add(u32::try_from(count).unwrap_or(u32::MAX));
}

/// An archive that was read to its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchiveScan {
    /// SHA-256 of the whole file.
    pub(crate) sha256: Sha256Digest,
    /// Number of bytes read.
    pub(crate) bytes: u64,
    tables: Tables,
    gaps: Gaps,
}

/// What reading an archive came to.
#[derive(Debug)]
pub(crate) enum ArchiveRead {
    /// Read to the end.
    Scanned(ArchiveScan),
    /// Larger than the byte budget: its size. It was not read.
    OverBudget(u64),
    /// The file system refused.
    Failed,
}

/// Hashes everything read through it.
struct Hashed<R> {
    inner: R,
    hasher: Sha256Stream,
    bytes: u64,
}

impl<R: Read> Read for Hashed<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        self.hasher.update(buf.get(..count).unwrap_or_default());
        self.bytes = self.bytes.saturating_add(count as u64);
        Ok(count)
    }
}

thread_local! {
    /// One read buffer per worker thread, reused for every archive.
    static SCRATCH: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Reads the archive at `path` in one pass: hashes all of it and searches
/// the scripts its header names.
///
/// An archive larger than `budget` is not read. One that grows while it is
/// read stops one byte past `budget` and is reported the same way.
pub(crate) fn read_archive(
    path: &Path,
    dependency: bool,
    matchers: &Matchers<'_>,
    budget: u64,
) -> ArchiveRead {
    let Ok(file) = File::open(path) else { return ArchiveRead::Failed };
    match file.metadata() {
        Ok(metadata) if metadata.len() > budget => return ArchiveRead::OverBudget(metadata.len()),
        Ok(_) => {}
        Err(_) => return ArchiveRead::Failed,
    }
    let mut source = Hashed {
        inner: (&file).take(budget.saturating_add(1)),
        hasher: Sha256Stream::new(),
        bytes: 0,
    };
    SCRATCH.with_borrow_mut(|buf| {
        let needed = read::buffer_len(script_engine(matchers), WINDOW);
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        let Ok((tables, gaps)) = scan_archive(&mut source, buf, WINDOW, dependency, matchers)
        else {
            return ArchiveRead::Failed;
        };
        // The digest covers the whole file, whatever was made of it.
        if skip(&mut source, buf, u64::MAX).is_err() {
            return ArchiveRead::Failed;
        }
        if source.bytes > budget {
            return match file.metadata() {
                Ok(metadata) => ArchiveRead::OverBudget(metadata.len().max(source.bytes)),
                Err(_) => ArchiveRead::Failed,
            };
        }
        ArchiveRead::Scanned(ArchiveScan {
            sha256: source.hasher.finish(),
            bytes: source.bytes,
            tables,
            gaps,
        })
    })
}

/// The engine that searches script text. The same literals are looked for
/// in the app's own code and in its dependencies; only the label differs.
fn script_engine<'m>(matchers: &'m Matchers<'_>) -> &'m xs_match::ContentEngine {
    matchers.content(MatcherKind::ContentLiteral, Scope::AppCode)
}

/// Reads and drops up to `count` bytes. Says whether that many were there.
fn skip(source: &mut impl Read, buf: &mut [u8], count: u64) -> io::Result<bool> {
    let mut left = count;
    while left > 0 {
        let want = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        let got = read_full(source, buf.get_mut(..want).unwrap_or_default())?;
        left = left.saturating_sub(got as u64);
        if got < want || got == 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Searches the next `len` bytes of `source` as one stream of their own,
/// `window` fresh bytes at a time. `None` if the source ends before that.
///
/// `buf` holds at least [`read::buffer_len`] bytes for `matcher` and
/// `window`.
fn search_stream<M: ContentMatcher + ?Sized>(
    source: &mut impl Read,
    len: u64,
    buf: &mut [u8],
    window: usize,
    matcher: &M,
) -> io::Result<Option<HitAcc>> {
    let overlap = matcher.overlap();
    let mut hits = HitAcc::new();
    let mut left = len;
    let mut carry: usize = 0;
    loop {
        // buf = [carry bytes repeated from the last window | fresh bytes]
        let want = usize::try_from(left).map_or(window, |left| left.min(window));
        let Some(fresh) = buf.get_mut(carry..carry.saturating_add(want)) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "scratch buffer is too small"));
        };
        let got = read_full(source, fresh)?;
        if got < want {
            return Ok(None);
        }
        left = left.saturating_sub(got as u64);
        // The length is known, so the last window is known without reading
        // past it.
        let last = left == 0;
        let filled = carry.saturating_add(got);
        matcher.scan(buf.get(..filled).unwrap_or_default(), carry, last, &mut hits);
        if last {
            return Ok(Some(hits));
        }
        let keep = overlap.min(filled);
        buf.copy_within(filled.saturating_sub(keep)..filled, 0);
        carry = keep;
    }
}

/// A file of an archive whose content is searched.
#[derive(Debug, Clone, Copy)]
struct Member {
    offset: u64,
    size: u64,
    entry: usize,
    scope: Scope,
}

/// Reads the header of the archive that starts at `source` and leaves the
/// source at the first byte after the header's padding.
fn read_header(
    source: &mut impl Read,
    buf: &mut [u8],
) -> io::Result<Result<asar::Header, FormatError>> {
    let mut head = [0u8; asar::PREFIX_BYTES];
    let got = read_full(source, &mut head)?;
    let prefix = match asar::prefix(head.get(..got).unwrap_or_default()) {
        Ok(prefix) => prefix,
        Err(error) => return Ok(Err(error)),
    };
    // The buffer grows with what is actually there, so a prefix that claims
    // a large header in a small file costs nothing.
    let mut json = Vec::new();
    source.by_ref().take(prefix.json_len as u64).read_to_end(&mut json)?;
    if json.len() < prefix.json_len {
        // The archive ends inside its own header.
        return Ok(Err(FormatError::Malformed));
    }
    let header = asar::parse_header(&json);
    drop(json);
    let read_so_far = (asar::PREFIX_BYTES as u64).saturating_add(prefix.json_len as u64);
    // If the archive ends here, every file it names is missing, which the
    // caller finds out when it goes looking for the first one.
    skip(source, buf, prefix.data_start.saturating_sub(read_so_far))?;
    Ok(header)
}

/// Reads an archive from its first byte: the header, then every script the
/// header names, in the order they lie in the archive.
///
/// Reading stops after the last script; what is left of `source` is the
/// caller's to hash.
fn scan_archive(
    source: &mut impl Read,
    buf: &mut [u8],
    window: usize,
    dependency: bool,
    matchers: &Matchers<'_>,
) -> io::Result<(Tables, Gaps)> {
    let mut tables = Tables::default();
    let mut gaps = Gaps::new();
    let header = match read_header(source, buf)? {
        Ok(header) => header,
        Err(FormatError::Malformed) => {
            add_gap(&mut gaps, CoverageStatus::Unrecognized, CoverageReason::ParseError, 1);
            return Ok((tables, gaps));
        }
        Err(FormatError::OverBudget(_)) => {
            add_gap(&mut gaps, CoverageStatus::Skipped, CoverageReason::OverBudget, 1);
            return Ok((tables, gaps));
        }
    };

    let engine = script_engine(matchers);
    let mut members: Vec<Member> = Vec::new();
    let mut bytecode: usize = 0;
    // For a folder: whether what it holds is a dependency.
    let mut dependencies = vec![false; header.len()];
    for entry in header.entries() {
        let inherited = entry
            .parent
            .map_or(dependency, |parent| dependencies.get(parent).copied().unwrap_or(false));
        let (offset, size) = match entry.kind {
            asar::Kind::Dir => {
                if let Some(folder) = dependencies.get_mut(entry.index) {
                    *folder = inherited || entry.name == NODE_MODULES;
                }
                continue;
            }
            asar::Kind::Link => continue,
            // Listed here, stored in the folder beside the archive.
            asar::Kind::Unpacked { .. } => (None, 0),
            asar::Kind::File { offset, size } => (Some(offset), size),
        };
        if inherited && entry.name == PACKAGE_JSON {
            note_package(matchers, &header.path(entry.index), &mut tables.packages);
        }
        let Some(offset) = offset else { continue };
        let scope = if inherited { Scope::Dependency } else { Scope::AppCode };
        let code = code_of(entry.name);
        if code == Code::Bytecode {
            bytecode = bytecode.saturating_add(1);
        } else if searched(code, scope) && size > 0 && !engine.is_empty() {
            members.push(Member { offset, size, entry: entry.index, scope });
        }
    }
    drop(dependencies);

    // In the order the bytes lie in, so the archive is read front to back.
    // The entry index only makes the order total.
    members.sort_unstable_by_key(|member| (member.offset, member.size, member.entry));
    // How many of the archive's data bytes have been read.
    let mut position: u64 = 0;
    let mut unreadable: usize = 0;
    let mut rest = members.as_slice();
    while let Some(first) = rest.first().copied() {
        // Entries that name the very same bytes are one file under several
        // names: searched once, counted for each.
        let same = rest
            .iter()
            .take_while(|member| (member.offset, member.size) == (first.offset, first.size))
            .count();
        let (group, later) = rest.split_at_checked(same).unwrap_or((rest, &[]));
        rest = later;

        let range = first.offset.checked_add(first.size).filter(|_| first.offset >= position);
        let Some(end) = range else {
            // Overlaps bytes that were already read, or cannot exist.
            unreadable = unreadable.saturating_add(group.len());
            continue;
        };
        let hits = if skip(source, buf, first.offset.saturating_sub(position))? {
            search_stream(source, first.size, buf, window, engine)?
        } else {
            None
        };
        let Some(hits) = hits else {
            // The archive ended before or inside this file, so nothing after
            // it can be read either.
            unreadable = unreadable.saturating_add(group.len()).saturating_add(rest.len());
            break;
        };
        position = end;
        if hits.is_empty() {
            continue;
        }
        let verdict = matchers.judge(&hits);
        for member in group {
            tables.file(member.scope, &header.path(member.entry), &verdict);
        }
    }

    let unrecognized = CoverageStatus::Unrecognized;
    add_gap(&mut gaps, unrecognized, CoverageReason::ParseError, unreadable);
    let unusable = usize::try_from(header.unusable()).unwrap_or(usize::MAX);
    add_gap(&mut gaps, unrecognized, CoverageReason::ParseError, unusable);
    add_gap(&mut gaps, CoverageStatus::Skipped, CoverageReason::CompiledScript, bytecode);
    Ok((tables, gaps))
}

/// One code root of a bundle.
#[derive(Debug, Default)]
struct Root {
    /// An archive, as opposed to a loose folder.
    archive: bool,
    tables: Tables,
    /// For a loose folder: the paths inside it that evidence was drawn from
    /// without reading the file, which is its bytecode files and, in
    /// `Contents/Resources/app`, its `package.json` files under
    /// `node_modules`.
    listed: Vec<String>,
    gaps: Gaps,
}

/// An edge this module found, without the subject it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Found {
    /// The id of the rule whose token matched.
    pub(crate) rule: String,
    /// Where and how it matched.
    pub(crate) proof: Proof,
}

/// A gap this module found: the code root it is about, if it is about one,
/// what it is, and how many items it stands for.
pub(crate) type FoundGap = (Option<RelPath>, CoverageStatus, CoverageReason, u32);

/// The code roots of one bundle and what was learned from each.
///
/// The bundle collector feeds it every regular file it listed, every loose
/// script it read and every archive it read, in any order, and asks for the
/// result at the end.
#[derive(Debug, Default)]
pub(crate) struct Roots {
    roots: BTreeMap<RelPath, Root>,
}

impl Roots {
    fn root(&mut self, path: &str) -> Option<&mut Root> {
        // A root is a prefix of a path the walk already stored, so this
        // cannot fail; if it did, the finding would have no place to be.
        Some(self.roots.entry(RelPath::new(path).ok()?).or_default())
    }

    /// Takes in a regular file the walk listed, read or not: in a loose
    /// folder the listing alone names the bytecode, and in
    /// `Contents/Resources/app` the npm packages. The packages of a
    /// `*.asar.unpacked` folder are the ones its archive's header lists.
    pub(crate) fn listed(&mut self, path: &RelPath, matchers: &Matchers<'_>) {
        let Some((root, inner)) = loose_root(path.as_str()) else { return };
        let name = split_name(inner).1;
        let package = root == LOOSE_APP && name == PACKAGE_JSON && npm_package(inner).is_some();
        let bytecode = code_of(name) == Code::Bytecode;
        if !(package || bytecode) {
            return;
        }
        let Some(root) = self.root(root) else { return };
        root.listed.push(inner.to_string());
        if package {
            note_package(matchers, inner, &mut root.tables.packages);
        }
        if bytecode {
            add_gap(&mut root.gaps, CoverageStatus::Skipped, CoverageReason::CompiledScript, 1);
        }
    }

    /// Takes in what the content of the file at `path` matched. Anything
    /// but a loose script is ignored.
    pub(crate) fn script(&mut self, path: &RelPath, hits: &HitAcc, matchers: &Matchers<'_>) {
        if hits.is_empty() {
            return;
        }
        let FileKind::Script { root, inner, scope } = classify(path.as_str()) else { return };
        let verdict = matchers.judge(hits);
        if let Some(root) = self.root(root) {
            root.tables.file(scope, inner, &verdict);
        }
    }

    /// Takes in the archive at `path`.
    pub(crate) fn archive(&mut self, path: &RelPath, scan: ArchiveScan) {
        let root = Root { archive: true, tables: scan.tables, listed: Vec::new(), gaps: scan.gaps };
        self.roots.insert(path.clone(), root);
    }

    /// Turns what was gathered into edges and gaps, and enters the folder
    /// listings that evidence was drawn from into `manifest`, so that the
    /// bundle digest covers them. Archives are covered by their file hash.
    ///
    /// At most [`MAX_EDGES`] edges come back. Roots are gone through in path
    /// order, so the ones kept do not depend on the order files were read
    /// in.
    pub(crate) fn finish(
        self,
        matchers: &Matchers<'_>,
        manifest: &mut BundleManifest,
    ) -> (Vec<Found>, Vec<FoundGap>) {
        let mut found = Kept { edges: Vec::new(), dropped: 0 };
        let mut gaps = Vec::new();
        for (path, root) in self.roots {
            if !root.archive && !root.listed.is_empty() {
                manifest.listing(path.clone(), root.listed.iter().map(String::as_str));
            }
            // The file table is one table: its hits are judged together, so
            // a rule's minimum of distinct package names applies.
            let region = if root.archive { Region::AsarHeader } else { Region::DirEntries };
            for finding in matchers.judge(&root.tables.packages).edges {
                found.push(Found {
                    rule: finding.rule.id.clone(),
                    proof: Proof {
                        matcher: finding.matcher,
                        token: finding.token.lit.clone(),
                        count: finding.count,
                        example: finding.example,
                        location: path.clone(),
                        region,
                        scope: Scope::Dependency,
                        max_sdk: None,
                    },
                });
            }
            // Each file was judged when it was read. What is left to do is
            // to say in how many files a token is evidence, and name one.
            let tables = [
                (Scope::AppCode, &root.tables.app_code),
                (Scope::Dependency, &root.tables.dependency),
            ];
            for (scope, table) in tables {
                for (pattern, count) in table.iter() {
                    let Some(token) = matchers.pattern(pattern) else { continue };
                    let example = table.example(pattern).map(|bytes| {
                        text::clean(&String::from_utf8_lossy(bytes), text::MAX_EXAMPLE_BYTES)
                    });
                    found.push(Found {
                        rule: token.rule.id.clone(),
                        proof: Proof {
                            matcher: token.matcher,
                            token: token.token.lit.clone(),
                            count,
                            example,
                            location: path.clone(),
                            region: Region::Files,
                            scope,
                            max_sdk: None,
                        },
                    });
                }
            }
            for ((status, reason), count) in root.gaps {
                gaps.push((Some(path.clone()), status, reason, count));
            }
        }
        if found.dropped > 0 {
            gaps.push((None, CoverageStatus::Skipped, CoverageReason::OverBudget, found.dropped));
        }
        (found.edges, gaps)
    }
}

/// The edges of one bundle, up to [`MAX_EDGES`], and how many came after.
struct Kept {
    edges: Vec<Found>,
    dropped: u32,
}

impl Kept {
    fn push(&mut self, edge: Found) {
        if self.edges.len() < MAX_EDGES {
            self.edges.push(edge);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use proptest::prelude::*;
    use xs_model::Pack;
    use xs_model::matcher::Boundary;
    use xs_model::pack::{Category, Entity, Layer, LoadedLayer, Rule, Token};
    use xs_model::record::V1;

    use super::*;

    #[test]
    fn files_are_code_by_the_end_of_their_name() {
        for (name, code) in [
            ("main.js", Code::Script),
            ("worker.MJS", Code::Script),
            ("preload.cjs", Code::Script),
            (".js", Code::Script),
            ("index.html", Code::Other),
            ("about.HTM", Code::Other),
            ("main.jsc", Code::Bytecode),
            ("main.js.map", Code::Other),
            ("types.d.ts", Code::Other),
            ("package.json", Code::Other),
            ("js", Code::Other),
            ("README", Code::Other),
            ("", Code::Other),
        ] {
            assert_eq!(code_of(name), code, "{name:?}");
        }
    }

    /// Design report, section 5.2, controls 1 and 7.
    #[test]
    fn only_scripts_of_the_app_and_its_dependencies_are_searched() {
        assert!(searched(Code::Script, Scope::AppCode));
        assert!(searched(Code::Script, Scope::Dependency));
        assert!(!searched(Code::Script, Scope::Runtime));
        assert!(!searched(Code::Script, Scope::Resource));
        for scope in [Scope::AppCode, Scope::Dependency, Scope::Runtime, Scope::Resource] {
            assert!(!searched(Code::Other, scope));
            assert!(!searched(Code::Bytecode, scope));
        }
    }

    #[test]
    fn a_package_is_named_by_the_folder_its_package_json_is_in() {
        for (path, package) in [
            ("node_modules/lodash/package.json", Some("lodash")),
            ("node_modules/@sentry/electron/package.json", Some("@sentry/electron")),
            ("node_modules/a/node_modules/@scope/b/package.json", Some("@scope/b")),
            ("node_modules/a/node_modules/b/package.json", Some("b")),
            ("packages/x/node_modules/posthog-js/package.json", Some("posthog-js")),
            // The app's own, and files deeper inside a package.
            ("package.json", None),
            ("src/package.json", None),
            ("node_modules/package.json", None),
            ("node_modules/lodash/fp/package.json", None),
            ("node_modules/@sentry/package.json", None),
            ("node_modules/@sentry/electron/esm/package.json", None),
            // Not under a folder named exactly `node_modules`.
            ("my_node_modules/lodash/package.json", None),
            ("@sentry/electron/package.json", None),
            ("x/@sentry/electron/package.json", None),
            // Not a file named exactly `package.json`.
            ("node_modules/lodash/xpackage.json", None),
            ("node_modules/lodash/package.json5", None),
            ("node_modules/lodash/package.json/x", None),
        ] {
            assert_eq!(npm_package(path), package, "{path}");
        }
    }

    #[test]
    fn a_bundle_file_is_an_archive_a_loose_script_or_neither() {
        let script = |root, inner, scope| FileKind::Script { root, inner, scope };
        let app = "Contents/Resources/app";
        let unpacked = "Contents/Resources/app.asar.unpacked";
        for (path, kind) in [
            ("Contents/Resources/app.asar", FileKind::Archive { dependency: false }),
            ("Contents/Resources/obsidian.asar", FileKind::Archive { dependency: false }),
            ("x.asar", FileKind::Archive { dependency: false }),
            (
                "Contents/Resources/app/node_modules/x/lib.asar",
                FileKind::Archive { dependency: true },
            ),
            ("Contents/Resources/app/main.js", script(app, "main.js", Scope::AppCode)),
            (
                "Contents/Resources/app/node_modules/a/index.js",
                script(app, "node_modules/a/index.js", Scope::Dependency),
            ),
            (
                "Contents/Resources/app.asar.unpacked/node_modules/a/b.cjs",
                script(unpacked, "node_modules/a/b.cjs", Scope::Dependency),
            ),
            (
                "Contents/Resources/app.asar.unpacked/tools/run.mjs",
                script(unpacked, "tools/run.mjs", Scope::AppCode),
            ),
            // The outermost root wins.
            (
                "Contents/Resources/app/x.asar.unpacked/y.js",
                script(app, "x.asar.unpacked/y.js", Scope::AppCode),
            ),
            (
                "a.asar.unpacked/b.asar.unpacked/c.js",
                script("a.asar.unpacked", "b.asar.unpacked/c.js", Scope::AppCode),
            ),
            // A page, a source map and data are not searched.
            ("Contents/Resources/app/ui/index.html", FileKind::Other),
            ("Contents/Resources/app.asar.unpacked/about.htm", FileKind::Other),
            ("Contents/Resources/app/node_modules/lunr/index.html", FileKind::Other),
            ("Contents/Resources/app/main.js.map", FileKind::Other),
            ("Contents/Resources/app/package.json", FileKind::Other),
            ("Contents/Resources/app/main.jsc", FileKind::Other),
            // Scripts and pages outside a code root are not this module's.
            ("Contents/Resources/LICENSES.chromium.html", FileKind::Other),
            ("Contents/Resources/help/index.js", FileKind::Other),
            ("Contents/Resources/application/main.js", FileKind::Other),
            ("Contents/Resources/app", FileKind::Other),
            ("Contents/Resources/app.asar.unpacked", FileKind::Other),
            ("Contents/Resources/app.asar.unpackedx/a.js", FileKind::Other),
            ("Contents/Resources/app.ASAR", FileKind::Other),
            ("Contents/MacOS/App", FileKind::Other),
        ] {
            assert_eq!(classify(path), kind, "{path}");
        }
    }

    /// One file of a test archive.
    #[derive(Debug, Clone)]
    enum Item {
        /// A file whose bytes are in the archive.
        File(Vec<u8>),
        /// A file the header lists and the archive does not hold.
        Unpacked(u64),
    }

    /// The bytes of an archive that holds `files`, by path, laid out the way
    /// `@electron/asar` writes one: the files back to back in the order
    /// given.
    fn archive(files: &[(&str, Item)]) -> Vec<u8> {
        let mut data = Vec::new();
        let mut tree = serde_json::Map::new();
        for (path, item) in files {
            let mut folder = &mut tree;
            let (folders, name) = split_name(path);
            for part in folders.split('/').filter(|part| !part.is_empty()) {
                folder = folder
                    .entry(part)
                    .or_insert_with(|| serde_json::json!({"files": {}}))
                    .get_mut("files")
                    .and_then(serde_json::Value::as_object_mut)
                    .unwrap();
            }
            let entry = match item {
                Item::File(bytes) => {
                    let offset = data.len().to_string();
                    data.extend_from_slice(bytes);
                    serde_json::json!({"offset": offset, "size": bytes.len()})
                }
                Item::Unpacked(size) => serde_json::json!({"size": size, "unpacked": true}),
            };
            folder.insert((*name).to_string(), entry);
        }
        let header = serde_json::json!({"files": tree}).to_string();
        with_header(&header, &data)
    }

    /// The bytes of an archive with the given header JSON and data.
    fn with_header(json: &str, data: &[u8]) -> Vec<u8> {
        let len = u32::try_from(json.len()).unwrap();
        let padded = len.div_ceil(4) * 4;
        let mut bytes = Vec::new();
        for word in [4, padded + 8, padded + 4, len] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(json.as_bytes());
        bytes.resize(16 + padded as usize, 0);
        bytes.extend_from_slice(data);
        bytes
    }

    fn text(content: &str) -> Item {
        Item::File(content.as_bytes().to_vec())
    }

    /// A pack with two SDKs of two companies, each known by a package name
    /// and by script literals, and eight more companies known by one host
    /// each, for the breadth guard.
    fn pack() -> Pack {
        let entity = |id: &str| Entity {
            id: id.into(),
            name: id.into(),
            parent: None,
            website: format!("https://{id}.example/"),
            team_ids: Vec::new(),
            app_ids: Vec::new(),
            domains: Vec::new(),
            sources: vec![format!("https://{id}.example/terms")],
        };
        let token = |lit: &str, at| Token { lit: lit.into(), at };
        let rule = |id: &str, entity: &str, packages: &[&str], literals: Vec<Token>| Rule {
            id: id.into(),
            name: id.into(),
            entity: Some(entity.into()),
            category: "analytics".into(),
            sources: vec![],
            notes: vec![],
            matchers: BTreeMap::from([
                (
                    MatcherKind::NpmPackage,
                    packages.iter().map(|name| token(name, Boundary::Exact)).collect(),
                ),
                (MatcherKind::ContentLiteral, literals),
            ]),
            min_distinct: BTreeMap::new(),
        };
        let mut entities = vec![entity("sentry"), entity("posthog")];
        let mut rules = vec![
            rule(
                "sdk/sentry",
                "sentry",
                &["@sentry/electron", "@sentry/browser"],
                vec![token("sentry.javascript.", Boundary::Word)],
            ),
            rule(
                "sdk/posthog",
                "posthog",
                &["posthog-js"],
                vec![
                    token("app.posthog.com", Boundary::Host),
                    token("us.i.posthog.com", Boundary::Host),
                ],
            ),
        ];
        for n in 0..8 {
            let id = format!("vendor-{n}");
            entities.push(entity(&id));
            let host = format!("collect.vendor-{n}.example");
            rules.push(rule(&format!("sdk/{id}"), &id, &[], vec![token(&host, Boundary::Host)]));
        }
        for rule in &mut rules {
            rule.matchers.retain(|_, tokens| !tokens.is_empty());
        }
        let layer = Layer {
            format: V1,
            fixes: xs_model::fix::Fixes::default(),
            layer: "core".into(),
            version: 1,
            license: "CC-BY-4.0".into(),
            categories: vec![Category {
                id: "analytics".into(),
                name: "Analytics".into(),
                headline: true,
            }],
            entities,
            rules,
        };
        Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
    }

    /// A script that names all eight vendors, the way a filter list does.
    fn filter_list() -> String {
        (0..8).map(|n| format!("||collect.vendor-{n}.example^\n")).collect()
    }

    const SENTRY: &str = "name=`sentry.javascript.${n}`;";
    const POSTHOG: &str = "init({api_host:\"https://app.posthog.com\"});";

    /// What a table says: per token, the number of files and the example.
    fn rows(matchers: &Matchers<'_>, table: &HitAcc) -> Vec<(String, u32, String)> {
        table
            .iter()
            .map(|(pattern, count)| {
                let token = matchers.pattern(pattern).unwrap().token.lit.clone();
                let example = String::from_utf8(table.example(pattern).unwrap().to_vec()).unwrap();
                (token, count, example)
            })
            .collect()
    }

    fn row(token: &str, count: u32, example: &str) -> (String, u32, String) {
        (token.to_string(), count, example.to_string())
    }

    fn scan(bytes: &[u8], window: usize, dependency: bool) -> (Tables, Gaps, usize) {
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let mut buf = vec![0xAA; read::buffer_len(script_engine(&matchers), window)];
        let mut source = Cursor::new(bytes);
        let (tables, gaps) =
            scan_archive(&mut source, &mut buf, window, dependency, &matchers).unwrap();
        (tables, gaps, usize::try_from(source.position()).unwrap())
    }

    fn gaps_of(list: &[(CoverageStatus, CoverageReason, u32)]) -> Gaps {
        list.iter().map(|&(status, reason, count)| ((status, reason), count)).collect()
    }

    const NOT_UNDERSTOOD: (CoverageStatus, CoverageReason) =
        (CoverageStatus::Unrecognized, CoverageReason::ParseError);

    /// The oracle for each expectation is the table in the module
    /// documentation, applied by hand to the paths below.
    #[test]
    fn an_archive_yields_its_packages_and_the_scripts_that_hold_a_literal() {
        let bytes = archive(&[
            ("package.json", text("{\"name\":\"app\"}")),
            ("js/main.js", text(&format!("boot();{SENTRY}{POSTHOG}{SENTRY}"))),
            ("js/extra.js", text(SENTRY)),
            // Not searched: the app's own page, a source map, data, a style
            // sheet, a page of a dependency, and a file with no extension.
            ("index.html", text(&format!("<script>{POSTHOG}</script>"))),
            ("js/main.js.map", text(SENTRY)),
            ("config.json", text(POSTHOG)),
            ("app.css", text(SENTRY)),
            ("node_modules/lunr/index.html", text(POSTHOG)),
            ("node_modules/lunr/LICENSE", text(SENTRY)),
            // Dependencies: scripts only.
            ("node_modules/lunr/lunr.js", text("search()")),
            ("node_modules/lunr/package.json", text("{}")),
            ("node_modules/@sentry/electron/package.json", text("{}")),
            ("node_modules/@sentry/electron/main.cjs", text(SENTRY)),
            ("node_modules/a/node_modules/@sentry/electron/package.json", text("{}")),
            ("node_modules/posthog-js/package.json", Item::Unpacked(2)),
            ("node_modules/posthog-js/lib.js", Item::Unpacked(40)),
        ]);
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let (tables, gaps, _) = scan(&bytes, WINDOW, false);

        assert_eq!(
            rows(&matchers, &tables.packages),
            [
                row("posthog-js", 1, "node_modules/posthog-js/package.json"),
                row("@sentry/electron", 2, "node_modules/@sentry/electron/package.json"),
            ]
        );
        assert_eq!(
            rows(&matchers, &tables.app_code),
            [row("app.posthog.com", 1, "js/main.js"), row("sentry.javascript.", 2, "js/extra.js")]
        );
        assert_eq!(
            rows(&matchers, &tables.dependency),
            [row("sentry.javascript.", 1, "node_modules/@sentry/electron/main.cjs")]
        );
        assert!(gaps.is_empty(), "{gaps:?}");
    }

    #[test]
    fn an_archive_under_node_modules_is_all_dependency() {
        let bytes = archive(&[("lib/index.js", text(SENTRY)), ("demo.html", text(POSTHOG))]);
        let (tables, gaps, _) = scan(&bytes, WINDOW, true);
        assert!(tables.app_code.is_empty());
        assert_eq!(tables.dependency.iter().count(), 1);
        assert!(gaps.is_empty());
    }

    /// Design report, section 5.2 control 4: the guard sees one file.
    #[test]
    fn a_filter_list_is_held_back_without_silencing_the_script_beside_it() {
        let list = filter_list();
        let bytes = archive(&[
            ("js/blocklist.js", text(&format!("{list}{SENTRY}"))),
            ("js/main.js", text(SENTRY)),
            // Seven companies are not a list.
            ("js/seven.js", text(&list.lines().take(7).collect::<Vec<_>>().join("\n"))),
        ]);
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let (tables, gaps, _) = scan(&bytes, WINDOW, false);
        let found = rows(&matchers, &tables.app_code);
        assert_eq!(found.len(), 8, "{found:?}");
        assert!(found.contains(&row("sentry.javascript.", 1, "js/main.js")));
        assert!(found.contains(&row("collect.vendor-0.example", 1, "js/seven.js")));
        assert!(!found.iter().any(|(token, ..)| token == "collect.vendor-7.example"));
        assert!(gaps.is_empty());
    }

    /// A literal must not be found across the edge of two files, and the
    /// edge of a file is a boundary.
    #[test]
    fn each_file_is_its_own_stream() {
        let bytes = archive(&[
            ("a.js", text("x='sentry.java")),
            ("b.js", text("script.';y='app.posthog")),
            ("c.js", text(".com'")),
            ("d.js", text("app.posthog.com")),
            ("e.js", text("xapp.posthog.com")),
        ]);
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        for window in [read::HEAD, 17, 64, WINDOW] {
            let (tables, ..) = scan(&bytes, window, false);
            assert_eq!(
                rows(&matchers, &tables.app_code),
                [row("app.posthog.com", 1, "d.js")],
                "window {window}"
            );
        }
    }

    #[test]
    fn what_is_found_does_not_depend_on_the_window() {
        let filler = "function f(){return 1};".repeat(40);
        let bytes = archive(&[
            ("js/main.js", text(&format!("{filler}{SENTRY}{filler}{POSTHOG}{filler}{SENTRY}"))),
            ("js/list.js", text(&format!("{filler}{}{filler}", filter_list()))),
            ("node_modules/x/y.js", text(&format!("{POSTHOG}{filler}"))),
            ("z.mjs", text(&format!("{filler}us.i.posthog.com"))),
        ]);
        let reference = scan(&bytes, bytes.len() * 2, false);
        assert_eq!(reference.0.app_code.iter().count(), 3);
        assert_eq!(reference.0.dependency.iter().count(), 1);
        for window in (read::HEAD..80).chain([255, 256, 257, 1000, WINDOW]) {
            assert_eq!(scan(&bytes, window, false), reference, "window {window}");
        }
    }

    #[test]
    fn reading_stops_after_the_last_script() {
        let padding = vec![b' '; 5000];
        let bytes = archive(&[
            ("a.js", text(SENTRY)),
            ("big.bin", Item::File(padding.clone())),
            ("b.js", text(POSTHOG)),
            ("tail.bin", Item::File(padding)),
        ]);
        let (tables, _, position) = scan(&bytes, 64, false);
        assert_eq!(tables.app_code.iter().count(), 2);
        assert_eq!(position, bytes.len() - 5000);
    }

    #[test]
    fn a_file_that_is_not_an_archive_is_reported_and_yields_nothing() {
        let good = archive(&[("main.js", text(SENTRY))]);
        let json_end = 16 + u32::from_le_bytes(good[12..16].try_into().unwrap()) as usize;
        let mut wrong_pickle = good.clone();
        wrong_pickle[0] = 8;
        let mut not_json = good.clone();
        not_json[20] = b'!';
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("shorter than the prefix", good[..10].to_vec()),
            ("ends inside the header", good[..json_end - 3].to_vec()),
            ("a pickle no writer makes", wrong_pickle),
            ("a header that is not JSON", not_json),
            ("some other file", b"<html>sentry.javascript. app.posthog.com</html>".to_vec()),
        ];
        for (case, bytes) in cases {
            let (tables, gaps, _) = scan(&bytes, 64, false);
            assert_eq!(tables, Tables::default(), "{case}");
            assert_eq!(gaps, gaps_of(&[(NOT_UNDERSTOOD.0, NOT_UNDERSTOOD.1, 1)]), "{case}");
        }
    }

    #[test]
    fn a_header_over_a_budget_is_skipped_as_over_budget() {
        let mut json = String::from(r#"{"files":{"#);
        for _ in 0..=asar::MAX_DEPTH {
            json.push_str(r#""d":{"files":{"#);
        }
        json.push_str(r#""main.js":{"offset":"0","size":30}"#);
        json.push_str(&"}}".repeat(asar::MAX_DEPTH + 1));
        json.push_str("}}");
        let (tables, gaps, _) = scan(&with_header(&json, SENTRY.as_bytes()), 64, false);
        assert_eq!(tables, Tables::default());
        assert_eq!(gaps, gaps_of(&[(CoverageStatus::Skipped, CoverageReason::OverBudget, 1)]));

        // A prefix that claims more header than the budget allows is refused
        // before any of it is read.
        let mut huge = with_header("{}", b"");
        let claimed = u32::try_from(asar::MAX_HEADER_BYTES).unwrap() + 4;
        for (word, value) in [(1, claimed + 8), (2, claimed + 4), (3, claimed)] {
            huge[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        let (_, gaps, position) = scan(&huge, 64, false);
        assert_eq!(gaps, gaps_of(&[(CoverageStatus::Skipped, CoverageReason::OverBudget, 1)]));
        assert_eq!(position, asar::PREFIX_BYTES);
    }

    /// No byte is searched twice and no entry is trusted. The data below is
    /// `SENTRY` then `POSTHOG`; every expectation follows from which byte
    /// ranges the header names.
    #[test]
    fn entries_that_overlap_or_reach_past_the_end_are_counted_not_searched() {
        let data = format!("{SENTRY}{POSTHOG}");
        let (first, second, total) = (SENTRY.len(), POSTHOG.len(), data.len());
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let found = |entries: &str| {
            let json = format!(r#"{{"files":{{{entries}}}}}"#);
            let (tables, gaps, _) = scan(&with_header(&json, data.as_bytes()), 64, false);
            let tokens: Vec<String> =
                rows(&matchers, &tables.app_code).into_iter().map(|(token, ..)| token).collect();
            (tokens, gaps.get(&NOT_UNDERSTOOD).copied().unwrap_or(0))
        };
        let both = vec!["app.posthog.com".to_string(), "sentry.javascript.".to_string()];

        // The honest layout.
        let honest = format!(
            r#""a.js":{{"offset":"0","size":{first}}},"b.js":{{"offset":"{first}","size":{second}}}"#
        );
        assert_eq!(found(&honest), (both.clone(), 0));

        // The same bytes under two names are one file, searched once.
        let twice = format!(
            r#""a.js":{{"offset":"0","size":{first}}},"copy.js":{{"offset":"0","size":{first}}}"#
        );
        let json = format!(r#"{{"files":{{{twice}}}}}"#);
        let (tables, gaps, _) = scan(&with_header(&json, data.as_bytes()), 64, false);
        assert_eq!(rows(&matchers, &tables.app_code), [row("sentry.javascript.", 2, "a.js")]);
        assert!(gaps.is_empty());

        // A second entry that starts inside the first.
        let overlap = format!(
            r#""a.js":{{"offset":"0","size":{first}}},"b.js":{{"offset":"5","size":{}}}"#,
            total - 5
        );
        assert_eq!(found(&overlap), (vec!["sentry.javascript.".to_string()], 1));

        // A short entry inside the first, and an honest one after it. The
        // bytes after the first file are not the short entry's, so reading
        // it there would lose the place of everything that follows.
        let inside = format!(
            r#""a.js":{{"offset":"0","size":{first}}},"b.js":{{"offset":"5","size":4}},"c.js":{{"offset":"{first}","size":{second}}}"#
        );
        assert_eq!(found(&inside), (both.clone(), 1));

        // An entry over everything, and one inside it.
        let nested = format!(
            r#""all.js":{{"offset":"0","size":{total}}},"b.js":{{"offset":"{first}","size":{second}}}"#
        );
        assert_eq!(found(&nested), (both.clone(), 1));

        // An entry that reaches past the end takes the ones after it along:
        // the stream has ended.
        let past = format!(
            r#""a.js":{{"offset":"0","size":{first}}},"b.js":{{"offset":"{first}","size":{}}},"c.js":{{"offset":"{}","size":1}}"#,
            second + 1,
            total + 10
        );
        assert_eq!(found(&past), (vec!["sentry.javascript.".to_string()], 2));

        // An entry that starts past the end.
        let beyond = format!(r#""a.js":{{"offset":"{}","size":4}}"#, total + 1);
        assert_eq!(found(&beyond), (Vec::new(), 1));

        // A range that cannot exist.
        let wrapped = format!(
            r#""a.js":{{"offset":"18446744073709551615","size":2}},"b.js":{{"offset":"{first}","size":{second}}}"#
        );
        assert_eq!(found(&wrapped), (vec!["app.posthog.com".to_string()], 1));
    }

    #[test]
    fn bytecode_and_unreachable_names_are_reported() {
        let json = format!(
            r#"{{"files":{{
                "main.jsc":{{"offset":"0","size":4}},
                "node_modules":{{"files":{{"x":{{"files":{{"y.jsc":{{"offset":"4","size":4}}}}}}}}}},
                "unpacked.jsc":{{"size":4,"unpacked":true}},
                "a/b.js":{{"offset":"8","size":{}}},
                "..":{{"files":{{"c.js":{{"offset":"8","size":{}}}}}}}
            }}}}"#,
            SENTRY.len(),
            SENTRY.len()
        );
        let data = format!("aaaabbbb{SENTRY}");
        let (tables, gaps, _) = scan(&with_header(&json, data.as_bytes()), 64, false);
        assert_eq!(tables, Tables::default());
        assert_eq!(
            gaps,
            gaps_of(&[
                (CoverageStatus::Skipped, CoverageReason::CompiledScript, 2),
                (NOT_UNDERSTOOD.0, NOT_UNDERSTOOD.1, 2),
            ])
        );
    }

    #[test]
    fn a_stream_is_searched_to_its_length_and_no_further() {
        let pack = pack();
        let matchers = Matchers::build(&pack).unwrap();
        let engine = script_engine(&matchers);
        let data = format!("{SENTRY}app.posthog.com");
        for window in [read::HEAD, 17, 30, 64, 1000] {
            let mut buf = vec![0; read::buffer_len(engine, window)];
            let search = |len: usize, buf: &mut [u8]| {
                let mut source = Cursor::new(data.as_bytes());
                let hits = search_stream(&mut source, len as u64, buf, window, engine).unwrap();
                (hits.map(|hits| hits.iter().count()), source.position())
            };
            // The whole of it: both literals.
            assert_eq!(search(data.len(), &mut buf), (Some(2), data.len() as u64));
            // Cut one byte short, the host is no longer whole.
            assert_eq!(search(data.len() - 1, &mut buf), (Some(1), data.len() as u64 - 1));
            // Nothing asked for, nothing read.
            assert_eq!(search(0, &mut buf), (Some(0), 0));
            // More than there is.
            assert_eq!(search(data.len() + 1, &mut buf).0, None);
        }
        // A buffer too small for the window is an error, not a panic.
        let mut small = vec![0; 8];
        let mut source = Cursor::new(data.as_bytes());
        assert!(search_stream(&mut source, 20, &mut small, 64, engine).is_err());
    }

    #[test]
    fn skipping_says_whether_the_bytes_were_there() {
        let data = vec![7u8; 1000];
        let mut buf = vec![0; 64];
        for (count, there, position) in
            [(0, true, 0), (1, true, 1), (64, true, 64), (999, true, 999), (1000, true, 1000)]
        {
            let mut source = Cursor::new(&data);
            assert_eq!(skip(&mut source, &mut buf, count).unwrap(), there, "{count}");
            assert_eq!(source.position(), position, "{count}");
        }
        let mut source = Cursor::new(&data);
        assert!(!skip(&mut source, &mut buf, 1001).unwrap());
        assert!(!skip(&mut source, &mut buf, u64::MAX).unwrap());
        assert_eq!(source.position(), 1000);
    }

    proptest! {
        /// Whatever the bytes, reading ends, without a panic, and never
        /// reads past the end.
        #[test]
        fn arbitrary_bytes_are_read_or_refused(
            bytes in prop::collection::vec(any::<u8>(), 0..300),
            window in read::HEAD..100usize,
        ) {
            let (_, _, position) = scan(&bytes, window, false);
            prop_assert!(position <= bytes.len());
        }

        /// A valid archive with a few bytes changed anywhere, header and
        /// data alike, is read or refused the same way at every window.
        #[test]
        fn a_damaged_archive_reads_the_same_at_every_window(
            edits in prop::collection::vec((0usize..400, any::<u8>()), 0..5),
            window in read::HEAD..100usize,
        ) {
            let mut bytes = archive(&[
                ("js/main.js", text(&format!("{SENTRY}{POSTHOG}"))),
                ("node_modules/posthog-js/package.json", text("{}")),
                ("node_modules/posthog-js/lib.js", text(POSTHOG)),
                ("list.js", text(&filter_list())),
            ]);
            for (at, byte) in edits {
                let at = at % bytes.len();
                bytes[at] = byte;
            }
            let whole = scan(&bytes, bytes.len() + read::HEAD, false);
            let (tables, gaps, _) = scan(&bytes, window, false);
            prop_assert_eq!((tables, gaps), (whole.0, whole.1));
        }
    }
}
