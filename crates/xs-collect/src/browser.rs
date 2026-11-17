//! The browser extension collector.
//!
//! An extension is the one kind of software a person installs that sits
//! inside every page they open. What it may reach is not hidden in code: it
//! is listed in the extension's own `manifest.json`, because the browser
//! grants nothing that is not asked for there. This collector reads that
//! file and reports what it asks for.
//!
//! # What is read, and what never is
//!
//! | Browser | Where its extensions are | What is read of each |
//! |---|---|---|
//! | Chromium family: Arc, Brave, Chrome, Chromium, Dia, Edge, Vivaldi | `<profile>/Extensions/<id>/<version>/`, one folder per installed version, of which the highest is read | `manifest.json`, and the one message catalogue `_locales/<default_locale>/messages.json` when the name is a reference into it |
//! | Firefox | `<profile>/extensions/<id>.xpi`, one zip archive per add-on | the archive, for its hash, and the same two entries inside it |
//!
//! Nothing else in a profile is opened: not the history, the cookies, the
//! bookmarks, the saved logins or the preferences. Folders are listed to
//! find the extensions, and of a profile only the fact that it holds an
//! `Extensions` (or `extensions`) folder is used. A record holds no path of
//! the machine and no name of a profile.
//!
//! An update leaves the folder of the version it replaced until the browser
//! next tidies up, and which version runs is written only in the
//! preferences. So of an extension's version folders in one profile the
//! highest version is read, and the others are counted in one `coverage`
//! record under it, with the reason `superseded_version`.
//!
//! Everything is read-only and needs no privilege. A browser whose folders
//! the system will not let the scan list is not a failure of the scan: it
//! becomes one `coverage` record that says the extensions of that browser
//! were skipped, and why.
//!
//! # Subjects
//!
//! An extension is a subject of its own, of the kind `extension`, on the
//! platform `chromium` or `firefox`: the same extension is the same subject
//! in every browser of a family, on every machine.
//!
//! * A Chromium extension is a folder, so its digest is a bundle digest
//!   (`bd1`) over the files read from it. Its id is the name of the folder
//!   above its version folder, the id the browser derived from the
//!   extension's key.
//! * A Firefox add-on is one file, so its digest is the SHA-256 of that
//!   file, as for an Android package. Its id is the name of the file
//!   without `.xpi`, which is how Firefox stores an add-on under its id.
//!
//! Every byte evidence is drawn from is a byte the digest covers, so equal
//! digests give equal evidence. Which browser an extension was found in is
//! a fact about this device and is kept apart from that: it is in the
//! `artifact` record, and only there.
//!
//! # What becomes an edge
//!
//! Each entry of the manifest's permission keys that gives a wide view of
//! what a person does in the browser becomes an `access` edge at the grade
//! `requested`, to one of the fixed list in [`xs_model::permission`]. The
//! proof names the manifest key, how many of its entries ask for the same
//! thing, and the least of them, so a reader can open `manifest.json` and
//! find them. Two rules keep the edges from saying more than the manifest:
//!
//! * **Every website** is said only of a pattern that covers every site in
//!   full: `<all_urls>`, or any host on any port over `https` or both
//!   schemes. The browser ignores the path of a pattern that grants sites,
//!   under the permission keys, so there any path will do; a script's
//!   `matches` must have the path `/*`. A pattern with a wildcard host that
//!   covers less is **a broad set of websites**: `http` only, one port, a
//!   script's narrower path, a script that `include_globs` narrows, or
//!   every site under one public suffix such as `*.com`. A pattern for
//!   named sites is not reported.
//! * A script the browser puts into pages counts only if it lists a `js`
//!   file. Style sheets alone change how a page looks and cannot read it.
//!
//! An extension that already may reach every website is not also reported
//! for a broad set of them.
//!
//! # Budgets
//!
//! [`MAX_ARCHIVE_BYTES`] for an add-on archive, which is held in memory
//! while it is read, one at a time; the manifest reader's own budgets for
//! the two files; and the zip reader's for the directory of an archive.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use xs_formats::extension_manifest::{self, Host, Manifest, Scheme, SitePattern};
use xs_formats::{Budget, FormatError, ReadError, host, zip};
use xs_model::digest::BundleManifest;
use xs_model::permission::{self, ManifestKey, Permission};
use xs_model::record::{
    ArtifactRecord, Browser, Collector, CoverageReason, CoverageRecord, CoverageStatus, EdgeRecord,
    EdgeType, Facts, ObjectKind, ObjectRef, Platform, Proof, Record, Region, Scope, Subject,
    SubjectKind, V1,
};
use xs_model::{MatcherKind, RelPath, Sha256Digest, SubjectDigest, text};

/// Largest add-on archive read: 64 MiB. Add-ons are a few megabytes; the
/// largest in wide use stay under forty.
pub const MAX_ARCHIVE_BYTES: u64 = 64 << 20;

const MANIFEST: &str = "manifest.json";
const LOCALES: &str = "_locales";
const MESSAGES: &str = "messages.json";
/// The folder of a Chromium profile that holds its extensions.
const CHROMIUM_EXTENSIONS: &str = "Extensions";
/// The folder of a Firefox profile that holds its add-ons.
const FIREFOX_EXTENSIONS: &str = "extensions";
/// The id of an add-on whose file has no name to take one from. A
/// constant: the digest still tells two such add-ons apart.
const UNIDENTIFIED: &str = "unidentified";

/// Where each browser keeps its profiles, below the folder macOS gives
/// applications for their data (`~/Library/Application Support`).
const PROFILE_ROOTS: [(Browser, &str); 8] = [
    (Browser::Arc, "Arc/User Data"),
    (Browser::Brave, "BraveSoftware/Brave-Browser"),
    (Browser::Chrome, "Google/Chrome"),
    (Browser::Chromium, "Chromium"),
    (Browser::Dia, "Dia/User Data"),
    (Browser::Edge, "Microsoft Edge"),
    (Browser::Firefox, "Firefox/Profiles"),
    (Browser::Vivaldi, "Vivaldi"),
];

/// The folder, below a user's home folder, that applications keep their
/// data in on macOS.
const APPLICATION_SUPPORT: &str = "Library/Application Support";

/// How an extension is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Form {
    /// A folder `<id>/<version>` that holds the extension unpacked, as the
    /// Chromium family installs one.
    Folder,
    /// One zip archive named `<id>.xpi`, as Firefox installs one.
    Archive,
}

/// One extension found on disk.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Extension {
    /// The version folder or the archive.
    pub path: PathBuf,
    /// How it is stored.
    pub form: Form,
    /// The browser whose profile it was found in. `None` for an extension
    /// given by path.
    pub browser: Option<Browser>,
    /// How many older version folders of the same extension, in the same
    /// profile, were passed over for this one.
    pub superseded: u32,
}

/// The extensions installed in the browsers of one user, and the folders
/// that could not be listed while looking for them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Installed {
    /// Every extension found, in the order of their paths.
    pub extensions: Vec<Extension>,
    /// How many folders of each browser could not be listed, by the reason.
    pub unlisted: BTreeMap<(Browser, CoverageReason), u32>,
}

/// Whether `name` is the id of a Chromium extension: thirty-two letters
/// from `a` to `p`, the hash of its key written in base 16 with those
/// letters.
#[must_use]
pub fn is_chromium_id(name: &str) -> bool {
    name.len() == 32 && name.bytes().all(|byte| (b'a'..=b'p').contains(&byte))
}

/// Whether `path` is named like a Firefox add-on archive.
#[must_use]
pub fn is_archive_name(path: &Path) -> bool {
    path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("xpi"))
}

/// Whether the folder `path` is one installed version of a Chromium
/// extension: it holds a `manifest.json` file, and the folder above it is
/// named with an extension id.
#[must_use]
pub fn is_version_folder(path: &Path) -> bool {
    let id = path.parent().and_then(Path::file_name).and_then(|name| name.to_str());
    id.is_some_and(is_chromium_id)
        && fs::symlink_metadata(path.join(MANIFEST)).is_ok_and(|manifest| manifest.is_file())
}

/// The folder applications keep their data in, for the user whose home
/// folder is `home`.
#[must_use]
pub fn application_support(home: &Path) -> PathBuf {
    home.join(APPLICATION_SUPPORT)
}

/// Why a folder could not be listed, as a coverage reason: the system
/// refused for want of a privilege, or anything else.
fn refusal(error: &io::Error) -> CoverageReason {
    if error.kind() == io::ErrorKind::PermissionDenied {
        CoverageReason::NoPrivilege
    } else {
        CoverageReason::Unreadable
    }
}

/// The sub-folders of `folder`, by name, in the order of their names.
///
/// A folder that is not there holds none: `Ok` and empty. A symbolic link
/// is not a sub-folder, so a profile cannot point the scan anywhere else.
fn subfolders(folder: &Path) -> io::Result<Vec<PathBuf>> {
    entries(folder, |kind| kind.is_dir())
}

/// The entries of `folder` whose own type `wanted` accepts, in the order of
/// their names. A folder that is not there holds none.
fn entries(folder: &Path, wanted: fn(&fs::FileType) -> bool) -> io::Result<Vec<PathBuf>> {
    let listing = match fs::read_dir(folder) {
        Ok(listing) => listing,
        Err(error)
            if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) =>
        {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    let mut found = Vec::new();
    for entry in listing {
        let entry = entry?;
        // The type of the entry itself: a link is not followed.
        if entry.file_type().is_ok_and(|kind| wanted(&kind)) {
            found.push(entry.path());
        }
    }
    found.sort_unstable();
    Ok(found)
}

/// The extensions installed in the browsers whose profiles are below
/// `support`, the folder applications keep their data in.
///
/// A browser that is not installed has no folder there and yields nothing.
/// A folder that is there and cannot be listed is counted in
/// [`Installed::unlisted`] under its browser, and the search carries on
/// with the next one.
#[must_use]
pub fn installed(support: &Path) -> Installed {
    let mut found = Installed::default();
    for (browser, root) in PROFILE_ROOTS {
        let root = support.join(root);
        let mut search = Search { browser, found: &mut found };
        match browser.platform() {
            Platform::Firefox => search.firefox(&root),
            Platform::Chromium | Platform::Android | Platform::Macos => search.chromium(&root),
        }
    }
    found.extensions.sort_unstable();
    found
}

/// The search of one browser's profiles.
struct Search<'f> {
    browser: Browser,
    found: &'f mut Installed,
}

impl Search<'_> {
    /// Lists `folder`, or counts it as a folder of this browser that could
    /// not be listed.
    fn list(&mut self, folder: &Path, list: fn(&Path) -> io::Result<Vec<PathBuf>>) -> Vec<PathBuf> {
        list(folder).unwrap_or_else(|error| {
            let count = self.found.unlisted.entry((self.browser, refusal(&error))).or_insert(0);
            *count = count.saturating_add(1);
            Vec::new()
        })
    }

    fn add(&mut self, path: PathBuf, form: Form, superseded: u32) {
        let browser = Some(self.browser);
        self.found.extensions.push(Extension { path, form, browser, superseded });
    }

    /// `<root>/<profile>/Extensions/<id>/<version>/`, the highest version
    /// of each extension. The browser leaves the folder of the version an
    /// update replaced until it next tidies up, and which one it runs is
    /// written only in the profile's preferences, which are not read.
    fn chromium(&mut self, root: &Path) {
        for profile in self.list(root, subfolders) {
            for extension in self.list(&profile.join(CHROMIUM_EXTENSIONS), subfolders) {
                let named = extension.file_name().and_then(|name| name.to_str());
                if !named.is_some_and(is_chromium_id) {
                    // `Temp`, where the browser unpacks an update.
                    continue;
                }
                if let Some((latest, superseded)) = newest(self.list(&extension, subfolders)) {
                    self.add(latest, Form::Folder, superseded);
                }
            }
        }
    }

    /// `<root>/<profile>/extensions/<id>.xpi`.
    fn firefox(&mut self, root: &Path) {
        for profile in self.list(root, subfolders) {
            let archives = |folder: &Path| entries(folder, fs::FileType::is_file);
            for archive in self.list(&profile.join(FIREFOX_EXTENSIONS), archives) {
                if is_archive_name(&archive) {
                    self.add(archive, Form::Archive, 0);
                }
            }
        }
    }
}

/// The version and the suffix a Chromium version folder is named with,
/// such as `[2, 1, 0]` and `0` for `2.1.0_0`. `None` for a name not of that
/// shape.
fn folder_version(name: &OsStr) -> Option<(Vec<u64>, u64)> {
    fn number(digits: &str) -> Option<u64> {
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    }
    let (version, suffix) = name.to_str()?.rsplit_once('_')?;
    let parts = version.split('.').map(number).collect::<Option<Vec<_>>>()?;
    Some((parts, number(suffix)?))
}

/// The order of two version folders of one extension, the newest last.
///
/// The dotted parts of the version are compared as numbers, a missing part
/// counting as 0, then the suffix. A name not of that shape sorts below
/// every one that is. Names equal so far are ordered by their bytes, so
/// the order is total.
fn version_order(a: &OsStr, b: &OsStr) -> Ordering {
    let by_version = match (folder_version(a), folder_version(b)) {
        (Some((a_parts, a_suffix)), Some((b_parts, b_suffix))) => {
            let width = a_parts.len().max(b_parts.len());
            let part = |parts: &[u64], index: usize| parts.get(index).copied().unwrap_or(0);
            (0..width)
                .map(|index| part(&a_parts, index).cmp(&part(&b_parts, index)))
                .find(|order| order.is_ne())
                .unwrap_or(Ordering::Equal)
                .then(a_suffix.cmp(&b_suffix))
        }
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => Ordering::Equal,
    };
    by_version.then_with(|| a.as_encoded_bytes().cmp(b.as_encoded_bytes()))
}

/// The highest of `versions`, the version folders of one extension, by
/// [`version_order`], and how many others there are.
pub(crate) fn newest(versions: impl IntoIterator<Item = PathBuf>) -> Option<(PathBuf, u32)> {
    let name = |path: &PathBuf| path.file_name().unwrap_or_default().to_owned();
    let mut others: u32 = 0;
    let mut latest: Option<PathBuf> = None;
    for version in versions {
        latest = Some(match latest {
            None => version,
            Some(best) => {
                others = others.saturating_add(1);
                if version_order(&name(&version), &name(&best)).is_gt() { version } else { best }
            }
        });
    }
    latest.map(|latest| (latest, others))
}

/// The record that says `count` folders of `browser` could not be listed
/// for `reason`, so the extensions in them were not read.
#[must_use]
pub fn unlisted(browser: Browser, reason: CoverageReason, count: u32) -> Record {
    Record::Coverage(CoverageRecord {
        v: V1,
        collector: Collector::BrowserExtension,
        subject: Subject {
            kind: SubjectKind::Browser,
            platform: browser.platform(),
            id: String::from(browser.as_str()),
            version: None,
            digest: SubjectDigest::Unread,
        },
        status: CoverageStatus::Skipped,
        reason,
        location: None,
        bytes: None,
        count,
    })
}

/// An extension that was not read, as far as it can be told from others:
/// nothing of its content is known, so it has no digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Unread {
    platform: Platform,
    /// The extension's id.
    id: String,
    reason: CoverageReason,
    /// The size of an archive over [`MAX_ARCHIVE_BYTES`].
    bytes: Option<u64>,
}

/// The record that says `count` extensions like `unread` were skipped.
/// Extensions that cannot be told apart share the record, which counts
/// them: a record's id is its content, so two that say the same are one.
pub(crate) fn unread(unread: Unread, count: u32) -> Record {
    Record::Coverage(CoverageRecord {
        v: V1,
        collector: Collector::BrowserExtension,
        subject: Subject {
            kind: SubjectKind::Extension,
            platform: unread.platform,
            id: unread.id,
            version: None,
            digest: SubjectDigest::Unread,
        },
        status: CoverageStatus::Skipped,
        reason: unread.reason,
        location: None,
        bytes: unread.bytes,
        count,
    })
}

/// What became of one extension.
pub(crate) enum Outcome {
    /// Its manifest, or what stands where the manifest belongs, was read.
    Scanned {
        /// Every record about the extension.
        records: Vec<Record>,
        /// How many files were read.
        files: u64,
        /// How many bytes were read.
        bytes: u64,
    },
    /// Nothing of it could be read, so it has no digest to report under.
    Unread(Unread),
}

/// Something the collector could not cover inside an extension.
struct Gap {
    status: CoverageStatus,
    reason: CoverageReason,
    location: Option<RelPath>,
    /// The size of a file over its byte budget.
    bytes: Option<u64>,
}

impl Gap {
    fn skipped(reason: CoverageReason, location: &str) -> Self {
        Self { status: CoverageStatus::Skipped, reason, location: rel(location), bytes: None }
    }

    /// The gap a reader's refusal of the input at `location` leaves.
    fn refused(error: ReadError, location: Option<&str>) -> Self {
        let (status, reason) = match error {
            ReadError::Format(FormatError::Malformed) => {
                (CoverageStatus::Unrecognized, CoverageReason::ParseError)
            }
            ReadError::Format(FormatError::OverBudget(
                Budget::Bytes | Budget::Items | Budget::Depth,
            )) => (CoverageStatus::Skipped, CoverageReason::OverBudget),
            ReadError::Unsupported => (CoverageStatus::Skipped, CoverageReason::UnsupportedFormat),
        };
        Self { status, reason, location: location.and_then(rel), bytes: None }
    }
}

fn rel(path: &str) -> Option<RelPath> {
    RelPath::new(path).ok()
}

/// Hostile text made safe to store, or nothing if nothing is left of it.
fn clean(value: Option<&str>, max_bytes: usize) -> Option<String> {
    value.map(|value| text::clean(value, max_bytes)).filter(|value| !value.is_empty())
}

/// The place of the message catalogue of `locale` inside an extension.
fn catalogue_path(locale: &str) -> String {
    format!("{LOCALES}/{locale}/{MESSAGES}")
}

/// What was learned of one extension before it is turned into records.
struct Reading {
    platform: Platform,
    id: String,
    digest: SubjectDigest,
    browser: Option<Browser>,
    /// How many older version folders were passed over for this one.
    superseded: u32,
    manifest: Option<Manifest>,
    /// The name, once a reference into the message catalogue is resolved.
    name: Option<String>,
    gaps: Vec<Gap>,
    files: u64,
    bytes: u64,
}

/// Reads one extension. Nothing here fails the scan: what cannot be read
/// comes back as [`Outcome::Unread`] or as a `coverage` record among the
/// records.
pub(crate) fn read(extension: &Extension) -> Outcome {
    let reading = match extension.form {
        Form::Folder => read_folder(&extension.path),
        Form::Archive => read_archive(&extension.path),
    };
    match reading {
        Ok(mut reading) => {
            reading.browser = extension.browser;
            reading.superseded = extension.superseded;
            let (files, bytes) = (reading.files, reading.bytes);
            Outcome::Scanned { records: records(reading), files, bytes }
        }
        Err(unread) => Outcome::Unread(unread),
    }
}

/// What reading one file of an extension folder gave.
enum FileRead {
    Bytes(Vec<u8>),
    /// The file is larger than the budget, by its size.
    OverBudget(u64),
    /// It is not there, is not a regular file, or the system refused.
    Unreadable,
}

/// Reads the file at `components` below `root`, at most `limit` bytes of
/// it. Every component on the way must be a real folder and the last a real
/// file: a symbolic link is never followed, so an extension cannot point
/// the scan at a file outside itself.
fn read_inside(root: &Path, components: &[&str], limit: usize) -> FileRead {
    let mut path = root.to_path_buf();
    let mut size = 0;
    for (index, component) in components.iter().enumerate() {
        path.push(component);
        let Ok(metadata) = fs::symlink_metadata(&path) else { return FileRead::Unreadable };
        let is_last = index + 1 == components.len();
        if (is_last && !metadata.is_file()) || (!is_last && !metadata.is_dir()) {
            return FileRead::Unreadable;
        }
        size = metadata.len();
    }
    let limit = limit as u64;
    if size > limit {
        return FileRead::OverBudget(size);
    }
    let mut bytes = Vec::new();
    // One byte past the limit, so a file that grew since the stat is noticed.
    match File::open(&path).and_then(|file| file.take(limit + 1).read_to_end(&mut bytes)) {
        Ok(_) if bytes.len() as u64 > limit => FileRead::OverBudget(bytes.len() as u64),
        Ok(_) => FileRead::Bytes(bytes),
        Err(_) => FileRead::Unreadable,
    }
}

/// Reads a Chromium extension from its version folder.
fn read_folder(root: &Path) -> Result<Reading, Unread> {
    let id = root
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .filter(|name| is_chromium_id(name))
        .unwrap_or(UNIDENTIFIED);
    let mut reading = Reading {
        platform: Platform::Chromium,
        id: String::from(id),
        digest: SubjectDigest::Unread,
        browser: None,
        superseded: 0,
        manifest: None,
        name: None,
        gaps: Vec::new(),
        files: 0,
        bytes: 0,
    };
    let mut bundle = BundleManifest::new();
    // A file that was read enters the digest by its hash.
    let note =
        |reading: &mut Reading, bundle: &mut BundleManifest, location: &str, bytes: &[u8]| {
            if let Some(location) = rel(location) {
                bundle.file(location, Sha256Digest::of(bytes));
            }
            reading.files += 1;
            reading.bytes += bytes.len() as u64;
        };

    match read_inside(root, &[MANIFEST], extension_manifest::MAX_MANIFEST_BYTES) {
        FileRead::Bytes(bytes) => {
            note(&mut reading, &mut bundle, MANIFEST, &bytes);
            match extension_manifest::parse(&bytes) {
                Ok(manifest) => reading.manifest = Some(manifest),
                Err(error) => reading.gaps.push(Gap::refused(error.into(), Some(MANIFEST))),
            }
        }
        FileRead::OverBudget(size) => {
            if let Some(location) = rel(MANIFEST) {
                bundle.over_budget(location, size);
            }
            let gap = Gap::skipped(CoverageReason::OverBudget, MANIFEST);
            reading.gaps.push(Gap { bytes: Some(size), ..gap });
        }
        FileRead::Unreadable => {
            return Err(Unread {
                platform: Platform::Chromium,
                id: reading.id,
                reason: CoverageReason::Unreadable,
                bytes: None,
            });
        }
    }

    if let Some((key, locale)) = reference(reading.manifest.as_ref()) {
        let location = catalogue_path(&locale);
        let limit = extension_manifest::MAX_MESSAGES_BYTES;
        match read_inside(root, &[LOCALES, &locale, MESSAGES], limit) {
            FileRead::Bytes(bytes) => {
                note(&mut reading, &mut bundle, &location, &bytes);
                match extension_manifest::message(&bytes, &key) {
                    Ok(message) => reading.name = message,
                    Err(error) => reading.gaps.push(Gap::refused(error.into(), Some(&location))),
                }
            }
            FileRead::OverBudget(size) => {
                if let Some(location) = rel(&location) {
                    bundle.over_budget(location, size);
                }
                let gap = Gap::skipped(CoverageReason::OverBudget, &location);
                reading.gaps.push(Gap { bytes: Some(size), ..gap });
            }
            FileRead::Unreadable => {
                reading.gaps.push(Gap::skipped(CoverageReason::Unreadable, &location));
            }
        }
    } else {
        reading.name = stated_name(reading.manifest.as_ref());
    }
    reading.digest = bundle.digest();
    Ok(reading)
}

/// The message a manifest's name stands for and the locale whose catalogue
/// holds it, if the name is a reference and the manifest names a locale.
fn reference(manifest: Option<&Manifest>) -> Option<(String, String)> {
    let manifest = manifest?;
    let key = extension_manifest::message_key(manifest.name.as_deref()?)?;
    Some((String::from(key), manifest.default_locale.clone()?))
}

/// The name a manifest states as text. A reference into the message
/// catalogue is not a name: one that cannot be looked up, for want of a
/// locale, leaves the extension without one.
fn stated_name(manifest: Option<&Manifest>) -> Option<String> {
    let name = manifest?.name.as_deref()?;
    extension_manifest::message_key(name).is_none().then(|| String::from(name))
}

/// Reads a Firefox add-on from its archive.
fn read_archive(path: &Path) -> Result<Reading, Unread> {
    let stem = path.file_stem().map(|stem| stem.to_string_lossy()).unwrap_or_default();
    let id = clean(Some(&stem), text::MAX_ID_BYTES).unwrap_or_else(|| String::from(UNIDENTIFIED));
    let unread =
        |id: String, reason, bytes| Unread { platform: Platform::Firefox, id, reason, bytes };

    let mut archive = Vec::new();
    let read = File::open(path).and_then(|file| {
        let size = file.metadata()?.len();
        if size > MAX_ARCHIVE_BYTES {
            return Ok(Some(size));
        }
        // One byte past the limit, so a file that grew since the stat is
        // noticed.
        file.take(MAX_ARCHIVE_BYTES + 1).read_to_end(&mut archive)?;
        Ok((archive.len() as u64 > MAX_ARCHIVE_BYTES).then_some(archive.len() as u64))
    });
    match read {
        Ok(None) => {}
        Ok(Some(size)) => return Err(unread(id, CoverageReason::OverBudget, Some(size))),
        Err(_) => return Err(unread(id, CoverageReason::Unreadable, None)),
    }

    let mut reading = Reading {
        platform: Platform::Firefox,
        id,
        digest: SubjectDigest::Sha256(Sha256Digest::of(&archive)),
        browser: None,
        superseded: 0,
        manifest: None,
        name: None,
        gaps: Vec::new(),
        files: 1,
        bytes: archive.len() as u64,
    };
    let directory = match Directory::of(&archive) {
        Ok(directory) => directory,
        Err(error) => {
            reading.gaps.push(Gap::refused(error, None));
            return Ok(reading);
        }
    };

    match directory.content(MANIFEST, extension_manifest::MAX_MANIFEST_BYTES) {
        // An archive without a manifest is not an add-on.
        None => reading.gaps.push(Gap::refused(FormatError::Malformed.into(), Some(MANIFEST))),
        Some(Err(error)) => reading.gaps.push(Gap::refused(error, Some(MANIFEST))),
        Some(Ok(bytes)) => match extension_manifest::parse(&bytes) {
            Ok(manifest) => reading.manifest = Some(manifest),
            Err(error) => reading.gaps.push(Gap::refused(error.into(), Some(MANIFEST))),
        },
    }

    if let Some((key, locale)) = reference(reading.manifest.as_ref()) {
        let location = catalogue_path(&locale);
        match directory.content(&location, extension_manifest::MAX_MESSAGES_BYTES) {
            None => reading.gaps.push(Gap::skipped(CoverageReason::Unreadable, &location)),
            Some(Err(error)) => reading.gaps.push(Gap::refused(error, Some(&location))),
            Some(Ok(bytes)) => match extension_manifest::message(&bytes, &key) {
                Ok(message) => reading.name = message,
                Err(error) => reading.gaps.push(Gap::refused(error.into(), Some(&location))),
            },
        }
    } else {
        reading.name = stated_name(reading.manifest.as_ref());
    }
    Ok(reading)
}

/// The table of contents of a zip archive held in memory.
struct Directory<'a> {
    archive: &'a [u8],
    entries: Vec<zip::Entry<'a>>,
}

impl<'a> Directory<'a> {
    fn of(archive: &'a [u8]) -> Result<Self, ReadError> {
        let malformed = ReadError::Format(FormatError::Malformed);
        let tail_start = archive.len().saturating_sub(zip::MAX_TAIL_BYTES);
        let tail = archive.get(tail_start..).unwrap_or_default();
        let end = zip::locate(tail, archive.len() as u64)?;
        let start = usize::try_from(end.directory_offset).map_err(|_| malformed)?;
        let bytes = start
            .checked_add(end.directory_bytes)
            .and_then(|stop| archive.get(start..stop))
            .ok_or(malformed)?;
        Ok(Self { archive, entries: zip::directory(bytes, &end)? })
    }

    /// The content of the entry named `name`, at most `budget` bytes of it,
    /// or `None` if the archive has no such entry.
    fn content(&self, name: &str, budget: usize) -> Option<Result<Vec<u8>, ReadError>> {
        let entry = self.entries.iter().find(|entry| entry.name == name.as_bytes())?;
        let read = || {
            let malformed = ReadError::Format(FormatError::Malformed);
            let offset = usize::try_from(entry.offset).map_err(|_| malformed)?;
            let local = self.archive.get(offset..).ok_or(malformed)?;
            let data = zip::data(entry, local)?;
            Ok(zip::content(entry, data, budget)?.into_owned())
        };
        Some(read())
    }
}

/// How much of the web a site pattern covers, when that is a lot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Breadth {
    /// Every site, every page.
    All,
    /// A wildcard host that covers less than that.
    Broad,
}

impl Breadth {
    const fn permission(self) -> Permission {
        match self {
            Self::All => Permission::AllSites,
            Self::Broad => Permission::BroadSites,
        }
    }
}

/// Whether `domain` is a suffix under which unrelated parties register
/// names, such as `com`, `co.uk` or `github.io`, by the Public Suffix List
/// compiled into this build.
fn is_public_suffix(domain: &str) -> bool {
    psl::suffix(domain.as_bytes())
        .is_some_and(|suffix| suffix.is_known() && suffix.as_bytes() == domain.as_bytes())
}

/// Whether the path of a site pattern narrows what it covers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Paths {
    /// A permission to reach sites: the browser grants a pattern's whole
    /// site whatever its path says.
    Ignored,
    /// A script's `matches`: the script runs only on the pages whose path
    /// the pattern matches.
    Matched,
}

/// How broad the site pattern `entry` is, read as `paths` says. `None` for
/// an entry that is not a pattern for web pages, and for one that names
/// its sites.
fn breadth(entry: &str, paths: Paths) -> Option<Breadth> {
    match extension_manifest::site_pattern(entry)? {
        SitePattern::AllUrls => Some(Breadth::All),
        SitePattern::Web { scheme, host: Host::Any, every_path, every_port } => {
            // Sites are served over `https`: `http` alone reaches what is
            // left of the unencrypted web.
            let all = (every_path || paths == Paths::Ignored)
                && every_port
                && matches!(scheme, Scheme::Any | Scheme::Https);
            Some(if all { Breadth::All } else { Breadth::Broad })
        }
        SitePattern::Web { host: Host::Under(domain), .. } => {
            is_public_suffix(&domain).then_some(Breadth::Broad)
        }
        SitePattern::Web { host: Host::Named, .. } => None,
    }
}

/// The entries of one manifest key that ask for one permission.
type Asked<'m> = BTreeMap<(Permission, ManifestKey), BTreeSet<&'m str>>;

/// What `manifest` asks for, of the permissions the scanner reports.
fn asked(manifest: &Manifest) -> Asked<'_> {
    fn ask<'m>(asked: &mut Asked<'m>, permission: Permission, key: ManifestKey, entry: &'m str) {
        asked.entry((permission, key)).or_default().insert(entry);
    }
    let mut asked = Asked::new();

    // An interface name, or in a version 2 manifest a site pattern.
    let sites_in_permissions = manifest.sites_in_permissions();
    let named = [
        (ManifestKey::Permissions, &manifest.permissions),
        (ManifestKey::OptionalPermissions, &manifest.optional_permissions),
    ];
    for (key, entries) in named {
        for entry in entries {
            let permission = Permission::from_manifest_name(entry).or_else(|| {
                sites_in_permissions
                    .then(|| breadth(entry, Paths::Ignored))
                    .flatten()
                    .map(Breadth::permission)
            });
            if let Some(permission) = permission {
                ask(&mut asked, permission, key, entry);
            }
        }
    }
    // Site patterns, which a browser takes only from version 3.
    let sites = [
        (ManifestKey::HostPermissions, &manifest.host_permissions),
        (ManifestKey::OptionalHostPermissions, &manifest.optional_host_permissions),
    ];
    for (key, entries) in sites.into_iter().filter(|_| !sites_in_permissions) {
        for entry in entries {
            if let Some(breadth) = breadth(entry, Paths::Ignored) {
                ask(&mut asked, breadth.permission(), key, entry);
            }
        }
    }
    for script in manifest.content_scripts.iter().filter(|script| script.runs_script) {
        for entry in &script.matches {
            let breadth = breadth(entry, Paths::Matched).map(|breadth| match breadth {
                // The script runs on the matched pages its globs also cover.
                Breadth::All if script.narrowed => Breadth::Broad,
                other => other,
            });
            if let Some(breadth) = breadth {
                ask(&mut asked, breadth.permission(), ManifestKey::ContentScripts, entry);
            }
        }
    }

    // Every website holds every broad set of them: say the larger thing
    // once. An optional key does not make a held one redundant.
    let all = |optional: bool| {
        asked.keys().any(|(permission, key)| {
            *permission == Permission::AllSites && (optional || !key.is_optional())
        })
    };
    let (held, any) = (all(false), all(true));
    asked.retain(|(permission, key), _| {
        *permission != Permission::BroadSites || !(held || (any && key.is_optional()))
    });
    asked
}

/// Turns what was read of one extension into its records: one `artifact`
/// record, an `access` edge per permission and manifest key, and a
/// `coverage` record per gap.
fn records(reading: Reading) -> Vec<Record> {
    let manifest = reading.manifest.as_ref();
    let subject = Subject {
        kind: SubjectKind::Extension,
        platform: reading.platform,
        id: reading.id,
        version: clean(
            manifest.and_then(|manifest| manifest.version.as_deref()),
            text::MAX_VERSION_BYTES,
        ),
        digest: reading.digest,
    };
    let homepage =
        manifest.and_then(|manifest| manifest.homepage_url.as_deref()).and_then(host::of_url);
    let mut records = vec![Record::Artifact(ArtifactRecord {
        v: V1,
        collector: Collector::BrowserExtension,
        subject: subject.clone(),
        facts: Facts {
            name: clean(reading.name.as_deref(), text::MAX_NAME_BYTES),
            publisher: clean(
                manifest.and_then(|manifest| manifest.author.as_deref()),
                text::MAX_NAME_BYTES,
            ),
            homepage,
            browser: reading.browser,
            files_scanned: reading.files,
            bytes_scanned: reading.bytes,
            ..Facts::default()
        },
    })];

    let Some(location) = rel(MANIFEST) else { return records };
    for ((permission, key), entries) in manifest.map(asked).unwrap_or_default() {
        records.push(Record::Edge(EdgeRecord {
            v: V1,
            collector: Collector::BrowserExtension,
            subject: subject.clone(),
            edge: EdgeType::Access,
            grade: MatcherKind::ExtensionManifest.grade(),
            object: ObjectRef { kind: ObjectKind::Permission, id: String::from(permission.id()) },
            rule: String::from(permission::RULE),
            proof: Proof {
                matcher: MatcherKind::ExtensionManifest,
                token: String::from(key.as_str()),
                count: u32::try_from(entries.len()).unwrap_or(u32::MAX),
                // The least entry in byte order, never the first one seen.
                example: clean(entries.first().copied(), text::MAX_EXAMPLE_BYTES),
                location: location.clone(),
                region: Region::ManifestKey,
                scope: Scope::AppCode,
                max_sdk: None,
            },
        }));
    }
    if reading.superseded > 0 {
        records.push(Record::Coverage(CoverageRecord {
            v: V1,
            collector: Collector::BrowserExtension,
            subject: subject.clone(),
            status: CoverageStatus::Skipped,
            reason: CoverageReason::SupersededVersion,
            location: None,
            bytes: None,
            count: reading.superseded,
        }));
    }
    for gap in reading.gaps {
        records.push(Record::Coverage(CoverageRecord {
            v: V1,
            collector: Collector::BrowserExtension,
            subject: subject.clone(),
            status: gap.status,
            reason: gap.reason,
            location: gap.location,
            bytes: gap.bytes,
            count: 1,
        }));
    }
    records
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use xs_formats::testkit::ZipBuilder;

    use super::*;

    const ID: &str = "abcdefghijklmnopabcdefghijklmnop";
    const OTHER_ID: &str = "ponmlkjihgfedcbaponmlkjihgfedcba";

    const LOCALIZED: &str = r#"{
      "manifest_version": 3, "name": "__MSG_extName__", "version": "2.1.0",
      "default_locale": "en", "author": "Example Ltd",
      "homepage_url": "https://www.example.com/extension?ref=store",
      "permissions": ["storage", "tabs", "cookies"],
      "host_permissions": ["<all_urls>"]
    }"#;
    const MESSAGES_EN: &str = r#"{"extName": {"message": "Example Helper"}}"#;

    fn write(path: &Path, bytes: impl AsRef<[u8]>) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    /// A Chromium extension at `<profile>/Extensions/<id>/<version>`.
    fn chromium(profile: &Path, id: &str, version: &str, manifest: &str) -> PathBuf {
        let root = profile.join(CHROMIUM_EXTENSIONS).join(id).join(version);
        write(&root.join(MANIFEST), manifest);
        write(&root.join("_locales/en/messages.json"), MESSAGES_EN);
        root
    }

    fn xpi(manifest: &str) -> Vec<u8> {
        ZipBuilder::new()
            .deflated("background.js", b"// not read")
            .deflated(MANIFEST, manifest.as_bytes())
            .deflated("_locales/en/messages.json", MESSAGES_EN.as_bytes())
            .finish()
    }

    fn scanned(extension: &Extension) -> Vec<Record> {
        match read(extension) {
            Outcome::Scanned { records, .. } => records,
            Outcome::Unread(unread) => panic!("not read: {unread:?}"),
        }
    }

    fn folder(path: PathBuf) -> Extension {
        Extension { path, form: Form::Folder, browser: Some(Browser::Brave), superseded: 0 }
    }

    fn artifact(records: &[Record]) -> &ArtifactRecord {
        let mut artifacts = records.iter().filter_map(|record| match record {
            Record::Artifact(artifact) => Some(artifact),
            _ => None,
        });
        let artifact = artifacts.next().unwrap();
        assert!(artifacts.next().is_none());
        artifact
    }

    fn edges(records: &[Record]) -> Vec<String> {
        records
            .iter()
            .filter_map(|record| match record {
                Record::Edge(edge) => Some(format!("{} {}", edge.object.id, edge.proof.token)),
                _ => None,
            })
            .collect()
    }

    fn gaps(records: &[Record]) -> Vec<String> {
        records
            .iter()
            .filter_map(|record| match record {
                Record::Coverage(gap) => Some(format!(
                    "{:?} {:?} {}",
                    gap.status,
                    gap.reason,
                    gap.location.as_ref().map_or("-", RelPath::as_str)
                )),
                _ => None,
            })
            .collect()
    }

    /// Every record must be one an evidence set accepts.
    fn valid(records: &[Record]) {
        for record in records {
            record.validate().unwrap();
        }
    }

    #[test]
    fn the_profiles_of_every_known_browser_are_searched_and_nothing_else() {
        let support = tempfile::tempdir().unwrap();
        let support = support.path();
        let brave = support.join("BraveSoftware/Brave-Browser");
        // An update leaves the folder of the version it replaced behind.
        chromium(&brave.join("Default"), ID, "2.1.0_0", LOCALIZED);
        chromium(&brave.join("Default"), ID, "2.0.9_0", LOCALIZED);
        chromium(&brave.join("Default"), ID, "10_0", LOCALIZED);
        chromium(&brave.join("Profile 1"), OTHER_ID, "1.0_0", "{}");
        // Where an update is unpacked, and a folder that is no extension id.
        chromium(&brave.join("Default"), "Temp", "x", "{}");
        // A profile folder that holds no extensions, and a plain file.
        fs::create_dir_all(brave.join("System Profile")).unwrap();
        write(&brave.join("Local State"), "{}");
        // A link is never followed, whatever it points at.
        let elsewhere = chromium(&support.join("Elsewhere/Default"), OTHER_ID, "9_0", "{}");
        let linked = brave.join("Default").join(CHROMIUM_EXTENSIONS).join("linked");
        symlink(elsewhere.parent().unwrap(), &linked).unwrap();
        symlink(support.join("Elsewhere/Default"), brave.join("Linked Profile")).unwrap();

        let firefox = support.join("Firefox/Profiles/abc123.default-release/extensions");
        write(&firefox.join("addon@example.org.xpi"), xpi(LOCALIZED));
        write(&firefox.join("staged.json"), "{}");
        // A browser this build does not know is not looked at.
        chromium(&support.join("Unknown Browser/Default"), ID, "1_0", "{}");

        let found = installed(support);
        assert!(found.unlisted.is_empty(), "{:?}", found.unlisted);
        let listed: Vec<(String, Form, Option<Browser>, u32)> = found
            .extensions
            .iter()
            .map(|extension| {
                let path = extension.path.strip_prefix(support).unwrap();
                let shown = path.display().to_string();
                (shown, extension.form, extension.browser, extension.superseded)
            })
            .collect();
        let brave_at = |path: &str, superseded| {
            let path = format!("BraveSoftware/Brave-Browser/{path}");
            (path, Form::Folder, Some(Browser::Brave), superseded)
        };
        assert_eq!(
            listed,
            [
                brave_at(&format!("Default/Extensions/{ID}/10_0"), 2),
                brave_at(&format!("Profile 1/Extensions/{OTHER_ID}/1.0_0"), 0),
                (
                    "Firefox/Profiles/abc123.default-release/extensions/addon@example.org.xpi"
                        .into(),
                    Form::Archive,
                    Some(Browser::Firefox),
                    0
                ),
            ]
        );
        // With no browser installed there is nothing, and nothing failed.
        assert_eq!(installed(&support.join("nobody")), Installed::default());
    }

    /// A browser whose folders the system will not let the scan list is
    /// skipped and said so, and does not stop the search of the others.
    #[test]
    fn a_browser_that_cannot_be_listed_is_counted_by_reason() {
        let support = tempfile::tempdir().unwrap();
        let support = support.path();
        let chrome = support.join("Google/Chrome");
        chromium(&chrome.join("Default"), ID, "1_0", "{}");
        chromium(&support.join("Dia/User Data/Default"), ID, "1_0", "{}");
        fs::set_permissions(&chrome, fs::Permissions::from_mode(0o000)).unwrap();
        let found = installed(support);
        fs::set_permissions(&chrome, fs::Permissions::from_mode(0o700)).unwrap();
        if found.unlisted.is_empty() {
            // Run with privileges that ignore the folder's mode.
            return;
        }
        assert_eq!(
            found.unlisted,
            BTreeMap::from([((Browser::Chrome, CoverageReason::NoPrivilege), 1)])
        );
        assert_eq!(found.extensions.len(), 1);
        assert_eq!(found.extensions[0].browser, Some(Browser::Dia));

        let record = unlisted(Browser::Chrome, CoverageReason::NoPrivilege, 1);
        record.validate().unwrap();
        assert_eq!(record.subject().id, "chrome");
        assert_eq!(record.subject().kind, SubjectKind::Browser);
    }

    #[test]
    fn a_chromium_extension_is_named_from_its_catalogue_and_identified_by_its_files() {
        let profile = tempfile::tempdir().unwrap();
        let root = chromium(profile.path(), ID, "2.1.0_0", LOCALIZED);
        let records = scanned(&folder(root.clone()));
        valid(&records);

        let found = artifact(&records);
        assert_eq!(found.subject.kind, SubjectKind::Extension);
        assert_eq!(found.subject.platform, Platform::Chromium);
        assert_eq!(found.subject.id, ID);
        assert_eq!(found.subject.version.as_deref(), Some("2.1.0"));
        assert!(matches!(found.subject.digest, SubjectDigest::Bundle(_)));
        assert_eq!(
            found.facts,
            Facts {
                name: Some("Example Helper".into()),
                publisher: Some("Example Ltd".into()),
                homepage: Some("www.example.com".into()),
                browser: Some(Browser::Brave),
                files_scanned: 2,
                bytes_scanned: (LOCALIZED.len() + MESSAGES_EN.len()) as u64,
                ..Facts::default()
            }
        );
        assert_eq!(
            edges(&records),
            [
                "extension/all-sites host_permissions",
                "extension/tabs permissions",
                "extension/cookies permissions"
            ]
        );
        assert!(gaps(&records).is_empty());

        // The browser is a fact about this device: the subject, and so every
        // edge, is the same in another browser.
        let elsewhere = scanned(&Extension { browser: None, ..folder(root.clone()) });
        assert_eq!(artifact(&elsewhere).subject, found.subject);
        assert_eq!(artifact(&elsewhere).facts.browser, None);
        assert_eq!(&elsewhere[1..], &records[1..]);

        // A file that is read is part of the identity; one that is not is not.
        write(&root.join("background.js"), "changed, and never read");
        assert_eq!(artifact(&scanned(&folder(root.clone()))).subject.digest, found.subject.digest);
        write(&root.join("_locales/en/messages.json"), r#"{"extName": {"message": "Renamed"}}"#);
        let renamed = scanned(&folder(root));
        assert_ne!(artifact(&renamed).subject.digest, found.subject.digest);
        assert_eq!(artifact(&renamed).facts.name.as_deref(), Some("Renamed"));
    }

    #[test]
    fn what_cannot_be_read_inside_a_folder_is_a_coverage_record() {
        let profile = tempfile::tempdir().unwrap();
        let profile = profile.path();

        // A manifest that does not parse: read, hashed, not understood.
        let broken = chromium(profile, ID, "1_0", "{\"name\": ");
        let records = scanned(&folder(broken));
        valid(&records);
        assert_eq!(gaps(&records), ["Unrecognized ParseError manifest.json"]);
        assert!(edges(&records).is_empty());
        assert_eq!(artifact(&records).subject.version, None);

        // A reference into a catalogue that is not there leaves no name.
        let root = profile.join("b").join(CHROMIUM_EXTENSIONS).join(ID).join("1_0");
        write(&root.join(MANIFEST), LOCALIZED);
        let records = scanned(&folder(root));
        valid(&records);
        assert_eq!(gaps(&records), ["Skipped Unreadable _locales/en/messages.json"]);
        assert_eq!(artifact(&records).facts.name, None);

        // A reference without a locale is no name either.
        let root = profile.join("c").join(CHROMIUM_EXTENSIONS).join(ID).join("1_0");
        write(&root.join(MANIFEST), r#"{"name": "__MSG_extName__"}"#);
        let records = scanned(&folder(root));
        assert_eq!(artifact(&records).facts.name, None);
        assert!(gaps(&records).is_empty());

        // An oversized manifest is not read, and enters the digest by size.
        let root = profile.join("d").join(CHROMIUM_EXTENSIONS).join(ID).join("1_0");
        write(&root.join(MANIFEST), vec![b' '; extension_manifest::MAX_MANIFEST_BYTES + 1]);
        let records = scanned(&folder(root));
        valid(&records);
        assert_eq!(gaps(&records), ["Skipped OverBudget manifest.json"]);
    }

    /// Nothing outside an extension is read through it: a manifest, or a
    /// folder on the way to the catalogue, that is a link is not followed.
    #[test]
    fn links_inside_an_extension_are_never_followed() {
        let profile = tempfile::tempdir().unwrap();
        let profile = profile.path();
        write(&profile.join("secret.json"), LOCALIZED);

        let root = profile.join("a").join(CHROMIUM_EXTENSIONS).join(ID).join("1_0");
        fs::create_dir_all(&root).unwrap();
        symlink(profile.join("secret.json"), root.join(MANIFEST)).unwrap();
        match read(&folder(root)) {
            Outcome::Unread(unread) => {
                let record = super::unread(unread, 1);
                record.validate().unwrap();
                assert_eq!(record.subject().id, ID);
                assert_eq!(record.subject().digest, SubjectDigest::Unread);
            }
            Outcome::Scanned { .. } => panic!("a linked manifest was read"),
        }

        let root = profile.join("b").join(CHROMIUM_EXTENSIONS).join(ID).join("1_0");
        write(&root.join(MANIFEST), LOCALIZED);
        write(&profile.join("elsewhere/en/messages.json"), MESSAGES_EN);
        symlink(profile.join("elsewhere"), root.join(LOCALES)).unwrap();
        let records = scanned(&folder(root));
        assert_eq!(gaps(&records), ["Skipped Unreadable _locales/en/messages.json"]);
        assert_eq!(artifact(&records).facts.name, None);
    }

    #[test]
    fn a_firefox_add_on_is_identified_by_the_hash_of_its_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("addon@example.org.xpi");
        let bytes = xpi(LOCALIZED);
        write(&path, &bytes);
        let extension =
            Extension { path: path.clone(), form: Form::Archive, browser: None, superseded: 0 };
        let records = scanned(&extension);
        valid(&records);
        let found = artifact(&records);
        assert_eq!(found.subject.platform, Platform::Firefox);
        assert_eq!(found.subject.id, "addon@example.org");
        assert_eq!(found.subject.digest, SubjectDigest::Sha256(Sha256Digest::of(&bytes)));
        assert_eq!(found.facts.name.as_deref(), Some("Example Helper"));
        assert_eq!((found.facts.files_scanned, found.facts.bytes_scanned), (1, bytes.len() as u64));
        assert_eq!(edges(&records).len(), 3);
        assert!(gaps(&records).is_empty());

        // Not a zip archive, or one without a manifest.
        write(&path, b"not an archive");
        let records = scanned(&extension);
        valid(&records);
        assert_eq!(gaps(&records), ["Unrecognized ParseError -"]);
        write(&path, ZipBuilder::new().deflated("README", b"hello").finish());
        assert_eq!(gaps(&scanned(&extension)), ["Unrecognized ParseError manifest.json"]);

        // An archive over the budget is not read, and says how large it is.
        let file = File::create(&path).unwrap();
        file.set_len(MAX_ARCHIVE_BYTES + 1).unwrap();
        match read(&extension) {
            Outcome::Unread(unread) => {
                let record = super::unread(unread, 1);
                record.validate().unwrap();
                let Record::Coverage(coverage) = record else { panic!() };
                assert_eq!(coverage.reason, CoverageReason::OverBudget);
                assert_eq!(coverage.bytes, Some(MAX_ARCHIVE_BYTES + 1));
            }
            Outcome::Scanned { .. } => panic!("an oversized archive was read"),
        }
    }

    /// Text from a hostile manifest is cleaned before it enters a record,
    /// and an address is cut down to its host.
    #[test]
    fn hostile_text_is_cleaned_and_addresses_become_hosts() {
        let profile = tempfile::tempdir().unwrap();
        let manifest = format!(
            r#"{{"name": "Evil\u202eTxt.exe {}", "version": "1\u0000", "author": "{}",
                "homepage_url": "javascript:alert(1)"}}"#,
            "x".repeat(400),
            "a".repeat(400)
        );
        let root = chromium(profile.path(), ID, "1_0", &manifest);
        let records = scanned(&folder(root));
        valid(&records);
        let facts = &artifact(&records).facts;
        let name = facts.name.as_deref().unwrap();
        assert!(name.starts_with("Evil\u{fffd}Txt.exe") && name.ends_with('…'), "{name}");
        assert!(name.len() <= text::MAX_NAME_BYTES);
        assert_eq!(artifact(&records).subject.version.as_deref(), Some("1\u{fffd}"));
        assert!(facts.publisher.as_deref().unwrap().len() <= text::MAX_NAME_BYTES);
        assert_eq!(facts.homepage, None);
    }

    fn manifest(json: &str) -> Manifest {
        extension_manifest::parse(json.as_bytes()).unwrap()
    }

    /// What a manifest asks for, as `permission key count least-entry`.
    fn asks(json: &str) -> Vec<String> {
        let manifest = manifest(json);
        asked(&manifest)
            .into_iter()
            .map(|((permission, key), entries)| {
                let least = entries.first().copied().unwrap_or_default();
                format!("{} {key} {} {least}", permission.id(), entries.len())
            })
            .collect()
    }

    #[test]
    fn only_a_pattern_for_every_page_of_every_site_is_every_website() {
        for paths in [Paths::Ignored, Paths::Matched] {
            for all in ["<all_urls>", "*://*/*", "https://*/*", "*://*:*/*", "HTTPS://*/*"] {
                assert!(matches!(breadth(all, paths), Some(Breadth::All)), "{all}");
            }
            for broad in [
                "http://*/*",
                "http://*/",
                "https://*:8443/*",
                "*://*:80/*",
                "*://*.com/*",
                "https://*.co.uk/*",
                "*://*.github.io/*",
                "*://*.COM/path/*",
            ] {
                assert!(matches!(breadth(broad, paths), Some(Breadth::Broad)), "{broad}");
            }
            for named in [
                "https://example.com/*",
                "*://*.example.com/*",
                "*://*.google.co.uk/*",
                "http://localhost:8545/",
                "*://*.localhost/*",
                "*://*.internal/*",
                "file:///*",
                "ws://*/*",
                "tabs",
                "",
                "https://*",
                "*://*:*",
            ] {
                assert!(breadth(named, paths).is_none(), "{named}");
            }
        }
        // A permission grants whole sites, whatever its path says; a
        // script runs only on the pages its path matches.
        for path_only in ["https://*/", "*://*/*.pdf", "*://*:*/app/*"] {
            assert!(
                matches!(breadth(path_only, Paths::Ignored), Some(Breadth::All)),
                "{path_only}"
            );
            assert!(
                matches!(breadth(path_only, Paths::Matched), Some(Breadth::Broad)),
                "{path_only}"
            );
        }
    }

    /// A browser ignores the path of a pattern that grants sites, so the
    /// common version 2 idiom of two bare origins holds every website.
    #[test]
    fn the_path_of_a_granted_pattern_does_not_narrow_it() {
        assert_eq!(
            asks(r#"{"manifest_version": 2, "permissions": ["http://*/", "https://*/", "tabs"]}"#),
            ["extension/all-sites permissions 1 https://*/", "extension/tabs permissions 1 tabs"]
        );
        assert_eq!(
            asks(
                r#"{"manifest_version": 3, "host_permissions": ["https://*/"], "optional_host_permissions": ["*://*/x"]}"#
            ),
            [
                "extension/all-sites host_permissions 1 https://*/",
                "extension/all-sites optional_host_permissions 1 *://*/x",
            ]
        );
        assert_eq!(
            asks(r#"{"permissions": ["http://*/"]}"#),
            ["extension/broad-sites permissions 1 http://*/"]
        );
        assert_eq!(
            asks(r#"{"manifest_version": 3, "host_permissions": ["https://*:8443/*"]}"#),
            ["extension/broad-sites host_permissions 1 https://*:8443/*"]
        );
        assert_eq!(
            asks(r#"{"content_scripts": [{"matches": ["https://*/"], "js": ["a.js"]}]}"#),
            ["extension/broad-sites content_scripts 1 https://*/"]
        );
    }

    #[test]
    fn a_version_3_manifest_is_read_key_by_key() {
        assert_eq!(
            asks(
                r#"{
                  "manifest_version": 3,
                  "permissions": ["storage", "tabs", "webRequest", "webRequestBlocking", "cookies", "activeTab"],
                  "optional_permissions": ["clipboardRead", "history"],
                  "host_permissions": ["https://*/*", "http://*/*", "https://api.example.com/*"],
                  "optional_host_permissions": ["https://other.example.com/*"],
                  "content_scripts": [{"matches": ["<all_urls>", "*://*/*"], "js": ["content.js"]}]
                }"#
            ),
            [
                "extension/all-sites host_permissions 1 https://*/*",
                "extension/all-sites content_scripts 2 *://*/*",
                "extension/history optional_permissions 1 history",
                "extension/tabs permissions 1 tabs",
                "extension/web-request permissions 2 webRequest",
                "extension/cookies permissions 1 cookies",
                "extension/clipboard-read optional_permissions 1 clipboardRead",
            ]
        );
        // From version 3 the browser grants sites only under the host keys:
        // a pattern left under `permissions` is refused, and grants nothing.
        assert_eq!(
            asks(
                r#"{"manifest_version": 3,
                    "permissions": ["<all_urls>", "storage", "tabs"],
                    "optional_permissions": ["*://*/*"],
                    "host_permissions": ["*://*.com/*"]}"#
            ),
            [
                "extension/broad-sites host_permissions 1 *://*.com/*",
                "extension/tabs permissions 1 tabs",
            ]
        );
    }

    /// Before version 3 a browser does not know the host keys, and grants
    /// nothing listed under them.
    #[test]
    fn a_version_2_manifest_grants_no_sites_under_the_host_keys() {
        for manifest in [
            r#"{"manifest_version": 2, "host_permissions": ["<all_urls>"], "permissions": ["storage"]}"#,
            r#"{"host_permissions": ["<all_urls>"], "optional_host_permissions": ["*://*/*"]}"#,
        ] {
            assert_eq!(asks(manifest), Vec::<String>::new(), "{manifest}");
        }
        assert_eq!(
            asks(
                r#"{"manifest_version": 2, "permissions": ["*://*.com/*"],
                    "host_permissions": ["<all_urls>"]}"#
            ),
            ["extension/broad-sites permissions 1 *://*.com/*"]
        );
    }

    /// In a version 2 manifest the site patterns sit among the interface
    /// names, under `permissions`.
    #[test]
    fn a_version_2_manifest_lists_its_sites_among_its_permissions() {
        assert_eq!(
            asks(
                r#"{"manifest_version": 2,
                    "permissions": ["<all_urls>", "nativeMessaging", "downloads", "downloads.open",
                                    "management", "debugger", "proxy", "webNavigation",
                                    "clipboardWrite", "https://example.com/*"],
                    "optional_permissions": ["*://*/*"]}"#
            ),
            [
                "extension/all-sites permissions 1 <all_urls>",
                "extension/all-sites optional_permissions 1 *://*/*",
                "extension/web-navigation permissions 1 webNavigation",
                "extension/clipboard-write permissions 1 clipboardWrite",
                "extension/downloads permissions 2 downloads",
                "extension/native-messaging permissions 1 nativeMessaging",
                "extension/management permissions 1 management",
                "extension/debugger permissions 1 debugger",
                "extension/proxy permissions 1 proxy",
            ]
        );
    }

    #[test]
    fn a_manifest_that_asks_for_little_yields_no_edge() {
        for quiet in [
            "{}",
            r#"{"permissions": ["storage", "alarms", "activeTab", "scripting", "contextMenus"]}"#,
            r#"{"manifest_version": 3, "host_permissions": ["https://api.example.com/*", "*://*.example.com/*"]}"#,
            r#"{"content_scripts": [{"matches": ["https://mail.example.com/*"], "js": ["a.js"]}]}"#,
            // Interface names are not looked for among site patterns.
            r#"{"manifest_version": 3, "host_permissions": ["history", "tabs"]}"#,
        ] {
            assert_eq!(asks(quiet), Vec::<String>::new(), "{quiet}");
        }
    }

    /// A script only counts if it runs code, and one that globs narrow
    /// does not cover every page it matches.
    #[test]
    fn scripts_count_by_what_they_can_do() {
        assert_eq!(
            asks(r#"{"content_scripts": [{"matches": ["<all_urls>"], "css": ["dark.css"]}]}"#),
            Vec::<String>::new()
        );
        assert_eq!(
            asks(
                r#"{"content_scripts": [
                     {"matches": ["<all_urls>"], "js": ["pdf.js"], "include_globs": ["*.pdf"]}]}"#
            ),
            ["extension/broad-sites content_scripts 1 <all_urls>"]
        );
        assert_eq!(
            asks(
                r#"{"content_scripts": [
                     {"matches": ["<all_urls>"], "css": ["dark.css"]},
                     {"matches": ["https://*/*"], "js": ["a.js"], "exclude_globs": ["*.pdf"]}]}"#
            ),
            ["extension/all-sites content_scripts 1 https://*/*"]
        );
    }

    /// Every website holds every broad set of them, so the larger thing is
    /// said once. What an extension holds is not made redundant by what it
    /// may only ask for.
    #[test]
    fn a_broad_set_is_not_reported_next_to_every_website() {
        assert_eq!(
            asks(
                r#"{"manifest_version": 3, "host_permissions": ["http://*/*", "https://*/*", "*://*.com/*"]}"#
            ),
            ["extension/all-sites host_permissions 1 https://*/*"]
        );
        assert_eq!(
            asks(
                r#"{"manifest_version": 3, "host_permissions": ["https://*/*"],
                    "optional_host_permissions": ["*://*.com/*"],
                    "content_scripts": [{"matches": ["http://*/*"], "js": ["a.js"]}]}"#
            ),
            ["extension/all-sites host_permissions 1 https://*/*"]
        );
        assert_eq!(
            asks(
                r#"{"manifest_version": 3, "host_permissions": ["*://*.com/*", "*://*.org/*"],
                    "optional_host_permissions": ["<all_urls>", "http://*/*"]}"#
            ),
            [
                "extension/all-sites optional_host_permissions 1 <all_urls>",
                "extension/broad-sites host_permissions 2 *://*.com/*",
            ]
        );
        assert_eq!(
            asks(r#"{"manifest_version": 3, "optional_host_permissions": ["http://*/*"]}"#),
            ["extension/broad-sites optional_host_permissions 1 http://*/*"]
        );
    }

    #[test]
    fn an_entry_listed_twice_counts_once() {
        assert_eq!(
            asks(
                r#"{"manifest_version": 3, "permissions": ["tabs", "tabs", "history"], "host_permissions": ["*://*/*", "*://*/*"]}"#
            ),
            [
                "extension/all-sites host_permissions 1 *://*/*",
                "extension/history permissions 1 history",
                "extension/tabs permissions 1 tabs",
            ]
        );
    }

    /// Of the version folders an update leaves side by side, the highest
    /// version is the one reported; the order is by number, not by text.
    #[test]
    fn version_folders_are_ordered_by_number() {
        let newest = |names: &[&str]| {
            names
                .iter()
                .map(OsStr::new)
                .max_by(|a, b| version_order(a, b))
                .and_then(OsStr::to_str)
                .map(String::from)
        };
        assert_eq!(newest(&["9.9_0", "10.0_0"]).as_deref(), Some("10.0_0"));
        assert_eq!(newest(&["1.2_1", "1.2_0"]).as_deref(), Some("1.2_1"));
        assert_eq!(newest(&["1.10_0", "1.9.9_0"]).as_deref(), Some("1.10_0"));
        assert_eq!(newest(&["1.2.1_0", "1.2_5"]).as_deref(), Some("1.2.1_0"));
        // `1.2` is `1.2.0`: the same version, so the name decides, by bytes.
        assert_eq!(newest(&["1.2.0_0", "1.2_0"]).as_deref(), Some("1.2_0"));
        assert_eq!(newest(&["1.2_0", "1.2.0_0"]).as_deref(), Some("1.2_0"));
        // A name not of the shape sorts below every one that is.
        for odd in ["latest", "2.0", "2.0_x", "2..0_0", "+2_0", "z_0", "99999999999999999999_0"] {
            assert_eq!(newest(&[odd, "0_0"]).as_deref(), Some("0_0"), "{odd}");
        }
        assert_eq!(newest(&["b", "a"]).as_deref(), Some("b"));
    }

    /// The folders an update left behind are not scanned, and the report
    /// says they are there under the extension that is.
    #[test]
    fn older_version_folders_are_a_coverage_record() {
        let profile = tempfile::tempdir().unwrap();
        let root = chromium(profile.path(), ID, "2.1.0_0", LOCALIZED);
        let records = scanned(&Extension { superseded: 2, ..folder(root.clone()) });
        valid(&records);
        assert_eq!(gaps(&records), ["Skipped SupersededVersion -"]);
        let Some(Record::Coverage(coverage)) = records.last() else { panic!() };
        assert_eq!(coverage.count, 2);
        assert_eq!(coverage.subject, artifact(&records).subject);
        assert!(gaps(&scanned(&folder(root))).is_empty());
    }

    #[test]
    fn an_extension_id_is_thirty_two_letters_from_a_to_p() {
        assert!(is_chromium_id("nkbihfbeogaeaoehlefnkodbefgpgknn"));
        assert!(is_chromium_id(&"a".repeat(32)));
        for not in [
            "",
            "Temp",
            &"a".repeat(31),
            &"a".repeat(33),
            "nkbihfbeogaeaoehlefnkodbefgpgknq",
            "NKBIHFBEOGAEAOEHLEFNKODBEFGPGKNN",
            "nkbihfbeogaeaoehlefnkodbefgpgk.n",
        ] {
            assert!(!is_chromium_id(not), "{not}");
        }
    }
}
