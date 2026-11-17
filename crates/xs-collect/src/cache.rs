//! The results cache: what lets a scan skip the apps that have not changed.
//!
//! Reading is nearly all of a scan's cost, and between two scans nearly no
//! app changes. So the result of reading an app is kept, and the next scan
//! reads only the apps whose files look different (design report, sections
//! 4.7 and 6.2 decision 7).
//!
//! ```text
//! list the app (names, sizes, times; no content) ─▶ state
//!        state as stored? ── yes ─▶ the stored records, nothing is read
//!                         └─ no ──▶ read as ever ─▶ records ─▶ stored
//! ```
//!
//! **Nothing about a report depends on the cache.** A stored result is used
//! only when it was made from the app in this very state, by this very
//! program, with these very rules. Anything else is a miss, and a miss is an
//! ordinary read. A scan with the cache and one without it give the same
//! report, byte for byte.
//!
//! # What a result is valid for
//!
//! * **The app's state**, without reading it. Every entry of every folder of
//!   a bundle is listed, and each regular file adds its size, both its
//!   modification and its change time, its inode and its device.
//!   The listing is the one the collector itself makes, so the cache sees
//!   exactly what the collector would go by. A package is one file and adds
//!   the same of itself.
//! * **Where the app is.** The entry of an app is named after the hash of
//!   its path, and a bundle's folder name can reach its records.
//! * **The program**: the SHA-256 of the file this program was started from.
//!   A version number would not do: two builds of one version can read an
//!   app differently, and the stored result of the older one would then
//!   stand in for the newer one's.
//! * **The rules**: the hash of every layer of the rule pack.
//!
//! # What is kept, and where
//!
//! One file per app, in a folder of the user's own (see [`default_dir`]),
//! created for its owner alone and written whole under another name before it
//! takes its place, so that a reader never sees half of one. A file holds
//! the app's records, the hash of the state above, the hash of its own
//! content, and the hashes of the app's path and of each folder above it
//! whose search finds the app, and the same of the link the app was found
//! through, if it was. It holds no path and no list of the app's
//! files. The state is kept as its hash, because that is all a comparison
//! needs (the spec's trust rule 5: store the minimum).
//!
//! A scan removes the entry of an app that it did not find although it
//! searched a folder that finds the app, so the cache does not go on holding
//! an app that was removed. It touches no other entry: a scan of the
//! installed apps leaves what scans of given paths elsewhere stored, and the
//! other way round. An entry whose first line cannot be read is removed too.
//!
//! The cache is the user's own, so a scan run as root keeps none: it would
//! leave files in the user's folder that the user cannot replace.
//!
//! # What is not trusted
//!
//! * **A damaged or edited file.** The content hash, the state hash and
//!   every record's own id are checked, and what fails is passed over: the
//!   app is read and the entry replaced.
//! * **Somebody else's file.** An entry is only read if it is a regular file
//!   that belongs to the user who runs the scan and that nobody else may
//!   write. That user can still write anything into the cache, as into any
//!   file of theirs, the report included; the checks are against damage and
//!   against other users, not against the owner.
//! * **A file that may still be changing.** A change made in the same clock
//!   tick as the listing can leave size and times as they were. So a result
//!   is stored only if every file of the app was last touched a few seconds
//!   before the scan began, by the file system's own clock ([`SETTLE_SECONDS`];
//!   git guards its index the same way). The scanner itself has no clock and
//!   no report ever holds a time: this one only decides whether to store.
//! * **A partial read.** A result with a part that the file system refused
//!   is not stored, since the refusal may not be there the next time.
//!
//! What the state cannot show is a right to read that is taken away without
//! any file changing. Then the stored result still says what the app holds.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use xs_match::Matchers;
use xs_model::evidence::EvidenceError;
use xs_model::record::{CoverageReason, Record};
use xs_model::{EvidenceSet, Sha256Digest, Sha256Stream};

/// The name of the scanner's folder inside the user's cache folder.
const FOLDER: &str = "exposure";
/// The first word of every entry. The number is the format's version: an
/// entry of another format is not understood and so not used.
const MAGIC: &str = "exposure-cache/2";
/// What an entry's file name ends in, after the hash of the app's path.
const ENTRY_SUFFIX: &str = ".entry";
/// What the name of a file that is still being written ends in.
const TEMP_SUFFIX: &str = ".tmp";
/// Largest entry that is written or read: 8 MiB. The records of a real app
/// take a few kilobytes. An app whose records take more than this is read
/// on every scan.
pub const MAX_ENTRY_BYTES: u64 = 8 << 20;
/// Largest first line of an entry that is read to decide whether to remove
/// it. Its words take a few hundred bytes.
const MAX_HEAD_BYTES: u64 = 1 << 10;
/// How long before the scan began every file of an app must have been
/// touched last for its result to be stored, in whole seconds. It covers the
/// coarsest clock of a file system in use, the two seconds of FAT.
pub const SETTLE_SECONDS: i64 = 2;

/// Why the cache could not be used. The scan then runs without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    /// The scan runs as root. Nothing is created or read.
    Root,
    /// The folder cannot be created or written to.
    Folder {
        /// The folder.
        path: PathBuf,
        /// What the operating system said.
        error: String,
    },
    /// The file this program was started from cannot be read, so its results
    /// cannot be told from those of another build.
    Program(String),
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => f.write_str("it is not used when run as root"),
            Self::Folder { path, error } => write!(f, "cannot use {}: {error}", path.display()),
            Self::Program(error) => write!(f, "cannot read this program's own file: {error}"),
        }
    }
}

impl std::error::Error for CacheError {}

/// The folder the cache is kept in when none is named: `exposure` inside the
/// user's cache folder.
///
/// That is `~/Library/Caches` on macOS. Elsewhere it is the folder
/// `XDG_CACHE_HOME` names, or `~/.cache` without one, as the XDG base
/// directory specification has it. `None` if the user has no home folder to
/// go by.
#[must_use]
pub fn default_dir() -> Option<PathBuf> {
    let home = std::env::home_dir().filter(|home| home.is_absolute());
    let caches = if cfg!(target_os = "macos") {
        home.map(|home| home.join("Library/Caches"))
    } else {
        xdg_cache_home().or_else(|| home.map(|home| home.join(".cache")))
    };
    caches.map(|caches| caches.join(FOLDER))
}

/// The folder `XDG_CACHE_HOME` names. The specification has a value that is
/// not an absolute path ignored.
#[expect(
    clippy::disallowed_methods,
    reason = "where the cache is kept is not output: no report depends on the cache"
)]
fn xdg_cache_home() -> Option<PathBuf> {
    std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from).filter(|path| path.is_absolute())
}

/// What a listing saw, as the byte that stands for it in a [`Listing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Seen {
    /// A folder is about to be listed. Its path follows.
    Listed = b'D',
    /// An entry that is a folder. Its name follows.
    Folder = b'd',
    /// An entry that is a regular file. Its name follows.
    File = b'f',
    /// An entry that is a symbolic link. Its name follows.
    Link = b'l',
    /// An entry that is none of these, or something where a file belongs.
    /// Its name follows where it has one.
    Other = b'o',
    /// The file system refused: to list a folder, to give an entry, to say
    /// what an entry is.
    Refused = b'!',
    /// A folder that was not listed because it holds more than the budget.
    OverBudget = b'+',
    /// What the file system says of a regular file. See [`Listing::file`].
    State = b's',
}

/// The state of an artifact as far as the file system tells it without any
/// content being read: a running hash of everything a listing saw.
///
/// Everything is added with its kind in front and at a fixed or a stated
/// length, so two different listings never add the same bytes.
#[derive(Debug, Clone)]
pub(crate) struct Listing {
    hash: Sha256Stream,
    /// The latest time any file was touched, in seconds.
    newest: i64,
}

impl Listing {
    pub(crate) fn new() -> Self {
        Self { hash: Sha256Stream::new(), newest: i64::MIN }
    }

    /// Adds something that has no name.
    pub(crate) fn note(&mut self, seen: Seen) {
        self.hash.update(&[seen as u8]);
    }

    /// Adds something with its name, or its path.
    pub(crate) fn name(&mut self, seen: Seen, name: &[u8]) {
        self.note(seen);
        self.hash.update(&(name.len() as u64).to_le_bytes());
        self.hash.update(name);
    }

    /// Adds what the file system says of a regular file: its size, when its
    /// content and when its inode last changed, and which file it is.
    ///
    /// Writing to a file moves both times, and the change time cannot be set
    /// back, so a file that was written to differs in at least one of them.
    /// A file put in the place of another is another inode.
    pub(crate) fn file(&mut self, metadata: &Metadata) {
        self.note(Seen::State);
        self.hash.update(&metadata.len().to_le_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let times =
                [metadata.mtime(), metadata.mtime_nsec(), metadata.ctime(), metadata.ctime_nsec()];
            for time in times {
                self.hash.update(&time.to_le_bytes());
            }
            self.hash.update(&metadata.ino().to_le_bytes());
            self.hash.update(&metadata.dev().to_le_bytes());
            self.newest = self.newest.max(metadata.mtime()).max(metadata.ctime());
        }
    }

    /// The state listed so far.
    pub(crate) fn state(&self) -> State {
        State { digest: self.hash.clone().finish(), newest: self.newest }
    }
}

/// The state of an artifact: the hash of its [`Listing`], and when it was
/// last touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct State {
    digest: Sha256Digest,
    newest: i64,
}

impl State {
    /// The state of an artifact that is one file.
    pub(crate) fn of_file(metadata: &Metadata) -> Self {
        let mut listing = Listing::new();
        listing.file(metadata);
        listing.state()
    }
}

/// What kind of artifact an entry is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    /// A macOS application bundle.
    Bundle = b'b',
    /// An Android package.
    Package = b'p',
}

/// Which artifact an entry is about: the hash of its kind and its path. An
/// entry's file is named after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Key(Sha256Digest);

impl Key {
    /// The key of the artifact at `path`, which is canonical.
    pub(crate) fn of(kind: Kind, path: &Path) -> Self {
        let mut hash = Sha256Stream::new();
        hash.update(b"exposure cache key\0");
        hash.update(&[kind as u8]);
        hash.update(path.as_os_str().as_encoded_bytes());
        Self(hash.finish())
    }

    fn file_name(self) -> String {
        format!("{}{ENTRY_SUFFIX}", self.0)
    }

    /// The key a file of this name is the entry of, if it is named like one.
    fn of_file_name(name: &str) -> Option<Self> {
        name.strip_suffix(ENTRY_SUFFIX).and_then(Sha256Digest::from_hex).map(Self)
    }
}

/// The hash of a path that a scan searches, as an entry holds it.
pub(crate) fn path_digest(path: &Path) -> Sha256Digest {
    let mut hash = Sha256Stream::new();
    hash.update(b"exposure cache path\0");
    hash.update(path.as_os_str().as_encoded_bytes());
    hash.finish()
}

/// The first line of an entry: what its result is valid for, the hash of
/// what follows the line, and the hashes of the paths whose search finds the
/// artifact.
struct Head {
    valid_for: Sha256Digest,
    sum: Sha256Digest,
    reached_from: Vec<Sha256Digest>,
}

impl Head {
    /// The first line `line`, without its end, if it is one of this format.
    fn parse(line: &[u8]) -> Option<Self> {
        let mut words = std::str::from_utf8(line).ok()?.split(' ');
        if words.next()? != MAGIC {
            return None;
        }
        let valid_for = Sha256Digest::from_hex(words.next()?)?;
        let sum = Sha256Digest::from_hex(words.next()?)?;
        let reached_from =
            words.next()?.split(',').map(Sha256Digest::from_hex).collect::<Option<Vec<_>>>()?;
        words.next().is_none().then_some(Self { valid_for, sum, reached_from })
    }
}

/// What reading one artifact produced: what an entry holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Collected {
    /// How many files were read and hashed.
    pub(crate) files: u64,
    /// How many bytes were read and hashed.
    pub(crate) bytes: u64,
    /// Every record about the artifact. Read back from a file, each record
    /// and each id is checked again.
    pub(crate) evidence: EvidenceSet,
}

impl Collected {
    /// # Errors
    ///
    /// Fails if a record breaks the evidence format, which is a bug in the
    /// collector that made it.
    pub(crate) fn new(records: Vec<Record>, files: u64, bytes: u64) -> Result<Self, EvidenceError> {
        let mut evidence = EvidenceSet::new();
        for record in records {
            evidence.insert(record)?;
        }
        Ok(Self { files, bytes, evidence })
    }

    /// Whether reading the artifact again in the same state is sure to give
    /// this result. It is not if the file system refused a part of it.
    fn repeatable(&self) -> bool {
        !self.evidence.iter().any(|(_, record)| {
            matches!(
                record,
                Record::Coverage(gap)
                    if matches!(gap.reason, CoverageReason::Unreadable | CoverageReason::NoPrivilege)
            )
        })
    }
}

/// The cache of one scan.
#[derive(Debug)]
pub(crate) struct Cache {
    dir: PathBuf,
    /// What every result depends on besides the artifact: this program and
    /// the rules.
    context: Sha256Digest,
    /// The user who runs the scan.
    owner: u32,
    /// The file system's clock when the cache was opened, in seconds.
    opened: i64,
}

/// Numbers the files this process writes, so that no two share a name.
static WRITTEN: AtomicU64 = AtomicU64::new(0);

/// A name no other file of this process, and none of another one running,
/// is being written under.
fn temp_name(stem: &str) -> String {
    let number = WRITTEN.fetch_add(1, Ordering::Relaxed);
    format!("{stem}.{}-{number}{TEMP_SUFFIX}", std::process::id())
}

/// Creates a file that only its owner can read and that was not there
/// before, so that nothing is written through a link somebody left. A file
/// of that name can only be what a run that was cut short left behind.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    match options.open(path) {
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(path)?;
            options.open(path)
        }
        outcome => outcome,
    }
}

/// The SHA-256 of the file this program was started from. It is the same
/// for the whole run, so it is taken once.
fn program_digest() -> Result<Sha256Digest, String> {
    static PROGRAM: OnceLock<Result<Sha256Digest, String>> = OnceLock::new();
    PROGRAM.get_or_init(|| hash_program().map_err(|error| error.to_string())).clone()
}

fn hash_program() -> io::Result<Sha256Digest> {
    let mut file = std::env::current_exe().and_then(File::open)?;
    let mut hash = Sha256Stream::new();
    let mut buffer = vec![0; 1 << 16];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => return Ok(hash.finish()),
            Ok(read) => hash.update(buffer.get(..read).unwrap_or_default()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// The user this process acts as.
#[cfg(unix)]
fn effective_user() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(not(unix))]
fn effective_user() -> u32 {
    u32::MAX
}

impl Cache {
    /// Opens the cache in `dir`, which is created if it is not there, for
    /// results made with `matchers`.
    ///
    /// # Errors
    ///
    /// Fails if the scan runs as root, if the folder belongs to another user,
    /// cannot be created or written to, or if this program's own file cannot
    /// be read.
    pub(crate) fn open(dir: &Path, matchers: &Matchers<'_>) -> Result<Self, CacheError> {
        Self::open_as(effective_user(), dir, matchers)
    }

    /// Opens the cache in `dir` for `user`. Who that is decides before
    /// anything is created.
    fn open_as(user: u32, dir: &Path, matchers: &Matchers<'_>) -> Result<Self, CacheError> {
        if user == 0 {
            return Err(CacheError::Root);
        }
        let program = program_digest().map_err(CacheError::Program)?;
        let mut context = Sha256Stream::new();
        context.update(b"exposure cache context\0");
        context.update(program.as_bytes());
        for layer in matchers.pack().layers() {
            context.update(layer.sha256.as_bytes());
        }

        let fail = |error: io::Error| CacheError::Folder {
            path: dir.to_path_buf(),
            error: error.to_string(),
        };
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if fs::metadata(dir).is_ok_and(|metadata| metadata.uid() != user) {
                return Err(fail(io::Error::other("it belongs to another user")));
            }
        }
        builder.create(dir).map_err(fail)?;
        let opened = probe(dir).map_err(fail)?;
        Ok(Self { dir: dir.to_path_buf(), context: context.finish(), owner: user, opened })
    }

    /// The place in the cache of the artifact at `path` in `state`, which
    /// a search of each of `reached_from` finds.
    pub(crate) fn slot<'p>(
        &self,
        kind: Kind,
        path: &Path,
        reached_from: impl IntoIterator<Item = &'p Path>,
        state: State,
    ) -> Slot<'_> {
        let key = Key::of(kind, path);
        let mut valid_for = Sha256Stream::new();
        valid_for.update(b"exposure cache state\0");
        valid_for.update(self.context.as_bytes());
        valid_for.update(key.0.as_bytes());
        valid_for.update(state.digest.as_bytes());
        Slot {
            cache: self,
            key,
            reached_from: reached_from.into_iter().map(path_digest).collect(),
            valid_for: valid_for.finish(),
            newest: state.newest,
        }
    }

    /// Removes the entry of every artifact that is not among `present` and
    /// that the search of one of `searched` finds, and every entry whose first
    /// line cannot be read. Only files named like an entry are looked at,
    /// whatever else the folder holds.
    pub(crate) fn evict(&self, searched: &BTreeSet<Sha256Digest>, present: &BTreeSet<Key>) {
        let Ok(entries) = fs::read_dir(&self.dir) else { return };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(key) = name.to_str().and_then(Key::of_file_name) else { continue };
            if present.contains(&key) {
                continue;
            }
            let path = entry.path();
            let gone = self
                .head(&path)
                .is_none_or(|head| head.reached_from.iter().any(|from| searched.contains(from)));
            if gone {
                let _ = fs::remove_file(path);
            }
        }
    }

    /// The entry at `path`, opened, if it is one to read: trusted, and no
    /// larger than any entry is.
    fn open_entry(&self, path: &Path) -> Option<File> {
        // Looked at before it is opened: opening a pipe that somebody left
        // under this name would wait for its other end. And once more when
        // it is open, since what is at a name can be exchanged in between.
        if !fs::symlink_metadata(path).is_ok_and(|metadata| self.trusts(&metadata)) {
            return None;
        }
        let file = File::open(path).ok()?;
        let metadata = file.metadata().ok()?;
        (self.trusts(&metadata) && metadata.len() <= MAX_ENTRY_BYTES).then_some(file)
    }

    /// The bytes of the entry at `path`, if it is one to read.
    fn read(&self, path: &Path) -> Option<Vec<u8>> {
        let mut bytes = Vec::new();
        // One byte past the limit, so a file that grew since is noticed.
        self.open_entry(path)?.take(MAX_ENTRY_BYTES + 1).read_to_end(&mut bytes).ok()?;
        (bytes.len() as u64 <= MAX_ENTRY_BYTES).then_some(bytes)
    }

    /// The first line of the entry at `path`, if it is one to read. Nothing
    /// after the line is read or checked.
    fn head(&self, path: &Path) -> Option<Head> {
        let mut bytes = Vec::new();
        self.open_entry(path)?.take(MAX_HEAD_BYTES).read_to_end(&mut bytes).ok()?;
        Head::parse(bytes.get(..bytes.iter().position(|byte| *byte == b'\n')?)?)
    }

    /// Whether an entry with this `metadata` is one to read: a regular file
    /// of the user who runs the scan that nobody else may write.
    #[cfg(unix)]
    fn trusts(&self, metadata: &Metadata) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        metadata.is_file() && metadata.uid() == self.owner && metadata.mode() & 0o022 == 0
    }

    #[cfg(not(unix))]
    fn trusts(&self, _: &Metadata) -> bool {
        false
    }
}

/// Asks the file system of `dir` what time it is, by writing a file there
/// and looking at it. The file is removed again.
///
/// The time is the file system's because it is compared with the times of
/// files, which the file system set.
#[cfg(unix)]
fn probe(dir: &Path) -> io::Result<i64> {
    use std::os::unix::fs::MetadataExt as _;
    let path = dir.join(temp_name("probe"));
    let seen =
        create_private(&path).and_then(|file| file.metadata()).map(|metadata| metadata.mtime());
    let removed = fs::remove_file(&path);
    seen.and_then(|seen| removed.map(|()| seen))
}

/// This build does not know how to tell one state of a file from another on
/// a system that is not Unix, so it keeps no cache there.
#[cfg(not(unix))]
fn probe(_: &Path) -> io::Result<i64> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

/// The place in the cache of one artifact in one state.
#[derive(Debug)]
pub(crate) struct Slot<'c> {
    cache: &'c Cache,
    key: Key,
    /// The hashes of the paths whose search finds the artifact.
    reached_from: Vec<Sha256Digest>,
    /// What a result kept here is valid for: the hash of the program, the
    /// rules, the artifact's path and its state.
    valid_for: Sha256Digest,
    /// When the artifact was last touched, in seconds.
    newest: i64,
}

impl Slot<'_> {
    fn path(&self) -> PathBuf {
        self.cache.dir.join(self.key.file_name())
    }

    /// The result stored here, if one is and it was made from the artifact
    /// in this state. Anything else, a damaged file included, is no result.
    pub(crate) fn load(&self) -> Option<Collected> {
        let bytes = self.cache.read(&self.path())?;
        let (line, body) = bytes.split_at_checked(bytes.iter().position(|byte| *byte == b'\n')?)?;
        let body = body.get(1..)?;
        let head = Head::parse(line)?;
        let sound = head.valid_for == self.valid_for && head.sum == Sha256Digest::of(body);
        if !sound {
            return None;
        }
        serde_json::from_slice(body).ok()
    }

    /// Stores `result` here, in place of whatever was. Says whether it did.
    ///
    /// It does not if the artifact was touched too close to the scan for
    /// its state to be told from a later one, if the file system refused a
    /// part of it, or if the result is too large. Failing to write is no
    /// error either: the artifact is then read again the next time.
    pub(crate) fn store(&self, result: &Collected) -> bool {
        let settled = self.newest.saturating_add(SETTLE_SECONDS) < self.cache.opened;
        if !settled || !result.repeatable() {
            return false;
        }
        let Ok(body) = serde_json::to_vec(result) else { return false };
        let reached_from: Vec<String> =
            self.reached_from.iter().map(Sha256Digest::to_hex).collect();
        let head = format!(
            "{MAGIC} {} {} {}\n",
            self.valid_for,
            Sha256Digest::of(&body),
            reached_from.join(",")
        );
        if (head.len() + body.len()) as u64 > MAX_ENTRY_BYTES {
            return false;
        }
        let temp = self.cache.dir.join(temp_name(&self.key.0.to_hex()));
        let written = create_private(&temp)
            .and_then(|mut file| {
                file.write_all(head.as_bytes()).and_then(|()| file.write_all(&body))
            })
            .and_then(|()| fs::rename(&temp, self.path()));
        if written.is_err() {
            let _ = fs::remove_file(&temp);
        }
        written.is_ok()
    }
}

#[cfg(test)]
mod tests;
