//! The cache from the inside: a scan's reading step run against a cache
//! whose clock the test sets, so that no test has to wait for files to age.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use xs_formats::testkit::{self, DexBuilder, ZipBuilder};
use xs_model::matcher::Boundary;
use xs_model::pack::{Category, Layer, LoadedLayer, Rule, Token};
use xs_model::record::V1;
use xs_model::{MatcherKind, Pack};

use super::*;
use crate::schedule::Pool;
use crate::{ScanStats, collect, discover, forget_gone};

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A bundle with the given app id that ships the Sentry framework.
fn bundle(path: &Path, id: &str) -> PathBuf {
    let plist = format!(
        r#"<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleExecutable</key><string>Example</string>
</dict></plist>"#
    );
    write(&path.join("Contents/Info.plist"), plist);
    let binary = xs_formats::macho_build::Binary::new().build();
    write(&path.join("Contents/MacOS/Example"), &binary);
    write(&path.join("Contents/Frameworks/Sentry.framework/Sentry"), &binary);
    path.to_path_buf()
}

/// A package with the given app id whose one DEX file defines a Sentry
/// class.
fn package(path: &Path, id: &str) -> PathBuf {
    let apk = ZipBuilder::new()
        .deflated("AndroidManifest.xml", &testkit::manifest(id, "1.0", &[("activity", ".Main")]))
        .deflated("classes.dex", &DexBuilder::new().class("io.sentry.Sentry").finish())
        .finish();
    write(path, apk);
    path.to_path_buf()
}

/// A pack with one rule for Sentry, read from a layer file with this hash.
fn pack(sha256: Sha256Digest) -> Pack {
    let rule = Rule {
        id: "sdk/sentry".into(),
        name: "Sentry".into(),
        entity: None,
        category: "component".into(),
        sources: vec![],
        notes: vec![],
        matchers: BTreeMap::from([
            (
                MatcherKind::AppleFramework,
                vec![Token { lit: "Sentry.framework".into(), at: Boundary::Exact }],
            ),
            (
                MatcherKind::AndroidClassPrefix,
                vec![Token { lit: "io.sentry.".into(), at: Boundary::Prefix }],
            ),
        ]),
        min_distinct: BTreeMap::new(),
    };
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
        rules: vec![rule],
    };
    Pack::new(vec![LoadedLayer { layer, sha256 }]).unwrap()
}

/// A folder of apps of both kinds, and a folder to keep a cache in.
struct Lab {
    dir: tempfile::TempDir,
    pack: Pack,
}

/// How many apps a [`Lab`] holds.
const APPS: u64 = 5;

impl Lab {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let apps = dir.path().join("Apps");
        bundle(&apps.join("One.app"), "org.example.one");
        bundle(&apps.join("Two.app"), "org.example.two");
        bundle(&apps.join("Utilities/Three.app"), "org.example.three");
        package(&apps.join("one.apk"), "org.example.droid.one");
        package(&apps.join("two.apk"), "org.example.droid.two");
        Self { dir, pack: pack(Sha256Digest::of(b"rules")) }
    }

    fn apps(&self) -> PathBuf {
        self.dir.path().join("Apps")
    }

    fn app(&self, name: &str) -> PathBuf {
        self.apps().join(name)
    }

    fn cache_dir(&self) -> PathBuf {
        self.dir.path().join("cache")
    }

    /// The cache, opened at a time by which every app has long settled.
    fn cache(&self) -> Cache {
        self.cache_at(i64::MAX, &self.pack)
    }

    fn cache_at(&self, opened: i64, pack: &Pack) -> Cache {
        let matchers = Matchers::build(pack).unwrap();
        let mut cache = Cache::open(&self.cache_dir(), &matchers).unwrap();
        cache.opened = opened;
        cache
    }

    /// Reads the apps as a scan does, with `cache` or without one.
    fn scan(&self, cache: Option<&Cache>) -> (EvidenceSet, ScanStats) {
        self.scan_with(&self.pack, cache)
    }

    fn scan_with(&self, pack: &Pack, cache: Option<&Cache>) -> (EvidenceSet, ScanStats) {
        let found = discover::artifacts(&[self.apps()]).unwrap();
        let matchers = Matchers::build(pack).unwrap();
        collect(&found, &matchers, &Pool::new(3).unwrap(), cache).unwrap()
    }

    /// The file the cache keeps about the app at `name`.
    fn entry(&self, kind: Kind, name: &str) -> PathBuf {
        let path = fs::canonicalize(self.app(name)).unwrap();
        self.cache_dir().join(Key::of(kind, &path).file_name())
    }

    /// The names of the files in the cache folder, sorted.
    fn kept(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.cache_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

/// With `reused` apps not read: the same evidence and the same totals as a
/// scan that reads everything.
#[track_caller]
fn assert_same(lab: &Lab, cache: &Cache, reused: u64) {
    let (expected, read) = lab.scan(None);
    let (evidence, stats) = lab.scan(Some(cache));
    assert_eq!(evidence, expected);
    assert_eq!(stats, ScanStats { reused, ..read });
    assert_eq!(read.reused, 0);
}

/// Design report, section 4.7: nothing about correctness depends on the
/// cache. The first scan reads every app and the second none, and both give
/// what a scan without the cache gives.
#[test]
fn a_second_scan_reads_nothing_and_gives_the_same_evidence() {
    let lab = Lab::new();
    let cache = lab.cache();
    assert_same(&lab, &cache, 0);
    assert_same(&lab, &cache, APPS);
    assert_same(&lab, &cache, APPS);
    // One file per app, and nothing left over from writing them.
    let kept = lab.kept();
    assert_eq!(kept.len() as u64, APPS);
    assert!(kept.iter().all(|name| Key::of_file_name(name).is_some()), "{kept:?}");
    // A cache that is opened again holds what the last one stored.
    assert_same(&lab, &lab.cache(), APPS);
}

/// The first use of the folder creates it for its owner alone, and every
/// entry is the owner's alone to read. An entry names the app by what the
/// records say of it, never by where it is.
#[test]
fn the_cache_is_private_and_holds_no_path() {
    let lab = Lab::new();
    assert_same(&lab, &lab.cache(), 0);
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&lab.cache_dir()), 0o700);
    let here = fs::canonicalize(lab.dir.path()).unwrap();
    for name in lab.kept() {
        let path = lab.cache_dir().join(name);
        assert_eq!(mode(&path), 0o600);
        let entry = String::from_utf8(fs::read(&path).unwrap()).unwrap();
        assert!(entry.starts_with("exposure-cache/1 "), "{entry}");
        assert!(!entry.contains(here.to_str().unwrap()), "{entry}");
        assert!(!entry.contains("Apps"), "{entry}");
    }
}

/// Something done to an app between two scans.
type Change<'a> = Box<dyn Fn() + 'a>;

/// Design report, section 6.2 decision 7: only an app whose files look
/// different is read again, whatever it was that changed.
#[test]
fn changing_one_app_reads_only_that_app_again() {
    let lab = Lab::new();
    let cache = lab.cache();
    assert_same(&lab, &cache, 0);
    let (before, _) = lab.scan(None);

    let binary = lab.app("One.app/Contents/MacOS/Example");
    let framework = lab.app("Two.app/Contents/Frameworks/Sentry.framework");
    let changes: [(&str, Change<'_>); 7] = [
        (
            "a file grows",
            Box::new(|| write(&binary, [&fs::read(&binary).unwrap()[..], b"x"].concat())),
        ),
        (
            "a file changes content, but neither its size nor its modification time",
            Box::new(|| {
                let before = fs::metadata(&binary).unwrap();
                let mut bytes = fs::read(&binary).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                // The change time is what tells, and on some file systems
                // it moves in steps of milliseconds. A test cannot open a
                // cache early enough to have such a file left out, as a
                // scan does, so it writes until the clock has moved.
                loop {
                    fs::write(&binary, &bytes).unwrap();
                    let file = File::options().write(true).open(&binary).unwrap();
                    file.set_modified(before.modified().unwrap()).unwrap();
                    let after = fs::metadata(&binary).unwrap();
                    assert_eq!((after.len(), after.mtime()), (before.len(), before.mtime()));
                    if (after.ctime(), after.ctime_nsec()) != (before.ctime(), before.ctime_nsec())
                    {
                        break;
                    }
                }
            }),
        ),
        ("a file is added", Box::new(|| write(&lab.app("One.app/Contents/Resources/new"), "x"))),
        (
            "a file is removed",
            Box::new(|| fs::remove_file(lab.app("One.app/Contents/Resources/new")).unwrap()),
        ),
        (
            "a folder is renamed",
            Box::new(|| {
                fs::rename(&framework, framework.with_file_name("Other.framework")).unwrap()
            }),
        ),
        (
            "an empty folder is added",
            Box::new(|| fs::create_dir(lab.app("Two.app/Empty")).unwrap()),
        ),
        (
            "a package is replaced",
            Box::new(|| drop(package(&lab.app("one.apk"), "org.example.droid.changed"))),
        ),
    ];
    for (what, change) in changes {
        change();
        let (evidence, stats) = lab.scan(Some(&cache));
        assert_eq!(stats.reused, APPS - 1, "{what}");
        assert_eq!(evidence, lab.scan(None).0, "{what}");
        // What was read is what the next scan goes by.
        assert_same(&lab, &cache, APPS);
    }
    // The changes did reach the evidence: Two.app lost its framework.
    assert_ne!(lab.scan(None).0, before);
}

/// A file that was replaced by another one is another file, even where the
/// new one has the size and the modification time of the old.
#[test]
fn a_file_put_in_the_place_of_another_is_seen() {
    let lab = Lab::new();
    let cache = lab.cache();
    assert_same(&lab, &cache, 0);
    let binary = lab.app("Two.app/Contents/MacOS/Example");
    let modified = fs::metadata(&binary).unwrap().modified().unwrap();
    let mut bytes = fs::read(&binary).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let other = binary.with_file_name("Other");
    fs::write(&other, bytes).unwrap();
    File::options().write(true).open(&other).unwrap().set_modified(modified).unwrap();
    fs::rename(&other, &binary).unwrap();
    assert_same(&lab, &cache, APPS - 1);
}

/// The headline of an entry with another sum, for a body that was edited by
/// someone who took care to make the file whole again.
fn with_sum(head: &str, body: &str) -> Vec<u8> {
    let words: Vec<&str> = head.split(' ').collect();
    let sum = Sha256Digest::of(body.as_bytes());
    format!("{} {} {sum} {}\n{body}", words[0], words[1], words[3]).into_bytes()
}

/// Build plan, task 12: a corrupt cache file falls back to a cold scan. So
/// does one that was edited. Either way the app is read, the report is the
/// one a scan without the cache gives, and the entry is put right.
#[test]
fn a_damaged_or_edited_entry_is_passed_over_and_replaced() {
    let lab = Lab::new();
    let cache = lab.cache();
    assert_same(&lab, &cache, 0);
    let entry = lab.entry(Kind::Bundle, "One.app");
    let sound = fs::read(&entry).unwrap();
    let text = String::from_utf8(sound.clone()).unwrap();
    let (head, body) = text.split_once('\n').unwrap();
    assert!(body.contains("Sentry.framework"), "{body}");

    let flipped = |at: usize| {
        let mut bytes = sound.clone();
        bytes[at] ^= 1;
        bytes
    };
    let damage: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("cut short", sound[..sound.len() / 2].to_vec()),
        ("cut short by one byte", sound[..sound.len() - 1].to_vec()),
        ("one byte more", [&sound[..], b" "].concat()),
        ("a bit flipped in the records", flipped(sound.len() - 40)),
        ("a bit flipped in the state", flipped(MAGIC.len() + 5)),
        ("a bit flipped in the sum", flipped(MAGIC.len() + 1 + 64 + 1 + 5)),
        (
            "no root",
            text.replacen(&format!(" {}\n", head.rsplit(' ').next().unwrap()), "\n", 1)
                .into_bytes(),
        ),
        ("not an entry", b"not an entry\n{}".to_vec()),
        ("no records", format!("{head}\n").into_bytes()),
        ("another format", text.replacen("exposure-cache/1", "exposure-cache/2", 1).into_bytes()),
        ("a word more", text.replacen('\n', " more\n", 1).into_bytes()),
        // Edited, with the file's sum set right: the record no longer has
        // the id it is stored under.
        ("an edited record", with_sum(head, &body.replace("Sentry.framework", "Benign.framework"))),
        // Edited to hold something a record cannot hold.
        ("a record of no known shape", with_sum(head, &body.replace("\"edge\"", "\"hearsay\""))),
        ("a field no entry has", with_sum(head, &body.replacen('{', "{\"extra\":1,", 1))),
        ("larger than any entry", vec![b'x'; MAX_ENTRY_BYTES as usize + 1]),
    ];
    for (what, bytes) in damage {
        assert_ne!(bytes, sound, "{what}");
        fs::write(&entry, bytes).unwrap();
        let (expected, _) = lab.scan(None);
        let (evidence, stats) = lab.scan(Some(&cache));
        assert_eq!(stats.reused, APPS - 1, "{what}");
        assert_eq!(evidence, expected, "{what}");
        assert_eq!(fs::read(&entry).unwrap(), sound, "{what}: the entry was not put right");
    }
    assert_same(&lab, &cache, APPS);
}

/// An entry is the result of one app, in one place, read with one set of
/// rules. It answers for nothing else.
#[test]
fn an_entry_answers_only_for_the_app_the_place_and_the_rules_it_was_made_for() {
    let lab = Lab::new();
    let cache = lab.cache();
    assert_same(&lab, &cache, 0);

    // The entry of another app, put where this one's belongs.
    let one = lab.entry(Kind::Bundle, "One.app");
    fs::copy(lab.entry(Kind::Bundle, "Two.app"), &one).unwrap();
    assert_same(&lab, &cache, APPS - 1);
    // A package's entry is not a bundle's, even at the same path.
    let path = fs::canonicalize(lab.app("one.apk")).unwrap();
    assert_ne!(Key::of(Kind::Bundle, &path), Key::of(Kind::Package, &path));

    // The app in another place: a bundle's folder name can be its app id.
    fs::rename(lab.app("One.app"), lab.app("Moved.app")).unwrap();
    assert_same(&lab, &cache, APPS - 1);
    assert_same(&lab, &cache, APPS);

    // Other rules: nothing that was stored answers for them.
    let other = pack(Sha256Digest::of(b"other rules"));
    let other_cache = lab.cache_at(i64::MAX, &other);
    assert_eq!(lab.scan_with(&other, Some(&other_cache)).1.reused, 0);
    assert_eq!(lab.scan_with(&other, Some(&other_cache)).1.reused, APPS);
    // And what they stored took the place of what the first rules had.
    assert_same(&lab, &cache, 0);
}

/// An entry that somebody else may write is not read. What takes its place
/// is the owner's alone again.
#[test]
fn an_entry_that_others_may_write_is_not_trusted() {
    let lab = Lab::new();
    let cache = lab.cache();
    assert_same(&lab, &cache, 0);
    let entry = lab.entry(Kind::Package, "one.apk");
    for mode in [0o620, 0o602, 0o666] {
        fs::set_permissions(&entry, fs::Permissions::from_mode(mode)).unwrap();
        assert_same(&lab, &cache, APPS - 1);
        assert_eq!(fs::metadata(&entry).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // Neither is a link, even to an entry that is sound.
    let sound = lab.dir.path().join("sound");
    fs::rename(&entry, &sound).unwrap();
    std::os::unix::fs::symlink(&sound, &entry).unwrap();
    assert_same(&lab, &cache, APPS - 1);
    assert!(fs::symlink_metadata(&entry).unwrap().is_file());
    // Readable by others is the owner's choice, and harmless.
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o644)).unwrap();
    assert_same(&lab, &cache, APPS);
    // A file of another user is not read either.
    let stranger = Cache { owner: cache.owner.wrapping_add(1), ..lab.cache() };
    assert_same(&lab, &stranger, 0);
}

/// A pipe where an entry belongs is not opened: opening one waits until
/// somebody writes to it, and the scan would wait with it.
#[test]
#[expect(clippy::disallowed_types, reason = "the standard library cannot make a pipe with a name")]
fn a_pipe_in_the_place_of_an_entry_does_not_stop_the_scan() {
    let lab = Lab::new();
    let cache = lab.cache();
    assert_same(&lab, &cache, 0);
    let entry = lab.entry(Kind::Bundle, "Two.app");
    fs::remove_file(&entry).unwrap();
    let made = std::process::Command::new("mkfifo").arg(&entry).status();
    if !made.is_ok_and(|status| status.success()) {
        return;
    }
    assert_same(&lab, &cache, APPS - 1);
    assert!(fs::symlink_metadata(&entry).unwrap().is_file());
    assert_same(&lab, &cache, APPS);
}

/// The latest time any file of the apps was touched, in seconds.
fn newest(dir: &Path) -> i64 {
    let mut newest = i64::MIN;
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let metadata = entry.metadata().unwrap();
        newest = if metadata.is_dir() {
            newest.max(self::newest(&entry.path()))
        } else {
            newest.max(metadata.mtime()).max(metadata.ctime())
        };
    }
    newest
}

/// A change made in the same tick of the clock as the listing could leave
/// an app looking as it was listed. So what was touched within
/// [`SETTLE_SECONDS`] of the scan is read and not stored.
#[test]
fn a_result_is_stored_only_once_the_app_has_settled() {
    let lab = Lab::new();
    let touched = newest(&lab.apps());
    for too_early in [touched - 100, touched, touched + SETTLE_SECONDS] {
        let cache = lab.cache_at(too_early, &lab.pack);
        assert_same(&lab, &cache, 0);
        assert_same(&lab, &cache, 0);
        assert!(lab.kept().is_empty(), "stored at {} s", too_early - touched);
    }
    let cache = lab.cache_at(touched + SETTLE_SECONDS + 1, &lab.pack);
    assert_same(&lab, &cache, 0);
    assert_same(&lab, &cache, APPS);

    // One app is touched again: it alone is read from then on, until it
    // has settled too.
    write(&lab.app("Two.app/Contents/Resources/new"), "x");
    let touched = newest(&lab.apps());
    let early = lab.cache_at(touched + SETTLE_SECONDS, &lab.pack);
    assert_same(&lab, &early, APPS - 1);
    assert_same(&lab, &early, APPS - 1);
    let later = lab.cache_at(touched + SETTLE_SECONDS + 1, &lab.pack);
    assert_same(&lab, &later, APPS - 1);
    assert_same(&lab, &later, APPS);
}

/// The clock a real cache goes by is the file system's, read when the cache
/// is opened: it is not behind the files that were just written, and the
/// user it trusts is the one who wrote them.
#[test]
fn an_opened_cache_knows_the_time_and_the_user_from_the_file_system() {
    let lab = Lab::new();
    let matchers = Matchers::build(&lab.pack).unwrap();
    let cache = Cache::open(&lab.cache_dir(), &matchers).unwrap();
    let touched = newest(&lab.apps());
    assert!((touched..=touched + 60).contains(&cache.opened), "{} {touched}", cache.opened);
    assert_eq!(cache.owner, fs::metadata(lab.dir.path()).unwrap().uid());
    // Asking left nothing behind.
    assert!(lab.kept().is_empty());
}

/// What the file system refused once it may allow the next time, with no
/// file looking any different. Such a result is not kept.
#[test]
fn a_result_with_a_part_that_could_not_be_read_is_not_stored() {
    let lab = Lab::new();
    let cache = lab.cache();
    let locked = lab.app("One.app/Contents/MacOS/Example");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    // Running as root, permissions do not bind and there is nothing to test.
    if fs::read(&locked).is_ok() {
        return;
    }
    assert_same(&lab, &cache, 0);
    assert_same(&lab, &cache, APPS - 1);
    assert!(!lab.entry(Kind::Bundle, "One.app").exists());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
    assert_same(&lab, &cache, APPS - 1);
    assert_same(&lab, &cache, APPS);
}

/// Scans `path` as a scan does with `cache`, including what it removes
/// from the cache afterwards.
fn scan_paths(lab: &Lab, path: &Path, cache: &Cache) -> ScanStats {
    let found = discover::artifacts(&[path.to_path_buf()]).unwrap();
    let matchers = Matchers::build(&lab.pack).unwrap();
    let (_, stats) = collect(&found, &matchers, &Pool::new(3).unwrap(), Some(cache)).unwrap();
    forget_gone(cache, &found);
    stats
}

/// A scan drops what the cache holds about an app that was found in a root
/// it searched and is not there any more, and nothing else: not the entries
/// of apps found in another root, whatever the scan was, and not what else
/// may be in the folder.
#[test]
fn only_the_entries_of_apps_that_are_gone_from_a_root_searched_are_removed() {
    let lab = Lab::new();
    let cache = lab.cache();
    let elsewhere = lab.dir.path().join("Elsewhere");
    let given = bundle(&elsewhere.join("Given.app"), "org.example.given");
    let left = bundle(&elsewhere.join("Left.app"), "org.example.left");

    assert_eq!(scan_paths(&lab, &lab.apps(), &cache).reused, 0);
    assert_eq!(scan_paths(&lab, &given, &cache).reused, 0);
    assert_eq!(scan_paths(&lab, &elsewhere, &cache).reused, 1);
    assert_eq!(lab.kept().len() as u64, APPS + 2);

    // Things that are not entries, some of them named almost like one.
    let key = "0".repeat(64);
    let others =
        ["notes.txt", "CACHEDIR.TAG", &format!("{key}.entry.tmp"), &format!("{key}.ENTRY")];
    for name in others {
        fs::write(lab.cache_dir().join(name), "not an entry").unwrap();
    }
    let folder = format!("{}.entry", "1".repeat(64));
    fs::create_dir(lab.cache_dir().join(&folder)).unwrap();
    let mut kept = lab.kept();

    // Scans of one root leave the entries of apps found in another alone.
    assert_eq!(scan_paths(&lab, &lab.apps(), &cache).reused, APPS);
    assert_eq!(scan_paths(&lab, &given, &cache).reused, 1);
    assert_eq!(scan_paths(&lab, &lab.apps(), &cache).reused, APPS);
    assert_eq!(lab.kept(), kept);

    // An app removed from a root is dropped by the next scan of that root.
    let gone = [lab.entry(Kind::Bundle, "Two.app"), lab.entry(Kind::Package, "one.apk")];
    fs::remove_dir_all(lab.app("Two.app")).unwrap();
    fs::remove_file(lab.app("one.apk")).unwrap();
    assert_eq!(scan_paths(&lab, &elsewhere, &cache).reused, 2);
    assert_eq!(lab.kept(), kept, "a scan of another root removed an entry");
    assert_eq!(scan_paths(&lab, &lab.apps(), &cache).reused, APPS - 2);
    kept.retain(|name| !gone.iter().any(|entry| entry.ends_with(name)));
    assert_eq!(lab.kept(), kept);
    for name in others.iter().map(ToString::to_string).chain([folder]) {
        assert!(kept.contains(&name), "{name} was removed");
    }

    // A folder given is a root like any other.
    let left_entry = Key::of(Kind::Bundle, &fs::canonicalize(&left).unwrap()).file_name();
    fs::remove_dir_all(&left).unwrap();
    assert_eq!(scan_paths(&lab, &elsewhere, &cache).reused, 1);
    kept.retain(|name| *name != left_entry);
    assert_eq!(lab.kept(), kept);
    assert_eq!(scan_paths(&lab, &given, &cache).reused, 1);
    // What is left still answers.
    assert_same(&lab, &cache, APPS - 2);
}

/// A scan run as root keeps no cache: it would leave files in the user's
/// folder that the user cannot replace. Nothing is created, not even the
/// folder.
#[test]
fn root_neither_creates_nor_uses_a_cache() {
    let lab = Lab::new();
    let matchers = Matchers::build(&lab.pack).unwrap();
    let dir = lab.cache_dir().join("made");
    assert_eq!(Cache::open_as(0, &dir, &matchers).unwrap_err(), CacheError::Root);
    assert!(!lab.cache_dir().exists());

    // Not even in a folder that is there and holds what the user stored.
    assert_same(&lab, &lab.cache(), 0);
    let kept = lab.kept();
    assert_eq!(Cache::open_as(0, &lab.cache_dir(), &matchers).unwrap_err(), CacheError::Root);
    assert_eq!(lab.kept(), kept);
}

/// A folder that is there and belongs to someone else is not used either,
/// and nothing is written into it.
#[test]
fn a_folder_of_another_user_is_not_used() {
    let lab = Lab::new();
    let matchers = Matchers::build(&lab.pack).unwrap();
    let dir = lab.cache_dir();
    fs::create_dir(&dir).unwrap();
    let owner = fs::metadata(&dir).unwrap().uid();
    let error = Cache::open_as(owner.wrapping_add(1), &dir, &matchers).unwrap_err();
    assert_eq!(
        error.to_string(),
        format!("cannot use {}: it belongs to another user", dir.display())
    );
    assert!(lab.kept().is_empty());
    // Its owner does use it.
    Cache::open_as(owner, &dir, &matchers).unwrap();
}

#[test]
fn a_folder_that_cannot_be_used_is_an_error_that_names_it() {
    let lab = Lab::new();
    let matchers = Matchers::build(&lab.pack).unwrap();
    let file = lab.dir.path().join("a file");
    fs::write(&file, "in the way").unwrap();
    for dir in [file.clone(), file.join("below")] {
        let error = Cache::open(&dir, &matchers).unwrap_err();
        assert!(matches!(&error, CacheError::Folder { path, .. } if *path == dir), "{error:?}");
        assert!(error.to_string().starts_with(&format!("cannot use {}: ", dir.display())));
    }
    // Folders that are missing on the way are made, each for its owner alone.
    let deep = lab.dir.path().join("made/on/the/way");
    Cache::open(&deep, &matchers).unwrap();
    for dir in [deep.as_path(), deep.parent().unwrap()] {
        assert_eq!(fs::metadata(dir).unwrap().permissions().mode() & 0o777, 0o700);
    }
}

/// A listing is told from every other one: names are added at their stated
/// length and everything else at a fixed one, so nothing can run together.
#[test]
fn different_listings_are_different_states() {
    let state = |entries: &[(Seen, &str)]| {
        let mut listing = Listing::new();
        for (seen, name) in entries {
            listing.name(*seen, name.as_bytes());
        }
        listing.state()
    };
    let base = state(&[(Seen::File, "ab"), (Seen::File, "c")]);
    assert_eq!(base, state(&[(Seen::File, "ab"), (Seen::File, "c")]));
    for other in [
        &[(Seen::File, "a"), (Seen::File, "bc")][..],
        &[(Seen::File, "abc")],
        // A name that holds what stands for a file, and then another name.
        &[(Seen::File, "abfc")],
        &[(Seen::File, "ab"), (Seen::Link, "c")],
        &[(Seen::File, "c"), (Seen::File, "ab")],
        &[(Seen::File, "ab"), (Seen::File, "c"), (Seen::File, "")],
        &[],
    ] {
        assert_ne!(state(other), base, "{other:?}");
    }
    let mut noted = Listing::new();
    noted.name(Seen::File, b"ab");
    noted.note(Seen::Refused);
    noted.name(Seen::File, b"c");
    assert_ne!(noted.state(), base);
}

/// Where the cache is kept by default: a folder of the scanner's own in the
/// user's cache folder, wherever the system this runs on has that.
#[test]
fn the_default_folder_is_the_scanner_s_own_in_the_user_s_cache_folder() {
    let Some(dir) = default_dir() else { return };
    assert!(dir.is_absolute(), "{}", dir.display());
    assert!(dir.ends_with("exposure"), "{}", dir.display());
    if cfg!(target_os = "macos") {
        assert!(dir.ends_with("Library/Caches/exposure"), "{}", dir.display());
    }
}
