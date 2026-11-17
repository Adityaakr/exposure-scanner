//! The results cache from the outside (build plan, task 12): cached and
//! uncached reports are byte-identical, a damaged or edited cache file falls
//! back to reading the app, and changing one app reads only that app again.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "tests run the binary, set its environment and may wait for files to age"
)]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

/// The committed fixtures: a folder of two bundles, and a package.
const BUNDLES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos");
const PACKAGE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/android/Skeleton.apk");
const APPS: usize = 3;

fn exposure() -> Command {
    Command::new(env!("CARGO_BIN_EXE_exposure"))
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// What a scan wrote: its report, and what it told the terminal.
struct Scanned {
    report: String,
    summary: String,
}

impl Scanned {
    fn of(output: &Output) -> Self {
        let summary = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(output.status.success(), "exit {:?}: {summary}", output.status.code());
        Self { report: String::from_utf8(output.stdout.clone()).unwrap(), summary }
    }

    /// What the summary says the cache did, if it says anything.
    fn cache(&self) -> Option<&str> {
        self.summary.lines().find_map(|line| line.strip_prefix("exposure: cache: "))
    }

    /// How many apps the summary says were not read, and how many were.
    #[track_caller]
    fn assert_read(&self, unchanged: usize, read: usize) {
        let apps =
            |count: usize| if count == 1 { String::from("1 app") } else { format!("{count} apps") };
        let expected = format!(
            "{} unchanged since an earlier scan and not read again, {} read",
            apps(unchanged),
            apps(read)
        );
        assert_eq!(self.cache(), Some(expected.as_str()), "{}", self.summary);
    }
}

/// A scan as the user whose home folder is `home`.
fn at_home(home: &Path) -> Command {
    let mut command = exposure();
    command.env("HOME", home).env_remove("XDG_CACHE_HOME").arg("scan");
    command
}

/// Where a scan as the user whose home folder is `home` keeps its cache.
fn cache_in(home: &Path) -> PathBuf {
    let caches = if cfg!(target_os = "macos") { "Library/Caches" } else { ".cache" };
    home.join(caches).join("exposure")
}

/// Scans `paths` with these options, with no cache folder to go by.
fn scan(paths: &[&Path], options: &[&str]) -> Scanned {
    let output = exposure().arg("scan").args(options).arg("--").args(paths).output().unwrap();
    Scanned::of(&output)
}

/// Scans `paths` with these options as the user whose home folder is `home`.
fn scan_at(home: &Path, paths: &[&Path], options: &[&str]) -> Scanned {
    Scanned::of(&at_home(home).args(options).arg("--").args(paths).output().unwrap())
}

/// Scans `paths` with the cache of the user whose home folder is `home`.
fn scan_cached(paths: &[&Path], home: &Path) -> Scanned {
    scan_at(home, paths, &[])
}

/// The latest time anything at `path` was touched, in seconds.
fn newest(path: &Path) -> i64 {
    let metadata = fs::symlink_metadata(path).unwrap();
    if !metadata.is_dir() {
        return metadata.mtime().max(metadata.ctime());
    }
    fs::read_dir(path).unwrap().map(|entry| newest(&entry.unwrap().path())).max().unwrap_or(0)
}

/// Waits, if it has to, until the files at `paths` were last touched long
/// enough ago for a result to be stored: a few seconds. A checkout a test
/// binary was built from is older than that, so it waits for nothing.
fn settle(paths: &[&Path]) {
    let newest = paths.iter().map(|path| newest(path)).max().unwrap_or(0);
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let ready = u64::try_from(newest + 4).unwrap_or(0);
    std::thread::sleep(Duration::from_secs(ready.saturating_sub(now)));
}

fn fixtures() -> [&'static Path; 2] {
    let paths = [Path::new(BUNDLES), Path::new(PACKAGE)];
    settle(&paths);
    paths
}

/// The entries in the cache folder `dir`, sorted by name.
fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> =
        fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().path()).collect();
    entries.sort();
    assert!(
        entries.iter().all(|path| path.extension().is_some_and(|kind| kind == "entry")),
        "{entries:?}"
    );
    entries
}

/// Copies a folder, keeping symbolic links as links.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        if kind.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(entry.path()).unwrap(), target).unwrap();
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Build plan, task 12, and design report, section 7 property 3: cached and
/// uncached reports are byte-identical, whatever the cache holds and at any
/// thread count.
#[test]
fn a_scan_gives_the_same_report_with_the_cache_cold_warm_and_off() {
    let paths = fixtures();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let cache = cache_in(home);

    let off = scan_at(home, &paths, &["--no-cache"]);
    assert_eq!(off.cache(), None, "{}", off.summary);
    assert!(off.summary.contains("scanned 3 apps"), "{}", off.summary);
    assert!(!cache.exists());

    let cold = scan_cached(&paths, home);
    cold.assert_read(0, APPS);
    assert_eq!(cold.report, off.report);
    assert_eq!(entries(&cache).len(), APPS);

    for threads in ["1", "2", "8"] {
        let warm = scan_at(home, &paths, &["--threads", threads]);
        warm.assert_read(APPS, 0);
        assert_eq!(warm.report, off.report, "{threads} threads");
        // What the summary says of the scan is what the report covers,
        // whenever it was read.
        let scanned = |summary: &str| summary.lines().next().unwrap().to_owned();
        assert_eq!(scanned(&warm.summary), scanned(&off.summary));
    }
    // An app named by itself is the app found in its folder.
    let alone = scan_cached(&[&Path::new(BUNDLES).join("Skeleton.app")], home);
    alone.assert_read(1, 0);
    // With the cache off, what it holds is neither used nor touched.
    let before = entries(&cache).iter().map(|path| fs::read(path).unwrap()).collect::<Vec<_>>();
    assert_eq!(scan_at(home, &paths, &["--no-cache"]).report, off.report);
    assert_eq!(
        entries(&cache).iter().map(|path| fs::read(path).unwrap()).collect::<Vec<_>>(),
        before
    );
}

/// The cache is the user's alone, and it holds what was found in the apps:
/// not where they are, and not the summary's "no app, no path" either way.
#[test]
fn the_cache_is_readable_by_its_owner_only_and_names_no_path() {
    let paths = fixtures();
    let dir = tempfile::tempdir().unwrap();
    let cache = cache_in(dir.path());
    let scanned = scan_cached(&paths, dir.path());
    scanned.assert_read(0, APPS);
    assert!(!scanned.summary.contains(text(dir.path())), "{}", scanned.summary);

    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&cache), 0o700);
    assert_eq!(mode(cache.parent().unwrap()), 0o700);
    let repository = fs::canonicalize(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).unwrap();
    for entry in entries(&cache) {
        assert_eq!(mode(&entry), 0o600);
        let kept = fs::read_to_string(&entry).unwrap();
        assert!(kept.starts_with("exposure-cache/1 "), "{kept}");
        assert!(!kept.contains(text(&repository)), "{kept}");
        assert!(!kept.contains("fixtures"), "{kept}");
    }
}

/// What is done to the bytes of a cache file to damage it.
type Edit = fn(&[u8]) -> Vec<u8>;

/// Build plan, task 12: a corrupt cache file falls back to a cold scan, and
/// so does one that was edited. The report is the one a scan without the
/// cache gives, and the next scan finds the cache whole again.
#[test]
fn a_corrupt_or_edited_cache_file_falls_back_to_reading_the_app() {
    let paths = fixtures();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let cache = cache_in(home);
    let off = scan(&paths, &["--no-cache"]);
    scan_cached(&paths, home).assert_read(0, APPS);
    let sound: Vec<Vec<u8>> = entries(&cache).iter().map(|path| fs::read(path).unwrap()).collect();

    // Every file damaged at once: the whole scan is cold.
    for (entry, bytes) in entries(&cache).iter().zip(&sound) {
        fs::write(entry, &bytes[..bytes.len() / 2]).unwrap();
    }
    let cold = scan_cached(&paths, home);
    cold.assert_read(0, APPS);
    assert_eq!(cold.report, off.report);
    scan_cached(&paths, home).assert_read(APPS, 0);

    // One file at a time, damaged or edited in one way at a time.
    let edits: [(&str, Edit); 5] = [
        ("emptied", |_| Vec::new()),
        ("one bit flipped", |bytes| {
            let mut bytes = bytes.to_vec();
            let last = bytes.len() - 20;
            bytes[last] ^= 0x04;
            bytes
        }),
        ("a finding edited out of the records", |bytes| {
            String::from_utf8(bytes.to_vec())
                .unwrap()
                .replace("\"contains\"", "\"declared\"")
                .into()
        }),
        ("the app's name edited", |bytes| {
            String::from_utf8(bytes.to_vec()).unwrap().replace("org.example", "org.innocent").into()
        }),
        ("not a cache file at all", |_| b"{\"claims\":[]}\n".to_vec()),
    ];
    for (index, entry) in entries(&cache).iter().enumerate() {
        for (what, edit) in &edits {
            let edited = edit(&sound[index]);
            assert_ne!(edited, sound[index], "{what} changed nothing in entry {index}");
            fs::write(entry, edited).unwrap();
            let scanned = scan_cached(&paths, home);
            scanned.assert_read(APPS - 1, 1);
            assert_eq!(scanned.report, off.report, "{what}");
            assert_eq!(fs::read(entry).unwrap(), sound[index], "{what}: not put right");
        }
    }
    scan_cached(&paths, home).assert_read(APPS, 0);
}

/// Build plan, task 12, and design report, section 6.2 decision 7: changing
/// one app reads only that app again.
#[test]
fn changing_one_app_reads_only_that_app_again() {
    let dir = tempfile::tempdir().unwrap();
    let apps = dir.path().join("Apps");
    copy_tree(Path::new(BUNDLES), &apps);
    fs::copy(PACKAGE, apps.join("Skeleton.apk")).unwrap();
    let home = dir.path().join("home");
    let paths = [apps.as_path()];
    settle(&paths);

    scan_cached(&paths, &home).assert_read(0, APPS);
    let before = scan_cached(&paths, &home);
    before.assert_read(APPS, 0);
    assert!(before.report.contains("sdk/sentry"));

    // One app gets another app id: one of its files is written again.
    let plist = apps.join("Skeleton.app/Contents/Info.plist");
    let declared = fs::read_to_string(&plist).unwrap();
    assert!(declared.contains("org.example.exposure.skeleton"));
    fs::write(&plist, declared.replace("org.example.exposure.skeleton", "org.example.changed"))
        .unwrap();
    let after = scan_cached(&paths, &home);
    after.assert_read(APPS - 1, 1);
    assert_eq!(after.report, scan(&paths, &["--no-cache"]).report);
    assert_ne!(after.report, before.report);

    assert!(after.report.contains("org.example.changed"));
    // A file that was written this close to the scan is not stored yet: it
    // could still be changing. The app is read again, and it alone.
    let again = scan_cached(&paths, &home);
    again.assert_read(APPS - 1, 1);
    assert_eq!(again.report, after.report);
    // Once it has settled, it is stored like the others.
    settle(&paths);
    scan_cached(&paths, &home).assert_read(APPS - 1, 1);
    let settled = scan_cached(&paths, &home);
    settled.assert_read(APPS, 0);
    assert_eq!(settled.report, after.report);
}

/// Without an option the cache is kept in the user's cache folder, and
/// `--no-cache` keeps nothing anywhere.
#[test]
fn the_cache_is_kept_in_the_user_s_cache_folder_unless_it_is_off() {
    let paths = fixtures();
    let home = tempfile::tempdir().unwrap();
    let at_home = || {
        let mut command = at_home(home.path());
        command.args(["--json", "/dev/null"]);
        command
    };
    let listed = |dir: &Path| fs::read_dir(dir).unwrap().count();

    Scanned::of(&at_home().arg("--no-cache").args(paths).output().unwrap());
    assert_eq!(listed(home.path()), 0, "--no-cache wrote into the home folder");

    Scanned::of(&at_home().args(paths).output().unwrap()).assert_read(0, APPS);
    let cache = cache_in(home.path());
    assert_eq!(entries(&cache).len(), APPS);
    Scanned::of(&at_home().args(paths).output().unwrap()).assert_read(APPS, 0);

    if !cfg!(target_os = "macos") {
        // Where XDG_CACHE_HOME names a folder, that is the cache folder.
        let xdg = home.path().join("xdg");
        let scanned = at_home().env("XDG_CACHE_HOME", &xdg).args(paths).output().unwrap();
        Scanned::of(&scanned).assert_read(0, APPS);
        assert_eq!(entries(&xdg.join("exposure")).len(), APPS);
    }
}

/// A cache folder that cannot be used is said, with the reason, and the
/// scan runs without it.
#[test]
fn a_cache_that_cannot_be_used_is_said_and_does_not_fail_the_scan() {
    let paths = fixtures();
    let home = tempfile::tempdir().unwrap();
    let cache = cache_in(home.path());
    // A file where the folder the cache goes into belongs.
    let file = cache.parent().unwrap();
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, "in the way").unwrap();
    let off = scan(&paths, &["--no-cache"]);

    let scanned = scan_cached(&paths, home.path());
    assert_eq!(scanned.report, off.report);
    let said = scanned.cache().unwrap();
    assert!(said.starts_with(&format!("not used: cannot use {}: ", cache.display())), "{said}");
    assert_eq!(fs::read(file).unwrap(), b"in the way");
}

/// The cache is kept in the user's cache folder and nowhere else: no option
/// names another folder.
#[test]
fn no_option_puts_the_cache_anywhere_else() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("elsewhere");
    for options in [&["--cache-dir", text(&elsewhere)][..], &["--no-cache", "--cache-dir", "x"]] {
        let refused = at_home(dir.path()).args(options).arg(BUNDLES).output().unwrap();
        assert_eq!(refused.status.code(), Some(2), "{options:?}");
    }
    assert!(!elsewhere.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}
