//! The results cache through the scan's own interface (build plan, task 12):
//! a scan that is given a folder to keep it in reads an app once, and a
//! folder that cannot be used costs the scan nothing but that.
//!
//! How an entry is checked, and what is and is not stored, is tested next
//! to the cache itself, where a test can set the clock.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "a test may have to wait until the files it scans are old enough to be cached"
)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use xs_collect::cache::SETTLE_SECONDS;
use xs_collect::{CacheError, ScanOptions, ScanOutcome, scan};
use xs_match::Matchers;
use xs_model::matcher::Boundary;
use xs_model::pack::{Category, Layer, LoadedLayer, Rule, Token};
use xs_model::record::V1;
use xs_model::{MatcherKind, Pack, Sha256Digest};

/// The committed fixtures: two bundles and a package.
const FIXTURES: [&str; 2] = [
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos"),
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/android/Skeleton.apk"),
];
const APPS: u64 = 3;

fn pack() -> Pack {
    let rule = Rule {
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
    Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
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
/// enough ago for a result to be stored. A checkout that is older than a
/// few seconds, which is every one a test binary was built from, waits for
/// nothing.
fn settle(paths: &[PathBuf]) {
    let newest = paths.iter().map(|path| newest(path)).max().unwrap_or(0);
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let ready = u64::try_from(newest + SETTLE_SECONDS + 2).unwrap_or(0);
    std::thread::sleep(Duration::from_secs(ready.saturating_sub(now)));
}

fn fixtures() -> Vec<PathBuf> {
    let paths: Vec<PathBuf> = FIXTURES.iter().map(PathBuf::from).collect();
    settle(&paths);
    paths
}

fn scan_with(paths: &[PathBuf], threads: usize, cache: Option<&Path>) -> ScanOutcome {
    let pack = pack();
    scan(paths, &Matchers::build(&pack).unwrap(), ScanOptions { threads, cache }).unwrap()
}

/// Build plan, task 12: cached and uncached scans give the same evidence,
/// and an app that has not changed is read once.
#[test]
fn a_scan_that_is_given_a_cache_folder_reads_an_unchanged_app_once() {
    let paths = fixtures();
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("kept/here");

    let without = scan_with(&paths, 2, None);
    assert_eq!(without.stats.artifacts, APPS);
    assert_eq!((without.stats.reused, &without.cache_failure), (0, &None));
    assert!(!cache.exists(), "a scan without a cache folder writes nothing");

    let first = scan_with(&paths, 2, Some(&cache));
    assert_eq!(first, without);
    assert_eq!(fs::read_dir(&cache).unwrap().count() as u64, APPS);

    for threads in [1, 2, 8] {
        let again = scan_with(&paths, threads, Some(&cache));
        assert_eq!(again.stats.reused, APPS, "{threads} threads");
        assert_eq!(again.evidence, without.evidence);
        // The totals say what the report covers, whenever it was read.
        let mut stats = again.stats;
        stats.reused = 0;
        assert_eq!(stats, without.stats);
        assert_eq!(again.cache_failure, None);
    }
    // In whatever order and however often the apps are named.
    let mut named = paths.clone();
    named.reverse();
    named.push(paths[0].join("Skeleton.app"));
    assert_eq!(scan_with(&named, 3, Some(&cache)).stats.reused, APPS);
}

/// A cache that cannot be used is no reason not to scan: the outcome says
/// why, and every app is read.
#[test]
fn a_cache_folder_that_cannot_be_used_does_not_fail_the_scan() {
    let paths = fixtures();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a file");
    fs::write(&file, "in the way").unwrap();

    let without = scan_with(&paths, 2, None);
    for _ in 0..2 {
        let outcome = scan_with(&paths, 2, Some(&file));
        assert!(
            matches!(&outcome.cache_failure, Some(CacheError::Folder { path, .. }) if *path == file),
            "{:?}",
            outcome.cache_failure
        );
        assert_eq!((&outcome.evidence, outcome.stats), (&without.evidence, without.stats));
    }
    assert_eq!(fs::read(&file).unwrap(), b"in the way");
}
