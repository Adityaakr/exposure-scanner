//! The scan as a whole (build plan, task 9): artifacts of both kinds found
//! in one folder, read on one schedule, and an artifact that cannot be read.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use xs_collect::{ScanOptions, ScanOutcome, ScanScope, scan};
use xs_formats::testkit::{self, DexBuilder, ZipBuilder};
use xs_match::Matchers;
use xs_model::matcher::Boundary;
use xs_model::pack::{Category, Layer, LoadedLayer, Rule, Token};
use xs_model::record::{CoverageReason, CoverageRecord, CoverageStatus, Platform, Record, V1};
use xs_model::{EvidenceSet, MatcherKind, Pack, Sha256Digest, SubjectDigest};

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A bundle with the given app id that ships the Sentry framework, and
/// whose main executable is `filler` bytes long past its header.
fn bundle(path: &Path, id: &str, filler: usize) -> PathBuf {
    let plist = format!(
        r#"<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleExecutable</key><string>Example</string>
</dict></plist>"#
    );
    write(&path.join("Contents/Info.plist"), plist);
    let header = xs_formats::macho_build::Binary::new().build();
    let mut binary = header.clone();
    binary.resize(header.len() + filler, b'.');
    write(&path.join("Contents/MacOS/Example"), &binary);
    write(&path.join("Contents/Frameworks/Sentry.framework/Sentry"), &header);
    path.to_path_buf()
}

/// A package with the given app id whose one DEX file defines a Sentry
/// class, stored with `padding` bytes after it.
fn package(path: &Path, id: &str, padding: usize) -> PathBuf {
    let apk = ZipBuilder::new()
        .deflated("AndroidManifest.xml", &testkit::manifest(id, "1.0", &[("activity", ".Main")]))
        .deflated("classes.dex", &DexBuilder::new().class("io.sentry.Sentry").finish())
        .stored("assets/padding.bin", &vec![b'.'; padding])
        .finish();
    write(path, apk);
    path.to_path_buf()
}

fn pack() -> Pack {
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
    Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
}

fn scan_with(paths: &[PathBuf], threads: usize) -> ScanOutcome {
    let pack = pack();
    scan(paths, &Matchers::build(&pack).unwrap(), ScanOptions { threads }).unwrap()
}

fn coverage(evidence: &EvidenceSet) -> Vec<&CoverageRecord> {
    evidence
        .iter()
        .filter_map(|(_, record)| if let Record::Coverage(gap) = record { Some(gap) } else { None })
        .collect()
}

/// Edges as `platform app-id matcher`, sorted.
fn edges(evidence: &EvidenceSet) -> Vec<String> {
    let mut edges: Vec<String> = evidence
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Edge(edge) => Some(format!(
                "{} {} {}",
                edge.subject.platform.as_str(),
                edge.subject.id,
                edge.proof.matcher
            )),
            _ => None,
        })
        .collect();
    edges.sort();
    edges
}

/// A folder of apps of both kinds and of very different sizes, some two
/// levels down.
fn apps(dir: &Path) -> PathBuf {
    let apps = dir.join("Apps");
    bundle(&apps.join("Large.app"), "org.example.large", 3 << 20);
    bundle(&apps.join("Small.app"), "org.example.small", 10);
    bundle(&apps.join("Utilities/Tool.app"), "org.example.tool", 70_000);
    package(&apps.join("large.apk"), "org.example.droid.large", 2 << 20);
    package(&apps.join("small.apk"), "org.example.droid.small", 0);
    package(&apps.join("Utilities/tool.apk"), "org.example.droid.tool", 300_000);
    apps
}

const ALL_EDGES: [&str; 6] = [
    "android org.example.droid.large android_class_prefix",
    "android org.example.droid.small android_class_prefix",
    "android org.example.droid.tool android_class_prefix",
    "macos org.example.large apple_framework",
    "macos org.example.small apple_framework",
    "macos org.example.tool apple_framework",
];

#[test]
fn a_folder_is_scanned_for_bundles_and_packages_alike() {
    let dir = tempfile::tempdir().unwrap();
    let outcome = scan_with(&[apps(dir.path())], 4);
    assert_eq!(edges(&outcome.evidence), ALL_EDGES);
    assert!(coverage(&outcome.evidence).is_empty());
    assert_eq!(outcome.stats.artifacts, 6);
    // A scan of given paths says that it covered those and nothing else,
    // and names none of them.
    assert_eq!(outcome.scope, ScanScope::Given);
    let scope = outcome.scope.to_string();
    assert!(scope.contains("the paths given and nothing else"), "{scope}");
    assert!(!scope.contains(dir.path().to_str().unwrap()) && !scope.contains("Apps"), "{scope}");
    // Three files per bundle and one per package.
    assert_eq!(outcome.stats.files, 3 * 3 + 3);
}

/// Design report, section 7 property 3, for the schedule: which thread reads
/// which file, in which order the files are queued and in which order the
/// artifacts were named cannot reach the evidence.
#[test]
fn one_evidence_set_whatever_the_thread_count_and_the_order_of_the_paths() {
    let dir = tempfile::tempdir().unwrap();
    let apps = apps(dir.path());
    let whole = scan_with(std::slice::from_ref(&apps), 1);
    for threads in [2, 3, 8, 32] {
        assert_eq!(scan_with(std::slice::from_ref(&apps), threads), whole, "{threads} threads");
    }

    // The same artifacts, each named by itself, forwards and backwards.
    let mut named: Vec<PathBuf> = ["Large.app", "large.apk", "Small.app", "small.apk"]
        .iter()
        .map(|name| apps.join(name))
        .collect();
    named.push(apps.join("Utilities"));
    assert_eq!(scan_with(&named, 4), whole);
    named.reverse();
    assert_eq!(scan_with(&named, 4), whole);
    // Named twice, and found in the folder as well: still scanned once.
    named.push(apps.clone());
    named.push(apps.join("large.apk"));
    assert_eq!(scan_with(&named, 4), whole);
}

/// One artifact that cannot be read does not cost the scan the others: it
/// becomes a record that says so, and every other record is what it would
/// have been without it.
#[test]
fn an_artifact_that_cannot_be_read_is_reported_and_the_rest_is_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let apps = apps(dir.path());
    let without = scan_with(std::slice::from_ref(&apps), 4);

    let locked = [
        package(&apps.join("locked.apk"), "org.example.locked", 100),
        package(&apps.join("Utilities/locked.apk"), "org.example.locked.too", 5 << 20),
        package(&apps.join("other.apk"), "org.example.other", 0),
    ];
    for path in &locked {
        fs::set_permissions(path, fs::Permissions::from_mode(0o000)).unwrap();
    }
    let readable = fs::read(&locked[0]).is_ok();
    let with: Vec<ScanOutcome> =
        [1, 4].iter().map(|&threads| scan_with(std::slice::from_ref(&apps), threads)).collect();
    // Named by itself, a package that cannot be read is treated the same.
    let alone = scan_with(&locked[..1], 2);
    for path in &locked {
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    // Running as root, permissions do not bind and there is nothing to test.
    if readable {
        return;
    }

    assert_eq!(with[0], with[1]);
    let with = &with[0];
    assert_eq!(with.stats, without.stats, "what was not read is not counted as scanned");
    assert_eq!(edges(&with.evidence), ALL_EDGES);

    // Everything the scan said without the locked packages, it still says.
    for (id, record) in without.evidence.iter() {
        assert_eq!(with.evidence.get(id), Some(record));
    }
    let unread: Vec<&CoverageRecord> = coverage(&with.evidence);
    assert_eq!(with.evidence.len(), without.evidence.len() + unread.len());
    let told: Vec<(&str, u32)> =
        unread.iter().map(|gap| (gap.subject.id.as_str(), gap.count)).collect();
    // Two files of one name are one record that counts two.
    assert_eq!(told, [("locked.apk", 2), ("other.apk", 1)]);
    for gap in unread {
        assert_eq!(gap.subject.platform, Platform::Android);
        assert_eq!(gap.subject.digest, SubjectDigest::Unread);
        assert_eq!(gap.subject.version, None);
        assert_eq!((gap.status, gap.reason), (CoverageStatus::Skipped, CoverageReason::Unreadable));
        assert_eq!((gap.location.as_ref(), gap.bytes), (None, None));
    }

    assert_eq!(alone.stats.artifacts, 0);
    assert_eq!(alone.evidence.len(), 1);
    assert_eq!(coverage(&alone.evidence)[0].subject.id, "locked.apk");
}

/// A bundle whose folder cannot be listed is reported the same way, and
/// costs the scan nothing else either.
#[test]
fn a_bundle_that_cannot_be_listed_is_reported_and_the_rest_is_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let apps = apps(dir.path());
    let without = scan_with(std::slice::from_ref(&apps), 4);

    let locked = bundle(&apps.join("Locked.app"), "org.example.locked", 100);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let listable = fs::read_dir(&locked).is_ok();
    let with = scan_with(std::slice::from_ref(&apps), 4);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    if listable {
        return;
    }

    assert_eq!(edges(&with.evidence), ALL_EDGES);
    for (id, record) in without.evidence.iter() {
        assert_eq!(with.evidence.get(id), Some(record));
    }
    let gaps = coverage(&with.evidence);
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].subject.id, "Locked.app");
    assert_eq!(
        (gaps[0].status, gaps[0].reason),
        (CoverageStatus::Skipped, CoverageReason::Unreadable)
    );
}
