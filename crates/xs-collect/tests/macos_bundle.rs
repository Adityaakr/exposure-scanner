//! The macOS bundle collector against synthetic bundles built in a temporary
//! folder.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use xs_collect::{ScanOptions, scan};
use xs_match::Matchers;
use xs_model::matcher::Boundary;
use xs_model::pack::{Category, Layer, LoadedLayer, Rule, Token};
use xs_model::record::{
    CoverageReason, CoverageRecord, CoverageStatus, EdgeRecord, Platform, Record, Region, Scope, V1,
};
use xs_model::{EvidenceSet, MatcherKind, Pack, Sha256Digest, SubjectDigest};

/// The header of a 64-bit little-endian Mach-O file that has no load
/// commands, then filler.
fn macho(filler: &[u8]) -> Vec<u8> {
    let mut bytes = xs_formats::macho_build::Binary::new().build();
    bytes.extend_from_slice(filler);
    bytes
}

fn info_plist(id: &str, version: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleShortVersionString</key><string>{version}</string>
<key>CFBundleName</key><string>Example</string>
<key>CFBundleExecutable</key><string>Example</string>
</dict></plist>"#
    )
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A bundle that ships the Sentry framework the way Xcode lays one out.
fn bundle(parent: &Path, name: &str) -> PathBuf {
    let root = parent.join(name);
    write(&root.join("Contents/Info.plist"), info_plist("com.example.app", "1.2.3"));
    write(&root.join("Contents/MacOS/Example"), macho(b"main executable"));
    let framework = root.join("Contents/Frameworks/Sentry.framework");
    write(&framework.join("Versions/A/Sentry"), macho(b"sentry binary"));
    symlink("A", framework.join("Versions/Current")).unwrap();
    symlink("Versions/Current/Sentry", framework.join("Sentry")).unwrap();
    // A resource that merely mentions SDK and ad-network names.
    write(&root.join("Contents/Resources/notes.txt"), "Sparkle.framework doubleclick.net Sentry");
    root
}

fn pack() -> Pack {
    let rule = |id: &str, framework: &str| Rule {
        id: id.into(),
        name: id.into(),
        entity: None,
        category: "component".into(),
        sources: vec![],
        notes: vec![],
        matchers: BTreeMap::from([(
            MatcherKind::AppleFramework,
            vec![Token { lit: framework.into(), at: Boundary::Exact }],
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
        rules: vec![
            rule("sdk/sentry", "Sentry.framework"),
            rule("sdk/sparkle", "Sparkle.framework"),
        ],
    };
    Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
}

fn evidence_with(paths: &[PathBuf], threads: usize) -> EvidenceSet {
    let pack = pack();
    scan(paths, &Matchers::build(&pack).unwrap(), ScanOptions { threads, cache: None })
        .unwrap()
        .evidence
}

fn evidence(path: &Path) -> EvidenceSet {
    evidence_with(&[path.to_path_buf()], 2)
}

fn edges(evidence: &EvidenceSet) -> Vec<&EdgeRecord> {
    evidence
        .iter()
        .filter_map(|(_, record)| if let Record::Edge(edge) = record { Some(edge) } else { None })
        .collect()
}

fn coverage(evidence: &EvidenceSet) -> Vec<&CoverageRecord> {
    evidence
        .iter()
        .filter_map(|(_, record)| if let Record::Coverage(gap) = record { Some(gap) } else { None })
        .collect()
}

fn digest(evidence: &EvidenceSet) -> SubjectDigest {
    let digests: Vec<SubjectDigest> =
        evidence.iter().map(|(_, record)| record.subject().digest).collect();
    assert!(digests.windows(2).all(|pair| pair[0] == pair[1]), "one bundle, one digest");
    digests[0]
}

#[test]
fn a_bundle_with_one_known_framework_yields_one_edge_and_its_facts() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = evidence(&bundle(dir.path(), "Example.app"));

    assert_eq!(evidence.len(), 2, "one artifact record and one edge");
    assert!(coverage(&evidence).is_empty());

    let edges = edges(&evidence);
    assert_eq!(edges.len(), 1);
    let edge = edges[0];
    assert_eq!(edge.rule, "sdk/sentry");
    assert_eq!(edge.subject.platform, Platform::Macos);
    assert_eq!(edge.subject.id, "com.example.app");
    assert_eq!(edge.subject.version.as_deref(), Some("1.2.3"));
    assert!(matches!(edge.subject.digest, SubjectDigest::Bundle(_)));
    assert_eq!(edge.proof.matcher, MatcherKind::AppleFramework);
    assert_eq!(edge.proof.token, "Sentry.framework");
    assert_eq!(edge.proof.example.as_deref(), Some("Sentry.framework"));
    assert_eq!(edge.proof.location.as_str(), "Contents/Frameworks");
    assert_eq!(edge.proof.region, Region::DirEntries);
    assert_eq!(edge.proof.scope, Scope::Dependency);
    assert_eq!(edge.proof.count, 1);

    let facts = evidence
        .iter()
        .find_map(|(_, record)| {
            if let Record::Artifact(artifact) = record { Some(&artifact.facts) } else { None }
        })
        .unwrap();
    assert_eq!(facts.name.as_deref(), Some("Example"));
    // Info.plist and the two Mach-O files. The text resource is not read.
    assert_eq!(facts.files_scanned, 3);
    let expected_bytes = info_plist("com.example.app", "1.2.3").len()
        + macho(b"main executable").len()
        + macho(b"sentry binary").len();
    assert_eq!(facts.bytes_scanned, expected_bytes as u64);
}

#[test]
fn where_the_bundle_sits_and_what_it_is_called_do_not_reach_the_evidence() {
    let one = tempfile::tempdir().unwrap();
    let two = tempfile::tempdir().unwrap();
    let nested = two.path().join("some/other/place");
    fs::create_dir_all(&nested).unwrap();
    let first = evidence(&bundle(one.path(), "Example.app"));
    let second = evidence(&bundle(&nested, "Renamed Copy.app"));
    assert_eq!(first, second);
}

#[test]
fn thread_count_and_path_order_do_not_reach_the_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let mut paths: Vec<PathBuf> = (0..6)
        .map(|n| {
            let root = bundle(dir.path(), &format!("App{n}.app"));
            write(
                &root.join("Contents/Info.plist"),
                info_plist(&format!("com.example.app{n}"), "1.0"),
            );
            // Different sizes, so the largest-first order differs from path order.
            write(
                &root.join("Contents/MacOS/Example"),
                macho(&vec![n; 1000 * (7 - usize::from(n))]),
            );
            root
        })
        .collect();
    let reference = evidence_with(&paths, 1);
    assert_eq!(edges(&reference).len(), 6);
    paths.reverse();
    assert_eq!(evidence_with(&paths, 1), reference);
    paths.rotate_left(2);
    for threads in [2, 4, 8] {
        assert_eq!(evidence_with(&paths, threads), reference, "{threads} threads");
    }
    // Scanning the folder finds the same bundles as naming each one.
    assert_eq!(evidence_with(&[dir.path().to_path_buf()], 3), reference);
}

/// Rule 1 of the evidence format: two builds that share one app id and
/// version are two subjects.
#[test]
fn two_builds_with_one_app_id_are_two_subjects() {
    let dir = tempfile::tempdir().unwrap();
    let play = bundle(dir.path(), "Play.app");
    let other = bundle(dir.path(), "Other.app");
    write(&other.join("Contents/MacOS/Example"), macho(b"a different build"));

    let both = evidence_with(&[play.clone(), other.clone()], 2);
    assert_eq!(edges(&both).len(), 2);
    assert_ne!(digest(&evidence(&play)), digest(&evidence(&other)));
}

#[test]
fn the_digest_covers_exactly_what_evidence_is_drawn_from() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let reference = digest(&evidence(&root));

    // A file the collector does not read: no change.
    write(&root.join("Contents/Resources/notes.txt"), "edited");
    write(&root.join("Contents/Resources/new.png"), b"\x89PNG");
    assert_eq!(digest(&evidence(&root)), reference);

    // The property list: changed.
    write(&root.join("Contents/Info.plist"), info_plist("com.example.app", "1.2.4"));
    let after_plist = digest(&evidence(&root));
    assert_ne!(after_plist, reference);

    // A Mach-O file: changed.
    write(&root.join("Contents/Frameworks/Sentry.framework/Versions/A/Sentry"), macho(b"patched"));
    let after_binary = digest(&evidence(&root));
    assert_ne!(after_binary, after_plist);

    // A new framework folder, even an empty one: changed.
    fs::create_dir(root.join("Contents/Frameworks/Unknown.framework")).unwrap();
    assert_ne!(digest(&evidence(&root)), after_binary);
}

#[test]
fn only_real_folders_under_frameworks_count() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let frameworks = root.join("Contents/Frameworks");
    // A plain file named like a framework is not a framework. (A symbolic
    // link named like one is covered by the test on links below.)
    fs::write(frameworks.join("Sparkle.framework"), b"a file").unwrap();
    // Names that merely contain or resemble a token do not match either.
    // (A name differing only in case cannot coexist with the real one on a
    // case-insensitive volume; the table's own tests cover case.)
    for near_miss in ["Sentry.framework.bak", "MySentry.framework", "Sentry"] {
        fs::create_dir(frameworks.join(near_miss)).unwrap();
    }
    // A framework folder elsewhere in the bundle is not under Frameworks.
    fs::create_dir_all(root.join("Contents/Resources/Sparkle.framework")).unwrap();

    let evidence = evidence(&root);
    let rules: Vec<&str> = edges(&evidence).iter().map(|edge| edge.rule.as_str()).collect();
    assert_eq!(rules, ["sdk/sentry"]);
}

#[test]
fn every_known_framework_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    fs::create_dir(root.join("Contents/Frameworks/Sparkle.framework")).unwrap();
    let evidence = evidence(&root);
    let mut rules: Vec<&str> = edges(&evidence).iter().map(|edge| edge.rule.as_str()).collect();
    rules.sort_unstable();
    assert_eq!(rules, ["sdk/sentry", "sdk/sparkle"]);
}

#[test]
fn a_bundle_without_frameworks_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    fs::remove_dir_all(root.join("Contents/Frameworks")).unwrap();
    let evidence = evidence(&root);
    assert!(edges(&evidence).is_empty());
    assert!(coverage(&evidence).is_empty());
    assert_eq!(evidence.len(), 1, "the artifact record alone");
}

#[test]
fn symbolic_links_are_never_followed_out_of_the_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let reference = evidence(&root);

    // A Mach-O file outside the bundle, linked from inside it twice.
    let outside = dir.path().join("outside");
    write(&outside.join("Secret"), macho(b"not part of the app"));
    symlink(outside.join("Secret"), root.join("Contents/MacOS/Linked")).unwrap();
    symlink(&outside, root.join("Contents/Resources/LinkedFolder")).unwrap();
    // A framework that is a link to a folder outside the bundle.
    fs::create_dir(outside.join("Sparkle.framework")).unwrap();
    symlink(outside.join("Sparkle.framework"), root.join("Contents/Frameworks/Sparkle.framework"))
        .unwrap();

    assert_eq!(evidence(&root), reference);
}

/// The collector's own promise (crate docs: "symbolic links inside an
/// artifact are never followed") must also hold for the folders its two
/// fixed-path reads pass through, not only for the entries `walk` lists.
#[test]
fn a_linked_contents_folder_does_not_stand_another_bundle_in() {
    let dir = tempfile::tempdir().unwrap();
    let other = bundle(dir.path(), "Other.app");
    let root = dir.path().join("Evil.app");
    fs::create_dir(&root).unwrap();
    symlink(other.join("Contents"), root.join("Contents")).unwrap();
    let evidence = evidence(&root);

    // Nothing of the other bundle is reported as this one's.
    assert!(edges(&evidence).is_empty());
    let gap = gap(&evidence, CoverageReason::ParseError);
    assert_eq!(gap.status, CoverageStatus::Unrecognized);
    assert_eq!(gap.location.as_ref().unwrap().as_str(), "Contents");
    assert_eq!(gap.subject.id, "Evil.app");
    assert_eq!(gap.subject.version, None);
    assert_eq!(evidence.len(), 2, "the artifact record and the gap");
    // The digest covers no file of the other bundle: it is the digest of a
    // bundle with nothing in it.
    let empty = dir.path().join("Hollow/Evil.app");
    fs::create_dir_all(&empty).unwrap();
    assert_eq!(digest(&evidence), digest(&self::evidence(&empty)));
}

#[test]
fn a_linked_frameworks_folder_is_reported_not_listed() {
    let dir = tempfile::tempdir().unwrap();
    let other = bundle(dir.path(), "Other.app");
    let root = bundle(dir.path(), "Example.app");
    fs::remove_dir_all(root.join("Contents/Frameworks")).unwrap();
    let without = evidence(&root);
    symlink(other.join("Contents/Frameworks"), root.join("Contents/Frameworks")).unwrap();
    let evidence = evidence(&root);

    assert!(edges(&evidence).is_empty(), "the other bundle's Sentry is not this bundle's");
    let gap = gap(&evidence, CoverageReason::ParseError);
    assert_eq!(gap.status, CoverageStatus::Unrecognized);
    assert_eq!(gap.location.as_ref().unwrap().as_str(), "Contents/Frameworks");
    assert_eq!(gap.subject.id, "com.example.app");
    assert_eq!(digest(&evidence), digest(&without));
}

/// "Nothing found" must never be confused with "not looked at", and the same
/// bundle must give the same evidence on a volume that ignores letter case
/// (the macOS default) as on one that does not (Linux CI). So a layout name
/// in another case is reported, and nothing is drawn from it on either.
#[test]
fn a_layout_name_in_another_case_is_reported_and_not_used() {
    let dir = tempfile::tempdir().unwrap();
    let miscased = |name: &str, from: &str, to: &str| {
        let root = bundle(dir.path(), name);
        fs::rename(root.join(from), root.join(to)).unwrap();
        evidence(&root)
    };
    let reported = |evidence: &EvidenceSet, at: &str| {
        let gap = gap(evidence, CoverageReason::UnexpectedCase);
        assert_eq!(gap.status, CoverageStatus::Skipped);
        assert_eq!(gap.location.as_ref().unwrap().as_str(), at);
        gap.subject.id.clone()
    };
    let missing_plist = |evidence: &EvidenceSet| {
        let gap = gap(evidence, CoverageReason::ParseError);
        assert_eq!(gap.location.as_ref().unwrap().as_str(), "Contents/Info.plist");
    };

    // The frameworks folder: the app is still identified, but the Sentry
    // framework inside is not reported as found, and the gap says why.
    let frameworks = miscased("Frameworks.app", "Contents/Frameworks", "Contents/frameworks");
    assert_eq!(reported(&frameworks, "Contents/frameworks"), "com.example.app");
    assert!(edges(&frameworks).is_empty());
    assert_eq!(coverage(&frameworks).len(), 1);

    // The property list: not read, so the folder's name stands in.
    let plist = miscased("Plist.app", "Contents/Info.plist", "Contents/info.plist");
    assert_eq!(reported(&plist, "Contents/info.plist"), "Plist.app");
    missing_plist(&plist);
    assert_eq!(edges(&plist).len(), 1);

    // The contents folder: neither the property list nor the frameworks.
    let contents = miscased("Contents.app", "Contents", "contents");
    assert_eq!(reported(&contents, "contents"), "Contents.app");
    missing_plist(&contents);
    assert!(edges(&contents).is_empty());
    assert_eq!(coverage(&contents).len(), 2);

    // A bundle spelled the usual way has no such record.
    let usual = evidence(&bundle(dir.path(), "Usual.app"));
    assert!(coverage(&usual).is_empty());
    assert_eq!(edges(&usual).len(), 1);
}

fn gap(evidence: &EvidenceSet, reason: CoverageReason) -> &CoverageRecord {
    let gaps = coverage(evidence);
    let matching: Vec<&&CoverageRecord> = gaps.iter().filter(|gap| gap.reason == reason).collect();
    assert_eq!(matching.len(), 1, "expected one {reason:?} record, got {gaps:#?}");
    matching[0]
}

#[test]
fn a_missing_property_list_is_reported_and_the_folder_name_stands_in() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    fs::remove_file(root.join("Contents/Info.plist")).unwrap();
    let evidence = evidence(&root);

    let gap = gap(&evidence, CoverageReason::ParseError);
    assert_eq!(gap.status, CoverageStatus::Unrecognized);
    assert_eq!(gap.location.as_ref().unwrap().as_str(), "Contents/Info.plist");
    assert_eq!(gap.count, 1);
    assert_eq!(gap.subject.id, "Example.app");
    assert_eq!(gap.subject.version, None);
    // The framework is still found: a gap is not a reason to stop looking.
    assert_eq!(edges(&evidence).len(), 1);
}

#[test]
fn a_damaged_or_idless_property_list_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let damaged = bundle(dir.path(), "Damaged.app");
    write(&damaged.join("Contents/Info.plist"), "<plist><dict><key>CFBundleIdentifier</key>");
    let gap_damaged = gap(&evidence(&damaged), CoverageReason::ParseError).clone();
    assert_eq!(gap_damaged.subject.id, "Damaged.app");
    assert_eq!(gap_damaged.count, 1);

    let idless = bundle(dir.path(), "Idless.app");
    write(&idless.join("Contents/Info.plist"), r#"<plist version="1.0"><dict/></plist>"#);
    let gap_idless = gap(&evidence(&idless), CoverageReason::ParseError).clone();
    assert_eq!(gap_idless.subject.id, "Idless.app");
    assert_eq!(gap_idless.status, CoverageStatus::Unrecognized);
}

#[test]
fn an_oversized_property_list_is_skipped_as_over_budget() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let file = fs::File::create(root.join("Contents/Info.plist")).unwrap();
    file.set_len(16 * 1024 * 1024 + 1).unwrap(); // sparse; never read
    let evidence = evidence(&root);
    let gap = gap(&evidence, CoverageReason::OverBudget);
    assert_eq!(gap.status, CoverageStatus::Skipped);
    assert_eq!(gap.location.as_ref().unwrap().as_str(), "Contents/Info.plist");
}

#[test]
fn hostile_text_is_cleaned_before_it_enters_a_record() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let long_id = "a".repeat(400);
    write(
        &root.join("Contents/Info.plist"),
        format!(
            "<plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>{long_id}</string>\
             <key>CFBundleShortVersionString</key><string>1.0&#x1b;[31m&#x202e;</string>\
             <key>CFBundleName</key><string>&lt;script&gt;alert(1)&lt;/script&gt;</string>\
             </dict></plist>"
        ),
    );
    let evidence = evidence(&root);
    let subject = evidence.iter().next().unwrap().1.subject().clone();
    assert_eq!(subject.id.len(), 255);
    assert!(subject.id.ends_with('…'));
    assert_eq!(subject.version.as_deref(), Some("1.0\u{fffd}[31m\u{fffd}"));
    // Markup is kept verbatim: escaping is the renderer's job, and the JSON
    // writer escapes what JSON needs.
    let name = evidence
        .iter()
        .find_map(
            |(_, record)| {
                if let Record::Artifact(a) = record { a.facts.name.clone() } else { None }
            },
        )
        .unwrap();
    assert_eq!(name, "<script>alert(1)</script>");
}

#[test]
fn an_unreadable_file_is_reported_and_the_rest_is_scanned() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let locked = root.join("Contents/MacOS/Locked");
    write(&locked, macho(b"locked"));
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&locked).is_ok() {
        // Running as root: permissions do not bind, nothing to test.
        return;
    }
    let evidence = evidence(&root);
    let gap = gap(&evidence, CoverageReason::Unreadable);
    assert_eq!(gap.status, CoverageStatus::Skipped);
    assert_eq!(gap.location.as_ref().unwrap().as_str(), "Contents/MacOS/Locked");
    assert_eq!(edges(&evidence).len(), 1);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn nesting_past_the_depth_budget_is_reported_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let mut deep = root.join("Contents/Resources");
    for level in 0..70 {
        deep.push(format!("d{level}"));
    }
    write(&deep.join("Buried"), macho(b"too deep"));
    let evidence = evidence(&root);
    let gap = gap(&evidence, CoverageReason::OverBudget);
    assert_eq!(gap.status, CoverageStatus::Skipped);
    let location = gap.location.as_ref().unwrap().as_str();
    assert_eq!(location.split('/').count(), 64, "{location}");
}

fn facts(evidence: &EvidenceSet) -> (u64, u64) {
    evidence
        .iter()
        .find_map(|(_, record)| match record {
            Record::Artifact(artifact) => {
                Some((artifact.facts.files_scanned, artifact.facts.bytes_scanned))
            }
            _ => None,
        })
        .unwrap()
}

fn resize(path: &Path, len: u64) -> std::io::Result<()> {
    fs::OpenOptions::new().write(true).open(path)?.set_len(len)
}

/// Every limit is a budget: a Mach-O file over `MAX_FILE_BYTES` (2 GiB) is
/// not read. The file here is sparse, so the test would take minutes and
/// count two gibibytes if the collector read it.
#[test]
fn a_file_over_the_byte_budget_is_reported_with_its_size_and_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let reference = evidence(&root);
    let huge = root.join("Contents/MacOS/Huge");
    write(&huge, macho(b""));
    let scan_with = |len: u64| {
        resize(&huge, len).unwrap();
        evidence(&root)
    };
    let size = (2u64 << 30) + 1;
    assert_eq!(size, xs_collect::macos::MAX_FILE_BYTES + 1);
    let evidence = scan_with(size);

    let gap = gap(&evidence, CoverageReason::OverBudget);
    assert_eq!(gap.status, CoverageStatus::Skipped);
    assert_eq!(gap.location.as_ref().unwrap().as_str(), "Contents/MacOS/Huge");
    assert_eq!(gap.bytes, Some(size));
    assert_eq!(gap.count, 1);
    // Nothing of it was read, and the rest of the bundle was scanned.
    assert_eq!(facts(&evidence), facts(&reference));
    assert_eq!(edges(&evidence).len(), 1);
    // The bundle is a different subject with the file than without it, and
    // again when only the file's size differs.
    assert_ne!(digest(&evidence), digest(&reference));
    assert_ne!(digest(&scan_with(size + 1)), digest(&evidence));
}

/// The bundle digest covers what evidence is drawn from (`bd1`, design
/// report section 4.3), and a coverage record says something relevant was
/// skipped. A large file the collector would never read is neither.
#[test]
fn a_large_file_the_collector_does_not_read_leaves_no_trace() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let reference = evidence(&root);
    let pack = root.join("Contents/Resources/data.pak");
    write(&pack, b"PACK: assets, not a binary");

    resize(&pack, 3 << 30).unwrap();
    assert_eq!(evidence(&root), reference);
    resize(&pack, (3 << 30) + 1).unwrap();
    assert_eq!(evidence(&root), reference);
}

/// "A problem inside a bundle never fails the scan": a file whose size does
/// not fit a canonical JSON integer (2^53 - 1, RFC 7493) is still one
/// coverage record, and the other app is still reported.
#[test]
#[allow(clippy::print_stderr, reason = "a skipped case must be visible in the test output")]
fn a_file_too_large_for_a_json_integer_does_not_stop_the_scan() {
    let dir = tempfile::tempdir().unwrap();
    let hostile = bundle(dir.path(), "Hostile.app");
    let other = bundle(dir.path(), "Other.app");
    write(&other.join("Contents/Info.plist"), info_plist("com.example.other", "1.0"));
    let huge = hostile.join("Contents/MacOS/Huge");
    write(&huge, macho(b""));
    if let Err(error) = resize(&huge, 1 << 53) {
        eprintln!("SKIPPED: this file system refuses a file of 2^53 bytes ({error})");
        return;
    }
    let scan = || evidence_with(&[dir.path().to_path_buf()], 2);
    let evidence = scan();

    let gap = gap(&evidence, CoverageReason::OverBudget);
    assert_eq!(gap.subject.id, "com.example.app");
    assert_eq!(gap.location.as_ref().unwrap().as_str(), "Contents/MacOS/Huge");
    assert_eq!(gap.bytes, Some((1 << 53) - 1));
    let mut subjects: Vec<&str> =
        edges(&evidence).iter().map(|edge| edge.subject.id.as_str()).collect();
    subjects.sort_unstable();
    assert_eq!(subjects, ["com.example.app", "com.example.other"]);

    // The exact size still reaches the digest.
    let before = gap.subject.digest;
    resize(&huge, (1 << 53) + 1).unwrap();
    let evidence = scan();
    assert_ne!(self::gap(&evidence, CoverageReason::OverBudget).subject.digest, before);
}

#[test]
fn an_empty_declared_value_does_not_hide_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    write(
        &root.join("Contents/Info.plist"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string></string>
<key>CFBundleVersion</key><string>42</string>
<key>CFBundleDisplayName</key><string></string>
<key>CFBundleName</key><string>Foo</string>
</dict></plist>"#,
    );
    let evidence = evidence(&root);
    let artifact = evidence
        .iter()
        .find_map(|(_, record)| match record {
            Record::Artifact(artifact) => Some(artifact),
            _ => None,
        })
        .unwrap();
    assert_eq!(artifact.subject.version.as_deref(), Some("42"));
    assert_eq!(artifact.facts.name.as_deref(), Some("Foo"));
    assert!(coverage(&evidence).is_empty());
}

#[test]
fn a_file_larger_than_one_window_hashes_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), "Example.app");
    let reference = digest(&evidence(&root));

    // 2.5 windows of non-repeating content.
    let big: Vec<u8> =
        (0..(5 << 19)).map(|i: u32| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    write(&root.join("Contents/MacOS/Example"), macho(&big));
    let with_big = digest(&evidence(&root));
    assert_ne!(with_big, reference);

    // One changed byte in the last window changes the digest.
    let mut edited = big;
    *edited.last_mut().unwrap() ^= 1;
    write(&root.join("Contents/MacOS/Example"), macho(&edited));
    assert_ne!(digest(&evidence(&root)), with_big);
}

#[test]
fn a_folder_without_bundles_is_an_empty_scan() {
    let dir = tempfile::tempdir().unwrap();
    assert!(evidence(dir.path()).is_empty());
}
