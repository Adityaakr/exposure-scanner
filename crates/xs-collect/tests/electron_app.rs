//! The Electron part of the bundle collector against synthetic bundles built
//! in a temporary folder: asar archives written by a helper here, and loose
//! code folders.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use xs_collect::{ScanOptions, scan};
use xs_match::Matchers;
use xs_model::matcher::Boundary;
use xs_model::pack::{Category, Entity, Layer, LoadedLayer, Rule, Token};
use xs_model::record::{
    Collector, CoverageReason, CoverageRecord, CoverageStatus, EdgeRecord, EdgeType, Facts, Grade,
    Record, Region, Scope, V1,
};
use xs_model::{EvidenceSet, MatcherKind, Pack, Sha256Digest, SubjectDigest};

const SENTRY: &str = "name=`sentry.javascript.${n}`;";
const POSTHOG: &str = "init({api_host:\"https://app.posthog.com\"});";

/// The bytes of an asar archive that holds `files`, by path, laid out the
/// way `@electron/asar` writes one: a 16-byte prefix, the JSON header padded
/// to four bytes, and the files back to back in the order given.
fn archive(files: &[(&str, &str)]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut tree = serde_json::Map::new();
    for (path, content) in files {
        let mut folder = &mut tree;
        let (folders, name) = path.rsplit_once('/').unwrap_or(("", path));
        for part in folders.split('/').filter(|part| !part.is_empty()) {
            folder = folder
                .entry(part)
                .or_insert_with(|| serde_json::json!({"files": {}}))
                .get_mut("files")
                .and_then(serde_json::Value::as_object_mut)
                .unwrap();
        }
        let offset = data.len().to_string();
        data.extend_from_slice(content.as_bytes());
        folder
            .insert(name.to_string(), serde_json::json!({"offset": offset, "size": content.len()}));
    }
    let json = serde_json::json!({"files": tree}).to_string();
    let len = u32::try_from(json.len()).unwrap();
    let padded = len.div_ceil(4) * 4;
    let mut bytes = Vec::new();
    for word in [4, padded + 8, padded + 4, len] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(json.as_bytes());
    bytes.resize(16 + padded as usize, 0);
    bytes.extend_from_slice(&data);
    bytes
}

fn info_plist(id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleShortVersionString</key><string>1.0.0</string>
<key>CFBundleName</key><string>Example</string>
</dict></plist>"#
    )
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// The first bytes of a 64-bit little-endian Mach-O file, then filler.
fn macho(filler: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];
    bytes.extend_from_slice(filler);
    bytes
}

/// The files of the archive in [`electron_bundle`]. The app's own bundle
/// holds both SDKs; Sentry is also installed as a package.
fn app_files() -> Vec<(&'static str, String)> {
    vec![
        ("package.json", String::from("{\"name\":\"example\"}")),
        ("js/main.js", format!("boot();{SENTRY}{POSTHOG}{SENTRY}")),
        ("js/publishing/main.js", String::from(SENTRY)),
        ("index.html", String::from("<script src=js/main.js></script>")),
        ("node_modules/@sentry/electron/package.json", String::from("{}")),
        ("node_modules/@sentry/electron/main/index.js", format!("exports.x=1;{SENTRY}")),
        ("node_modules/@sentry/browser/package.json", String::from("{}")),
        ("node_modules/lodash/package.json", String::from("{}")),
        ("node_modules/lodash/lodash.js", String::from("module.exports={}")),
    ]
}

fn archive_of(files: &[(&'static str, String)]) -> Vec<u8> {
    let files: Vec<(&str, &str)> =
        files.iter().map(|(path, text)| (*path, text.as_str())).collect();
    archive(&files)
}

/// An Electron app the way a packager lays one out on macOS.
fn electron_bundle(parent: &Path, name: &str) -> PathBuf {
    let root = parent.join(name);
    write(&root.join("Contents/Info.plist"), info_plist("com.example.electron"));
    write(&root.join("Contents/MacOS/Example"), macho(b"main executable"));
    write(
        &root
            .join("Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"),
        macho(b"browser engine: doubleclick.net app.posthog.com sentry.javascript."),
    );
    write(&root.join("Contents/Resources/app.asar"), archive_of(&app_files()));
    // What every Electron app ships beside its archive.
    write(&root.join("Contents/Resources/icon.icns"), b"icns");
    write(
        &root.join("Contents/Resources/LICENSES.chromium.html"),
        format!("<html>{SENTRY}{POSTHOG}</html>"),
    );
    root
}

fn pack() -> Pack {
    let entity = |id: &str| Entity {
        id: id.into(),
        name: id.into(),
        parent: None,
        website: format!("https://{id}.example/"),
        source: format!("https://{id}.example/terms"),
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
            vec![token("app.posthog.com", Boundary::Host)],
        ),
    ];
    // Eight more companies, each known by one host, for the breadth guard.
    for n in 0..8 {
        let id = format!("vendor-{n}");
        entities.push(entity(&id));
        let host = format!("collect.vendor-{n}.example");
        let mut vendor = rule(&format!("sdk/{id}"), &id, &[], vec![token(&host, Boundary::Host)]);
        vendor.matchers.remove(&MatcherKind::NpmPackage);
        rules.push(vendor);
    }
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
        entities,
        rules,
    };
    Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
}

fn evidence_with(paths: &[PathBuf], threads: usize) -> EvidenceSet {
    let pack = pack();
    scan(paths, &Matchers::build(&pack).unwrap(), ScanOptions { threads }).unwrap().evidence
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

fn facts(evidence: &EvidenceSet) -> &Facts {
    evidence
        .iter()
        .find_map(|(_, record)| {
            if let Record::Artifact(artifact) = record { Some(&artifact.facts) } else { None }
        })
        .unwrap()
}

fn digest(evidence: &EvidenceSet) -> SubjectDigest {
    let digests: Vec<SubjectDigest> =
        evidence.iter().map(|(_, record)| record.subject().digest).collect();
    assert!(digests.windows(2).all(|pair| pair[0] == pair[1]), "one bundle, one digest");
    digests[0]
}

/// One edge, reduced to what a reader re-checks by hand: the token, where it
/// was found, in which table, as what kind of code, how often, and the
/// example.
type Row = (String, String, Region, Scope, u32, Option<String>);

fn rows(evidence: &EvidenceSet) -> Vec<Row> {
    let mut rows: Vec<Row> = edges(evidence)
        .iter()
        .map(|edge| {
            // Every edge of this collector has the same frame.
            assert_eq!(edge.collector, Collector::ElectronApp);
            assert_eq!(edge.edge, EdgeType::Channel);
            assert_eq!(edge.grade, Grade::Contains);
            assert_eq!(edge.object.id, edge.rule);
            (
                edge.proof.token.clone(),
                edge.proof.location.as_str().to_string(),
                edge.proof.region,
                edge.proof.scope,
                edge.proof.count,
                edge.proof.example.clone(),
            )
        })
        .collect();
    rows.sort();
    rows
}

fn row(token: &str, at: &str, region: Region, scope: Scope, count: u32, example: &str) -> Row {
    (token.to_string(), at.to_string(), region, scope, count, Some(example.to_string()))
}

const ASAR: &str = "Contents/Resources/app.asar";

/// The expected rows follow from `app_files` by the rules the collector
/// documents: a package is named by `node_modules/<name>/package.json`; a
/// script outside `node_modules` is app code and one inside is a dependency;
/// the count is a number of files and the example the smallest path.
#[test]
fn an_archive_yields_package_and_literal_witnesses_with_their_place() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    let evidence = evidence(&root);

    let header = Region::AsarHeader;
    let dependency = Scope::Dependency;
    assert_eq!(
        rows(&evidence),
        [
            row(
                "@sentry/browser",
                ASAR,
                header,
                dependency,
                1,
                "node_modules/@sentry/browser/package.json"
            ),
            row(
                "@sentry/electron",
                ASAR,
                header,
                dependency,
                1,
                "node_modules/@sentry/electron/package.json"
            ),
            row("app.posthog.com", ASAR, Region::Files, Scope::AppCode, 1, "js/main.js"),
            row("sentry.javascript.", ASAR, Region::Files, Scope::AppCode, 2, "js/main.js"),
            row(
                "sentry.javascript.",
                ASAR,
                Region::Files,
                dependency,
                1,
                "node_modules/@sentry/electron/main/index.js"
            ),
        ]
    );
    assert!(coverage(&evidence).is_empty(), "{:#?}", coverage(&evidence));

    // The property list, the two Mach-O files and the archive were read. The
    // icon and the licence page beside the archive were not.
    let facts = facts(&evidence);
    assert_eq!(facts.files_scanned, 4);
    let archive_len = fs::metadata(root.join(ASAR)).unwrap().len();
    let others = info_plist("com.example.electron").len()
        + macho(b"main executable").len()
        + macho(b"browser engine: doubleclick.net app.posthog.com sentry.javascript.").len();
    assert_eq!(facts.bytes_scanned, archive_len + others as u64);

    let subject = evidence.iter().next().unwrap().1.subject().clone();
    assert_eq!(subject.id, "com.example.electron");
    assert_eq!(subject.version.as_deref(), Some("1.0.0"));
}

/// Design report, section 5.2: what is not the app's script is not searched,
/// however many SDK names it holds.
#[test]
fn only_scripts_are_searched_and_dependencies_for_scripts_only() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    let both = format!("{SENTRY}{POSTHOG}");
    let files: Vec<(&'static str, String)> = vec![
        ("js/main.js", String::from("boot()")),
        ("js/main.js.map", both.clone()),
        ("config.json", both.clone()),
        ("docs/readme.md", both.clone()),
        ("styles/app.css", both.clone()),
        ("LICENSE", both.clone()),
        // The demo page of a library: the spike's false finding on
        // Bitwarden desktop.
        ("node_modules/lunr/index.html", both.clone()),
        ("node_modules/lunr/notes.txt", both.clone()),
        ("node_modules/lunr/lunr.js.map", both.clone()),
        ("node_modules/lunr/lunr.d.ts", both),
        ("node_modules/lunr/package.json", String::from("{}")),
    ];
    write(&root.join(ASAR), archive_of(&files));
    let evidence = evidence(&root);
    assert!(edges(&evidence).is_empty(), "{:#?}", edges(&evidence));
    assert!(coverage(&evidence).is_empty());

    // The same text in the app's own page is a finding.
    let mut with_page = files;
    with_page.push(("about.html", format!("<script>{POSTHOG}</script>")));
    write(&root.join(ASAR), archive_of(&with_page));
    assert_eq!(
        rows(&self::evidence(&root)),
        [row("app.posthog.com", ASAR, Region::Files, Scope::AppCode, 1, "about.html")]
    );
}

/// Design report, section 5.2 control 4.
#[test]
fn a_filter_list_in_the_archive_is_a_mention_not_a_finding() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    let list: String = (0..8).map(|n| format!("||collect.vendor-{n}.example^\n")).collect();
    let files: Vec<(&'static str, String)> =
        vec![("js/blocklist.js", format!("{list}{POSTHOG}")), ("js/main.js", String::from(SENTRY))];
    write(&root.join(ASAR), archive_of(&files));
    assert_eq!(
        rows(&evidence(&root)),
        [row("sentry.javascript.", ASAR, Region::Files, Scope::AppCode, 1, "js/main.js")]
    );
}

/// An app that Electron runs from a folder gives the same witnesses as one
/// packed into an archive.
#[test]
fn a_loose_code_folder_is_read_like_an_archive() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    fs::remove_file(root.join(ASAR)).unwrap();
    for (path, content) in app_files() {
        write(&root.join("Contents/Resources/app").join(path), content);
    }
    // Not searched in a folder either.
    write(&root.join("Contents/Resources/app/js/main.js.map"), format!("{SENTRY}{POSTHOG}"));
    write(&root.join("Contents/Resources/app/node_modules/lodash/demo.html"), POSTHOG);
    // A script outside the code folder is not the app's code.
    write(&root.join("Contents/Resources/help/search.js"), POSTHOG);
    let evidence = evidence(&root);

    let app = "Contents/Resources/app";
    let listing = Region::DirEntries;
    let dependency = Scope::Dependency;
    assert_eq!(
        rows(&evidence),
        [
            row(
                "@sentry/browser",
                app,
                listing,
                dependency,
                1,
                "node_modules/@sentry/browser/package.json"
            ),
            row(
                "@sentry/electron",
                app,
                listing,
                dependency,
                1,
                "node_modules/@sentry/electron/package.json"
            ),
            row("app.posthog.com", app, Region::Files, Scope::AppCode, 1, "js/main.js"),
            row("sentry.javascript.", app, Region::Files, Scope::AppCode, 2, "js/main.js"),
            row(
                "sentry.javascript.",
                app,
                Region::Files,
                dependency,
                1,
                "node_modules/@sentry/electron/main/index.js"
            ),
        ]
    );
    assert!(coverage(&evidence).is_empty());
    // The property list, two Mach-O files, and the five scripts and pages
    // of the code folder. The package files are listed, not read.
    assert_eq!(facts(&evidence).files_scanned, 3 + 5);
}

/// A file an archive lists as unpacked lives in the folder beside it, and
/// is searched there.
#[test]
fn the_folder_beside_an_archive_is_a_code_root_of_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    write(&root.join(ASAR), archive(&[("main.js", "boot()")]));
    let unpacked = "Contents/Resources/app.asar.unpacked";
    write(&root.join(unpacked).join("node_modules/posthog-js/package.json"), "{}");
    write(&root.join(unpacked).join("node_modules/posthog-js/dist/main.js"), POSTHOG);
    write(&root.join(unpacked).join("node_modules/keytar/build/keytar.node"), macho(b"native"));
    write(&root.join(unpacked).join("workers/sync.mjs"), SENTRY);

    assert_eq!(
        rows(&evidence(&root)),
        [
            row(
                "app.posthog.com",
                unpacked,
                Region::Files,
                Scope::Dependency,
                1,
                "node_modules/posthog-js/dist/main.js"
            ),
            row(
                "posthog-js",
                unpacked,
                Region::DirEntries,
                Scope::Dependency,
                1,
                "node_modules/posthog-js/package.json"
            ),
            row(
                "sentry.javascript.",
                unpacked,
                Region::Files,
                Scope::AppCode,
                1,
                "workers/sync.mjs"
            ),
        ]
    );
}

#[test]
fn every_archive_of_a_bundle_is_a_code_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    // Obsidian ships a small `app.asar` and the app itself in a second one.
    write(&root.join(ASAR), archive(&[("main.js", "load('obsidian.asar')")]));
    let second = "Contents/Resources/obsidian.asar";
    write(&root.join(second), archive(&[("app.js", POSTHOG)]));
    assert_eq!(
        rows(&evidence(&root)),
        [row("app.posthog.com", second, Region::Files, Scope::AppCode, 1, "app.js")]
    );
}

#[test]
fn a_bundle_without_electron_code_is_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    fs::remove_file(root.join(ASAR)).unwrap();
    let evidence = evidence(&root);
    assert_eq!(evidence.len(), 1, "the artifact record alone");
    assert_eq!(facts(&evidence).files_scanned, 3);
}

/// Equal digests must mean equal evidence, so the digest covers every byte
/// of an archive and every listing evidence is drawn from, and nothing else.
#[test]
fn the_digest_covers_archives_scripts_and_the_package_listing() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    let reference = digest(&evidence(&root));

    // Files the collector does not read: no change.
    write(&root.join("Contents/Resources/icon.icns"), b"another icon");
    write(&root.join("Contents/Resources/LICENSES.chromium.html"), "edited");
    write(&root.join("Contents/Resources/help/search.js"), POSTHOG);
    assert_eq!(digest(&evidence(&root)), reference);

    // A byte of the archive that belongs to no script: changed.
    let mut files = app_files();
    files[0].1 = String::from("{\"name\":\"exampel\"}");
    write(&root.join(ASAR), archive_of(&files));
    let after_archive = digest(&evidence(&root));
    assert_ne!(after_archive, reference);

    // A loose script: changed, also when it holds nothing of interest.
    let loose = root.join("Contents/Resources/app.asar.unpacked");
    write(&loose.join("tools/run.js"), "run()");
    let after_script = digest(&evidence(&root));
    assert_ne!(after_script, after_archive);
    write(&loose.join("tools/run.js"), "run(1)");
    let after_edit = digest(&evidence(&root));
    assert_ne!(after_edit, after_script);

    // A package in a loose folder, which is listed and not read: its
    // presence changes the digest, its content does not.
    write(&loose.join("node_modules/left-pad/package.json"), "{}");
    let after_package = digest(&evidence(&root));
    assert_ne!(after_package, after_edit);
    write(&loose.join("node_modules/left-pad/package.json"), "{\"version\":\"2\"}");
    assert_eq!(digest(&evidence(&root)), after_package);
    // A loose file that is neither read nor listed for evidence.
    write(&loose.join("node_modules/left-pad/README.md"), POSTHOG);
    assert_eq!(digest(&evidence(&root)), after_package);
}

#[test]
fn where_the_bundle_sits_thread_count_and_path_order_do_not_reach_the_evidence() {
    let one = tempfile::tempdir().unwrap();
    let two = tempfile::tempdir().unwrap();
    let nested = two.path().join("some/other/place");
    fs::create_dir_all(&nested).unwrap();
    let first = evidence(&electron_bundle(one.path(), "Example.app"));
    assert_eq!(evidence(&electron_bundle(&nested, "Renamed Copy.app")), first);

    let dir = tempfile::tempdir().unwrap();
    let mut paths: Vec<PathBuf> = (0..5)
        .map(|n| {
            let root = electron_bundle(dir.path(), &format!("App{n}.app"));
            write(&root.join("Contents/Info.plist"), info_plist(&format!("com.example.app{n}")));
            // Different sizes, so the largest-first order differs from path
            // order, and a loose script beside the archive.
            let mut files = app_files();
            files.push(("js/filler.js", "f();".repeat(500 * (6 - n))));
            write(&root.join(ASAR), archive_of(&files));
            write(&root.join("Contents/Resources/app.asar.unpacked/w.js"), POSTHOG);
            root
        })
        .collect();
    let reference = evidence_with(&paths, 1);
    assert_eq!(edges(&reference).len(), 5 * 6);
    paths.reverse();
    assert_eq!(evidence_with(&paths, 1), reference);
    paths.rotate_left(2);
    for threads in [2, 4, 8] {
        assert_eq!(evidence_with(&paths, threads), reference, "{threads} threads");
    }
}

fn gap(evidence: &EvidenceSet, reason: CoverageReason) -> &CoverageRecord {
    let gaps = coverage(evidence);
    let matching: Vec<&&CoverageRecord> = gaps.iter().filter(|gap| gap.reason == reason).collect();
    assert_eq!(matching.len(), 1, "expected one {reason:?} record, got {gaps:#?}");
    matching[0]
}

/// "Nothing found" must never be confused with "not looked at".
#[test]
fn an_archive_that_cannot_be_understood_is_reported_and_still_hashed() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    let good = fs::read(root.join(ASAR)).unwrap();
    let without = {
        fs::remove_file(root.join(ASAR)).unwrap();
        evidence(&root)
    };

    let mut damaged = good.clone();
    damaged[20] = b'!';
    for (case, bytes) in [
        ("not an archive", format!("{SENTRY}{POSTHOG}").into_bytes()),
        ("empty", Vec::new()),
        ("cut inside the header", good[..40].to_vec()),
        ("damaged header", damaged),
    ] {
        write(&root.join(ASAR), &bytes);
        let evidence = evidence(&root);
        assert!(edges(&evidence).is_empty(), "{case}");
        let gap = gap(&evidence, CoverageReason::ParseError);
        assert_eq!(gap.status, CoverageStatus::Unrecognized, "{case}");
        assert_eq!(gap.location.as_ref().unwrap().as_str(), ASAR, "{case}");
        assert_eq!(gap.count, 1, "{case}");
        assert_eq!(coverage(&evidence).len(), 1, "{case}");
        // The file was read to its end and is part of the bundle's identity.
        assert_eq!(facts(&evidence).files_scanned, 4, "{case}");
        assert_ne!(digest(&evidence), digest(&without), "{case}");
    }
}

#[test]
fn an_archive_cut_short_reports_the_scripts_it_no_longer_holds() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    let files: Vec<(&'static str, String)> = vec![
        ("a.js", String::from(SENTRY)),
        ("b.js", String::from(POSTHOG)),
        ("c.js", String::from("tail()")),
    ];
    let whole = archive_of(&files);
    // Cut inside `b.js`: `a.js` is whole, `b.js` and `c.js` are not there.
    write(&root.join(ASAR), &whole[..whole.len() - 10]);
    let evidence = evidence(&root);
    assert_eq!(
        rows(&evidence),
        [row("sentry.javascript.", ASAR, Region::Files, Scope::AppCode, 1, "a.js")]
    );
    let gap = gap(&evidence, CoverageReason::ParseError);
    assert_eq!((gap.status, gap.count), (CoverageStatus::Unrecognized, 2));
    assert_eq!(gap.location.as_ref().unwrap().as_str(), ASAR);
}

#[test]
fn an_archive_over_the_byte_budget_is_reported_with_its_size_and_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    let size = xs_collect::macos::MAX_FILE_BYTES + 1;
    let file = fs::File::create(root.join(ASAR)).unwrap();
    file.set_len(size).unwrap(); // sparse; never read
    let evidence = evidence(&root);
    let gap = gap(&evidence, CoverageReason::OverBudget);
    assert_eq!(gap.status, CoverageStatus::Skipped);
    assert_eq!(gap.location.as_ref().unwrap().as_str(), ASAR);
    assert_eq!(gap.bytes, Some(size));
    assert_eq!(facts(&evidence).files_scanned, 3);
}

/// V8 bytecode cannot be searched for literals, so its presence is said.
#[test]
fn bytecode_is_reported_as_not_searched() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    write(&root.join(ASAR), archive(&[("main.js", "require('./app.jsc')"), ("app.jsc", "\0\0")]));
    write(&root.join("Contents/Resources/app.asar.unpacked/worker.jsc"), "\0\0");
    write(&root.join("Contents/Resources/app.asar.unpacked/node_modules/x/y.jsc"), "\0\0");
    let evidence = evidence(&root);
    let mut gaps: Vec<(&str, u32)> = coverage(&evidence)
        .iter()
        .map(|gap| {
            assert_eq!(
                (gap.status, gap.reason),
                (CoverageStatus::Skipped, CoverageReason::UnsupportedFormat)
            );
            (gap.location.as_ref().unwrap().as_str(), gap.count)
        })
        .collect();
    gaps.sort_unstable();
    assert_eq!(gaps, [(ASAR, 1), ("Contents/Resources/app.asar.unpacked", 2)]);
}

#[test]
fn links_to_code_are_never_followed() {
    let dir = tempfile::tempdir().unwrap();
    let other = electron_bundle(dir.path(), "Other.app");
    let root = electron_bundle(dir.path(), "Example.app");
    fs::remove_file(root.join(ASAR)).unwrap();
    let reference = evidence(&root);

    // An archive, a code folder and a script that are links to another app.
    symlink(other.join(ASAR), root.join(ASAR)).unwrap();
    let outside = dir.path().join("outside/app");
    write(&outside.join("main.js"), POSTHOG);
    symlink(&outside, root.join("Contents/Resources/app")).unwrap();
    fs::create_dir_all(root.join("Contents/Resources/x.asar.unpacked")).unwrap();
    symlink(outside.join("main.js"), root.join("Contents/Resources/x.asar.unpacked/main.js"))
        .unwrap();
    assert_eq!(evidence(&root), reference);
}

/// A hostile bundle must not produce an unbounded report: past the cap, the
/// edges of the roots with the greatest paths are counted, not kept.
#[test]
fn edges_past_the_cap_are_counted_in_one_gap() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    fs::remove_file(root.join(ASAR)).unwrap();
    let one = archive(&[("main.js", POSTHOG)]);
    let total = 1000 + 7;
    for n in 0..total {
        write(&root.join(format!("Contents/Resources/parts/p{n:04}.asar")), &one);
    }
    let evidence = evidence(&root);
    let found = rows(&evidence);
    assert_eq!(found.len(), 1000);
    assert_eq!(found[0].1, "Contents/Resources/parts/p0000.asar");
    assert_eq!(found[999].1, "Contents/Resources/parts/p0999.asar");
    let gap = gap(&evidence, CoverageReason::OverBudget);
    assert_eq!((gap.status, gap.count, gap.location.as_ref()), (CoverageStatus::Skipped, 7, None));
    // Every archive was still read and is part of the bundle's identity.
    assert_eq!(facts(&evidence).files_scanned, 3 + total as u64);
}

/// Text from a hostile archive is cut and cleaned before it enters a record.
#[test]
fn a_hostile_path_is_cleaned_before_it_enters_a_record() {
    let dir = tempfile::tempdir().unwrap();
    let root = electron_bundle(dir.path(), "Example.app");
    let long = "d".repeat(200);
    let long_path = format!("{long}/{long}/main.js");
    write(
        &root.join(ASAR),
        archive(&[("a\u{1b}[31m\u{202e}.js", POSTHOG), (long_path.as_str(), SENTRY)]),
    );
    let evidence = evidence(&root);
    for edge in edges(&evidence) {
        let example = edge.proof.example.as_deref().unwrap();
        assert!(
            xs_model::text::is_clean(example, xs_model::text::MAX_EXAMPLE_BYTES),
            "{example:?}"
        );
    }
    let examples: Vec<Option<String>> = rows(&evidence).into_iter().map(|row| row.5).collect();
    assert_eq!(examples[0].as_deref(), Some("a\u{fffd}[31m\u{fffd}.js"));
    let cut = examples[1].as_deref().unwrap();
    assert!(cut.starts_with("ddd") && cut.ends_with('…') && cut.len() <= 160, "{cut:?}");
}
