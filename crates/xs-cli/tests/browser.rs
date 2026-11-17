//! Browser extensions through the `exposure` binary: what a scan of the
//! committed fixture extensions reports, byte for byte, and the properties
//! every report keeps (determinism, no path of the machine, no headline).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "tests run the binary and may read the environment"
)]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use xs_formats::testkit::ZipBuilder;
use xs_model::record::{EdgeType, Grade, ObjectKind, Platform, Record, SubjectKind};
use xs_model::{Headline, Party, Report, permission};

/// Two Chromium extensions, as a profile's `Extensions` folder holds them.
const EXTENSIONS: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/browser/Extensions");
/// One Firefox add-on, written by [`addon`].
const ADDON: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/browser/addon@example.org.xpi");
const GOLDEN: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/browser/Extensions.report.json");

fn exposure(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_exposure")).args(args).output().unwrap()
}

fn stdout(output: &Output) -> String {
    assert!(output.status.success(), "exit {:?}: {}", output.status.code(), stderr(output));
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn scan(paths: &[&str], threads: usize) -> String {
    let threads = threads.to_string();
    let mut args = vec!["scan", "--threads", &threads];
    args.extend(paths);
    stdout(&exposure(&args))
}

fn blessing() -> bool {
    std::env::var_os("EXPOSURE_BLESS").is_some()
}

/// The fixture add-on, byte for byte: a version 2 manifest, as Firefox
/// still accepts, with its site patterns among its permissions and its
/// publisher under `developer`.
fn addon() -> Vec<u8> {
    let manifest = br#"{
  "manifest_version": 2,
  "name": "Example Proxy",
  "version": "0.9.1",
  "developer": { "name": "Example Foundation", "url": "https://addons.example.org/proxy" },
  "browser_specific_settings": { "gecko": { "id": "addon@example.org" } },
  "permissions": ["<all_urls>", "webRequest", "webRequestBlocking", "proxy", "nativeMessaging"],
  "optional_permissions": ["history", "*://*.com/*"]
}
"#;
    ZipBuilder::new()
        .deflated("manifest.json", manifest)
        .deflated("background.js", b"// Never read.\n")
        .finish()
}

#[test]
fn the_fixture_add_on_is_what_its_writer_produces() {
    let bytes = addon();
    if blessing() {
        fs::write(ADDON, &bytes).unwrap();
    }
    assert!(
        fs::read(ADDON).unwrap() == bytes,
        "tests/fixtures/browser/addon@example.org.xpi is not what `addon()` writes. \
         If the change is intended, run: EXPOSURE_BLESS=1 cargo test -p exposure"
    );
}

#[test]
fn the_report_of_the_fixture_extensions_is_byte_for_byte_the_committed_one() {
    let report = scan(&[EXTENSIONS, ADDON], 2);
    if blessing() {
        fs::write(GOLDEN, &report).unwrap();
    }
    let golden = fs::read_to_string(GOLDEN).unwrap();
    assert!(
        report == golden,
        "the report for the fixture extensions changed.\n--- committed\n{golden}\n--- now\n{report}\n\
         If the change is intended, run: EXPOSURE_BLESS=1 cargo test -p exposure"
    );
}

/// What each extension asks for, as `extension permission [manifest keys]
/// notes`, in the order claims are listed: by subject, then by object id.
/// The keys are those of the records behind the claim, sorted.
#[test]
fn each_extension_is_reported_for_what_its_manifest_asks_for() {
    let report: Report = serde_json::from_str(&scan(&[EXTENSIONS, ADDON], 1)).unwrap();
    let found: Vec<String> = (0..report.claims.len())
        .map(|index| {
            let claim = &report.claims[index];
            let keys = found_keys(&report, index).join(" ");
            format!("{} {} [{keys}] {:?}", claim.subject.id, claim.object.id, claim.notes)
        })
        .collect();
    assert_eq!(
        found,
        [
            "abcdefghijklmnopabcdefghijklmnop extension/all-sites [content_scripts host_permissions] []",
            "abcdefghijklmnopabcdefghijklmnop extension/clipboard-read [optional_permissions] [\"optional\"]",
            "abcdefghijklmnopabcdefghijklmnop extension/cookies [permissions] []",
            "abcdefghijklmnopabcdefghijklmnop extension/tabs [permissions] []",
            "addon@example.org extension/all-sites [permissions] []",
            "addon@example.org extension/history [optional_permissions] [\"optional\"]",
            "addon@example.org extension/native-messaging [permissions] []",
            "addon@example.org extension/proxy [permissions] []",
            "addon@example.org extension/web-request [permissions] []",
        ]
    );

    for claim in &report.claims {
        assert_eq!(claim.edge, EdgeType::Access);
        assert_eq!(claim.grade, Grade::Requested);
        assert_eq!(claim.object.kind, ObjectKind::Permission);
        assert_eq!(claim.category, permission::CATEGORY);
        assert_eq!(
            (claim.company.as_deref(), claim.party, claim.headline),
            (None, Party::Unknown, false)
        );
        assert_eq!(claim.subject.kind, SubjectKind::Extension);
    }
    // A permission is not a company: nothing here counts in the headline.
    assert_eq!(report.headline, Headline::default());

    // The quiet extension asks for nothing broad, and is still accounted for.
    let mut artifacts: Vec<Facts> = report
        .evidence
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Artifact(artifact) => Some((
                artifact.subject.id.clone(),
                artifact.subject.platform,
                artifact.facts.name.clone(),
                artifact.facts.publisher.clone(),
                artifact.facts.homepage.clone(),
            )),
            _ => None,
        })
        .collect();
    artifacts.sort();
    assert_eq!(
        artifacts,
        [
            (
                "abcdefghijklmnopabcdefghijklmnop".into(),
                Platform::Chromium,
                Some("Example Helper".into()),
                Some("Example Ltd".into()),
                Some("www.example.com".into())
            ),
            (
                "addon@example.org".into(),
                Platform::Firefox,
                Some("Example Proxy".into()),
                Some("Example Foundation".into()),
                Some("addons.example.org".into())
            ),
            (
                "ponmlkjihgfedcbaponmlkjihgfedcba".into(),
                Platform::Chromium,
                Some("Quiet Theme".into()),
                None,
                None
            ),
        ]
    );
    // Extensions given by path were found in no browser's profile.
    assert!(report.evidence.iter().all(|(_, record)| match record {
        Record::Artifact(artifact) => artifact.facts.browser.is_none(),
        _ => true,
    }));
}

/// The subject id, platform, name, publisher and home page of an extension.
type Facts = (String, Platform, Option<String>, Option<String>, Option<String>);

/// The manifest keys of the records behind claim number `index`, sorted.
fn found_keys(report: &Report, index: usize) -> Vec<String> {
    let mut keys: Vec<String> = report.claims[index]
        .evidence
        .iter()
        .map(|id| match report.evidence.get(id) {
            Some(Record::Edge(edge)) => edge.proof.token.clone(),
            _ => String::new(),
        })
        .collect();
    keys.sort();
    keys
}

#[test]
fn the_report_depends_on_neither_threads_nor_path_order() {
    let one = scan(&[EXTENSIONS, ADDON], 1);
    assert_eq!(scan(&[ADDON, EXTENSIONS], 4), one);
    assert_eq!(scan(&[EXTENSIONS, ADDON, EXTENSIONS], 8), one);
}

/// The report holds no path of the machine, wherever the extensions sit,
/// and the terminal summary counts them apart from apps.
#[test]
fn the_report_names_no_path_of_the_machine() {
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("Some Profile/Extensions");
    copy_tree(Path::new(EXTENSIONS), &copy);
    let output = exposure(&["scan", copy.to_str().unwrap(), ADDON]);
    let report = stdout(&output);
    assert_eq!(report, scan(&[EXTENSIONS, ADDON], 2), "the report depends on where the files are");
    for path in [dir.path().to_str().unwrap(), "Some Profile", "/Users/", "tests/fixtures"] {
        assert!(!report.contains(path), "{path}");
    }
    let summary = stderr(&output);
    assert!(summary.contains("scanned 0 apps and 3 browser extensions"), "{summary}");
}

/// `exposure report` derives the same report again from the saved evidence.
#[test]
fn a_saved_report_renders_again_to_the_same_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let saved = dir.path().join("report.json");
    let output = exposure(&["scan", EXTENSIONS, ADDON, "--json", saved.to_str().unwrap()]);
    assert!(output.status.success(), "{}", stderr(&output));
    let again = stdout(&exposure(&["report", saved.to_str().unwrap()]));
    assert_eq!(again, fs::read_to_string(&saved).unwrap());
}

/// A single version folder and a single add-on may be named directly.
#[test]
fn one_extension_may_be_named_by_its_own_path() {
    let version = format!("{EXTENSIONS}/abcdefghijklmnopabcdefghijklmnop/2.1.0_0");
    let report: Report = serde_json::from_str(&scan(&[&version], 1)).unwrap();
    assert_eq!(report.claims.len(), 4);
    let report: Report = serde_json::from_str(&scan(&[ADDON], 1)).unwrap();
    assert_eq!(report.claims.len(), 5);
    // The folder above a version folder is not an extension by itself.
    let id_folder = format!("{EXTENSIONS}/abcdefghijklmnopabcdefghijklmnop");
    let report: Report = serde_json::from_str(&scan(&[&id_folder], 1)).unwrap();
    assert_eq!(report.claims.len(), 4, "the versions below an id folder are found");
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
