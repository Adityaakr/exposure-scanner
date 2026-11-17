//! The `exposure` binary from the outside: the walking skeleton's acceptance
//! tests (build plan, task 4) and the properties that must hold for every
//! later task.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "tests run the binary and may read the environment"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use xs_model::record::{Grade, Record};
use xs_model::{Confidence, Headline, Party, Report};

const FIXTURE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos/Skeleton.app");
const GOLDEN: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos/Skeleton.report.json");
const PACK: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/dist/core.pack.json");
const PACK_SIGNATURE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/dist/core.pack.json.minisig");

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

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn scan(paths: &[&Path], threads: usize) -> String {
    let threads = threads.to_string();
    let mut args = vec!["scan", "--threads", &threads];
    args.extend(paths.iter().map(|path| text(path)));
    stdout(&exposure(&args))
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

/// A copy of the fixture bundle with another app id and main binary.
fn variant(parent: &Path, name: &str, id: &str, binary: &[u8]) -> PathBuf {
    let root = parent.join(name);
    copy_tree(Path::new(FIXTURE), &root);
    let plist = fs::read_to_string(root.join("Contents/Info.plist")).unwrap();
    fs::write(root.join("Contents/Info.plist"), plist.replace("org.example.exposure.skeleton", id))
        .unwrap();
    // The header of a 64-bit Mach-O file that has no load commands.
    let mut bytes = vec![0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];
    bytes.resize(32, 0);
    bytes.extend_from_slice(binary);
    fs::write(root.join("Contents/MacOS/Skeleton"), bytes).unwrap();
    root
}

/// Build plan, task 4: a fixture bundle yields one claim.
#[test]
fn the_fixture_bundle_yields_one_claim() {
    let report: Report = serde_json::from_str(&scan(&[Path::new(FIXTURE)], 2)).unwrap();

    assert_eq!(report.claims.len(), 1);
    let claim = &report.claims[0];
    assert_eq!(claim.object.id, "sdk/sentry");
    assert_eq!(claim.object.name, "Sentry");
    assert_eq!(claim.company.as_deref(), Some("sentry"));
    assert_eq!(claim.category, "crash_reporting");
    // Nobody the pack lists publishes the fixture, so Sentry is a third
    // party to it. Crash reporting is outside the headline.
    assert_eq!(claim.party, Party::Third);
    assert!(!claim.headline);
    assert_eq!(report.headline, Headline::default());
    assert_eq!(claim.subject.id, "org.example.exposure.skeleton");
    assert_eq!(claim.subject.version.as_deref(), Some("1.0.0"));
    assert_eq!(claim.grade, Grade::Contains);
    assert_eq!(claim.confidence, Confidence::High);
    assert_eq!(claim.witnesses, 1);

    // Honest: the claim shows the raw record behind it.
    assert_eq!(claim.evidence.len(), 1);
    let Some(Record::Edge(edge)) = report.evidence.get(&claim.evidence[0]) else {
        panic!("the claim cites a record the report does not carry");
    };
    assert_eq!(edge.proof.token, "Sentry.framework");
    assert_eq!(edge.proof.location.as_str(), "Contents/Frameworks");

    // The resource that mentions other SDKs and ad domains found nothing.
    assert_eq!(report.evidence.len(), 2, "one artifact record, one edge");
    assert_eq!(report.scanner.name, "exposure");
    assert_eq!(report.packs.len(), 1);
    assert_eq!(report.packs[0].layer, "core");
}

/// The same bytes on every machine: the report for the committed fixture is
/// compared with a committed file, so Linux and macOS CI must both produce
/// it. Regenerate after a deliberate change (a rule-pack update changes the
/// pack hash the report names) with `EXPOSURE_BLESS=1 cargo test -p exposure`.
#[test]
fn the_fixture_report_matches_the_committed_bytes() {
    let report = scan(&[Path::new(FIXTURE)], 3);
    if std::env::var_os("EXPOSURE_BLESS").is_some() {
        fs::write(GOLDEN, &report).unwrap();
    }
    let golden = fs::read_to_string(GOLDEN).unwrap();
    assert!(
        report == golden,
        "the report for the fixture bundle changed.\n--- committed\n{golden}\n--- now\n{report}\n\
         If the change is intended, run: EXPOSURE_BLESS=1 cargo test -p exposure"
    );
}

/// Design report, section 7 property 3: one report across input order
/// (sorted, reversed, shuffled) and thread count (1 and N).
#[test]
fn one_report_whatever_the_input_order_and_thread_count() {
    let dir = tempfile::tempdir().unwrap();
    let apps = [
        variant(dir.path(), "Alpha.app", "org.example.alpha", b"alpha"),
        variant(dir.path(), "Beta.app", "org.example.beta", &vec![7u8; 300_000]),
        // Two builds that share one app id: the case that broke the spike.
        variant(dir.path(), "Gamma one.app", "org.example.gamma", b"build one"),
        variant(dir.path(), "Gamma two.app", "org.example.gamma", b"build two"),
        variant(dir.path(), "Delta.app", "org.example.delta", &vec![9u8; 2_500_000]),
    ];
    let sorted: Vec<&Path> = apps.iter().map(PathBuf::as_path).collect();
    let reference = scan(&sorted, 1);
    let parsed: Report = serde_json::from_str(&reference).unwrap();
    assert_eq!(parsed.claims.len(), 5, "two builds of one app id stay two claims");

    let mut reversed = sorted.clone();
    reversed.reverse();
    let shuffled = [sorted[3], sorted[0], sorted[4], sorted[2], sorted[1]];
    let with_repeats =
        [sorted[1], sorted[1], sorted[0], sorted[2], sorted[3], sorted[4], sorted[0]];
    for (name, order) in [
        ("sorted", &sorted[..]),
        ("reversed", &reversed[..]),
        ("shuffled", &shuffled[..]),
        ("repeats", &with_repeats[..]),
    ] {
        for threads in [1, 2, 8] {
            assert!(scan(order, threads) == reference, "{name} order, {threads} threads");
        }
    }
    // Naming the folder is the same as naming every bundle in it.
    assert!(scan(&[dir.path()], 4) == reference, "folder scan");
}

#[test]
fn where_the_apps_are_installed_does_not_reach_the_report() {
    let one = tempfile::tempdir().unwrap();
    let two = tempfile::tempdir().unwrap();
    let nested = two.path().join("a/b/c");
    let first = variant(one.path(), "App.app", "org.example.app", b"same build");
    let second = variant(&nested, "Renamed.app", "org.example.app", b"same build");
    let report = scan(&[&first], 2);
    assert!(report == scan(&[&second], 2));
    // No absolute path, and nothing of the temporary folders' names.
    assert!(!report.contains(text(one.path())));
    assert!(!report.contains("/Users/") && !report.contains("/home/") && !report.contains("/tmp"));
}

/// The determinism test drives `report`: rendering again from the saved
/// evidence gives the same bytes.
#[test]
fn report_reproduces_the_scan_from_saved_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let saved = dir.path().join("scan.json");
    let first = scan(&[Path::new(FIXTURE)], 2);
    fs::write(&saved, &first).unwrap();

    let again = stdout(&exposure(&["report", text(&saved)]));
    assert!(again == first);

    // And through a file, twice over.
    let second = dir.path().join("again.json");
    stdout(&exposure(&["report", text(&saved), "--json", text(&second)]));
    assert!(stdout(&exposure(&["report", text(&second)])) == first);
}

#[test]
fn edited_evidence_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let report = scan(&[Path::new(FIXTURE)], 1);
    let refuse = |edited: String, expect: &str| {
        assert_ne!(edited, report, "the edit must change something");
        let file = dir.path().join("edited.json");
        fs::write(&file, edited).unwrap();
        let output = exposure(&["report", text(&file)]);
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty(), "nothing is rendered from refused evidence");
        assert!(stderr(&output).contains(expect), "{}", stderr(&output));
    };
    // A record changed under its id.
    refuse(report.replace("\"count\":1", "\"count\":40"), "hashes to");
    // A record that names a path outside the artifact.
    refuse(
        report.replace("\"where\":\"Contents/Frameworks\"", "\"where\":\"/etc/passwd\""),
        "absolute",
    );
    // A field the format does not have.
    refuse(report.replace("\"schema\":", "\"confidential\":true,\"schema\":"), "unknown field");
    // A report from a format this build does not know.
    refuse(report.replace("exposure-report/1", "exposure-report/2"), "unsupported report schema");
    refuse(String::from("not json"), "cannot read");
}

#[test]
fn the_json_option_writes_an_owner_only_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("report.json");
    // An existing, world-readable file is tightened as well as replaced.
    fs::write(&file, "old content that is longer than nothing").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

    let output = exposure(&["scan", FIXTURE, "--json", text(&file)]);
    assert!(output.status.success());
    assert!(output.stdout.is_empty(), "the report goes to the file only");
    assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(fs::read_to_string(&file).unwrap() == scan(&[Path::new(FIXTURE)], 1));
}

/// `--json /dev/null` is the ordinary way to discard a report and keep the
/// summary. A device is not the scanner's file to change the mode of, and a
/// normal user may not change it at all.
#[test]
fn the_json_option_writes_to_a_device_without_changing_its_mode() {
    let mode = || fs::metadata("/dev/null").unwrap().permissions().mode();
    let before = mode();
    let output = exposure(&["scan", FIXTURE, "--json", "/dev/null"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("scanned 1 app"));
    assert_eq!(mode(), before);
}

#[test]
fn the_terminal_summary_names_no_app_and_no_path() {
    let dir = tempfile::tempdir().unwrap();
    let app = variant(dir.path(), "Secret Diary.app", "org.example.diary", b"x");
    let output = exposure(&["scan", text(&app)]);
    let summary = stderr(&output);
    assert!(summary.contains("scanned 1 app"), "{summary}");
    assert!(summary.contains("1 claim"), "{summary}");
    assert!(summary.contains("headline: 0 companies at contacts or above"), "{summary}");
    assert!(!summary.contains("Diary") && !summary.contains("diary"), "{summary}");
    assert!(!summary.contains(text(dir.path())), "{summary}");
}

/// A scan says what it covered on a line of its own. Given a path, that is
/// the path and nothing else: the installed apps were not looked at, and the
/// summary must not read as if they had been.
#[test]
fn a_scan_of_a_given_path_states_its_scope() {
    let output = exposure(&["scan", FIXTURE, "--json", "/dev/null"]);
    let summary = stderr(&output);
    let scope: Vec<&str> =
        summary.lines().filter_map(|line| line.strip_prefix("exposure: scope: ")).collect();
    assert_eq!(
        scope,
        ["the paths given and nothing else; the installed-app folders were not searched"],
        "{summary}"
    );
    assert!(!summary.contains("/Applications"), "{summary}");
}

#[test]
fn problems_with_the_command_line_are_told_apart_from_failed_scans() {
    // Usage errors: exit 2, with the usage text.
    for args in [&[][..], &["frobnicate"], &["scan", FIXTURE, "--no-cache"]] {
        let output = exposure(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr(&output).contains("usage:"), "{args:?}");
        assert!(output.stdout.is_empty());
    }
    // Failures: exit 1, with a reason and no report.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("notes.txt");
    fs::write(&file, "not an app").unwrap();
    for (path, reason) in
        [(dir.path().join("missing.app"), "cannot read"), (file, "not a macOS application bundle")]
    {
        let output = exposure(&["scan", text(&path)]);
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains(reason), "{}", stderr(&output));
        assert!(output.stdout.is_empty());
    }
}

/// Without a path the installed apps are scanned, and only macOS has a
/// place this build knows to look for them in. Anywhere else that is said,
/// not answered with an empty report.
#[test]
fn a_scan_without_a_path_needs_a_system_whose_apps_can_be_found() {
    if cfg!(target_os = "macos") {
        // It would read every app installed on the machine that runs the
        // tests. `cargo xtask bench` runs exactly that scan.
        return;
    }
    let output = exposure(&["scan"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("no PATH was given"), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
}

#[test]
fn an_empty_folder_is_an_empty_report_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let report: Report = serde_json::from_str(&scan(&[dir.path()], 1)).unwrap();
    assert!(report.claims.is_empty() && report.evidence.is_empty());
}

#[test]
fn help_and_version() {
    let help = stdout(&exposure(&["--help"]));
    assert!(help.contains("exposure scan [PATH...]"));
    assert!(help.contains("only what the PATHs name is scanned"), "{help}");
    assert_eq!(
        stdout(&exposure(&["--version"])),
        concat!("exposure ", env!("CARGO_PKG_VERSION"), "\n")
    );
}

/// The version the committed pack file declares. The expectations below
/// follow it, so a rule change does not have to touch these tests.
fn pack_version() -> u64 {
    let pack: serde_json::Value = serde_json::from_str(&fs::read_to_string(PACK).unwrap()).unwrap();
    pack["version"].as_u64().unwrap()
}

#[test]
fn rules_show_lists_the_built_in_pack() {
    let listing = stdout(&exposure(&["rules", "show"]));
    let heading = format!("layer core version {} (CC-BY-4.0), sha256 ", pack_version());
    assert!(listing.starts_with(&heading), "{listing}");
    for expected in
        ["sdk/sentry", "sdk/firebase-crashlytics", "sdk/posthog", "sdk/appcenter-crashes"]
    {
        assert!(listing.contains(expected), "{listing}");
    }
    let sparkle = listing.lines().find(|line| line.starts_with("sdk/sparkle")).unwrap();
    assert!(sparkle.ends_with("component, no company"), "{sparkle}");
}

/// Build plan, task 3: a tampered pack is refused.
#[test]
fn rules_verify_accepts_the_signed_pack_and_refuses_a_tampered_one() {
    let ok = stdout(&exposure(&["rules", "verify", PACK, "--sig", PACK_SIGNATURE]));
    assert!(ok.starts_with(&format!("ok: layer core version {},", pack_version())), "{ok}");
    assert!(ok.contains("signed by exposure-pack-1"), "{ok}");

    let dir = tempfile::tempdir().unwrap();
    let tampered = dir.path().join("core.pack.json");
    let original = fs::read_to_string(PACK).unwrap();
    fs::write(&tampered, original.replace("Sentry.framework", "Finder.framework")).unwrap();
    let output = exposure(&["rules", "verify", text(&tampered), "--sig", PACK_SIGNATURE]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("not signed by a trusted key"), "{}", stderr(&output));
}
