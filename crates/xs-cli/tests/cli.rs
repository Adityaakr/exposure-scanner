//! The `exposure` binary from the outside: the walking skeleton's acceptance
//! tests (build plan, task 4) and the properties that must hold for every
//! later task.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "tests run the binary and may read the environment"
)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::report_options;
use xs_model::record::{Grade, Record};
use xs_model::{Confidence, Headline, Party, Report};

const FIXTURE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos/Skeleton.app");
const GOLDEN: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos/Skeleton.report.json");
const PACK: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/dist/core.pack.json");
const PACK_SIGNATURE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../rules/dist/core.pack.json.minisig");

/// Runs the binary. A scan runs without the results cache, which has tests
/// of its own: these tests neither go by what an earlier run left in the
/// cache of whoever runs them, nor leave anything there.
fn exposure(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_exposure"));
    if let Some((&"scan", rest)) = args.split_first() {
        command.args(["scan", "--no-cache"]).args(report_options(rest)).args(rest);
    } else {
        command.args(args);
    }
    command.output().unwrap()
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

/// Security review S4: in a folder others can write to, someone can leave a
/// symbolic link where a report is about to be written, so that writing it
/// truncates the file the link leads to. A link is refused, and what it
/// leads to is left as it was.
#[test]
fn a_report_is_never_written_through_a_symbolic_link() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim.txt");
    fs::write(&victim, "the user's own file").unwrap();
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
    for option in ["--json", "--html"] {
        let planted = dir.path().join(format!("report{option}"));
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        let output = exposure(&["scan", FIXTURE, option, text(&planted)]);
        assert!(!output.status.success(), "{option}");
        assert!(stderr(&output).contains("symbolic link"), "{}", stderr(&output));
        assert_eq!(fs::read_to_string(&victim).unwrap(), "the user's own file", "{option}");
        assert_eq!(fs::metadata(&victim).unwrap().permissions().mode() & 0o777, 0o644);
        assert!(fs::symlink_metadata(&planted).unwrap().file_type().is_symlink());
    }
}

/// A hard link is the other way to make two names lead to one file. The
/// report replaces the name it was given, so the file behind the other name
/// keeps what it held; and no temporary file is left behind.
#[test]
fn a_report_replaces_its_name_and_never_writes_into_a_linked_file() {
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim.txt");
    fs::write(&victim, "the user's own file").unwrap();
    let linked = dir.path().join("report.json");
    fs::hard_link(&victim, &linked).unwrap();
    let output = exposure(&["scan", FIXTURE, "--json", text(&linked)]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "the user's own file");
    assert!(fs::read_to_string(&linked).unwrap() == scan(&[Path::new(FIXTURE)], 1));
    assert_eq!(fs::metadata(&linked).unwrap().permissions().mode() & 0o777, 0o600);
    let mut names: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["report.json", "victim.txt"]);
}

/// `/dev/stdout` is a symbolic link on macOS and Linux, and so is the
/// `/dev/fd/N` a shell's process substitution passes. Writing to it is
/// writing to the stream, so the report arrives on standard output.
#[test]
fn the_json_option_writes_through_a_link_to_standard_output() {
    let output = exposure(&["scan", FIXTURE, "--json", "/dev/stdout"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(String::from_utf8(output.stdout).unwrap() == scan(&[Path::new(FIXTURE)], 1));
}

/// A shell's process substitution, `--json >(jq .)`, passes `/dev/fd/N`.
/// On macOS that is not a link but a node of its own, which the system
/// reports under another device and inode once opened: it is the pipe
/// that is opened. `/dev/fd/1` is that node for standard output, a pipe
/// here, so the report has to arrive on standard output, as it did before
/// reports were written without following links.
#[test]
fn the_json_option_writes_to_the_dev_fd_node_of_a_pipe() {
    let output = exposure(&["scan", FIXTURE, "--json", "/dev/fd/1"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(String::from_utf8(output.stdout).unwrap() == scan(&[Path::new(FIXTURE)], 1));
}

/// A link to a device is written to as the device is; the link and the
/// device stay as they were.
#[test]
fn a_report_is_written_through_a_symbolic_link_to_a_device() {
    let dir = tempfile::tempdir().unwrap();
    let planted = dir.path().join("report.json");
    std::os::unix::fs::symlink("/dev/null", &planted).unwrap();
    let output = exposure(&["scan", FIXTURE, "--json", text(&planted)]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(fs::symlink_metadata(&planted).unwrap().file_type().is_symlink());
    assert!(!fs::metadata(&planted).unwrap().is_file());
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

/// With no file named, a scan writes the report for reading to a private
/// folder of the user's, says where, and prints what needs attention first,
/// as the report's summary has it: the entries of the checklist of high and
/// medium priority, or the low-priority ones when there is nothing else. It
/// never starts a browser when it is not run in a terminal.
#[test]
fn a_scan_with_no_file_named_writes_the_page_to_a_private_folder_and_prints_the_checklist() {
    let home = tempfile::tempdir().unwrap();
    let data = home.path().join("data");
    let android = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/android/Skeleton.apk");
    let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data)
        .args(["scan", "--no-cache", FIXTURE, android])
        .output()
        .unwrap();
    let said = stdout(&output);
    let folder = if cfg!(target_os = "macos") {
        home.path().join("Library/Application Support/exposure")
    } else {
        data.join("exposure")
    };
    let page = folder.join("report.html");
    assert!(said.contains(&format!("Your report: {}", page.display())), "{said}");
    assert!(said.contains("Scanned 2 apps."), "{said}");
    assert!(said.contains("What needs your attention first (1 of 2 things you can do):"), "{said}");
    assert!(said.contains("1. [High] PostHog"), "{said}");
    assert!(!said.contains("[Low] Sentry"), "only what needs attention first: {said}");
    assert!(said.contains("1 more entry in the report, under What you can do."), "{said}");
    // What needs attention comes before the headline counts.
    let at = |part: &str| said.find(part).unwrap_or_else(|| panic!("no `{part}`: {said}"));
    assert!(at("Scanned 2 apps.") < at("[High] PostHog"));
    assert!(at("[High] PostHog") < at("The headline counts:"));
    assert!(!said.contains("open in your browser"), "no browser outside a terminal: {said}");
    assert!(stderr(&output).contains("scanned 2 apps"), "{}", stderr(&output));
    assert_eq!(fs::metadata(&folder).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&page).unwrap().permissions().mode() & 0o777, 0o600);
    let written = fs::read_to_string(&page).unwrap();
    assert!(written.starts_with("<!doctype html>\n") && written.contains("PostHog"));

    // The next scan replaces it, and tightens a folder that was opened up.
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", &data)
        .args(["scan", "--no-cache", "--no-open", FIXTURE])
        .output()
        .unwrap();
    let said = stdout(&output);
    assert!(
        said.contains(
            "Nothing needs your attention first. Things you can do, all of low priority (1 of 1):"
        ),
        "{said}"
    );
    assert!(said.contains("1. [Low] Sentry"), "{said}");
    assert_eq!(fs::metadata(&folder).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(!fs::read_to_string(&page).unwrap().contains("PostHog"));
}

/// An app names itself, and the checklist prints that name on the
/// terminal. A name made of escape sequences must not reach it as such.
#[test]
fn an_app_name_cannot_put_escape_sequences_on_the_terminal() {
    let home = tempfile::tempdir().unwrap();
    let app = variant(home.path(), "Odd.app", "org.example.odd", b"x");
    let plist = fs::read_to_string(app.join("Contents/Info.plist")).unwrap();
    let name = "<key>CFBundleName</key>\n\t<string>Skeleton</string>";
    let hostile = "<key>CFBundleName</key><string>Odd&#27;[2J&#27;]0;owned&#7;&#8238;App</string>";
    let renamed = plist.replacen(name, hostile, 1);
    assert_ne!(renamed, plist, "the fixture names itself Skeleton");
    fs::write(app.join("Contents/Info.plist"), renamed).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
        .env("HOME", home.path())
        .env("XDG_DATA_HOME", home.path().join("data"))
        .args(["scan", "--no-cache", "--no-open"])
        .arg(&app)
        .output()
        .unwrap();
    let said = stdout(&output);
    assert!(said.contains("[Low] Sentry"), "{said}");
    assert!(said.contains("Odd\u{FFFD}[2J\u{FFFD}]0;owned\u{FFFD}\u{FFFD}App"), "{said}");
    for byte in output.stdout.iter().chain(&output.stderr) {
        assert!(*byte == b'\n' || !byte.is_ascii_control(), "control byte {byte:#x}: {said}");
    }
}

/// Security review S1: a publisher may start a name with a left-to-right
/// mark, as WhatsApp does. The mark reorders nothing, so the name is shown
/// without it; an override still shows as U+FFFD.
#[test]
fn a_directional_mark_in_an_app_name_is_dropped_and_an_override_is_not() {
    let home = tempfile::tempdir().unwrap();
    for (folder, written, shown) in [
        ("Marked.app", "&#8206;Marked", "[Low] Sentry"),
        ("Override.app", "Over&#8238;ride", "Over\u{FFFD}ride"),
    ] {
        let app = variant(home.path(), folder, "org.example.marked", folder.as_bytes());
        let plist = fs::read_to_string(app.join("Contents/Info.plist")).unwrap();
        let name = "<key>CFBundleName</key>\n\t<string>Skeleton</string>";
        let renamed =
            plist.replacen(name, &format!("<key>CFBundleName</key><string>{written}</string>"), 1);
        assert_ne!(renamed, plist, "the fixture names itself Skeleton");
        fs::write(app.join("Contents/Info.plist"), renamed).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
            .env("HOME", home.path())
            .env("XDG_DATA_HOME", home.path().join("data"))
            .args(["scan", "--no-cache", "--no-open"])
            .arg(&app)
            .output()
            .unwrap();
        let said = stdout(&output);
        assert!(said.contains(shown), "{said}");
        if folder == "Marked.app" {
            assert!(said.contains("Marked"), "{said}");
            assert!(!said.contains('\u{FFFD}') && !said.contains('\u{200E}'), "{said}");
        }
    }
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
    for args in [&[][..], &["frobnicate"], &["scan", FIXTURE, "--frobnicate"]] {
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

    // The ids `--fail-on` takes are listed after the rules.
    let after = |heading: &str| {
        listing.split_once(heading).map(|(_, rest)| rest.to_owned()).unwrap_or_default()
    };
    let categories = after("categories, for --fail-on category:ID");
    assert!(categories.contains("\nanalytics                    Analytics *\n"), "{listing}");
    assert!(categories.contains("\ncrash_reporting              Crash reporting\n"), "{listing}");
    assert!(categories.contains("\ncapture "), "{listing}");
    let companies = after("companies, for --fail-on company:ID");
    assert!(companies.contains("\ngoogle                       Google LLC\n"), "{listing}");
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

const ANDROID_FIXTURE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/android/Skeleton.apk");

/// `--fail-on` turns a scan into a release gate: the reports are written
/// either way, and the exit status says whether a condition was met.
#[test]
fn fail_on_sets_the_exit_status_after_the_reports_are_written() {
    let dir = tempfile::tempdir().unwrap();
    let json = dir.path().join("report.json");
    let gate = |condition: &str| {
        let _ = fs::remove_file(&json);
        let output =
            exposure(&["scan", ANDROID_FIXTURE, "--json", text(&json), "--fail-on", condition]);
        (output.status.code(), stderr(&output), json.exists())
    };

    // The fixture ships PostHog (analytics, counted) and Sentry (crash
    // reporting, not counted), both by companies other than its own.
    for condition in ["headline", "company:posthog", "category:analytics", "company:sentry"] {
        let (code, err, written) = gate(condition);
        assert_eq!(code, Some(3), "{condition}: {err}");
        assert!(written, "{condition}: the report is written before the gate closes");
        assert!(err.contains(&format!("exposure: fail-on {condition}: met by 1 finding in 1 app")));
        assert!(err.contains("a condition was met, so the exit status is 3"), "{err}");
    }
    for condition in ["company:google", "category:advertising"] {
        let (code, err, written) = gate(condition);
        assert_eq!(code, Some(0), "{condition}: {err}");
        assert!(written);
        assert!(err.contains(&format!("exposure: fail-on {condition}: not met\n")), "{err}");
    }

    // A condition the rule pack does not know is refused before anything
    // is read, rather than being a gate that never closes.
    let (code, err, written) = gate("company:nobody");
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("the rule pack has no company `nobody`"), "{err}");
    assert!(!written);
    let (code, err, _) = gate("category:spying");
    assert_eq!(code, Some(1), "{err}");

    // A saved report is checked the same way.
    exposure(&["scan", ANDROID_FIXTURE, "--json", text(&json)]);
    let output = exposure(&["report", text(&json), "--json", "/dev/null", "--fail-on", "headline"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let output = exposure(&["report", text(&json), "--json", "/dev/null"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

/// `exposure diff` follows an app across builds by its platform and app
/// id, and says which findings were added, which removed and which changed
/// grade.
#[test]
fn diff_compares_two_reports_app_by_app() {
    let dir = tempfile::tempdir().unwrap();
    let android = dir.path().join("android.json");
    let macos = dir.path().join("macos.json");
    exposure(&["scan", ANDROID_FIXTURE, "--json", text(&android)]);
    exposure(&["scan", FIXTURE, "--json", text(&macos)]);
    let android_report: Report = serde_json::from_slice(&fs::read(&android).unwrap()).unwrap();

    // The same report twice: nothing changed.
    let same = stdout(&exposure(&["diff", text(&android), text(&android)]));
    assert_eq!(same, "No finding was added, removed or changed grade, in 1 app.\n");

    // A new build without PostHog: one finding removed, nothing added. The
    // claims are edited, the way a later build would differ.
    let mut without = android_report.clone();
    without.claims.retain(|claim| claim.object.id != "sdk/posthog");
    let older = dir.path().join("older.json");
    fs::write(&older, serde_json::to_vec(&without).unwrap()).unwrap();
    let output = exposure(&["diff", text(&android), text(&older), "--fail-on", "headline"]);
    assert_eq!(output.status.code(), Some(0), "removing a finding never closes the gate");
    let printed = stdout(&output);
    assert!(
        printed.contains(
            "\n  - PostHog (Analytics, PostHog Inc., counted in the headline): contains\n"
        ),
        "{printed}"
    );
    assert!(
        printed.ends_with(
            "0 findings added, 1 finding removed, 0 findings changed grade, in 1 of 1 app.\n"
        ),
        "{printed}"
    );
    assert!(stderr(&output).contains("fail-on headline: not met"), "{}", stderr(&output));

    // The other way round, PostHog is added, and the gate closes on it.
    let output = exposure(&["diff", text(&older), text(&android), "--fail-on", "headline"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("\n  + PostHog ("));
    assert!(stderr(&output).contains("fail-on headline: met by 1 new finding in 1 app"));

    // Apps in one report only are said to be, and the comparison as JSON
    // goes to standard output alone with `--json -`.
    let output = exposure(&["diff", text(&macos), text(&android), "--json", "-"]);
    let diff: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(diff["schema"], "exposure-diff/1");
    assert_eq!(diff["same_rules"], true);
    assert_eq!(diff["totals"]["apps"], 2);
    assert_eq!(diff["totals"]["added"], 2);
    assert_eq!(diff["totals"]["removed"], 1);
    let presence: Vec<_> =
        diff["apps"].as_array().unwrap().iter().map(|app| app["presence"].clone()).collect();
    assert_eq!(presence.len(), 2);
    assert!(presence.contains(&"only_new".into()) && presence.contains(&"only_old".into()));

    // The same two reports give the same bytes.
    let again = stdout(&exposure(&["diff", text(&macos), text(&android), "--json", "-"]));
    assert_eq!(again, stdout(&output));

    // A report that is not one is refused.
    let output = exposure(&["diff", text(&android), FIXTURE]);
    assert_eq!(output.status.code(), Some(1));
}

/// On a diff, `--fail-on` closes on a finding both reports have when it
/// newly meets the condition there: a finding of the app's own vendor is
/// counted in the headline from `contains` up, not at `declares`. One that
/// met it in the old report as well leaves the gate open.
#[test]
fn diff_fail_on_closes_on_a_finding_that_newly_meets_the_condition() {
    let dir = tempfile::tempdir().unwrap();
    let android = dir.path().join("android.json");
    exposure(&["scan", ANDROID_FIXTURE, "--json", text(&android)]);
    let report: Report = serde_json::from_slice(&fs::read(&android).unwrap()).unwrap();
    let at = |grade: Grade| {
        let mut edited = report.clone();
        let posthog =
            edited.claims.iter_mut().find(|claim| claim.object.id == "sdk/posthog").unwrap();
        assert!(posthog.headline);
        posthog.party = Party::First;
        posthog.grade = grade;
        posthog.rungs = vec![grade];
        let path = dir.path().join(format!("{grade:?}.json"));
        fs::write(&path, serde_json::to_vec(&edited).unwrap()).unwrap();
        path
    };
    let (declares, contains) = (at(Grade::Declares), at(Grade::Contains));

    let output = exposure(&["diff", text(&declares), text(&contains), "--fail-on", "headline"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\n  ~ PostHog ("),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(stderr(&output).contains("fail-on headline: met by 1 new finding in 1 app"));
    assert!(stderr(&output).contains(": grade declares → contains\n"), "{}", stderr(&output));

    let output = exposure(&["diff", text(&contains), text(&declares), "--fail-on", "headline"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).contains("fail-on headline: not met"), "{}", stderr(&output));

    // Counted in both, as the third-party finding of the fixture is.
    let output = exposure(&["diff", text(&android), text(&contains), "--fail-on", "headline"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

/// A finding whose grade stays the same can newly meet a condition, and
/// the diff lists only what was added, removed or changed grade: the gate
/// summary names each finding it closed on, and why it is new. A
/// `declares` finding counts in the headline only when it is third-party.
#[test]
fn diff_fail_on_names_a_finding_that_became_third_party() {
    let dir = tempfile::tempdir().unwrap();
    let android = dir.path().join("android.json");
    exposure(&["scan", ANDROID_FIXTURE, "--json", text(&android)]);
    let report: Report = serde_json::from_slice(&fs::read(&android).unwrap()).unwrap();
    let as_party = |party: Party| {
        let mut edited = report.clone();
        let posthog =
            edited.claims.iter_mut().find(|claim| claim.object.id == "sdk/posthog").unwrap();
        posthog.party = party;
        posthog.grade = Grade::Declares;
        posthog.rungs = vec![Grade::Declares];
        let path = dir.path().join(format!("{party:?}.json"));
        fs::write(&path, serde_json::to_vec(&edited).unwrap()).unwrap();
        (path, report.claims.first().unwrap().subject.id.clone())
    };
    let ((first, id), (third, _)) = (as_party(Party::First), as_party(Party::Third));

    let output = exposure(&["diff", text(&first), text(&third), "--fail-on", "headline"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "No finding was added, removed or changed grade, in 1 app.\n"
    );
    let err = stderr(&output);
    assert!(err.contains("exposure: fail-on headline: met by 1 new finding in 1 app\n"), "{err}");
    let named = err
        .lines()
        .find(|line| {
            line.starts_with("exposure: fail-on headline:   PostHog (Analytics, PostHog Inc.) in ")
        })
        .unwrap_or_else(|| panic!("{err}"));
    assert!(named.ends_with(&format!("(Android, {id}): now third-party")), "{named}");

    let output = exposure(&["diff", text(&third), text(&first), "--fail-on", "headline"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(stderr(&output).contains("fail-on headline: not met\n"), "{}", stderr(&output));
    assert!(!stderr(&output).contains("PostHog"), "{}", stderr(&output));
}

/// Beside the headline, the summary counts what the Android apps ship in
/// the categories it leaves out, and names no company: the fixture's
/// Sentry, which is crash reporting. A macOS app's crash reporter is not
/// part of it.
#[test]
fn the_summary_counts_what_android_apps_ship_beside_the_headline() {
    let output = exposure(&["scan", ANDROID_FIXTURE, "--json", "/dev/null"]);
    let err = stderr(&output);
    assert!(output.status.success(), "{err}");
    assert!(
        err.contains(
            "\nexposure: beside the headline: 1 SDK of 1 company in the Android apps, in \
             categories the headline does not count\n"
        ),
        "{err}"
    );
    assert!(!err.contains("Sentry") && !err.contains("sentry"), "{err}");
    let output = exposure(&["scan", FIXTURE, "--json", "/dev/null"]);
    assert!(!stderr(&output).contains("beside the headline"), "{}", stderr(&output));
}
