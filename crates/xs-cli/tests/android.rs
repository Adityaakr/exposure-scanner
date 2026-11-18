//! The Android collector through the `exposure` binary (build plan, task
//! 8), on synthetic packages. The same properties on real apps are in
//! `android_real_apps.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "tests run the binary and may read the environment"
)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::report_options;
use xs_formats::testkit::{self, Attr, AxmlBuilder, DexBuilder, ZipBuilder};
use xs_model::record::{Grade, Record};
use xs_model::{Confidence, MatcherKind, Report};

const FIXTURE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/android/Skeleton.apk");
const GOLDEN: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/android/Skeleton.report.json");
const BUNDLE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos/Skeleton.app");

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

fn blessing() -> bool {
    std::env::var_os("EXPOSURE_BLESS").is_some()
}

/// The fixture package, byte for byte.
///
/// A synthetic app that ships two SDKs of the seed pack, each visible to two
/// kinds of witness, next to names that only resemble an SDK's:
///
/// * Sentry: its provider in the manifest, and its classes in `classes.dex`.
/// * `PostHog`: its Android classes and its ingestion host in `classes2.dex`.
/// * Decoys that must find nothing: the server-side `PostHog` SDK, a host
///   that continues past the token, an ad host no rule names, a `meta-data`
///   key, and a resource that mentions Crashlytics.
fn fixture() -> Vec<u8> {
    let manifest = AxmlBuilder::new()
        .start(
            "manifest",
            &[
                Attr::int(testkit::ANDROID_VERSION_CODE, "versionCode", 1),
                Attr::android(testkit::ANDROID_VERSION_NAME, "versionName", "1.0.0"),
                Attr::plain("package", "org.example.exposure.skeleton"),
            ],
        )
        .start("application", &[Attr::android(testkit::ANDROID_LABEL, "label", "Skeleton")])
        .start("activity", &[Attr::android(testkit::ANDROID_NAME, "name", ".MainActivity")])
        .end()
        .start(
            "provider",
            &[Attr::android(
                testkit::ANDROID_NAME,
                "name",
                "io.sentry.android.core.SentryInitProvider",
            )],
        )
        .end()
        .start("meta-data", &[Attr::android(testkit::ANDROID_NAME, "name", "io.sentry.auto-init")])
        .end()
        .end()
        .end()
        .finish();
    let classes = DexBuilder::new()
        .class("org.example.exposure.skeleton.MainActivity")
        .class("io.sentry.Sentry")
        .class("io.sentry.android.core.SentryInitProvider")
        .referenced_type("Landroid/app/Activity;")
        .string("Hello from the skeleton")
        .finish();
    let classes2 = DexBuilder::new()
        .class("com.posthog.android.PostHogAndroid")
        .class("com.posthog.server.PostHog")
        .string("https://us.i.posthog.com")
        .string("https://us.i.posthog.community/forum")
        .string("googleads.g.doubleclick.net")
        .finish();
    let notes = b"This resource mentions com.google.firebase.crashlytics.CrashlyticsRegistrar \
        and firebase-settings.crashlytics.com. Resources are not searched.\n";
    ZipBuilder::new()
        .deflated("AndroidManifest.xml", &manifest)
        .stored_padded("classes.dex", &classes, 2)
        .deflated("classes2.dex", &classes2)
        .stored("assets/", b"")
        .deflated("assets/notes.txt", notes)
        .stored("lib/arm64-v8a/libskeleton.so", b"\x7fELF not a real library\n")
        .finish()
}

/// The committed fixture is exactly what the writer above produces, so the
/// file can be read about here instead of taken on trust. Regenerate it
/// after a deliberate change with `EXPOSURE_BLESS=1 cargo test -p exposure`.
#[test]
fn the_fixture_package_is_what_its_writer_produces() {
    let bytes = fixture();
    if blessing() {
        fs::write(FIXTURE, &bytes).unwrap();
    }
    assert!(
        fs::read(FIXTURE).unwrap() == bytes,
        "tests/fixtures/android/Skeleton.apk is not what `fixture()` writes. \
         If the change is intended, run: EXPOSURE_BLESS=1 cargo test -p exposure"
    );
}

#[test]
fn the_fixture_package_yields_two_sdks_from_two_kinds_of_witness_each() {
    let report: Report = serde_json::from_str(&scan(&[Path::new(FIXTURE)], 2)).unwrap();

    let found: Vec<(&str, Option<&str>, u32)> = report
        .claims
        .iter()
        .map(|claim| (claim.object.id.as_str(), claim.company.as_deref(), claim.witnesses))
        .collect();
    assert_eq!(found, [("sdk/posthog", Some("posthog"), 2), ("sdk/sentry", Some("sentry"), 2)]);
    for claim in &report.claims {
        assert_eq!(claim.subject.id, "org.example.exposure.skeleton");
        assert_eq!(claim.subject.version.as_deref(), Some("1.0.0"));
        assert_eq!(claim.subject.digest.to_string(), format!("sha256:{}", sha256(&fixture())));
        assert_eq!(claim.grade, Grade::Contains);
        assert_eq!(claim.confidence, Confidence::High);
    }

    // Honest: every claim shows the raw records behind it, and each record
    // says in which table of which file the hit is.
    let proofs: Vec<String> = report
        .claims
        .iter()
        .flat_map(|claim| &claim.evidence)
        .map(|id| match report.evidence.get(id) {
            Some(Record::Edge(edge)) => format!(
                "{} {} {} {}",
                edge.proof.matcher, edge.proof.token, edge.proof.count, edge.proof.location
            ),
            other => panic!("a claim cites {other:?}"),
        })
        .collect();
    let mut sorted = proofs.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        [
            "android_class_prefix com.posthog.android. 1 classes2.dex",
            "android_class_prefix io.sentry. 2 classes.dex",
            "dex_string us.i.posthog.com 1 classes2.dex",
            "manifest_component io.sentry.android.core.SentryInitProvider 1 AndroidManifest.xml",
        ]
    );
    // The artifact record and the four edges, and nothing from the decoys.
    assert_eq!(report.evidence.len(), 5);

    // A string constant is file content. The record that found the host
    // carries the rule's token and never the string it sat in.
    let strings: Vec<_> = report
        .evidence
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Edge(edge) if edge.proof.matcher == MatcherKind::DexString => Some(edge),
            _ => None,
        })
        .collect();
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].proof.example, None);
}

fn sha256(bytes: &[u8]) -> String {
    xs_model::Sha256Digest::of(bytes).to_hex()
}

/// The same bytes on every machine: the report for the committed fixture is
/// compared with a committed file, so Linux and macOS CI must both produce
/// it.
#[test]
fn the_fixture_report_matches_the_committed_bytes() {
    let report = scan(&[Path::new(FIXTURE)], 3);
    if blessing() {
        fs::write(GOLDEN, &report).unwrap();
    }
    let golden = fs::read_to_string(GOLDEN).unwrap();
    assert!(
        report == golden,
        "the report for the fixture package changed.\n--- committed\n{golden}\n--- now\n{report}\n\
         If the change is intended, run: EXPOSURE_BLESS=1 cargo test -p exposure"
    );
}

/// A package with the given app id whose one DEX file defines `class`.
fn variant(parent: &Path, file: &str, id: &str, class: &str) -> PathBuf {
    let path = parent.join(file);
    let apk = ZipBuilder::new()
        .deflated("AndroidManifest.xml", &testkit::manifest(id, "1.0", &[("activity", ".Main")]))
        .deflated("classes.dex", &DexBuilder::new().class(class).finish())
        .finish();
    fs::write(&path, apk).unwrap();
    path
}

/// Design report, section 7 property 3: one report across input order and
/// thread count, with packages and bundles in one scan.
#[test]
fn one_report_whatever_the_input_order_and_thread_count() {
    let dir = tempfile::tempdir().unwrap();
    let apps = [
        variant(dir.path(), "alpha.apk", "org.example.alpha", "io.sentry.Sentry"),
        variant(dir.path(), "beta.apk", "org.example.beta", "org.example.beta.Main"),
        // Two builds that share one app id and version.
        variant(dir.path(), "gamma-one.apk", "org.example.gamma", "io.sentry.One"),
        variant(dir.path(), "gamma-two.apk", "org.example.gamma", "io.sentry.Two"),
        PathBuf::from(FIXTURE),
        PathBuf::from(BUNDLE),
    ];
    let sorted: Vec<&Path> = apps.iter().map(PathBuf::as_path).collect();
    let reference = scan(&sorted, 1);
    let parsed: Report = serde_json::from_str(&reference).unwrap();
    // Sentry in alpha, in both builds of gamma and in the bundle; two SDKs
    // in the fixture package.
    assert_eq!(parsed.claims.len(), 6, "two builds of one app id stay two claims");

    let mut reversed = sorted.clone();
    reversed.reverse();
    let shuffled = [sorted[3], sorted[5], sorted[0], sorted[4], sorted[2], sorted[1]];
    let with_repeats =
        [sorted[4], sorted[1], sorted[1], sorted[0], sorted[2], sorted[3], sorted[5]];
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
    // A folder is searched for packages as well as for bundles: naming it
    // is the same as naming every package in it.
    let in_folder = scan(&[dir.path()], 4);
    let named = scan(&sorted[..4], 4);
    assert!(in_folder == named, "folder scan");
    let parsed: Report = serde_json::from_str(&in_folder).unwrap();
    assert_eq!(parsed.claims.len(), 3);
}

/// Evidence depends on the bytes of the artifact and nothing else: not on
/// where the file is, and not on what it is called.
#[test]
fn where_a_package_is_and_what_it_is_called_does_not_reach_the_report() {
    let one = tempfile::tempdir().unwrap();
    let two = tempfile::tempdir().unwrap();
    let nested = two.path().join("a/b");
    fs::create_dir_all(&nested).unwrap();
    let first = variant(one.path(), "app.apk", "org.example.app", "io.sentry.Sentry");
    let second = nested.join("Secret Diary (copy).APK");
    fs::copy(&first, &second).unwrap();

    let report = scan(&[&first], 2);
    assert!(report == scan(&[&second], 2));
    assert!(!report.contains(text(one.path())));
    assert!(!report.contains("Diary") && !report.contains("app.apk"));
    assert!(!report.contains("/Users/") && !report.contains("/home/") && !report.contains("/tmp"));
}

#[test]
fn report_reproduces_the_scan_of_a_package_from_saved_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let saved = dir.path().join("scan.json");
    let first = scan(&[Path::new(FIXTURE)], 2);
    fs::write(&saved, &first).unwrap();
    assert!(stdout(&exposure(&["report", text(&saved)])) == first);
}

/// "Nothing found" must not be confused with "not looked at": a file that
/// is named like a package and is not one gets a report that says so, under
/// the hash of what the file holds.
#[test]
fn a_file_that_is_not_a_package_is_reported_not_passed_over() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("download.apk");
    fs::write(&file, "<html>404 Not Found</html>").unwrap();

    let output = exposure(&["scan", text(&file)]);
    let summary = stderr(&output);
    assert!(
        summary.contains("scanned 1 app (1 file, 26 bytes): 0 claims, 1 coverage note"),
        "{summary}"
    );
    let report: Report = serde_json::from_str(&stdout(&output)).unwrap();
    assert!(report.claims.is_empty());
    let coverage: Vec<_> = report
        .evidence
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Coverage(gap) => Some(gap),
            _ => None,
        })
        .collect();
    assert_eq!(coverage.len(), 1);
    let expected = format!("sha256:{}", sha256(b"<html>404 Not Found</html>"));
    assert_eq!(coverage[0].subject.digest.to_string(), expected);
    assert_eq!(coverage[0].subject.id, "unidentified.apk");

    // A file that is not named like any artifact is still refused.
    let other = dir.path().join("notes.txt");
    fs::write(&other, "not an app").unwrap();
    let output = exposure(&["scan", text(&other)]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("an Android package (.apk)"), "{}", stderr(&output));
}

/// One app that cannot be read does not cost the scan the others (build
/// plan, task 9). It has no hash, so the report says under the name of its
/// file that it was skipped, and says nothing about what it holds.
#[test]
fn a_package_that_cannot_be_read_is_reported_and_the_others_are_scanned() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let open = variant(dir.path(), "open.apk", "org.example.open", "io.sentry.Sentry");
    let without = scan(&[&open], 2);
    let locked = variant(dir.path(), "locked.apk", "org.example.locked", "io.sentry.Sentry");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    let readable = fs::read(&locked).is_ok();
    let named = exposure(&["scan", text(&locked), text(&open)]);
    let found = exposure(&["scan", text(dir.path())]);
    let alone = exposure(&["scan", text(&locked)]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
    // Running as root, permissions do not bind and there is nothing to test.
    if readable {
        return;
    }

    // Named or found in a folder, it is the same scan.
    assert!(stdout(&named) == stdout(&found));
    let summary = stderr(&named);
    assert!(
        summary.contains("scanned 1 app") && summary.contains("1 claim, 1 coverage note"),
        "{summary}"
    );
    let report: Report = serde_json::from_str(&stdout(&named)).unwrap();
    let before: Report = serde_json::from_str(&without).unwrap();
    assert_eq!(report.claims, before.claims);
    assert_eq!(report.evidence.len(), before.evidence.len() + 1);
    let gaps: Vec<_> = report
        .evidence
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Coverage(gap) => Some(serde_json::to_value(gap).unwrap()),
            _ => None,
        })
        .collect();
    assert_eq!(
        gaps,
        [serde_json::json!({
            "v": 1, "collector": "android.apk",
            "subject": {
                "kind": "app", "platform": "android", "id": "locked.apk", "digest": "unread"
            },
            "status": "skipped", "reason": "unreadable", "count": 1
        })]
    );
    assert!(!stdout(&named).contains("org.example.locked"), "nothing of its content is known");

    // By itself it is still a scan, of nothing: the report says what was
    // skipped, and saved evidence gives the same report again.
    let summary = stderr(&alone);
    assert!(summary.contains("scanned 0 apps (0 files, 0 bytes): 0 claims, 1 coverage note"));
    let saved = dir.path().join("scan.json");
    fs::write(&saved, stdout(&alone)).unwrap();
    assert!(stdout(&exposure(&["report", text(&saved)])) == stdout(&alone));
}

/// A package that is not there was never an app to skip: a path that does
/// not exist is a mistake in the command, and is refused before any reading.
#[test]
fn a_path_that_does_not_exist_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let open = variant(dir.path(), "open.apk", "org.example.open", "io.sentry.Sentry");
    let missing = dir.path().join("missing.apk");
    let output = exposure(&["scan", text(&open), text(&missing)]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "no report");
    assert!(stderr(&output).contains("missing.apk"), "{}", stderr(&output));
}

#[test]
fn the_terminal_summary_names_no_package_and_no_path() {
    let dir = tempfile::tempdir().unwrap();
    let app = variant(dir.path(), "secret-diary.apk", "org.example.diary", "io.sentry.Sentry");
    let summary = stderr(&exposure(&["scan", text(&app)]));
    assert!(summary.contains("scanned 1 app"), "{summary}");
    assert!(summary.contains("1 claim"), "{summary}");
    assert!(!summary.contains("diary") && !summary.contains(text(dir.path())), "{summary}");
}

#[test]
fn the_usage_text_names_android_packages() {
    assert!(stdout(&exposure(&["--help"])).contains("an Android .apk"));
}
