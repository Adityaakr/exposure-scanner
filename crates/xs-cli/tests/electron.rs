//! The Electron collector from the outside (build plan, task 7): the
//! `exposure` binary with the built-in signed pack against a committed
//! fixture bundle, and against the three real apps the task is measured on.
//!
//! The real apps are never stored in this repository. They are read from a
//! folder named by `EXPOSURE_FIXTURE_CACHE`, laid out as
//! `tests/fixtures/README.md` describes, and the tests that need them are
//! skipped when that variable is not set.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::print_stderr,
    reason = "tests run the binary, may read the environment and say when they are skipped"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use xs_model::record::{Collector, EdgeType, Grade, Record, Region, Scope};
use xs_model::{Claim, Confidence, Headline, MatcherKind, Party, Report};

const FIXTURE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos/ElectronSkeleton.app");
const GOLDEN: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos/ElectronSkeleton.report.json");
const SKELETON: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos/Skeleton.app");

/// The JSON report on standard output, unless the arguments name a file
/// for a report: a scan given neither writes its report for reading to the
/// user's own folder instead.
fn report_options(rest: &[&str]) -> &'static [&'static str] {
    let named = rest.iter().take_while(|arg| **arg != "--").any(|arg| {
        ["--json", "--html"].iter().any(|option| {
            arg.strip_prefix(option).is_some_and(|tail| tail.is_empty() || tail.starts_with('='))
        })
    });
    if named { &[] } else { &["--json", "-"] }
}

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
    assert!(
        output.status.success(),
        "exit {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn scan(paths: &[&Path], threads: usize) -> String {
    let threads = threads.to_string();
    let mut args = vec!["scan", "--threads", &threads];
    args.extend(paths.iter().map(|path| path.to_str().unwrap()));
    stdout(&exposure(&args))
}

fn claim<'r>(report: &'r Report, sdk: &str) -> &'r Claim {
    let found: Vec<&Claim> = report.claims.iter().filter(|claim| claim.object.id == sdk).collect();
    assert_eq!(found.len(), 1, "one claim for {sdk}, got {:#?}", report.claims);
    found[0]
}

/// The proofs behind a claim, as `matcher region scope token count example`.
fn proofs(report: &Report, claim: &Claim) -> Vec<String> {
    let mut proofs: Vec<String> = claim
        .evidence
        .iter()
        .map(|id| {
            let Some(Record::Edge(edge)) = report.evidence.get(id) else {
                panic!("the claim cites a record the report does not carry");
            };
            assert_eq!(edge.collector, Collector::ElectronApp);
            let proof = &edge.proof;
            let region = match proof.region {
                Region::AsarHeader => "asar_header",
                Region::Files => "files",
                other => panic!("an Electron edge in {other:?}"),
            };
            let scope = match proof.scope {
                Scope::AppCode => "app_code",
                Scope::Dependency => "dependency",
                other => panic!("an Electron edge of scope {other:?}"),
            };
            format!(
                "{} {region} {scope} {} {} {} in {}",
                proof.matcher,
                proof.token,
                proof.count,
                proof.example.as_deref().unwrap_or("-"),
                proof.location
            )
        })
        .collect();
    proofs.sort();
    proofs
}

/// The fixture's archive was written by `@electron/asar`, not by this code
/// base, and what it holds is listed in `tests/fixtures/README.md`. Sentry
/// is in the app's own script and installed as a package; PostHog is in the
/// app's own script only; the page of a dependency and the source map that
/// name PostHog's host count for nothing.
#[test]
fn the_fixture_app_reports_sentry_and_posthog_with_their_proofs() {
    let report: Report = serde_json::from_str(&scan(&[Path::new(FIXTURE)], 2)).unwrap();
    assert_eq!(report.claims.len(), 2, "{:#?}", report.claims);
    let archive = "Contents/Resources/app.asar";

    let sentry = claim(&report, "sdk/sentry");
    assert_eq!(sentry.company.as_deref(), Some("sentry"));
    assert_eq!(sentry.subject.id, "org.example.exposure.electron-skeleton");
    assert_eq!(sentry.grade, Grade::Contains);
    // The package name is read from a table, so it is the stronger witness.
    assert_eq!(sentry.confidence, Confidence::High);
    assert_eq!(sentry.witnesses, 2);
    assert_eq!(
        proofs(&report, sentry),
        [
            format!("content_literal files app_code sentry.javascript. 1 main.js in {archive}"),
            format!(
                "content_literal files dependency sentry.javascript. 1 \
                 node_modules/@sentry/electron/index.js in {archive}"
            ),
            format!(
                "npm_package asar_header dependency @sentry/electron 1 \
                 node_modules/@sentry/electron/package.json in {archive}"
            ),
        ]
    );

    let posthog = claim(&report, "sdk/posthog");
    assert_eq!(posthog.company.as_deref(), Some("posthog"));
    assert_eq!(posthog.category, "analytics");
    // Analytics counts in the headline, crash reporting does not.
    assert!(posthog.headline && !sentry.headline);
    assert_eq!(posthog.party, Party::Third);
    assert_eq!(
        report.headline,
        Headline { companies_contacts: 0, companies_contains: 1, apps_third_party: 1 }
    );
    // A literal in the app's own script: medium, and one kind of witness.
    assert_eq!(posthog.confidence, Confidence::Medium);
    assert_eq!(posthog.witnesses, 1);
    assert_eq!(
        proofs(&report, posthog),
        [format!("content_literal files app_code app.posthog.com 1 main.js in {archive}")]
    );

    // The artifact record and the four edges. Nothing was skipped.
    assert_eq!(report.evidence.len(), 5);
}

/// The same bytes on every machine. Regenerate after a deliberate change
/// with `EXPOSURE_BLESS=1 cargo test -p exposure`.
#[test]
fn the_fixture_report_matches_the_committed_bytes() {
    let report = scan(&[Path::new(FIXTURE)], 3);
    if std::env::var_os("EXPOSURE_BLESS").is_some() {
        fs::write(GOLDEN, &report).unwrap();
    }
    let golden = fs::read_to_string(GOLDEN).unwrap();
    assert!(
        report == golden,
        "the report for the Electron fixture changed.\n--- committed\n{golden}\n--- now\n{report}\n\
         If the change is intended, run: EXPOSURE_BLESS=1 cargo test -p exposure"
    );
}

#[test]
fn one_report_whatever_the_thread_count_and_the_order_of_the_apps() {
    let both = [Path::new(FIXTURE), Path::new(SKELETON)];
    let reference = scan(&both, 1);
    let report: Report = serde_json::from_str(&reference).unwrap();
    assert_eq!(report.claims.len(), 3);
    for threads in [2, 8] {
        assert!(scan(&both, threads) == reference, "{threads} threads");
    }
    assert!(scan(&[both[1], both[0]], 4) == reference, "reversed");
}

/// The records of this collector survive being written and read back.
#[test]
fn report_reproduces_the_scan_from_saved_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let saved = dir.path().join("scan.json");
    let first = scan(&[Path::new(FIXTURE)], 2);
    fs::write(&saved, &first).unwrap();
    assert!(stdout(&exposure(&["report", saved.to_str().unwrap()])) == first);
}

/// The folder that holds the real apps, or `None` when the tests that need
/// them are to be skipped.
fn fixture_cache(test: &str) -> Option<PathBuf> {
    let Some(cache) = std::env::var_os("EXPOSURE_FIXTURE_CACHE") else {
        eprintln!("{test}: skipped, EXPOSURE_FIXTURE_CACHE is not set");
        return None;
    };
    Some(PathBuf::from(cache))
}

/// Scans a real app from the cache. A cache that was asked for and does not
/// hold the app is a failure, not a skip.
fn scan_real(cache: &Path, app: &str) -> Report {
    let path = cache.join(app);
    assert!(
        path.join("Contents/Info.plist").is_file(),
        "{} is not in the fixture cache; see tests/fixtures/README.md",
        path.display()
    );
    serde_json::from_str(&scan(&[&path], 4)).unwrap()
}

/// The SDKs the channel claims of a report name, other than components,
/// which are libraries with no network side of their own and name no company.
fn companies_sdks(report: &Report) -> Vec<&str> {
    let mut sdks: Vec<&str> = report
        .claims
        .iter()
        .filter(|claim| claim.edge == EdgeType::Channel && claim.category != "component")
        .map(|claim| claim.object.id.as_str())
        .collect();
    sdks.sort_unstable();
    sdks
}

/// The components a report names. Each one names no company and counts
/// nowhere.
fn components(report: &Report) -> Vec<&str> {
    let mut found: Vec<&str> = report
        .claims
        .iter()
        .filter(|claim| claim.edge == EdgeType::Channel && claim.category == "component")
        .inspect(|claim| assert_eq!(claim.company, None, "{claim:#?}"))
        .map(|claim| claim.object.id.as_str())
        .collect();
    found.sort_unstable();
    found
}

/// The permissions the app may access, by id. They come from the bundle's
/// property list and signature, not from the Electron collector: `plutil`
/// and `codesign -d --entitlements -` show the same on the same files.
fn may_access(report: &Report) -> Vec<&str> {
    report
        .claims
        .iter()
        .filter(|claim| claim.edge == EdgeType::Access)
        .map(|claim| claim.object.id.as_str())
        .collect()
}

/// What the Electron template's property list asks for, in every app built
/// from it, whether or not the app ever uses it.
const TEMPLATE_ASKS_FOR: [&str; 4] = ["bluetooth", "camera", "microphone", "system-audio"];

/// Bytes the collector read, to tell "nothing found" from "not looked at".
fn bytes_scanned(report: &Report) -> u64 {
    report
        .evidence
        .iter()
        .find_map(|(_, record)| match record {
            Record::Artifact(artifact) => Some(artifact.facts.bytes_scanned),
            _ => None,
        })
        .unwrap()
}

fn archive_len(cache: &Path, app: &str, archive: &str) -> u64 {
    fs::metadata(cache.join(app).join("Contents/Resources").join(archive)).unwrap().len()
}

/// Build plan, task 7: "Logseq reports Sentry and PostHog from app code."
///
/// Ground truth (project spec, spike results): Logseq's own `package.json`
/// lists `@sentry/react` and `posthog-js`; both are bundled into
/// `js/main.js`, and neither is among the 280 packages its archive lists.
#[test]
fn logseq_reports_sentry_and_posthog_from_app_code() {
    let Some(cache) = fixture_cache("logseq") else { return };
    let app = "logseq-2.0.2/Logseq.app";
    let report = scan_real(&cache, app);
    assert_eq!(companies_sdks(&report), ["sdk/posthog", "sdk/sentry"], "{:#?}", report.claims);
    // The updaters it ships: Electron's own, and electron-builder's.
    assert_eq!(components(&report), ["sdk/electron-updater", "sdk/squirrel"]);
    assert_eq!(may_access(&report), TEMPLATE_ASKS_FOR);
    for (sdk, company, token) in [
        ("sdk/sentry", "sentry", "sentry.javascript."),
        ("sdk/posthog", "posthog", "app.posthog.com"),
    ] {
        let claim = claim(&report, sdk);
        assert_eq!(claim.subject.id, "com.logseq.logseq");
        assert_eq!(claim.subject.version.as_deref(), Some("2.0.2"));
        assert_eq!(claim.company.as_deref(), Some(company));
        assert_eq!(claim.grade, Grade::Contains);
        assert_eq!(claim.confidence, Confidence::Medium);
        assert_eq!(claim.witnesses, 1);
        // In `js/main.js` and in the copy the app publishes pages with.
        assert_eq!(
            proofs(&report, claim),
            [format!(
                "{} files app_code {token} 2 js/main.js in Contents/Resources/app.asar",
                MatcherKind::ContentLiteral
            )]
        );
    }
    assert!(bytes_scanned(&report) >= archive_len(&cache, app, "app.asar"));
}

/// Build plan, task 7: "Bitwarden desktop and Obsidian report nothing."
///
/// Nothing that names a company: what they report is the updaters they ship,
/// which are components. Squirrel is part of Electron on macOS, so every
/// Electron app has it.
///
/// Bitwarden's archive carries an analytics snippet in the demo page of a
/// search library (`node_modules/lunr/index.html`), which is not the app's
/// code.
#[test]
fn bitwarden_desktop_reports_nothing() {
    let Some(cache) = fixture_cache("bitwarden desktop") else { return };
    let app = "bitwarden-desktop-2026.10.4/Bitwarden.app";
    let report = scan_real(&cache, app);
    assert!(companies_sdks(&report).is_empty(), "{:#?}", report.claims);
    assert_eq!(components(&report), ["sdk/electron-updater", "sdk/squirrel"]);
    assert_eq!(may_access(&report), TEMPLATE_ASKS_FOR);
    assert_eq!(report.headline, Headline::default());
    assert!(bytes_scanned(&report) >= archive_len(&cache, app, "app.asar"));
}

#[test]
fn obsidian_reports_nothing() {
    let Some(cache) = fixture_cache("obsidian") else { return };
    let app = "obsidian-1.15.1/Obsidian.app";
    let report = scan_real(&cache, app);
    assert!(companies_sdks(&report).is_empty(), "{:#?}", report.claims);
    assert_eq!(components(&report), ["sdk/squirrel"]);
    assert_eq!(
        may_access(&report),
        [
            "automation",
            "bluetooth",
            "calendars",
            "camera",
            "contacts",
            "microphone",
            "reminders",
            "system-audio"
        ]
    );
    assert_eq!(report.headline, Headline::default());
    // Both of its archives were read.
    let archives = archive_len(&cache, app, "app.asar") + archive_len(&cache, app, "obsidian.asar");
    assert!(bytes_scanned(&report) >= archives);
}
