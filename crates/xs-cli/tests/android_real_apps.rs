//! The Android collector on real apps (build plan, task 8): "Bitwarden's
//! Play build reports the five Google SDKs. The F-Droid build and `NewPipe`
//! report nothing."
//!
//! Real apps are never stored in this repository. They are pinned by hash
//! and download address in `tests/fixtures/real-apps.txt` and read from a
//! cache folder:
//!
//! ```console
//! $ cargo xtask fixtures fetch --dir DIR
//! $ EXPOSURE_FIXTURE_CACHE=DIR cargo test -p exposure --test android_real_apps
//! ```
//!
//! Without `EXPOSURE_FIXTURE_CACHE` these tests have nothing to scan and
//! pass after saying so. With it, a pinned app that is missing from the
//! folder or has another hash fails them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::print_stderr,
    reason = "tests run the binary, read the environment and say when they are skipped"
)]

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use xs_model::record::{Platform, Record};
use xs_model::{MatcherKind, Report, Sha256Stream};

const PINS: &str = include_str!("../../../tests/fixtures/real-apps.txt");

const BITWARDEN_PLAY: &str = "bitwarden-android-2026.9.1-play.apk";
const BITWARDEN_FDROID: &str = "bitwarden-android-2026.9.1-fdroid.apk";
const NEWPIPE: &str = "newpipe-0.29.3.apk";

/// The evidence record of the design spike (design report, appendix A),
/// in format version 1. Its id is fixed in `xs-model`'s tests from the
/// canonical JSON written out by hand; the collector must arrive at the
/// same record from the app file itself.
const SPIKE_RECORD_ID: &str =
    "sha256:6aaab06fe1e8cc0d0b77e75f9b5b97f25fa3d8434ffee9ead8cd1bac63c0badb";

/// The pinned SHA-256 of `file`.
fn pinned(file: &str) -> &'static str {
    PINS.lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| match line.split_whitespace().collect::<Vec<_>>()[..] {
            [sha256, name, _url] if name == file => Some(sha256),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{file} is not pinned in tests/fixtures/real-apps.txt"))
}

/// The path of `file` in the fixture cache, checked against its pin, or
/// `None` when no cache was given.
fn cached(file: &str) -> Option<PathBuf> {
    let Some(cache) = std::env::var_os("EXPOSURE_FIXTURE_CACHE") else {
        eprintln!(
            "skipped: set EXPOSURE_FIXTURE_CACHE to scan {file} (see tests/fixtures/README.md)"
        );
        return None;
    };
    let path = Path::new(&cache).join(file);
    let mut reader = File::open(&path).unwrap_or_else(|error| {
        panic!("{}: {error}. Run: cargo xtask fixtures fetch --dir <cache>", path.display())
    });
    let mut hasher = Sha256Stream::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    assert_eq!(hasher.finish().to_hex(), pinned(file), "{} is not the pinned file", path.display());
    Some(path)
}

fn scan(paths: &[&Path], threads: usize) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
        .args(["scan", "--threads", &threads.to_string()])
        .args(paths)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

/// The matcher kinds behind each claim, by SDK.
fn witnesses(report: &Report) -> Vec<(&str, Vec<MatcherKind>)> {
    report
        .claims
        .iter()
        .map(|claim| {
            let mut kinds: Vec<MatcherKind> = claim
                .evidence
                .iter()
                .map(|id| match report.evidence.get(id) {
                    Some(Record::Edge(edge)) => edge.proof.matcher,
                    other => panic!("a claim cites {other:?}"),
                })
                .collect();
            kinds.sort();
            kinds.dedup();
            (claim.object.id.as_str(), kinds)
        })
        .collect()
}

/// Project spec, spike results: "Google: Crashlytics, Cloud Messaging,
/// Installations ID, `DataTransport`, Play Billing". The app's build file
/// adds Crashlytics, Cloud Messaging and Billing to the standard flavor; the
/// other two come with them.
#[test]
fn the_play_build_of_bitwarden_reports_the_five_google_sdks() {
    let Some(apk) = cached(BITWARDEN_PLAY) else { return };
    let report: Report = serde_json::from_str(&scan(&[&apk], 2)).unwrap();

    use MatcherKind::{
        AndroidClassPrefix as Class, DexString as Strings, ManifestComponent as Manifest,
    };
    assert_eq!(
        witnesses(&report),
        [
            ("sdk/firebase-crashlytics", vec![Manifest, Class, Strings]),
            ("sdk/firebase-installations", vec![Manifest, Class, Strings]),
            ("sdk/firebase-messaging", vec![Manifest, Class]),
            ("sdk/google-datatransport", vec![Manifest, Class]),
            ("sdk/play-billing", vec![Manifest, Class]),
        ]
    );
    for claim in &report.claims {
        assert_eq!(claim.company.as_deref(), Some("google"), "{}", claim.object.id);
        assert_eq!(claim.subject.platform, Platform::Android);
        assert_eq!(claim.subject.id, "com.x8bit.bitwarden");
        assert_eq!(claim.subject.version.as_deref(), Some("2026.9.1"));
        assert_eq!(claim.subject.digest.to_string(), format!("sha256:{}", pinned(BITWARDEN_PLAY)));
    }
    // Every part of the package was read: no coverage record.
    assert!(!report.evidence.iter().any(|(_, record)| matches!(record, Record::Coverage(_))));

    // The spike's record, reproduced from the file: two Crashlytics classes
    // kept their names in `classes2.dex`.
    let spike = report.evidence.iter().find(|(id, _)| id.to_string() == SPIKE_RECORD_ID);
    let Some((_, Record::Edge(edge))) = spike else {
        panic!("the scan did not produce the spike's Crashlytics record")
    };
    assert_eq!(edge.proof.count, 2);
    assert_eq!(
        edge.proof.example.as_deref(),
        Some("com.google.firebase.crashlytics.CrashlyticsRegistrar")
    );
}

/// The same app built without the Google SDKs, and a negative control. Any
/// edge at any confidence fails (design report, section 3, issue A2).
#[test]
fn the_fdroid_build_of_bitwarden_and_newpipe_report_nothing() {
    for (file, id, version) in [
        (BITWARDEN_FDROID, "com.x8bit.bitwarden", "2026.9.1"),
        (NEWPIPE, "org.schabi.newpipe", "0.29.3"),
    ] {
        let Some(apk) = cached(file) else { return };
        let report: Report = serde_json::from_str(&scan(&[&apk], 2)).unwrap();
        assert!(report.claims.is_empty(), "{file}: {:?}", report.claims);
        // Nothing found, and nothing passed over: the one record is the
        // package's identity.
        let records: Vec<&Record> = report.evidence.iter().map(|(_, record)| record).collect();
        let [Record::Artifact(artifact)] = records[..] else {
            panic!("{file}: expected one artifact record, got {records:?}")
        };
        assert_eq!(artifact.subject.id, id);
        assert_eq!(artifact.subject.version.as_deref(), Some(version));
        assert_eq!(artifact.subject.digest.to_string(), format!("sha256:{}", pinned(file)));
    }
}

#[test]
fn the_real_apps_give_one_report_whatever_the_order_and_thread_count() {
    let files = [BITWARDEN_PLAY, BITWARDEN_FDROID, NEWPIPE];
    let Some(apks) = files.iter().map(|file| cached(file)).collect::<Option<Vec<_>>>() else {
        return;
    };
    let forward: Vec<&Path> = apks.iter().map(PathBuf::as_path).collect();
    let backward: Vec<&Path> = forward.iter().rev().copied().collect();
    let reference = scan(&forward, 1);
    let parsed: Report = serde_json::from_str(&reference).unwrap();
    assert_eq!(parsed.claims.len(), 5, "two builds of one app id: only the Play build has claims");
    for threads in [2, 8] {
        assert!(scan(&forward, threads) == reference, "{threads} threads");
        assert!(scan(&backward, threads) == reference, "{threads} threads, reversed");
    }
}
