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

use xs_model::record::{EdgeType, Platform, Record};
use xs_model::{Claim, MatcherKind, Report, Sha256Stream};

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
        .args(["scan", "--no-cache", "--json", "-", "--threads", &threads.to_string()])
        .args(paths)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

/// The claims about channels: SDKs the app ships. What it may access is a
/// claim of another type, checked by [`may_access`].
fn channels(report: &Report) -> impl Iterator<Item = &Claim> {
    report.claims.iter().filter(|claim| claim.edge == EdgeType::Channel)
}

/// What the app may access, each permission with the manifest permissions
/// that ask for it, without the `android.permission.` they start with.
fn may_access(report: &Report) -> Vec<(&str, Vec<&str>)> {
    report
        .claims
        .iter()
        .filter(|claim| claim.edge == EdgeType::Access)
        .map(|claim| {
            let mut asked: Vec<&str> = claim
                .evidence
                .iter()
                .map(|id| match report.evidence.get(id) {
                    Some(Record::Edge(edge)) => {
                        assert_eq!(edge.proof.matcher, MatcherKind::AndroidPermission);
                        assert_eq!(edge.proof.location.as_str(), "AndroidManifest.xml");
                        let name = edge.proof.token.as_str();
                        name.strip_prefix("android.permission.").unwrap_or(name)
                    }
                    other => panic!("a claim cites {other:?}"),
                })
                .collect();
            asked.sort_unstable();
            (claim.object.id.as_str(), asked)
        })
        .collect()
}

/// What both builds of Bitwarden ask for in their manifest. The names were
/// read out of the manifest's string pool by hand; the manifest asks for
/// nine more that reach nothing of the user's, such as `WAKE_LOCK`.
const BITWARDEN_MAY_ACCESS: [(&str, &[&str]); 5] = [
    ("biometrics", &["USE_BIOMETRIC", "USE_FINGERPRINT"]),
    ("camera", &["CAMERA"]),
    ("local-network", &["ACCESS_LOCAL_NETWORK"]),
    ("network-client", &["INTERNET"]),
    ("nfc", &["NFC"]),
];

fn expected(asked: &[(&'static str, &[&'static str])]) -> Vec<(&'static str, Vec<&'static str>)> {
    asked.iter().map(|(permission, names)| (*permission, names.to_vec())).collect()
}

/// The matcher kinds behind each claim about a channel, by SDK.
fn witnesses(report: &Report) -> Vec<(&str, Vec<MatcherKind>)> {
    channels(report)
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
    for claim in channels(&report) {
        assert_eq!(claim.company.as_deref(), Some("google"), "{}", claim.object.id);
    }
    for claim in &report.claims {
        assert_eq!(claim.subject.platform, Platform::Android);
        assert_eq!(claim.subject.id, "com.x8bit.bitwarden");
        assert_eq!(claim.subject.version.as_deref(), Some("2026.9.1"));
        assert_eq!(claim.subject.digest.to_string(), format!("sha256:{}", pinned(BITWARDEN_PLAY)));
    }
    // What the app may access is the same in both builds: the Google SDKs
    // add channels, not permissions that reach the user's data.
    assert_eq!(may_access(&report), expected(&BITWARDEN_MAY_ACCESS));
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
/// channel edge at any confidence fails (design report, section 3, issue
/// A2). What each may access is what its manifest asks for.
#[test]
fn the_fdroid_build_of_bitwarden_and_newpipe_report_nothing() {
    let newpipe: [(&str, &[&str]); 2] =
        [("network-client", &["INTERNET"]), ("shared-storage", &["WRITE_EXTERNAL_STORAGE"])];
    for (file, id, name, version, asked) in [
        (
            BITWARDEN_FDROID,
            "com.x8bit.bitwarden",
            "Bitwarden",
            "2026.9.1",
            &BITWARDEN_MAY_ACCESS[..],
        ),
        (NEWPIPE, "org.schabi.newpipe", "NewPipe", "0.29.3", &newpipe[..]),
    ] {
        let Some(apk) = cached(file) else { return };
        let report: Report = serde_json::from_str(&scan(&[&apk], 2)).unwrap();
        assert_eq!(channels(&report).count(), 0, "{file}: {:?}", report.claims);
        assert_eq!(may_access(&report), expected(asked), "{file}");
        // No SDK found, and nothing passed over: beside what the manifest
        // asks for, the one record is the package's identity.
        let records: Vec<&Record> = report
            .evidence
            .iter()
            .map(|(_, record)| record)
            .filter(|record| !matches!(record, Record::Edge(edge) if edge.edge == EdgeType::Access))
            .collect();
        let [Record::Artifact(artifact)] = records[..] else {
            panic!("{file}: expected one artifact record, got {records:?}")
        };
        assert_eq!(artifact.subject.id, id);
        // The name the label points at, from the resource table.
        assert_eq!(artifact.facts.name.as_deref(), Some(name), "{file}");
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
    let shipped = channels(&parsed).count();
    assert_eq!(shipped, 5, "two builds of one app id: only the Play build ships SDKs");
    assert_eq!(parsed.claims.len() - shipped, 5 + 5 + 2, "what each of the three may access");
    for threads in [2, 8] {
        assert!(scan(&forward, threads) == reference, "{threads} threads");
        assert!(scan(&backward, threads) == reference, "{threads} threads, reversed");
    }
}

/// The release-audit job: `exposure diff` of the two builds of Bitwarden
/// says what the Play build ships that the F-Droid build does not, by name.
#[test]
fn the_diff_of_the_two_builds_of_bitwarden_is_the_five_google_sdks() {
    let (Some(play), Some(fdroid)) = (cached(BITWARDEN_PLAY), cached(BITWARDEN_FDROID)) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let (old, new) = (dir.path().join("fdroid.json"), dir.path().join("play.json"));
    std::fs::write(&old, scan(&[&fdroid], 2)).unwrap();
    std::fs::write(&new, scan(&[&play], 2)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
        .args(["diff"])
        .args([&old, &new])
        .args(["--fail-on", "company:google"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "Bitwarden (Android, com.x8bit.bitwarden), 2026.9.1\n\
         \x20 + Firebase Cloud Messaging (Push messaging, Google LLC): contains\n\
         \x20 + Firebase Crashlytics (Crash reporting, Google LLC): contains\n\
         \x20 + Firebase Installations (Installation identifiers, Google LLC): contains\n\
         \x20 + Google DataTransport (Telemetry transport, Google LLC): contains\n\
         \x20 + Google Play Billing Library (Payments, Google LLC): contains\n\
         \n\
         5 findings added, 0 findings removed, 0 findings changed grade, in 1 of 1 app.\n"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("fail-on company:google: met by 5 new findings in 1 app")
    );
}
