//! The macOS collector against the real apps of the spec's spike table
//! (build plan, task 6):
//!
//! * AltTab reports App Center.
//! * NetNewsWire and Maccy report no SDK and a graded update feed.
//!
//! Real artifacts are never stored in the repository. These tests run only
//! when the environment variable `EXPOSURE_FIXTURE_CACHE` names a folder
//! that holds them, laid out as `tests/fixtures/README.md` describes, and
//! pass without doing anything otherwise. Each app is pinned twice: the
//! release archive by the SHA-256 its publisher lists, and the main
//! executable of the unpacked bundle by its own SHA-256, so what is scanned
//! is known to be what was published.
//!
//! The expected findings do not come from the scanner. They come from each
//! project's own source and from standard tools run on the same files:
//! AltTab vendors App Center Crashes; neither NetNewsWire nor Maccy ships an
//! analytics or crash-upload SDK; `plutil` shows the `SUFeedURL` of the two;
//! `codesign -dv` shows each Team ID.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::print_stderr,
    reason = "tests run the binary, read the environment and say when they are skipped"
)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use xs_model::record::{CoverageRecord, EdgeRecord, Facts, Grade, ObjectKind, Record, Region};
use xs_model::{Claim, Confidence, MatcherKind, Report, Sha256Digest};

/// One real app, pinned.
struct Pinned {
    /// Its folder in the cache.
    folder: &'static str,
    /// The release archive, as downloaded.
    archive: &'static str,
    /// SHA-256 of the archive, as the release page lists it.
    archive_sha256: &'static str,
    /// The bundle, unpacked into `app/` next to the archive.
    bundle: &'static str,
    /// The main executable inside the bundle, and its SHA-256.
    executable: &'static str,
    executable_sha256: &'static str,
}

/// <https://github.com/lwouis/alt-tab-macos/releases/tag/v11.10.2>
const ALTTAB: Pinned = Pinned {
    folder: "alttab-11.10.2",
    archive: "AltTab-11.10.2.zip",
    archive_sha256: "5a2a821a83be1092df0f63d2403359ef2f7d52ad39cec36d930e4c7554cc045b",
    bundle: "AltTab.app",
    executable: "Contents/MacOS/AltTab",
    executable_sha256: "8e20a2ead633334fb155bdbb9078c5a0fd14165f463bdf3ed46d64f521ee4022",
};

/// <https://github.com/Ranchero-Software/NetNewsWire/releases/tag/mac-7.2.1>
const NETNEWSWIRE: Pinned = Pinned {
    folder: "netnewswire-7.2.1",
    archive: "NetNewsWire7.2.1.zip",
    archive_sha256: "9459896e516ac6c34685b38111dc456a3d1a4e49c964e40bc8f8af8fdc3b17db",
    bundle: "NetNewsWire.app",
    executable: "Contents/MacOS/NetNewsWire",
    executable_sha256: "d82ba76a02a8ac42b171a4923f1f21c6e31b702b1cf334917258c4305f74e726",
};

/// <https://github.com/p0deje/Maccy/releases/tag/2.8.0>
const MACCY: Pinned = Pinned {
    folder: "maccy-2.8.0",
    archive: "Maccy.app.zip",
    archive_sha256: "e684e1ce0c60d7cffd3a2b182dc37bd7e88c29967a64a431a2c71be65b1d27e0",
    bundle: "Maccy.app",
    executable: "Contents/MacOS/Maccy",
    executable_sha256: "676958a599aaf82c8fd518ef3258467e808ab298ff472261ce8341006d511f38",
};

fn sha256_of(path: &PathBuf) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    Sha256Digest::of(&bytes).to_hex()
}

/// Scans the pinned app, or returns `None` when no fixture cache is set.
fn scan(app: &Pinned) -> Option<Report> {
    let Some(cache) = std::env::var_os("EXPOSURE_FIXTURE_CACHE") else {
        eprintln!("skipped: EXPOSURE_FIXTURE_CACHE is not set (see tests/fixtures/README.md)");
        return None;
    };
    let folder = PathBuf::from(cache).join(app.folder);
    assert_eq!(sha256_of(&folder.join(app.archive)), app.archive_sha256, "{}", app.archive);
    let bundle = folder.join("app").join(app.bundle);
    assert_eq!(
        sha256_of(&bundle.join(app.executable)),
        app.executable_sha256,
        "{} is not what {} holds",
        app.bundle,
        app.archive
    );

    let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
        .args(["scan", "--threads", "3"])
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    Some(serde_json::from_slice(&output.stdout).unwrap())
}

/// The ids of the claims that name a company, with the company.
fn company_claims(report: &Report) -> Vec<(&str, &str)> {
    report
        .claims
        .iter()
        .filter_map(|claim| Some((claim.object.id.as_str(), claim.company.as_deref()?)))
        .collect()
}

/// The ids of the claims about components: SDKs that name no company.
fn components(report: &Report) -> Vec<&str> {
    report
        .claims
        .iter()
        .filter(|claim| claim.object.kind == ObjectKind::Sdk && claim.company.is_none())
        .map(|claim| claim.object.id.as_str())
        .collect()
}

fn claim<'a>(report: &'a Report, object: &str) -> &'a Claim {
    report
        .claims
        .iter()
        .find(|claim| claim.object.id == object)
        .unwrap_or_else(|| panic!("no claim about {object}"))
}

/// The records a claim cites. Honest: each one is in the report.
fn evidence<'a>(report: &'a Report, claim: &Claim) -> Vec<&'a EdgeRecord> {
    assert!(!claim.evidence.is_empty());
    claim
        .evidence
        .iter()
        .map(|id| match report.evidence.get(id) {
            Some(Record::Edge(edge)) => edge,
            other => panic!("claim cites {id}, which is {other:?}"),
        })
        .collect()
}

fn facts(report: &Report) -> &Facts {
    report
        .evidence
        .iter()
        .find_map(|(_, record)| {
            if let Record::Artifact(artifact) = record { Some(&artifact.facts) } else { None }
        })
        .unwrap()
}

fn coverage(report: &Report) -> Vec<&CoverageRecord> {
    report
        .evidence
        .iter()
        .filter_map(|(_, record)| if let Record::Coverage(gap) = record { Some(gap) } else { None })
        .collect()
}

/// The one claim about the update feed: a host, declared, owned by nobody
/// the scanner names.
fn assert_feed(report: &Report, host: &str) {
    let hosts: Vec<&Claim> =
        report.claims.iter().filter(|claim| claim.object.kind == ObjectKind::Host).collect();
    assert_eq!(hosts.len(), 1, "{hosts:#?}");
    let feed = claim(report, host);
    assert_eq!(feed.object.name, host);
    assert_eq!(feed.category, "update_feed");
    assert_eq!(feed.grade, Grade::Declares);
    assert_eq!(feed.rungs, [Grade::Declares]);
    assert_eq!(feed.confidence, Confidence::High);
    assert_eq!(feed.company, None);

    let records = evidence(report, feed);
    assert_eq!(records.len(), 1);
    let proof = &records[0].proof;
    assert_eq!(proof.matcher, MatcherKind::UpdateFeed);
    assert_eq!(proof.token, "SUFeedURL");
    assert_eq!(proof.location.as_str(), "Contents/Info.plist");
    assert_eq!(proof.region, Region::PropertyList);
    assert_eq!(records[0].rule, "declared/update-feed");
}

/// Spec, spike table: "AltTab 11.10.2, macOS: Microsoft App Center". The
/// SDK is inside the main binary; the framework folder holds only a crash
/// capture library and an updater.
#[test]
fn alttab_reports_app_center() {
    let Some(report) = scan(&ALTTAB) else { return };

    assert_eq!(
        company_claims(&report),
        [("sdk/appcenter", "microsoft"), ("sdk/appcenter-crashes", "microsoft")]
    );
    for (object, class) in
        [("sdk/appcenter", "MSACAppCenter"), ("sdk/appcenter-crashes", "MSACCrashes")]
    {
        let claim = claim(&report, object);
        assert_eq!(claim.grade, Grade::Contains);
        assert_eq!(claim.confidence, Confidence::High);
        // `contains` can point at a dead service, and the claim says so.
        assert_eq!(claim.notes, ["retired:2025-03-31"]);

        let records = evidence(&report, claim);
        assert_eq!(records.len(), 1);
        let proof = &records[0].proof;
        assert_eq!(proof.matcher, MatcherKind::MachoObjcClass);
        assert_eq!(proof.token, class);
        assert_eq!(proof.example.as_deref(), Some(class));
        // Once in each of the two architectures of the universal binary.
        assert_eq!(proof.count, 2);
        assert_eq!(proof.location.as_str(), "Contents/MacOS/AltTab");
        assert_eq!(proof.region, Region::ObjcClassname);
    }
    assert_eq!(components(&report), ["sdk/plcrashreporter", "sdk/sparkle"]);

    // AltTab sets its feed address in code, so its property list names none.
    assert!(report.claims.iter().all(|claim| claim.object.kind == ObjectKind::Sdk));
    assert_eq!(facts(&report).name.as_deref(), Some("AltTab"));
    assert_eq!(facts(&report).team_id.as_deref(), Some("QXD7GW8FHY"));
    assert!(coverage(&report).is_empty(), "{:#?}", coverage(&report));
}

/// Spec, spike table: "NetNewsWire 7.2.1, macOS: No SDK. Update feed on its
/// own domain".
#[test]
fn netnewswire_reports_no_sdk_and_a_graded_update_feed() {
    let Some(report) = scan(&NETNEWSWIRE) else { return };

    assert_eq!(company_claims(&report), []);
    // The crash capture library is linked into the main binary here; it
    // and the updater have no network side of their own.
    assert_eq!(components(&report), ["sdk/plcrashreporter", "sdk/sparkle"]);
    assert_feed(&report, "ranchero.com");
    assert_eq!(facts(&report).team_id.as_deref(), Some("M8L2WTLA8W"));
    assert!(coverage(&report).is_empty(), "{:#?}", coverage(&report));
}

/// Spec, spike table: "Maccy 2.8.0, macOS: No SDK. Update feed hosted on
/// GitHub".
#[test]
fn maccy_reports_no_sdk_and_a_graded_update_feed() {
    let Some(report) = scan(&MACCY) else { return };

    assert_eq!(company_claims(&report), []);
    assert_eq!(components(&report), ["sdk/sparkle"]);
    assert_feed(&report, "raw.githubusercontent.com");
    assert_eq!(facts(&report).team_id.as_deref(), Some("MN3X4648SC"));
    assert!(coverage(&report).is_empty(), "{:#?}", coverage(&report));
}
