//! The resolver from the outside (build plan, task 10): who publishes an
//! app, whose a host is, which claims are first party, and what the
//! headline counts.
//!
//! The bundles are written here, into a temporary folder: a property list,
//! a main executable whose code signature names a Team ID or none, and
//! empty framework folders. Nothing in them can run. The built-in pack
//! decides what they mean, so these tests also pin what the pack lists for
//! the companies involved.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "tests run the binary and may read the environment"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use xs_formats::macho_build::{self, Binary};
use xs_model::claim::{Vendor, VendorBasis};
use xs_model::record::{Grade, ObjectKind, Record};
use xs_model::{Claim, Confidence, Headline, Party, Report};

const ELECTRON_FIXTURE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/macos/ElectronSkeleton.app");

/// The Team ID the pack lists for Microsoft.
const MICROSOFT_TEAM: &str = "UBF8T346G9";
/// NetNewsWire's Team ID, which the pack does not list.
const UNLISTED_TEAM: &str = "M8L2WTLA8W";

/// A bundle to write.
struct Bundle<'a> {
    id: &'a str,
    /// The Team ID the signature of the main executable names.
    team: Option<&'a str>,
    /// The address of the update feed in the property list.
    feed: Option<&'a str>,
    /// Folders under `Contents/Frameworks`.
    frameworks: &'a [&'a str],
}

impl Bundle<'_> {
    /// Writes the bundle as `<parent>/<name>.app`.
    fn write(&self, parent: &Path, name: &str) -> PathBuf {
        let root = parent.join(format!("{name}.app"));
        let contents = root.join("Contents");
        fs::create_dir_all(contents.join("MacOS")).unwrap();
        let feed = self
            .feed
            .map(|address| format!("<key>SUFeedURL</key><string>{address}</string>"))
            .unwrap_or_default();
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Main</string>
<key>CFBundleIdentifier</key><string>{}</string>
<key>CFBundleName</key><string>{name}</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
{feed}
</dict></plist>
"#,
            self.id
        );
        fs::write(contents.join("Info.plist"), plist).unwrap();
        let binary = match self.team {
            Some(team) => {
                Binary::new().signature(&macho_build::signature(self.id, Some(team))).build()
            }
            None => Binary::new().build(),
        };
        fs::write(contents.join("MacOS/Main"), binary).unwrap();
        for framework in self.frameworks {
            fs::create_dir_all(contents.join("Frameworks").join(framework)).unwrap();
        }
        root
    }
}

/// Scans `paths` and returns the report with the terminal summary.
fn scan(paths: &[&Path]) -> (Report, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
        .args(["scan", "--no-cache", "--threads", "2"])
        .args(paths)
        .output()
        .unwrap();
    let summary = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{summary}");
    (serde_json::from_slice(&output.stdout).unwrap(), summary)
}

fn scan_one(bundle: &Bundle<'_>) -> Report {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle.write(dir.path(), "App");
    scan(&[&root]).0
}

fn claim<'a>(report: &'a Report, object: &str) -> &'a Claim {
    report
        .claims
        .iter()
        .find(|claim| claim.object.id == object)
        .unwrap_or_else(|| panic!("no claim about {object}: {:#?}", report.claims))
}

/// The vendor of an app no listed company publishes.
fn unlisted(domain: &str) -> Option<Vendor> {
    Some(Vendor { company: None, by: None, domain: Some(domain.into()), evidence: vec![] })
}

fn headline(contacts: u32, contains: u32, apps: u32) -> Headline {
    Headline { companies_contacts: contacts, companies_contains: contains, apps_third_party: apps }
}

/// Build plan, task 10: "NetNewsWire's feed grades first party." The app
/// id, the Team ID and the feed address are those of NetNewsWire 7.2.1; the
/// real bundle is checked in `real_apps.rs` when the fixture cache is set.
#[test]
fn a_feed_on_the_app_s_own_domain_grades_first_party() {
    let report = scan_one(&Bundle {
        id: "com.ranchero.NetNewsWire-Evergreen",
        team: Some(UNLISTED_TEAM),
        feed: Some("https://ranchero.com/downloads/netnewswire-release.xml"),
        frameworks: &[],
    });
    assert_eq!(report.claims.len(), 1, "{:#?}", report.claims);
    let feed = claim(&report, "ranchero.com");
    assert_eq!(feed.object.kind, ObjectKind::Host);
    assert_eq!(feed.category, "update_feed");
    assert_eq!(feed.grade, Grade::Declares);
    assert_eq!(feed.confidence, Confidence::High);
    assert_eq!(feed.party, Party::First);
    // Nobody the pack lists publishes the app. The domain is its own word.
    assert_eq!(feed.vendor, unlisted("ranchero.com"));
    assert_eq!(feed.company, None);
    assert!(!feed.headline);
    assert_eq!(report.headline, headline(0, 0, 0));
}

/// Build plan, task 10: "An unmapped domain is shown and not counted."
#[test]
fn an_unmapped_domain_is_shown_and_not_counted() {
    let dir = tempfile::tempdir().unwrap();
    let root = Bundle {
        id: "org.example.diary",
        team: None,
        feed: Some("https://updates.example.net/diary/appcast.xml"),
        frameworks: &[],
    }
    .write(dir.path(), "Diary");
    let (report, summary) = scan(&[&root]);

    // Shown: as itself, with its grade and the record behind it.
    assert_eq!(report.claims.len(), 1, "{:#?}", report.claims);
    let host = claim(&report, "updates.example.net");
    assert_eq!(host.object.name, "updates.example.net");
    assert_eq!(host.grade, Grade::Declares);
    assert!(matches!(report.evidence.get(&host.evidence[0]), Some(Record::Edge(_))));
    // Unmapped: nobody is named as its owner, so nobody is first or third
    // party to it.
    assert_eq!(host.company, None);
    assert_eq!(host.party, Party::Unknown);
    assert_eq!(host.vendor, unlisted("example.org"));
    // Not counted.
    assert!(!host.headline);
    assert_eq!(report.headline, headline(0, 0, 0));
    assert!(
        summary.contains(
            "headline: 0 companies at contacts or above, 0 companies at contains, \
             0 apps with a third-party channel"
        ),
        "{summary}"
    );
}

/// Project spec, spike table: "Maccy: Update feed hosted on GitHub". The
/// host is GitHub's, GitHub is Microsoft's, and hosting is not receiving.
#[test]
fn a_feed_on_a_listed_company_s_host_names_the_company_and_is_not_counted() {
    let report = scan_one(&Bundle {
        id: "org.p0deje.Maccy",
        team: None,
        feed: Some("https://raw.githubusercontent.com/p0deje/Maccy/master/appcast.xml"),
        frameworks: &[],
    });
    let feed = claim(&report, "raw.githubusercontent.com");
    assert_eq!(feed.object.name, "raw.githubusercontent.com", "still shown as itself");
    assert_eq!(feed.company.as_deref(), Some("microsoft"), "the top of the ownership chain");
    assert_eq!(feed.party, Party::Third);
    assert_eq!(feed.category, "update_feed");
    assert!(!feed.headline);
    assert_eq!(report.headline, headline(0, 0, 0));
}

/// Design report, section 3, M5: the vendor is read from the signature
/// first. The claim cites the record that holds the Team ID.
#[test]
fn an_app_signed_by_a_listed_team_is_first_party_to_that_company() {
    let report = scan_one(&Bundle {
        id: "org.example.unrelated",
        team: Some(MICROSOFT_TEAM),
        feed: Some("https://download.microsoft.com/appcast.xml"),
        frameworks: &["AppCenter.framework", "Sentry.framework"],
    });

    let own = claim(&report, "sdk/appcenter");
    assert_eq!(own.company.as_deref(), Some("microsoft"));
    assert_eq!(own.party, Party::First);
    let vendor = own.vendor.as_ref().unwrap();
    assert_eq!(vendor.company.as_deref(), Some("microsoft"));
    assert_eq!(vendor.by, Some(VendorBasis::TeamId));
    assert_eq!(vendor.evidence.len(), 1);
    let Some(Record::Artifact(artifact)) = report.evidence.get(&vendor.evidence[0]) else {
        panic!("the vendor cites a record the report does not carry");
    };
    assert_eq!(artifact.facts.team_id.as_deref(), Some(MICROSOFT_TEAM));
    assert_eq!(artifact.subject, own.subject);

    assert_eq!(claim(&report, "download.microsoft.com").party, Party::First);
    let other = claim(&report, "sdk/sentry");
    assert_eq!(other.party, Party::Third);
    assert_eq!(other.vendor, own.vendor);
}

/// The app id comes second, and is not believed against a signature.
#[test]
fn the_app_id_names_the_vendor_only_when_no_signature_says_otherwise() {
    let app = |team| Bundle {
        id: "com.microsoft.Example",
        team,
        feed: None,
        frameworks: &["AppCenter.framework"],
    };

    let unsigned = scan_one(&app(None));
    let own = claim(&unsigned, "sdk/appcenter");
    assert_eq!(own.party, Party::First);
    assert_eq!(
        own.vendor,
        Some(Vendor {
            company: Some("microsoft".into()),
            by: Some(VendorBasis::AppId),
            domain: Some("microsoft.com".into()),
            evidence: vec![],
        })
    );

    // The pack lists Microsoft's Team ID, and this signature names another:
    // the app does not become Microsoft's by calling itself so.
    let lookalike = scan_one(&app(Some(UNLISTED_TEAM)));
    let claim = claim(&lookalike, "sdk/appcenter");
    assert_eq!(claim.vendor, None);
    assert_eq!(claim.party, Party::Unknown);
}

/// Design report, section 3, A7: of the fixed list of categories only
/// advertising, analytics, attribution, profiling and session replay count.
#[test]
fn the_built_in_pack_counts_exactly_five_categories() {
    let pack: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rules/dist/core.pack.json"
    )))
    .unwrap();
    let mut counted: Vec<&str> = pack["categories"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|category| category["headline"] == true)
        .map(|category| category["id"].as_str().unwrap())
        .collect();
    counted.sort_unstable();
    assert_eq!(counted, ["advertising", "analytics", "attribution", "profiling", "session_replay"]);
}

#[test]
fn the_headline_counts_companies_and_apps_in_the_tracking_categories_only() {
    let dir = tempfile::tempdir().unwrap();
    // Microsoft's own app with Microsoft's analytics: the company has the
    // channel, and it is nobody's third party.
    let own = Bundle {
        id: "com.microsoft.Example",
        team: Some(MICROSOFT_TEAM),
        feed: None,
        frameworks: &["AppCenterAnalytics.framework"],
    }
    .write(dir.path(), "Own");
    // Crash reporting, a component and an update feed: in the report, and
    // in no count.
    let quiet = Bundle {
        id: "org.example.quiet",
        team: None,
        feed: Some("https://raw.githubusercontent.com/example/quiet/main/appcast.xml"),
        frameworks: &["Sentry.framework", "Sparkle.framework", "AppCenterCrashes.framework"],
    }
    .write(dir.path(), "Quiet");
    // The Electron fixture bundles PostHog (analytics) and Sentry.
    let (report, summary) = scan(&[&own, &quiet, Path::new(ELECTRON_FIXTURE)]);

    let counted: Vec<(&str, &str, Party)> = report
        .claims
        .iter()
        .filter(|claim| claim.headline)
        .map(|claim| (claim.subject.id.as_str(), claim.object.id.as_str(), claim.party))
        .collect();
    assert_eq!(
        counted,
        [
            ("com.microsoft.Example", "sdk/appcenter-analytics", Party::First),
            ("org.example.exposure.electron-skeleton", "sdk/posthog", Party::Third),
        ]
    );
    assert_eq!(report.claims.len(), 7, "{:#?}", report.claims);
    for claim in report.claims.iter().filter(|claim| !claim.headline) {
        let category = claim.category.as_str();
        assert!(
            ["crash_reporting", "component", "update_feed"].contains(&category),
            "{} is not counted",
            claim.object.id
        );
    }
    assert_eq!(report.headline, headline(0, 2, 1));
    assert_eq!(report.headline, Headline::of(&report.claims));
    assert!(
        summary.contains(
            "headline: 0 companies at contacts or above, 2 companies at contains, \
             1 app with a third-party channel"
        ),
        "{summary}"
    );
    // The summary still names no app and no company.
    for name in ["microsoft", "posthog", "Microsoft", "PostHog", "Quiet", "example"] {
        assert!(!summary.contains(name), "{summary}");
    }
}
