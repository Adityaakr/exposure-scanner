//! What an app may access, from the outside: the `exposure` binary scans a
//! macOS bundle and an Android package that ask for permissions, and the
//! report states each one as an access claim that shows its evidence.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "tests run the binary and may read the environment"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use xs_formats::macho_build::{Binary, entitlements_part, entitlements_plist, signature_with};
use xs_formats::testkit::{ANDROID_NAME, Attr, AxmlBuilder, ZipBuilder};
use xs_model::record::{EdgeType, Grade, ObjectKind, Platform, Record};
use xs_model::{Claim, Confidence, Headline, MatcherKind, Party, Report, access};

fn exposure(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_exposure")).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "exit {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A video-call app: it asks for the camera and the microphone in both
/// places, for the screen's sound in one, and is sandboxed with leave to
/// open connections.
fn call_app(parent: &Path) -> PathBuf {
    let root = parent.join("Calls.app");
    let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>org.example.calls</string>
<key>CFBundleShortVersionString</key><string>3.1</string>
<key>CFBundleName</key><string>Calls</string>
<key>CFBundleExecutable</key><string>Calls</string>
<key>NSCameraUsageDescription</key><string>Calls shows you to the people you call.</string>
<key>NSMicrophoneUsageDescription</key><string>Calls lets the people you call hear you.</string>
<key>NSAudioCaptureUsageDescription</key><string>Calls shares the sound of your screen.</string>
</dict></plist>"#;
    write(&root.join("Contents/Info.plist"), plist);
    let granted = entitlements_plist(&[
        "com.apple.security.app-sandbox",
        "com.apple.security.device.camera",
        "com.apple.security.device.audio-input",
        "com.apple.security.network.client",
    ]);
    let signature =
        signature_with("org.example.calls", Some("ABCDE12345"), &[entitlements_part(&granted)]);
    write(&root.join("Contents/MacOS/Calls"), Binary::new().signature(&signature).build());
    root
}

/// The same app for Android.
fn call_package(parent: &Path) -> PathBuf {
    let mut manifest =
        AxmlBuilder::new().start("manifest", &[Attr::plain("package", "org.example.calls")]);
    for name in [
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
        "android.permission.WAKE_LOCK",
    ] {
        manifest =
            manifest.start("uses-permission", &[Attr::android(ANDROID_NAME, "name", name)]).end();
    }
    let manifest = manifest.start("application", &[]).end().end().finish();
    let path = parent.join("calls.apk");
    write(&path, ZipBuilder::new().deflated("AndroidManifest.xml", &manifest).finish());
    path
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// The permissions `platform`'s build of the app may access, by id.
fn may_access(report: &Report, platform: Platform) -> Vec<&Claim> {
    report
        .claims
        .iter()
        .filter(|claim| claim.edge == EdgeType::Access && claim.subject.platform == platform)
        .collect()
}

#[test]
fn the_report_says_what_each_app_may_access_and_shows_why() {
    let dir = tempfile::tempdir().unwrap();
    let (app, apk) = (call_app(dir.path()), call_package(dir.path()));
    let json = exposure(&["scan", text(&app), text(&apk)]);
    let report: Report = serde_json::from_str(&json).unwrap();

    let mac = may_access(&report, Platform::Macos);
    let ids = |claims: &[&Claim]| -> Vec<String> {
        claims.iter().map(|claim| claim.object.id.clone()).collect()
    };
    assert_eq!(ids(&mac), ["camera", "microphone", "network-client", "system-audio"]);
    let android = may_access(&report, Platform::Android);
    assert_eq!(ids(&android), ["camera", "contacts", "microphone", "network-client"]);

    for claim in mac.iter().chain(&android) {
        // "May access": the app asks for it. That is all the files say.
        assert_eq!(claim.grade, Grade::Requested);
        assert_eq!(claim.rungs, [Grade::Requested]);
        assert_eq!(claim.confidence, Confidence::High);
        assert_eq!(claim.object.kind, ObjectKind::Permission);
        // Nobody is named as receiving anything, and no headline number
        // moves.
        assert_eq!(claim.company, None);
        assert_eq!(claim.party, Party::Unknown);
        assert!(!claim.headline);
        // The claim is worded from the fixed list of permissions.
        let permission = access::permission(&claim.object.id).unwrap();
        assert_eq!(claim.object.name, permission.name);
        assert_eq!(claim.category, permission.category);
        assert!(access::category(&claim.category).is_some());
        // Honest: every claim shows the declaration it rests on.
        assert!(!claim.evidence.is_empty());
        for id in &claim.evidence {
            let Some(Record::Edge(edge)) = report.evidence.get(id) else {
                panic!("the claim cites a record the report does not carry");
            };
            assert_eq!(
                access::declared(edge.proof.matcher, &edge.proof.token).map(|asked| asked.id),
                Some(claim.object.id.as_str())
            );
        }
    }
    assert_eq!(report.headline, Headline::default());

    // The sentence a report can now write: "Calls may access your camera,
    // your microphone, ...", each with the app's own stated purpose.
    let phrases: Vec<&str> =
        mac.iter().map(|claim| access::permission(&claim.object.id).unwrap().phrase).collect();
    assert_eq!(
        phrases,
        [
            "your camera",
            "your microphone",
            "the network, to open connections",
            "the sound your device plays"
        ]
    );
    let camera = mac[0];
    assert_eq!(camera.witnesses, 2, "a usage description and an entitlement");
    let purposes: Vec<&str> = camera
        .evidence
        .iter()
        .filter_map(|id| match report.evidence.get(id) {
            Some(Record::Edge(edge)) if edge.proof.matcher == MatcherKind::UsageDescription => {
                edge.proof.example.as_deref()
            }
            _ => None,
        })
        .collect();
    assert_eq!(purposes, ["Calls shows you to the people you call."]);

    // The sandbox is a fact about the bundle, beside its Team ID.
    let sandboxes: Vec<(Platform, Option<bool>)> = report
        .evidence
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Artifact(artifact) => Some((artifact.subject.platform, artifact.facts.sandbox)),
            _ => None,
        })
        .collect();
    assert_eq!(sandboxes.len(), 2);
    assert!(sandboxes.contains(&(Platform::Macos, Some(true))));
    assert!(sandboxes.contains(&(Platform::Android, None)));

    // Nothing was skipped, and where the artifacts sit is not in the report.
    assert!(!report.evidence.iter().any(|(_, record)| matches!(record, Record::Coverage(_))));
    assert!(!json.contains(text(dir.path())));
}

/// Design report, section 7: the same bytes for any thread count and any
/// order of the paths, and again when rendered from the saved evidence.
#[test]
fn the_report_is_the_same_bytes_however_it_is_made() {
    let dir = tempfile::tempdir().unwrap();
    let (app, apk) = (call_app(dir.path()), call_package(dir.path()));
    let first = exposure(&["scan", "--threads", "1", text(&app), text(&apk)]);
    let second = exposure(&["scan", "--threads", "4", text(&apk), text(&app)]);
    assert!(first == second, "thread count or path order reached the report");

    let saved = dir.path().join("report.json");
    fs::write(&saved, &first).unwrap();
    let again = exposure(&["report", text(&saved)]);
    assert!(first == again, "rendering from saved evidence changed the report");
}

/// Evidence that was edited after the scan is refused: an access edge must
/// rest on a key that asks for the permission it points at.
#[test]
fn an_edited_access_edge_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let json = exposure(&["scan", text(&call_app(dir.path()))]);
    assert!(json.contains("\"id\":\"camera\",\"kind\":\"permission\""));
    let edited = json.replace(
        "\"id\":\"camera\",\"kind\":\"permission\"",
        "\"id\":\"contacts\",\"kind\":\"permission\"",
    );
    let saved = dir.path().join("edited.json");
    fs::write(&saved, edited).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
        .args(["report", text(&saved)])
        .output()
        .unwrap();
    assert!(!output.status.success());
}
