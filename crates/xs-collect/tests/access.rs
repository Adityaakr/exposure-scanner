//! What an app may access: the permissions a macOS bundle asks for in its
//! property list and in the signature of its main executable, and the ones
//! an Android package asks for in its manifest.
//!
//! Every artifact here is synthetic and built in a temporary folder, so
//! each expectation follows from what the test itself put into it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]

use std::fs;
use std::path::{Path, PathBuf};

use xs_collect::{ScanOptions, scan};
use xs_formats::macho_build::{
    self, Binary, SLOT_DER_ENTITLEMENTS, entitlements_part, entitlements_plist, fat, signature_with,
};
use xs_formats::testkit::{ANDROID_NAME, Attr, AxmlBuilder, ZipBuilder};
use xs_match::Matchers;
use xs_model::pack::{Category, Layer, LoadedLayer};
use xs_model::record::{
    Collector, CoverageReason, CoverageStatus, EdgeRecord, EdgeType, Grade, ObjectKind, Record,
    Region, Scope, V1,
};
use xs_model::{EvidenceSet, MatcherKind, Pack, Sha256Digest, canon};

const SANDBOX: &str = "com.apple.security.app-sandbox";
const CAMERA: &str = "com.apple.security.device.camera";
const AUDIO_INPUT: &str = "com.apple.security.device.audio-input";
const NETWORK_CLIENT: &str = "com.apple.security.network.client";
const MAIN: &str = "Contents/MacOS/Example";
const INFO_PLIST: &str = "Contents/Info.plist";

/// A pack with no rules: what an app asks for is found without one.
fn pack() -> Pack {
    let layer = Layer {
        format: V1,
        layer: "core".into(),
        version: 1,
        license: "CC-BY-4.0".into(),
        categories: vec![Category {
            id: "component".into(),
            name: "Component".into(),
            headline: false,
        }],
        entities: vec![],
        rules: vec![],
    };
    Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
}

fn evidence_with(paths: &[PathBuf], threads: usize) -> EvidenceSet {
    let pack = pack();
    scan(paths, &Matchers::build(&pack).unwrap(), ScanOptions { threads }).unwrap().evidence
}

fn evidence(path: &Path) -> EvidenceSet {
    evidence_with(&[path.to_path_buf()], 2)
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn info_plist(extra: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.app</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
<key>CFBundleName</key><string>Example</string>
<key>CFBundleExecutable</key><string>Example</string>
{extra}
</dict></plist>"#
    )
}

fn usage(key: &str, purpose: &str) -> String {
    format!("<key>{key}</key><string>{purpose}</string>")
}

/// A bundle whose main executable is `main` and whose property list holds
/// `extra` keys.
fn bundle(parent: &Path, main: &[u8], extra: &str) -> PathBuf {
    let root = parent.join("Example.app");
    write(&root.join(INFO_PLIST), info_plist(extra));
    write(&root.join(MAIN), main);
    root
}

/// A Mach-O file whose signature carries `parts` after its code directory.
fn signed_with(parts: &[(u32, Vec<u8>)]) -> Vec<u8> {
    Binary::new().signature(&signature_with("com.example.app", Some("ABCDE12345"), parts)).build()
}

/// A Mach-O file whose signature grants `keys`.
fn entitled(keys: &[&str]) -> Vec<u8> {
    signed_with(&[entitlements_part(&entitlements_plist(keys))])
}

fn access(evidence: &EvidenceSet) -> Vec<&EdgeRecord> {
    evidence
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Edge(edge) if edge.edge == EdgeType::Access => Some(edge),
            _ => None,
        })
        .collect()
}

/// `(permission, matcher, key, count)` of every access edge, sorted.
fn asked(evidence: &EvidenceSet) -> Vec<(&str, MatcherKind, &str, u32)> {
    let mut asked: Vec<_> = access(evidence)
        .iter()
        .map(|edge| {
            (
                edge.object.id.as_str(),
                edge.proof.matcher,
                edge.proof.token.as_str(),
                edge.proof.count,
            )
        })
        .collect();
    asked.sort();
    asked
}

/// `(where, status, reason, count)` of every coverage record, sorted.
fn gaps(evidence: &EvidenceSet) -> Vec<(String, CoverageStatus, CoverageReason, u32)> {
    let mut gaps: Vec<_> = evidence
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Coverage(gap) => Some((
                gap.location.as_ref().map(ToString::to_string).unwrap_or_default(),
                gap.status,
                gap.reason,
                gap.count,
            )),
            _ => None,
        })
        .collect();
    gaps.sort();
    gaps
}

fn sandbox(evidence: &EvidenceSet) -> Option<bool> {
    evidence
        .iter()
        .find_map(|(_, record)| match record {
            Record::Artifact(artifact) => Some(artifact.facts.sandbox),
            _ => None,
        })
        .unwrap()
}

/// The whole set as text, to look for what must not be in it.
fn text_of(evidence: &EvidenceSet) -> String {
    canon::to_string(evidence).unwrap()
}

/// The finding the task is named for: an app that asks for the camera says
/// so twice, with the sentence macOS would show, and both are recorded as
/// what the app may access.
#[test]
fn a_bundle_says_what_it_asks_for_in_its_property_list_and_its_signature() {
    let dir = tempfile::tempdir().unwrap();
    let extra = [
        usage("NSCameraUsageDescription", "Example uses the camera\n\t  for video calls."),
        usage("NSMicrophoneUsageDescription", ""),
        usage("NSLocationWhenInUseUsageDescription", "To show nearby places."),
        usage("NSLocationUsageDescription", "To show nearby places."),
    ]
    .concat();
    let main = entitled(&[SANDBOX, CAMERA, AUDIO_INPUT, NETWORK_CLIENT, "keychain-access-groups"]);
    let evidence = evidence(&bundle(dir.path(), &main, &extra));

    use MatcherKind::{Entitlement, UsageDescription};
    assert_eq!(
        asked(&evidence),
        [
            ("camera", UsageDescription, "NSCameraUsageDescription", 1),
            ("camera", Entitlement, CAMERA, 1),
            ("location", UsageDescription, "NSLocationUsageDescription", 1),
            ("location", UsageDescription, "NSLocationWhenInUseUsageDescription", 1),
            ("microphone", UsageDescription, "NSMicrophoneUsageDescription", 1),
            ("microphone", Entitlement, AUDIO_INPUT, 1),
            ("network-client", Entitlement, NETWORK_CLIENT, 1),
        ]
    );
    assert_eq!(sandbox(&evidence), Some(true));
    assert_eq!(gaps(&evidence), []);

    for edge in access(&evidence) {
        // "May access": the app asks. Nothing here says the user agreed.
        assert_eq!(edge.grade, Grade::Requested);
        assert_eq!(edge.object.kind, ObjectKind::Permission);
        assert_eq!(edge.collector, Collector::MacosBundle);
        assert_eq!(edge.proof.scope, Scope::AppCode);
        let (rule, place, region) = match edge.proof.matcher {
            UsageDescription => ("access/usage-description", INFO_PLIST, Region::PropertyList),
            _ => ("access/entitlement", MAIN, Region::Entitlements),
        };
        assert_eq!(edge.rule, rule);
        assert_eq!(edge.proof.location.as_str(), place);
        assert_eq!(edge.proof.region, region);
    }
    // The purpose is the app's own sentence, on one line. One left empty
    // is none, and an entitlement states none.
    let purpose = |key: &str| {
        let edge = access(&evidence).into_iter().find(|edge| edge.proof.token == key).unwrap();
        edge.proof.example.clone()
    };
    assert_eq!(
        purpose("NSCameraUsageDescription").as_deref(),
        Some("Example uses the camera for video calls.")
    );
    assert_eq!(purpose("NSMicrophoneUsageDescription"), None);
    assert_eq!(purpose(CAMERA), None);
}

/// A usage description for something this build has no name for is counted
/// as not understood, never dropped, and a hostile purpose is made safe.
#[test]
fn an_unknown_usage_description_is_a_gap_and_a_hostile_purpose_is_cleaned() {
    let dir = tempfile::tempdir().unwrap();
    let long = "why ".repeat(200);
    let extra = [
        usage("NSFutureSenseUsageDescription", "Something new."),
        usage("NSOtherThingUsageDescription", "Something else."),
        usage("NSContactsUsageDescription", &long),
        usage("NSCalendarsUsageDescription", "a&#x202e;b&#27;[2Jc"),
        // A value that is no text declares nothing readable.
        "<key>NSRemindersUsageDescription</key><true/>".to_string(),
    ]
    .concat();
    let evidence = evidence(&bundle(dir.path(), &entitled(&[]), &extra));

    use MatcherKind::UsageDescription;
    assert_eq!(
        asked(&evidence),
        [
            ("calendars", UsageDescription, "NSCalendarsUsageDescription", 1),
            ("contacts", UsageDescription, "NSContactsUsageDescription", 1),
        ]
    );
    assert_eq!(
        gaps(&evidence),
        [(
            INFO_PLIST.to_string(),
            CoverageStatus::Unrecognized,
            CoverageReason::UnrecognizedRecord,
            2
        )]
    );
    let purposes: Vec<&str> =
        access(&evidence).iter().filter_map(|edge| edge.proof.example.as_deref()).collect();
    assert_eq!(purposes.len(), 2);
    for purpose in purposes {
        assert!(purpose.len() <= 160, "{purpose}");
        assert!(!purpose.chars().any(|c| c.is_control() || c == '\u{202e}'), "{purpose:?}");
    }
    assert!(!text_of(&evidence).contains("NSFutureSense"), "an unknown key is counted, not kept");
}

/// An entitlement can hold a list of paths on the user's disk. The record
/// says how many, and never which.
#[test]
fn a_list_entitlement_is_counted_and_its_entries_are_not_kept() {
    let dir = tempfile::tempdir().unwrap();
    let plist = r#"<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.temporary-exception.files.home-relative-path.read-write</key>
<array><string>/Library/Secrets/</string><string>/Documents/Private/</string></array>
<key>com.apple.security.temporary-exception.apple-events</key>
<array><string>com.apple.finder</string></array>
<key>com.apple.security.device.usb</key><false/>
<key>com.apple.security.files.downloads.read-only</key><array/>
</dict></plist>"#;
    let main = signed_with(&[entitlements_part(plist)]);
    let evidence = evidence(&bundle(dir.path(), &main, ""));

    use MatcherKind::Entitlement;
    assert_eq!(
        asked(&evidence),
        [
            ("automation", Entitlement, "com.apple.security.temporary-exception.apple-events", 1),
            (
                "sandbox-exception-files",
                Entitlement,
                "com.apple.security.temporary-exception.files.home-relative-path.read-write",
                2
            ),
        ]
    );
    let text = text_of(&evidence);
    for kept in ["Secrets", "Private", "com.apple.finder"] {
        assert!(!text.contains(kept), "{kept}");
    }
}

/// Outside the sandbox no entitlement limits the app's files or its use of
/// the network, so that it is outside is a fact of its own.
#[test]
fn whether_the_app_asks_for_the_sandbox_is_a_fact_about_it() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox_of = |main: &[u8]| sandbox(&evidence(&bundle(dir.path(), main, "")));

    assert_eq!(sandbox_of(&entitled(&[SANDBOX, CAMERA])), Some(true));
    // Hardened runtime, no sandbox: the usual app from outside the store.
    assert_eq!(sandbox_of(&entitled(&[CAMERA])), Some(false));
    // A signature with no entitlements at all, and no signature at all.
    assert_eq!(sandbox_of(&signed_with(&[])), Some(false));
    assert_eq!(sandbox_of(&Binary::new().build()), Some(false));
    // Set to false is not asked for.
    let off = r#"<plist version="1.0"><dict>
<key>com.apple.security.app-sandbox</key><false/></dict></plist>"#;
    assert_eq!(sandbox_of(&signed_with(&[entitlements_part(off)])), Some(false));
}

/// A universal file has a signature per image. What any image asks for the
/// app may access; whether it is sandboxed is only said when all agree.
#[test]
fn the_images_of_a_universal_executable_are_read_together() {
    let dir = tempfile::tempdir().unwrap();
    let scan_of = |images: [&[u8]; 2]| evidence(&bundle(dir.path(), &fat(&images, false), ""));

    let both = scan_of([&entitled(&[SANDBOX, CAMERA]), &entitled(&[SANDBOX, AUDIO_INPUT])]);
    use MatcherKind::Entitlement;
    assert_eq!(
        asked(&both),
        [("camera", Entitlement, CAMERA, 1), ("microphone", Entitlement, AUDIO_INPUT, 1)]
    );
    assert_eq!(sandbox(&both), Some(true));

    let mixed = scan_of([&entitled(&[SANDBOX, CAMERA]), &entitled(&[CAMERA])]);
    assert_eq!(asked(&mixed), [("camera", Entitlement, CAMERA, 1)]);
    assert_eq!(sandbox(&mixed), None, "the images disagree");
}

/// Only the main executable speaks for the app. A helper's entitlements
/// are the helper's.
#[test]
fn the_entitlements_of_a_helper_are_not_the_app_s() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), &entitled(&[SANDBOX]), "");
    let helper = "Contents/Frameworks/Helper.app/Contents";
    write(&root.join(helper).join("MacOS/Helper"), entitled(&[CAMERA, NETWORK_CLIENT]));
    write(
        &root.join(helper).join("Info.plist"),
        info_plist(&usage("NSCameraUsageDescription", "The helper's.")),
    );
    let evidence = evidence(&root);
    assert_eq!(asked(&evidence), []);
    assert_eq!(sandbox(&evidence), Some(true));
    assert_eq!(gaps(&evidence), []);
}

/// "Nothing asked for" must not be confused with "not looked at": a
/// signature that could not be read leaves a record, and the sandbox
/// unknown.
#[test]
fn a_signature_that_cannot_be_read_is_reported_and_decides_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let scan_of = |main: &[u8]| evidence(&bundle(dir.path(), main, ""));
    let gap = |status, reason| vec![(MAIN.to_string(), status, reason, 1)];

    // Entitlements in the DER form alone: a form this build does not read.
    let der_only = scan_of(&signed_with(&[(SLOT_DER_ENTITLEMENTS, vec![0x70, 0x00])]));
    assert_eq!(asked(&der_only), []);
    assert_eq!(sandbox(&der_only), None);
    assert_eq!(gaps(&der_only), gap(CoverageStatus::Skipped, CoverageReason::UnsupportedFormat));

    // A damaged list of entitlements.
    let damaged = scan_of(&signed_with(&[entitlements_part("<plist><dict><key>")]));
    assert_eq!(asked(&damaged), []);
    assert_eq!(sandbox(&damaged), None);
    assert_eq!(gaps(&damaged), gap(CoverageStatus::Unrecognized, CoverageReason::ParseError));

    // One image readable, one not: what was read counts, the rest is unknown.
    let half = fat(&[&entitled(&[SANDBOX, CAMERA]), &signed_with(&[(5, b"junk".to_vec())])], false);
    let half = scan_of(&half);
    assert_eq!(asked(&half), [("camera", MatcherKind::Entitlement, CAMERA, 1)]);
    assert_eq!(sandbox(&half), None);
    assert_eq!(gaps(&half), gap(CoverageStatus::Unrecognized, CoverageReason::ParseError));
}

/// A main executable that is a link is never followed, and one that is a
/// script has no signature inside it. Either way the signature was not
/// looked at, and the report says so.
#[test]
fn a_main_executable_that_is_no_mach_o_file_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let unread =
        vec![(MAIN.to_string(), CoverageStatus::Skipped, CoverageReason::UnsupportedFormat, 1)];

    let script = evidence(&bundle(dir.path(), b"#!/bin/sh\nexec true\n", ""));
    assert_eq!(sandbox(&script), None);
    assert_eq!(gaps(&script), unread);

    let outside = dir.path().join("elsewhere");
    write(&outside, entitled(&[SANDBOX, CAMERA]));
    let root = bundle(dir.path(), b"", &usage("NSCameraUsageDescription", "For calls."));
    fs::remove_file(root.join(MAIN)).unwrap();
    std::os::unix::fs::symlink(&outside, root.join(MAIN)).unwrap();
    let linked = evidence(&root);
    // What the property list asks for is still found.
    assert_eq!(
        asked(&linked),
        [("camera", MatcherKind::UsageDescription, "NSCameraUsageDescription", 1)]
    );
    assert_eq!(sandbox(&linked), None);
    assert_eq!(gaps(&linked), unread);
}

fn permission(name: &str) -> (&'static str, Vec<Attr>) {
    ("uses-permission", vec![Attr::android(ANDROID_NAME, "name", name)])
}

/// A package whose manifest asks for `permissions`.
fn package(path: &Path, permissions: &[&str]) -> PathBuf {
    let mut manifest =
        AxmlBuilder::new().start("manifest", &[Attr::plain("package", "org.example.droid")]);
    for name in permissions {
        let (element, attributes) = permission(name);
        manifest = manifest.start(element, &attributes).end();
    }
    let manifest = manifest.start("application", &[]).end().end().finish();
    write(path, ZipBuilder::new().deflated("AndroidManifest.xml", &manifest).finish());
    path.to_path_buf()
}

/// Android: the permissions of the manifest that reach the user's data or
/// devices, each name once. The rest is plumbing and is no finding.
#[test]
fn a_package_says_what_it_asks_for_in_its_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let apk = package(
        &dir.path().join("droid.apk"),
        &[
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.INTERNET",
            "com.google.android.gms.permission.AD_ID",
            "android.permission.health.READ_HEART_RATE",
            "android.permission.CAMERA",
            "android.permission.VIBRATE",
            "android.permission.POST_NOTIFICATIONS",
            "org.example.droid.permission.OWN",
        ],
    );
    let evidence = evidence(&apk);

    use MatcherKind::AndroidPermission as Android;
    assert_eq!(
        asked(&evidence),
        [
            ("advertising-id", Android, "com.google.android.gms.permission.AD_ID", 1),
            ("camera", Android, "android.permission.CAMERA", 1),
            ("contacts", Android, "android.permission.READ_CONTACTS", 1),
            ("health", Android, "android.permission.health.READ_HEART_RATE", 1),
            ("location", Android, "android.permission.ACCESS_COARSE_LOCATION", 1),
            ("location", Android, "android.permission.ACCESS_FINE_LOCATION", 1),
            ("location-background", Android, "android.permission.ACCESS_BACKGROUND_LOCATION", 1),
            ("network-client", Android, "android.permission.INTERNET", 1),
        ]
    );
    for edge in access(&evidence) {
        assert_eq!(edge.grade, Grade::Requested);
        assert_eq!(edge.collector, Collector::AndroidManifest);
        assert_eq!(edge.rule, "access/android-permission");
        assert_eq!(edge.proof.location.as_str(), "AndroidManifest.xml");
        assert_eq!(edge.proof.region, Region::Permissions);
        assert_eq!(edge.proof.example, None);
    }
    assert_eq!(gaps(&evidence), []);
    // The sandbox of a macOS bundle is no fact about a package.
    assert_eq!(sandbox(&evidence), None);
}

/// One evidence set whatever the thread count and the order of the paths,
/// and every record in it is one the format accepts.
#[test]
fn what_is_found_does_not_depend_on_threads_or_order() {
    let dir = tempfile::tempdir().unwrap();
    let extra = usage("NSCameraUsageDescription", "For calls.");
    let app = bundle(dir.path(), &entitled(&[SANDBOX, CAMERA, NETWORK_CLIENT]), &extra);
    let apk = package(&dir.path().join("droid.apk"), &["android.permission.RECORD_AUDIO"]);

    let forward = evidence_with(&[app.clone(), apk.clone()], 1);
    let backward = evidence_with(&[apk, app], 4);
    assert_eq!(forward, backward);
    assert_eq!(access(&forward).len(), 4);
    for (_, record) in &forward {
        record.validate().unwrap();
    }
    // Where the artifacts sit on disk is in no record.
    assert!(!text_of(&forward).contains(dir.path().to_str().unwrap()));
}

/// The signature builder lays a signature out as the signing tool does:
/// the test above reads entitlements that lie after the code directory.
#[test]
fn the_synthetic_signature_carries_its_entitlements_after_the_code_directory() {
    let blob = signature_with(
        "com.example.app",
        None,
        &[macho_build::entitlements_part(&entitlements_plist(&[CAMERA]))],
    );
    let offset = |entry: usize| {
        u32::from_be_bytes(blob[12 + entry * 8 + 4..12 + entry * 8 + 8].try_into().unwrap())
    };
    assert!(offset(1) > offset(0), "slot 5 lies behind slot 0");
    assert_eq!(&blob[offset(1) as usize..offset(1) as usize + 4], [0xfa, 0xde, 0x71, 0x71]);
}
