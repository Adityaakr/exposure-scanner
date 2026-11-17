//! What the macOS collector finds inside the files of a bundle: Mach-O
//! tables and sections, the code signature, privacy manifests and the update
//! feed (build plan, task 6).
//!
//! Every bundle here is synthetic and built in a temporary folder. The
//! Mach-O files come from a writer whose output is known byte for byte, so
//! each expectation follows from what the test itself put into the bundle.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use xs_collect::{ScanOptions, scan};
use xs_formats::macho_build::{self, Binary, Section, fat};
use xs_match::Matchers;
use xs_model::matcher::Boundary;
use xs_model::pack::{Category, Layer, LoadedLayer, Rule, Token};
use xs_model::record::{
    CoverageReason, CoverageRecord, CoverageStatus, EdgeRecord, Facts, Grade, ObjectKind, Record,
    Region, Scope, V1,
};
use xs_model::{EvidenceSet, MatcherKind, Pack, Sha256Digest, SubjectDigest, canon};

const FEED: &str = "https://user:secret@updates.example.com:8443/app/appcast.xml?ring=stable";

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

fn feed_key(address: &str) -> String {
    format!("<key>SUFeedURL</key><string>{address}</string>")
}

fn privacy_manifest(domains: &[&str]) -> String {
    let listed: String =
        domains.iter().map(|domain| format!("<string>{domain}</string>")).collect();
    format!(
        r#"<plist version="1.0"><dict>
<key>NSPrivacyTracking</key><true/>
<key>NSPrivacyTrackingDomains</key><array>{listed}</array>
</dict></plist>"#
    )
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A bundle whose main executable is `main` and whose property list holds
/// `extra` keys.
fn bundle(parent: &Path, main: &[u8], extra: &str) -> PathBuf {
    let root = parent.join("Example.app");
    write(&root.join("Contents/Info.plist"), info_plist(extra));
    write(&root.join("Contents/MacOS/Example"), main);
    root
}

fn rule(id: &str, tokens: &[(MatcherKind, &str, Boundary)]) -> Rule {
    let mut matchers: BTreeMap<MatcherKind, Vec<Token>> = BTreeMap::new();
    for &(matcher, literal, at) in tokens {
        matchers.entry(matcher).or_default().push(Token { lit: literal.into(), at });
    }
    Rule {
        id: id.into(),
        name: id.into(),
        entity: None,
        category: "component".into(),
        sources: vec![],
        notes: vec![],
        matchers,
        min_distinct: BTreeMap::new(),
    }
}

/// Rules shaped like the seed pack's, one witness kind each.
fn pack() -> Pack {
    use Boundary::{Exact, Host, Prefix, Word};
    use MatcherKind::{
        AppleFramework, ContentLiteral, MachoDylib, MachoObjcClass, MachoToken, PrivacyManifest,
    };
    let layer = Layer {
        format: V1,
        fixes: xs_model::fix::Fixes::default(),
        layer: "core".into(),
        version: 1,
        license: "CC-BY-4.0".into(),
        categories: vec![Category {
            id: "component".into(),
            name: "Component".into(),
            headline: false,
        }],
        entities: vec![],
        rules: vec![
            rule(
                "sdk/appcenter",
                &[
                    (AppleFramework, "AppCenter.framework", Exact),
                    (MachoObjcClass, "MSACAppCenter", Exact),
                    (MachoToken, "in.appcenter.ms", Host),
                ],
            ),
            rule(
                "sdk/sentry",
                &[
                    (MachoDylib, "Sentry.framework", Exact),
                    (MachoObjcClass, "SentryHub", Prefix),
                    (ContentLiteral, "sentry.javascript.", Word),
                ],
            ),
            rule("sdk/posthog", &[(PrivacyManifest, "i.posthog.com", Host)]),
        ],
    };
    Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
}

fn evidence_with(paths: &[PathBuf], threads: usize) -> EvidenceSet {
    let pack = pack();
    scan(paths, &Matchers::build(&pack).unwrap(), ScanOptions { threads, cache: None })
        .unwrap()
        .evidence
}

fn evidence(path: &Path) -> EvidenceSet {
    evidence_with(&[path.to_path_buf()], 2)
}

fn edges(evidence: &EvidenceSet) -> Vec<&EdgeRecord> {
    evidence
        .iter()
        .filter_map(|(_, record)| if let Record::Edge(edge) = record { Some(edge) } else { None })
        .collect()
}

/// The edge to `object` found by `matcher`. There must be exactly one.
fn edge<'a>(evidence: &'a EvidenceSet, object: &str, matcher: MatcherKind) -> &'a EdgeRecord {
    let found: Vec<&EdgeRecord> = edges(evidence)
        .into_iter()
        .filter(|edge| edge.object.id == object && edge.proof.matcher == matcher)
        .collect();
    assert_eq!(found.len(), 1, "edges to {object} by {matcher}: {found:#?}");
    found[0]
}

/// `(object, matcher)` of every edge, sorted.
fn found(evidence: &EvidenceSet) -> Vec<(String, MatcherKind)> {
    let mut found: Vec<(String, MatcherKind)> =
        edges(evidence).iter().map(|edge| (edge.object.id.clone(), edge.proof.matcher)).collect();
    found.sort();
    found
}

fn coverage(evidence: &EvidenceSet) -> Vec<&CoverageRecord> {
    evidence
        .iter()
        .filter_map(|(_, record)| if let Record::Coverage(gap) = record { Some(gap) } else { None })
        .collect()
}

/// `(where, status, reason, count)` of every coverage record.
fn gaps(evidence: &EvidenceSet) -> Vec<(String, CoverageStatus, CoverageReason, u32)> {
    let mut gaps: Vec<_> = coverage(evidence)
        .iter()
        .map(|gap| {
            let place = gap.location.as_ref().map(ToString::to_string).unwrap_or_default();
            (place, gap.status, gap.reason, gap.count)
        })
        .collect();
    gaps.sort();
    gaps
}

fn facts(evidence: &EvidenceSet) -> &Facts {
    evidence
        .iter()
        .find_map(|(_, record)| {
            if let Record::Artifact(artifact) = record { Some(&artifact.facts) } else { None }
        })
        .unwrap()
}

fn digest(evidence: &EvidenceSet) -> SubjectDigest {
    evidence.iter().next().unwrap().1.subject().digest
}

/// Build plan, task 6: "AltTab reports App Center". The SDK is linked into
/// the main executable, so there is no framework folder to find it by; its
/// Objective-C class name is what remains (spec, "Framework folders miss
/// static SDKs").
#[test]
fn a_statically_linked_sdk_is_found_by_its_class_name() {
    let dir = tempfile::tempdir().unwrap();
    let main = Binary::new()
        .section(Section::code("__TEXT", "__text", b"\x90\x90"))
        .section(Section::data("__TEXT", "__objc_classname", b"AppDelegate\0MSACAppCenter\0"))
        .build();
    let root = bundle(dir.path(), &main, "");
    let evidence = evidence(&root);

    assert_eq!(found(&evidence), [("sdk/appcenter".to_string(), MatcherKind::MachoObjcClass)]);
    let edge = edge(&evidence, "sdk/appcenter", MatcherKind::MachoObjcClass);
    assert_eq!(edge.rule, "sdk/appcenter");
    assert_eq!(edge.object.kind, ObjectKind::Sdk);
    assert_eq!(edge.grade, Grade::Contains);
    assert_eq!(edge.proof.token, "MSACAppCenter");
    assert_eq!(edge.proof.example.as_deref(), Some("MSACAppCenter"));
    assert_eq!(edge.proof.count, 1);
    assert_eq!(edge.proof.location.as_str(), "Contents/MacOS/Example");
    assert_eq!(edge.proof.region, Region::ObjcClassname);
    assert_eq!(edge.proof.scope, Scope::AppCode);
    assert!(coverage(&evidence).is_empty());
}

#[test]
fn a_class_name_outside_the_name_table_is_not_a_class() {
    let dir = tempfile::tempdir().unwrap();
    // The same bytes as a string constant, a longer class name, and the
    // name in a resource: none of them says the class is defined here.
    let main = Binary::new()
        .section(Section::data("__TEXT", "__cstring", b"MSACAppCenter\0"))
        .section(Section::data("__TEXT", "__objc_classname", b"MSACAppCenterDelegate\0"))
        .build();
    let root = bundle(dir.path(), &main, "");
    write(&root.join("Contents/Resources/notes.txt"), "MSACAppCenter SentryHub in.appcenter.ms");
    assert_eq!(found(&evidence(&root)), []);
}

#[test]
fn a_linked_library_is_found_in_the_load_commands_wherever_it_is_installed() {
    let dir = tempfile::tempdir().unwrap();
    let main = Binary::new()
        .library("/usr/lib/libSystem.B.dylib")
        .library("@executable_path/../Libraries/Sentry.framework/Versions/A/Sentry")
        .build();
    let root = bundle(dir.path(), &main, "");
    let evidence = evidence(&root);

    let edge = edge(&evidence, "sdk/sentry", MatcherKind::MachoDylib);
    assert_eq!(edge.proof.token, "Sentry.framework");
    // An install name relative to the bundle is the example, whole.
    assert_eq!(
        edge.proof.example.as_deref(),
        Some("@executable_path/../Libraries/Sentry.framework/Versions/A/Sentry")
    );
    assert_eq!(edge.proof.region, Region::LoadCommands);
    assert_eq!(edge.proof.location.as_str(), "Contents/MacOS/Example");
    assert_eq!(found(&evidence).len(), 1);
}

/// Evidence format rule 5: no path outside the artifact. An absolute install
/// name is a path on the machine that built the binary, so only the part
/// from the matched component on is kept.
#[test]
fn the_build_machine_s_path_of_a_linked_library_does_not_reach_the_evidence() {
    let dir = tempfile::tempdir().unwrap();
    for (install_name, kept) in [
        (
            "/Users/alice/Library/Developer/Xcode/DerivedData/App/Build/Products/Debug/Sentry.framework/Sentry",
            "Sentry.framework/Sentry",
        ),
        (
            "/opt/homebrew/opt/x/lib/Sentry.framework/Versions/A/Sentry",
            "Sentry.framework/Versions/A/Sentry",
        ),
        ("/Users/alice/build/Sentry.framework", "Sentry.framework"),
        ("../alice/Sentry.framework/Sentry", "Sentry.framework/Sentry"),
        (
            "/Users/alice/Sentry.framework/x/Sentry.framework/Sentry",
            "Sentry.framework/x/Sentry.framework/Sentry",
        ),
        ("@rpath/Sentry.framework/Sentry", "@rpath/Sentry.framework/Sentry"),
        (
            "@loader_path/../Frameworks/Sentry.framework/Sentry",
            "@loader_path/../Frameworks/Sentry.framework/Sentry",
        ),
    ] {
        let main = Binary::new().library(install_name).build();
        let root = bundle(dir.path(), &main, "");
        let evidence = evidence(&root);

        let edge = edge(&evidence, "sdk/sentry", MatcherKind::MachoDylib);
        assert_eq!(edge.proof.token, "Sentry.framework");
        assert_eq!(edge.proof.count, 1, "{install_name}");
        assert_eq!(edge.proof.example.as_deref(), Some(kept), "{install_name}");
        for (_, record) in &evidence {
            let json = canon::to_string(record).unwrap();
            for part in ["alice", "Users", "homebrew", "DerivedData"] {
                assert!(!json.contains(part), "{part} in {json}");
            }
        }
    }
}

#[test]
fn a_literal_in_a_binary_s_data_is_found_and_one_among_its_instructions_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let in_data = Binary::new()
        .section(Section::data("__TEXT", "__cstring", b"https://in.appcenter.ms/logs\0"))
        .build();
    let in_code = Binary::new()
        .section(Section::code("__TEXT", "__text", b"https://in.appcenter.ms/logs\0"))
        .build();

    let root = bundle(dir.path(), &in_data, "");
    let evidence_of_data = evidence(&root);
    let edge = edge(&evidence_of_data, "sdk/appcenter", MatcherKind::MachoToken);
    assert_eq!(edge.proof.token, "in.appcenter.ms");
    assert_eq!(edge.proof.region, Region::NonCode);
    assert_eq!(edge.proof.scope, Scope::AppCode);
    // Free-form bytes are never copied into a record.
    assert_eq!(edge.proof.example, None);

    write(&root.join("Contents/MacOS/Example"), &in_code);
    assert_eq!(found(&evidence(&root)), []);
}

/// Design report, section 5.2 control 1: a browser engine holds host names
/// as data. Its file is hashed and its tables are read; it is not searched.
#[test]
fn a_browser_engine_is_not_searched_for_literals() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), &Binary::new().build(), "");
    let engine = Binary::new()
        .section(Section::data("__TEXT", "__cstring", b"https://in.appcenter.ms/logs\0"))
        .section(Section::data("__TEXT", "__objc_classname", b"MSACAppCenter\0"))
        .build();
    let frameworks = root.join("Contents/Frameworks");
    write(&frameworks.join("Electron Framework.framework/Versions/A/Electron Framework"), &engine);
    let evidence_of_engine = evidence(&root);
    assert_eq!(
        found(&evidence_of_engine),
        [("sdk/appcenter".to_string(), MatcherKind::MachoObjcClass)]
    );
    assert_eq!(
        edge(&evidence_of_engine, "sdk/appcenter", MatcherKind::MachoObjcClass).proof.scope,
        Scope::Runtime
    );

    // The same file as an ordinary dependency is searched.
    fs::rename(
        frameworks.join("Electron Framework.framework"),
        frameworks.join("Helper.framework"),
    )
    .unwrap();
    let evidence_of_dependency = evidence(&root);
    assert_eq!(
        found(&evidence_of_dependency),
        [
            ("sdk/appcenter".to_string(), MatcherKind::MachoObjcClass),
            ("sdk/appcenter".to_string(), MatcherKind::MachoToken),
        ]
    );
    assert_eq!(
        edge(&evidence_of_dependency, "sdk/appcenter", MatcherKind::MachoToken).proof.scope,
        Scope::Dependency
    );
}

/// Design report, M6: an app compiled into its runtime keeps its script in
/// a section of the executable. The script is the code of whoever ships the
/// file; the rest of the file is the runtime.
#[test]
fn a_script_embedded_in_a_binary_is_searched_as_the_code_of_who_ships_it() {
    let dir = tempfile::tempdir().unwrap();
    let main = Binary::new()
        .section(Section::data("__TEXT", "__cstring", b"https://in.appcenter.ms/logs\0"))
        .section(Section::data(
            "__BUN",
            "__bun",
            b"const sdk = { name: `sentry.javascript.${flavor}` };",
        ))
        .build();
    let root = bundle(dir.path(), &main, "");
    let evidence = evidence(&root);

    // The literal in the runtime's own data is not looked for.
    assert_eq!(found(&evidence), [("sdk/sentry".to_string(), MatcherKind::ContentLiteral)]);
    let edge = edge(&evidence, "sdk/sentry", MatcherKind::ContentLiteral);
    assert_eq!(edge.proof.region, Region::EmbeddedScript);
    assert_eq!(edge.proof.scope, Scope::AppCode);
    assert_eq!(edge.proof.location.as_str(), "Contents/MacOS/Example");
    assert_eq!(edge.proof.example, None);

    // The same file shipped by a dependency: its script is the dependency's
    // (spec: "Dependencies are not app code").
    write(&root.join("Contents/MacOS/Example"), Binary::new().build());
    write(&root.join("Contents/Frameworks/Tool.framework/Versions/A/Tool"), &main);
    let shipped = self::evidence(&root);
    let edge = self::edge(&shipped, "sdk/sentry", MatcherKind::ContentLiteral);
    assert_eq!(edge.proof.scope, Scope::Dependency);
    assert_eq!(found(&shipped).len(), 1);
}

/// Build plan, task 6: "An encrypted binary yields a coverage record". What
/// the load commands say is still read; the ciphertext is not searched.
#[test]
fn an_encrypted_binary_yields_a_coverage_record() {
    let dir = tempfile::tempdir().unwrap();
    let binary = Binary::new()
        .library("@rpath/Sentry.framework/Sentry")
        .section(Section::code("__TEXT", "__text", b"\x90\x90"))
        .section(Section::data("__TEXT", "__cstring", b"https://in.appcenter.ms/logs\0"))
        .section(Section::data("__TEXT", "__objc_classname", b"MSACAppCenter\0"))
        .encrypt_from("__TEXT", "__text");
    let root = bundle(dir.path(), &binary.build(), "");
    let encrypted = evidence(&root);

    assert_eq!(
        gaps(&encrypted),
        [(
            "Contents/MacOS/Example".to_string(),
            CoverageStatus::Skipped,
            CoverageReason::EncryptedBinary,
            1
        )]
    );
    assert_eq!(found(&encrypted), [("sdk/sentry".to_string(), MatcherKind::MachoDylib)]);

    // The same binary once decrypted is covered in full.
    write(&root.join("Contents/MacOS/Example"), binary.crypt_id(0).build());
    let decrypted = evidence(&root);
    assert!(coverage(&decrypted).is_empty());
    assert_eq!(found(&decrypted).len(), 3);
}

#[test]
fn a_universal_binary_counts_each_architecture() {
    let dir = tempfile::tempdir().unwrap();
    let image = Binary::new()
        .section(Section::data("__TEXT", "__objc_classname", b"MSACAppCenter\0SentryHubInternal\0"))
        .build();
    let other = Binary::new()
        .wide(false)
        .section(Section::data("__TEXT", "__objc_classname", b"MSACAppCenter\0"))
        .build();
    let root = bundle(dir.path(), &fat(&[&image, &other], false), "");
    let evidence = evidence(&root);
    assert_eq!(edge(&evidence, "sdk/appcenter", MatcherKind::MachoObjcClass).proof.count, 2);
    let sentry = edge(&evidence, "sdk/sentry", MatcherKind::MachoObjcClass);
    assert_eq!(sentry.proof.count, 1);
    assert_eq!(sentry.proof.token, "SentryHub");
    assert_eq!(sentry.proof.example.as_deref(), Some("SentryHubInternal"));
}

/// Design report, M5: the vendor is read from the code signature. The Team
/// ID is that of the main executable, whatever else the bundle ships.
#[test]
fn the_team_id_is_the_one_the_main_executable_s_signature_names() {
    let dir = tempfile::tempdir().unwrap();
    let signed = |team: Option<&str>| {
        Binary::new().signature(&macho_build::signature("com.example.app", team)).build()
    };
    let root = bundle(dir.path(), &signed(Some("ABCDE12345")), "");
    write(
        &root.join("Contents/Frameworks/Other.framework/Versions/A/Other"),
        signed(Some("ZZZZZ99999")),
    );
    assert_eq!(facts(&evidence(&root)).team_id.as_deref(), Some("ABCDE12345"));

    // Ad-hoc signed, and not signed at all: no team, and nothing amiss.
    for main in [signed(None), Binary::new().build()] {
        write(&root.join("Contents/MacOS/Example"), main);
        let evidence = evidence(&root);
        assert_eq!(facts(&evidence).team_id, None);
        assert!(coverage(&evidence).is_empty());
    }

    // Two architectures that name different teams name none.
    let universal = fat(&[&signed(Some("ABCDE12345")), &signed(Some("ZZZZZ99999"))], false);
    write(&root.join("Contents/MacOS/Example"), universal);
    let divided = evidence(&root);
    assert_eq!(facts(&divided).team_id, None);
    assert_eq!(
        gaps(&divided),
        [(
            "Contents/MacOS/Example".to_string(),
            CoverageStatus::Unrecognized,
            CoverageReason::ParseError,
            1
        )]
    );

    // A signature that is not one is reported where it is.
    let broken = Binary::new().signature(b"\xfa\xde\x0c\xc0 and then nothing useful").build();
    write(&root.join("Contents/MacOS/Example"), broken);
    let unsigned = evidence(&root);
    assert_eq!(facts(&unsigned).team_id, None);
    assert_eq!(gaps(&unsigned).len(), 1);
}

/// Build plan, task 6: "a graded update feed". The property list names the
/// feed; the record keeps the host and nothing else of the address.
#[test]
fn the_update_feed_is_reported_as_its_host_at_the_declares_grade() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), &Binary::new().build(), &feed_key(FEED));
    let evidence = evidence(&root);

    let feed = edge(&evidence, "updates.example.com", MatcherKind::UpdateFeed);
    assert_eq!(feed.object.kind, ObjectKind::Host);
    assert_eq!(feed.rule, "declared/update-feed");
    assert_eq!(feed.grade, Grade::Declares);
    assert_eq!(feed.proof.token, "SUFeedURL");
    assert_eq!(feed.proof.example, None);
    assert_eq!(feed.proof.count, 1);
    assert_eq!(feed.proof.location.as_str(), "Contents/Info.plist");
    assert_eq!(feed.proof.region, Region::PropertyList);
    assert_eq!(feed.proof.scope, Scope::AppCode);

    // The host is reported as itself and as nothing else.
    assert_eq!(found(&evidence), [("updates.example.com".to_string(), MatcherKind::UpdateFeed)]);
    assert!(coverage(&evidence).is_empty());

    // Evidence format rule 5: hosts only. Nothing else of the address is
    // anywhere in the evidence.
    for (_, record) in &evidence {
        let json = canon::to_string(record).unwrap();
        for part in ["appcast", "ring", "stable", "https", "/app", "secret", "8443"] {
            assert!(!json.contains(part), "{part} in {json}");
        }
    }
}

#[test]
fn a_feed_that_is_absent_or_empty_declares_nothing_and_an_odd_one_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    for extra in [String::new(), feed_key(""), feed_key("  ")] {
        let root = bundle(dir.path(), &Binary::new().build(), &extra);
        let evidence = evidence(&root);
        assert_eq!(found(&evidence), [], "{extra}");
        assert!(coverage(&evidence).is_empty(), "{extra}");
    }
    // Not an address the scanner can reduce to a host: said so, not dropped.
    for odd in ["file:///Users/someone/appcast.xml", "$(FEED_URL)", "https://[::1]/feed"] {
        let root = bundle(dir.path(), &Binary::new().build(), &feed_key(odd));
        let evidence = evidence(&root);
        assert_eq!(found(&evidence), [], "{odd}");
        assert_eq!(
            gaps(&evidence),
            [(
                "Contents/Info.plist".to_string(),
                CoverageStatus::Unrecognized,
                CoverageReason::ParseError,
                1
            )],
            "{odd}"
        );
    }
}

#[test]
fn tracking_domains_in_privacy_manifests_are_declared_hosts() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), &Binary::new().build(), "");
    let own = "Contents/Resources/PrivacyInfo.xcprivacy";
    let shipped = "Contents/Frameworks/Kit.framework/Resources/PrivacyInfo.xcprivacy";
    // The app's own manifest: two spellings of one host, one that a rule
    // names the parent of, and two entries that are not host names. Apple
    // defines the key as a list of domains, so an address is not one.
    write(
        &root.join(own),
        privacy_manifest(&[
            "Tracker.Example.net",
            "tracker.example.net.",
            "eu.i.posthog.com",
            "*",
            "https://address.example/v1",
        ]),
    );
    write(&root.join(shipped), privacy_manifest(&["collect.kit.example"]));
    let evidence = evidence(&root);

    assert_eq!(
        found(&evidence),
        [
            ("collect.kit.example".to_string(), MatcherKind::PrivacyManifest),
            ("eu.i.posthog.com".to_string(), MatcherKind::PrivacyManifest),
            ("sdk/posthog".to_string(), MatcherKind::PrivacyManifest),
            ("tracker.example.net".to_string(), MatcherKind::PrivacyManifest),
        ]
    );
    let host = edge(&evidence, "tracker.example.net", MatcherKind::PrivacyManifest);
    assert_eq!(host.object.kind, ObjectKind::Host);
    assert_eq!(host.rule, "declared/tracking-domain");
    assert_eq!(host.grade, Grade::Declares);
    assert_eq!(host.proof.token, "NSPrivacyTrackingDomains");
    assert_eq!(host.proof.count, 1);
    assert_eq!(host.proof.location.as_str(), own);
    assert_eq!(host.proof.region, Region::PropertyList);
    assert_eq!(host.proof.scope, Scope::AppCode);

    let sdk = edge(&evidence, "sdk/posthog", MatcherKind::PrivacyManifest);
    assert_eq!(sdk.grade, Grade::Declares);
    assert_eq!(sdk.proof.token, "i.posthog.com");
    assert_eq!(sdk.proof.example.as_deref(), Some("eu.i.posthog.com"));
    assert_eq!(sdk.proof.location.as_str(), own);

    // What a framework ships is the framework's declaration.
    let theirs = edge(&evidence, "collect.kit.example", MatcherKind::PrivacyManifest);
    assert_eq!(theirs.proof.location.as_str(), shipped);
    assert_eq!(theirs.proof.scope, Scope::Dependency);

    // The entries that are not host names were read and not understood.
    assert_eq!(
        gaps(&evidence),
        [(own.to_string(), CoverageStatus::Unrecognized, CoverageReason::ParseError, 2)]
    );
    // Both manifests were read, besides the property list and the binary.
    assert_eq!(facts(&evidence).files_scanned, 4);
}

/// A privacy manifest is the declaration of whatever holds it, by the folder
/// rule that says whose code a binary is: an extension or a helper is the
/// app's own, anything below a `Frameworks` or `node_modules` folder is
/// something it ships.
#[test]
fn a_privacy_manifest_has_the_scope_of_the_code_beside_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), &Binary::new().build(), "");
    let placed = [
        ("Contents/Resources/PrivacyInfo.xcprivacy", "app.example", Scope::AppCode),
        (
            "Contents/PlugIns/Share.appex/Contents/Resources/PrivacyInfo.xcprivacy",
            "extension.example",
            Scope::AppCode,
        ),
        (
            "Contents/Library/LoginItems/Helper.app/Contents/Resources/PrivacyInfo.xcprivacy",
            "helper.example",
            Scope::AppCode,
        ),
        (
            "Contents/Frameworks/Kit.framework/Resources/PrivacyInfo.xcprivacy",
            "kit.example",
            Scope::Dependency,
        ),
        (
            "Contents/Frameworks/Kit.framework/Resources/Kit.bundle/PrivacyInfo.xcprivacy",
            "bundle.kit.example",
            Scope::Dependency,
        ),
        (
            "Contents/PlugIns/Share.appex/Contents/Frameworks/Dep.framework/PrivacyInfo.xcprivacy",
            "dep.example",
            Scope::Dependency,
        ),
        (
            "Contents/Resources/app.asar.unpacked/node_modules/keytar/PrivacyInfo.xcprivacy",
            "keytar.example",
            Scope::Dependency,
        ),
    ];
    for (path, domain, _) in placed {
        write(&root.join(path), privacy_manifest(&[domain, "eu.i.posthog.com"]));
    }
    let evidence = evidence(&root);
    assert!(coverage(&evidence).is_empty());

    let sdk_edges: Vec<(&str, Scope)> = edges(&evidence)
        .into_iter()
        .filter(|edge| edge.object.id == "sdk/posthog")
        .map(|edge| (edge.proof.location.as_str(), edge.proof.scope))
        .collect();
    for (path, domain, scope) in placed {
        let host = edge(&evidence, domain, MatcherKind::PrivacyManifest);
        assert_eq!(host.proof.location.as_str(), path);
        assert_eq!(host.proof.scope, scope, "{path}");
        // The edge a rule adds for a host carries the same scope.
        assert!(sdk_edges.contains(&(path, scope)), "{path}: {sdk_edges:#?}");
    }
}

/// A native add-on of a package is the package's code, not the app's: the
/// spec counts what sits below `node_modules` as a dependency, as it does
/// for a script in the same folder.
#[test]
fn a_native_add_on_below_node_modules_is_a_dependency() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), &Binary::new().build(), "");
    let add_on =
        "Contents/Resources/app.asar.unpacked/node_modules/keytar/build/Release/keytar.node";
    let binary = Binary::new()
        .library("@rpath/Sentry.framework/Sentry")
        .section(Section::data("__TEXT", "__objc_classname", b"MSACAppCenter\0"))
        .section(Section::data("__TEXT", "__cstring", b"https://in.appcenter.ms\0"))
        .build();
    write(&root.join(add_on), binary);
    let evidence = evidence(&root);

    for (object, matcher) in [
        ("sdk/appcenter", MatcherKind::MachoObjcClass),
        ("sdk/appcenter", MatcherKind::MachoToken),
        ("sdk/sentry", MatcherKind::MachoDylib),
    ] {
        let edge = edge(&evidence, object, matcher);
        assert_eq!(edge.proof.location.as_str(), add_on);
        assert_eq!(edge.proof.scope, Scope::Dependency, "{matcher}");
    }
}

#[test]
fn a_privacy_manifest_that_declares_no_domains_or_cannot_be_read_yields_no_edge() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), &Binary::new().build(), "");
    let path = root.join("Contents/Resources/PrivacyInfo.xcprivacy");

    write(&path, privacy_manifest(&[]));
    let empty = evidence(&root);
    assert_eq!(found(&empty), []);
    assert!(coverage(&empty).is_empty());

    write(&path, "not a property list");
    let damaged = evidence(&root);
    assert_eq!(found(&damaged), []);
    assert_eq!(
        gaps(&damaged),
        [(
            "Contents/Resources/PrivacyInfo.xcprivacy".to_string(),
            CoverageStatus::Unrecognized,
            CoverageReason::ParseError,
            1
        )]
    );

    // More domains than the budget: reported, and none of them kept.
    let many: Vec<String> = (0..=1024).map(|n| format!("t{n}.example")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    write(&path, privacy_manifest(&many));
    let crowded = evidence(&root);
    assert_eq!(found(&crowded), []);
    assert_eq!(gaps(&crowded)[0].2, CoverageReason::OverBudget);
}

/// Evidence is drawn from privacy manifests, so the bundle digest covers
/// them: equal digests must imply equal evidence.
#[test]
fn the_digest_covers_privacy_manifests() {
    let dir = tempfile::tempdir().unwrap();
    let root = bundle(dir.path(), &Binary::new().build(), "");
    let without = digest(&evidence(&root));

    let path = root.join("Contents/Resources/Lib.bundle/PrivacyInfo.xcprivacy");
    write(&path, privacy_manifest(&["a.example"]));
    let with = digest(&evidence(&root));
    assert_ne!(with, without);

    write(&path, privacy_manifest(&["b.example"]));
    assert_ne!(digest(&evidence(&root)), with);

    // A file that merely has the extension is not a privacy manifest.
    fs::rename(&path, path.with_file_name("Other.xcprivacy")).unwrap();
    assert_eq!(digest(&evidence(&root)), without);
}

/// Design report, section 6.4: thread count and path order cannot reach the
/// evidence, with every kind of witness in play.
#[test]
fn thread_count_and_path_order_do_not_reach_the_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let mut paths: Vec<PathBuf> = (0..5u8)
        .map(|n| {
            let parent = dir.path().join(format!("copy{n}"));
            // Sizes differ, so largest-first order differs from path order.
            let padding = vec![b'x'; 3000 * (5 - usize::from(n))];
            let main = Binary::new()
                .library("@rpath/Sentry.framework/Sentry")
                .section(Section::code("__TEXT", "__text", &padding))
                .section(Section::data("__TEXT", "__cstring", b"https://in.appcenter.ms\0"))
                .section(Section::data("__TEXT", "__objc_classname", b"MSACAppCenter\0"))
                .signature(&macho_build::signature("com.example.app", Some("ABCDE12345")))
                .build();
            let root = bundle(&parent, &main, &feed_key(FEED));
            write(
                &root.join("Contents/Info.plist"),
                info_plist(&feed_key(FEED))
                    .replace("com.example.app", &format!("com.example.app{n}")),
            );
            write(
                &root.join("Contents/Resources/PrivacyInfo.xcprivacy"),
                privacy_manifest(&["tracker.example.net"]),
            );
            root
        })
        .collect();
    let reference = evidence_with(&paths, 1);
    // Per bundle: class name, library, literal, feed host, tracking domain.
    assert_eq!(edges(&reference).len(), 5 * 5);
    paths.reverse();
    assert_eq!(evidence_with(&paths, 1), reference);
    paths.rotate_left(2);
    for threads in [2, 4, 8] {
        assert_eq!(evidence_with(&paths, threads), reference, "{threads} threads");
    }
}
