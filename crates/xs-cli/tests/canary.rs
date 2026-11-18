//! Property 1, "finds what is there": canary recall over static plants
//! (design report, section 7).
//!
//! For every rule of the built-in pack and every kind of witness it has
//! tokens for, a synthetic app is written that holds those tokens the way
//! the real SDK leaves them in a build: a framework folder, Objective-C
//! class names and strings in a Mach-O file, a privacy manifest, classes,
//! strings, components and files in an Android package, packages and
//! script literals in an Electron archive. Each plant is a separate app,
//! so one plant cannot help another to be found.
//!
//! All the plants are scanned as one scan, through the real collectors, and
//! derived with the real pack. A plant is found when its app has a claim
//! for the rule it was written from. At least 95% of the plants must be
//! found; the test lists every one that was not.
//!
//! The plants come from the pack itself, so a rule added to the pack is
//! planted here without a change to this file.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(clippy::print_stdout, reason = "the test reports its recall")]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use xs_formats::macho_build::{Binary, Section};
use xs_formats::testkit::{self, Attr, AxmlBuilder, DexBuilder, ZipBuilder};
use xs_match::Matchers;
use xs_model::matcher::Boundary;
use xs_model::pack::{Rule, Token};
use xs_model::{MatcherKind, Pack};
use xs_rules::{SignedLayer, TRUSTED_KEYS};

const PACK: &[u8] = include_bytes!("../../../rules/dist/core.pack.json");
const SIGNATURE: &str = include_str!("../../../rules/dist/core.pack.json.minisig");

/// The recall gate, in percent of plants found.
const MIN_RECALL_PERCENT: usize = 95;

fn pack() -> Pack {
    xs_rules::load_pack(&[SignedLayer { bytes: PACK, signature: SIGNATURE }], TRUSTED_KEYS).unwrap()
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A value that a token of this boundary hits: the literal itself where it
/// must be the whole value or sits on word or host boundaries, and the
/// literal followed by a class or path name where it is a prefix.
fn value(token: &Token, separator: char) -> String {
    match token.at {
        Boundary::Prefix if token.lit.ends_with(separator) => format!("{}Canary", token.lit),
        Boundary::Prefix => format!("{}{separator}Canary", token.lit),
        _ => token.lit.clone(),
    }
}

/// How a literal sits in text where the SDK leaves it: a host inside an
/// address, anything else as a quoted string.
fn in_text(token: &Token) -> String {
    match token.at {
        Boundary::Host => format!("https://{}/v1/canary", token.lit),
        _ => format!("\"{}\"", value(token, '.')),
    }
}

fn info_plist(id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleName</key><string>Canary</string>
<key>CFBundleExecutable</key><string>Canary</string>
</dict></plist>"#
    )
}

/// A macOS bundle with `main` as its executable.
fn bundle(root: &Path, id: &str, main: &[u8]) {
    write(&root.join("Contents/Info.plist"), info_plist(id));
    write(&root.join("Contents/MacOS/Canary"), main);
}

/// The bytes of an asar archive that holds `files`, as `@electron/asar`
/// lays one out.
fn asar(files: &[(String, String)]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut tree = serde_json::Map::new();
    for (path, content) in files {
        let mut folder = &mut tree;
        let (folders, name) = path.rsplit_once('/').unwrap_or(("", path));
        for part in folders.split('/').filter(|part| !part.is_empty()) {
            folder = folder
                .entry(part)
                .or_insert_with(|| serde_json::json!({"files": {}}))
                .get_mut("files")
                .and_then(serde_json::Value::as_object_mut)
                .unwrap();
        }
        let offset = data.len().to_string();
        data.extend_from_slice(content.as_bytes());
        folder
            .insert(name.to_string(), serde_json::json!({"offset": offset, "size": content.len()}));
    }
    let json = serde_json::json!({"files": tree}).to_string();
    let len = u32::try_from(json.len()).unwrap();
    let padded = len.div_ceil(4) * 4;
    let mut bytes = Vec::new();
    for word in [4, padded + 8, padded + 4, len] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.extend_from_slice(json.as_bytes());
    bytes.resize(16 + padded as usize, 0);
    bytes.extend_from_slice(&data);
    bytes
}

/// An Android package named `id` with these extra manifest elements, DEX
/// classes and strings, and zip entries.
fn apk(
    id: &str,
    components: &[String],
    classes: &[String],
    strings: &[String],
    files: &[String],
) -> Vec<u8> {
    let mut manifest = AxmlBuilder::new()
        .start(
            "manifest",
            &[
                Attr::int(testkit::ANDROID_VERSION_CODE, "versionCode", 1),
                Attr::android(testkit::ANDROID_VERSION_NAME, "versionName", "1.0"),
                Attr::plain("package", id),
            ],
        )
        .start("application", &[Attr::android(testkit::ANDROID_LABEL, "label", "Canary")]);
    for name in components {
        manifest = manifest
            .start("service", &[Attr::android(testkit::ANDROID_NAME, "name", name)])
            .end()
            .start("meta-data", &[Attr::android(testkit::ANDROID_NAME, "name", name)])
            .end();
    }
    let manifest = manifest.end().end().finish();
    let mut dex = DexBuilder::new().class(&format!("{id}.MainActivity"));
    for class in classes {
        dex = dex.class(class);
    }
    for string in strings {
        dex = dex.string(string);
    }
    let mut zip = ZipBuilder::new()
        .deflated("AndroidManifest.xml", &manifest)
        .deflated("classes.dex", &dex.finish());
    for file in files {
        zip = zip.stored(file, b"canary");
    }
    zip.finish()
}

/// Writes the plant of `rule`'s tokens of `kind` as the app `id` under
/// `dir`, or says why that kind cannot be planted.
fn plant(dir: &Path, id: &str, rule: &Rule, kind: MatcherKind) -> Result<PathBuf, String> {
    let tokens = rule.matchers.get(&kind).map(Vec::as_slice).unwrap_or_default();
    let texts = || tokens.iter().map(in_text).collect::<Vec<_>>();
    let mut cstrings = Vec::new();
    match kind {
        MatcherKind::AppleFramework => {
            let root = dir.join(format!("{id}.app"));
            bundle(&root, id, &Binary::new().build());
            for token in tokens {
                let stem = token.lit.trim_end_matches(".framework");
                write(
                    &root.join("Contents/Frameworks").join(&token.lit).join(stem),
                    Binary::new().build(),
                );
            }
            Ok(root)
        }
        MatcherKind::MachoObjcClass | MatcherKind::MachoToken => {
            let root = dir.join(format!("{id}.app"));
            let mut names = Vec::new();
            for token in tokens {
                let text = if kind == MatcherKind::MachoObjcClass {
                    // A class name goes on with letters, not a separator.
                    match token.at {
                        Boundary::Prefix => format!("{}Canary", token.lit),
                        _ => token.lit.clone(),
                    }
                } else {
                    in_text(token).trim_matches('"').to_string()
                };
                let target =
                    if kind == MatcherKind::MachoObjcClass { &mut names } else { &mut cstrings };
                target.extend_from_slice(text.as_bytes());
                target.push(0);
            }
            let mut main = Binary::new().section(Section::code("__TEXT", "__text", b"\x90\x90"));
            if !names.is_empty() {
                main = main.section(Section::data("__TEXT", "__objc_classname", &names));
            }
            if !cstrings.is_empty() {
                main = main.section(Section::data("__TEXT", "__cstring", &cstrings));
            }
            bundle(&root, id, &main.build());
            Ok(root)
        }
        MatcherKind::PrivacyManifest => {
            let root = dir.join(format!("{id}.app"));
            bundle(&root, id, &Binary::new().build());
            let listed: String =
                tokens.iter().map(|token| format!("<string>{}</string>", token.lit)).collect();
            write(
                &root.join(
                    "Contents/Frameworks/CanaryKit.framework/Resources/PrivacyInfo.xcprivacy",
                ),
                format!(
                    r#"<plist version="1.0"><dict>
<key>NSPrivacyTracking</key><true/>
<key>NSPrivacyTrackingDomains</key><array>{listed}</array>
</dict></plist>"#
                ),
            );
            Ok(root)
        }
        MatcherKind::NpmPackage | MatcherKind::ContentLiteral => {
            let root = dir.join(format!("{id}.app"));
            bundle(&root, id, &Binary::new().build());
            write(
                &root.join("Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"),
                Binary::new().build(),
            );
            let mut files = vec![
                (String::from("package.json"), String::from("{\"name\":\"canary\"}")),
                (String::from("index.html"), String::from("<script src=main.js></script>")),
            ];
            if kind == MatcherKind::NpmPackage {
                for token in tokens {
                    files.push((
                        format!("node_modules/{}/package.json", token.lit),
                        String::from("{}"),
                    ));
                }
                files.push((String::from("main.js"), String::from("boot();")));
            } else {
                files.push((String::from("main.js"), format!("boot();{};", texts().join(";"))));
            }
            write(&root.join("Contents/Resources/app.asar"), asar(&files));
            Ok(root)
        }
        MatcherKind::ManifestComponent
        | MatcherKind::AndroidClassPrefix
        | MatcherKind::DexString
        | MatcherKind::ApkFile => {
            let values: Vec<String> = tokens.iter().map(|token| value(token, '.')).collect();
            let none = Vec::new();
            let strings: Vec<String> =
                tokens.iter().map(|token| in_text(token).trim_matches('"').to_string()).collect();
            let bytes = match kind {
                MatcherKind::ManifestComponent => apk(id, &values, &none, &none, &none),
                MatcherKind::AndroidClassPrefix => apk(id, &none, &values, &none, &none),
                MatcherKind::DexString => apk(id, &none, &none, &strings, &none),
                _ => apk(id, &none, &none, &none, &values),
            };
            let path = dir.join(format!("{id}.apk"));
            write(&path, bytes);
            Ok(path)
        }
        other => Err(format!("no plant is written for {other:?}")),
    }
}

#[test]
fn the_scan_finds_at_least_95_percent_of_planted_sdks() {
    let pack = pack();
    let matchers = Matchers::build(&pack).unwrap();
    let dir = tempfile::tempdir().unwrap();

    let mut plants: Vec<(String, String, MatcherKind)> = Vec::new();
    let mut paths = Vec::new();
    let mut unplanted = Vec::new();
    for rule in pack.rules() {
        for &kind in rule.matchers.keys() {
            let id = format!("org.canary.p{}", plants.len() + unplanted.len());
            match plant(dir.path(), &id, rule, kind) {
                Ok(path) => {
                    paths.push(path);
                    plants.push((id, rule.id.clone(), kind));
                }
                Err(why) => unplanted.push(format!("{} {kind:?}: {why}", rule.id)),
            }
        }
    }
    assert!(unplanted.is_empty(), "every kind a rule uses is planted: {unplanted:#?}");
    assert!(plants.len() >= pack.rule_count(), "at least one plant per rule");

    let outcome =
        xs_collect::scan(&paths, &matchers, xs_collect::ScanOptions { threads: 0, cache: None })
            .unwrap();
    let claims = xs_derive::derive(&outcome.evidence, &pack).unwrap();
    let found: BTreeSet<(&str, &str)> =
        claims.iter().map(|claim| (claim.subject.id.as_str(), claim.object.id.as_str())).collect();

    let missed: Vec<String> = plants
        .iter()
        .filter(|(id, rule, _)| !found.contains(&(id.as_str(), rule.as_str())))
        .map(|(id, rule, kind)| format!("{rule} from {kind:?} ({id})"))
        .collect();
    let hit = plants.len() - missed.len();
    println!(
        "canary recall: {hit} of {} plants ({}%), {} rules",
        plants.len(),
        hit * 100 / plants.len(),
        pack.rule_count()
    );
    assert!(
        hit * 100 >= plants.len() * MIN_RECALL_PERCENT,
        "recall {hit} of {} is under {MIN_RECALL_PERCENT}%; missed: {missed:#?}",
        plants.len()
    );
    // Every rule is found from at least one of its kinds of witness.
    for rule in pack.rules() {
        assert!(
            plants.iter().any(|(id, planted, _)| planted == &rule.id
                && found.contains(&(id.as_str(), rule.id.as_str()))),
            "{} is found from none of its plants",
            rule.id
        );
    }
}
