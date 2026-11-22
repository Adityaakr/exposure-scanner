//! The differential test: the scanner of a base commit and the scanner of
//! the working tree report the same on every input, byte for byte.
//!
//! A change made for speed or memory must not change what a scan finds.
//! The tests check what they were written to check; this checks everything
//! else, by building both binaries and scanning one corpus with each:
//!
//! * The base commit (by default `origin/main`) is exported with `git
//!   archive`, as `repro` does, and built in its own target folder under
//!   `target/difftest/`, which is kept so the next run against the same
//!   commit does not build it again. `--base-bin FILE` takes a binary
//!   instead.
//! * The working tree is built as `cargo build --release` builds it.
//!
//! The corpus is the committed fixtures, a corpus this command writes from
//! the rule pack's own tokens (see [`crafted`]), and any PATH given, such as
//! `/Applications` or a folder of real apps. Each input is scanned once by
//! the base binary, without the results cache and on one thread per core,
//! and four times by the new one: the same way, on one thread, with an empty
//! cache and with the cache that scan filled. Every one of the new reports
//! must equal the base report.
//!
//! One difference is expected and allowed: `scanner.version`, should the
//! two builds be of different releases. A report holds no time, no path of
//! the machine and nothing that depends on the order work was done in, so
//! there is nothing else to set aside. Anything else that differs fails the
//! command, which says which claims and which evidence records differ.
//!
//! A change that is meant to change what scans report, such as a new rule
//! or a fixed false positive, says so with `--expect-changes`: the
//! differences are listed and the command succeeds. CI passes it when a
//! change touches the rules or the committed fixture reports, which a
//! change to what is reported has to update (see CONTRIBUTING.md).
//!
//! The scans run with a home folder of their own, so the results cache and
//! report of the person running this are never touched; the reports stay in
//! a folder only its owner can read, removed at the end unless `--keep`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use xs_formats::macho_build::{Binary, Section};
use xs_formats::testkit::{self, Attr, AxmlBuilder, DexBuilder, ZipBuilder};
use xs_model::matcher::Boundary;
use xs_model::pack::Token;
use xs_model::{MatcherKind, Pack};

use crate::{Result, cargo, repo_root};

/// What the scan behind one report was, for the summary.
const NEW_RUNS: [(&str, Mode); 4] = [
    ("no cache", Mode::NoCache { threads: None }),
    ("no cache, 1 thread", Mode::NoCache { threads: Some(1) }),
    ("empty cache", Mode::Cache),
    ("full cache", Mode::Cache),
];

#[derive(Debug, Clone, Copy)]
enum Mode {
    NoCache {
        threads: Option<usize>,
    },
    /// With the results cache of the input's own home folder.
    Cache,
}

/// `difftest [--base REV | --base-bin FILE] [--keep] [--expect-changes] [PATH...]`
pub(crate) fn run(args: &[&str]) -> Result<()> {
    let mut base_rev = String::from("origin/main");
    let mut base_bin = None;
    let mut keep = false;
    let mut expect_changes = false;
    let mut paths = Vec::new();
    let mut rest = args.iter();
    while let Some(&arg) = rest.next() {
        match arg {
            "--base" => base_rev = rest.next().ok_or("--base needs a revision")?.to_string(),
            "--base-bin" => {
                base_bin = Some(PathBuf::from(rest.next().ok_or("--base-bin needs a file")?))
            }
            "--keep" => keep = true,
            "--expect-changes" => expect_changes = true,
            option if option.starts_with("--") => {
                return Err(format!("difftest does not know the option {option}"));
            }
            path => paths.push(PathBuf::from(path)),
        }
    }
    for path in &paths {
        if !path.exists() {
            return Err(format!("{} does not exist", path.display()));
        }
    }

    let root = repo_root();
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    let base = match base_bin {
        Some(binary) => binary,
        None => build_base(&root, &target, &base_rev)?,
    };
    build(&root, &target)?;
    let new = target.join("release/exposure");

    let work = std::env::temp_dir().join(format!("exposure-difftest-{}", std::process::id()));
    private_dir(&work)?;
    let outcome = compare_all(&root, &base, &new, &paths, &work, expect_changes);
    if keep || outcome.is_err() {
        println!("the reports are kept in {}", work.display());
    } else {
        let _ = fs::remove_dir_all(&work);
    }
    outcome
}

fn private_dir(dir: &Path) -> Result<()> {
    let made = fs::create_dir_all(dir);
    #[cfg(unix)]
    let made = made.and_then(|()| {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
    });
    made.map_err(|error| format!("cannot create {}: {error}", dir.display()))
}

fn build(source: &Path, target: &Path) -> Result<()> {
    let status = Command::new(cargo())
        .args(["build", "--release", "--locked", "--quiet", "--package", "exposure"])
        .current_dir(source)
        .env("CARGO_TARGET_DIR", target)
        .status()
        .map_err(|error| format!("cannot run cargo: {error}"))?;
    if status.success() { Ok(()) } else { Err(format!("the build in {} failed", source.display())) }
}

/// Builds `rev` from an export of it, or finds the build of an earlier run.
fn build_base(root: &Path, target: &Path, rev: &str) -> Result<PathBuf> {
    let commit = git(root, &["rev-parse", "--verify", &format!("{rev}^{{commit}}")])?;
    let dir = target.join("difftest").join(&commit);
    let binary = dir.join("target/release/exposure");
    if binary.is_file() {
        println!("base {rev} ({}): built before, in {}", short(&commit), dir.display());
        return Ok(binary);
    }
    let source = dir.join("source");
    let _ = fs::remove_dir_all(&source);
    fs::create_dir_all(&source)
        .map_err(|error| format!("cannot create {}: {error}", source.display()))?;
    let archive = dir.join("source.tar");
    let archive_text = archive.to_str().ok_or("the target folder is not UTF-8")?;
    git(root, &["archive", "--format=tar", "--output", archive_text, &commit])?;
    let unpacked = Command::new("tar")
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(&source)
        .status()
        .map_err(|error| format!("cannot run tar: {error}"))?;
    if !unpacked.success() {
        return Err(String::from("tar failed"));
    }
    println!("building base {rev} ({}) in {}", short(&commit), dir.display());
    build(&source, &dir.join("target"))?;
    Ok(binary)
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

/// One input of the corpus: a name for the summary and what is scanned.
struct Input {
    name: String,
    paths: Vec<PathBuf>,
}

fn corpus(root: &Path, extra: &[PathBuf], work: &Path) -> Result<Vec<Input>> {
    let fixtures = root.join("tests/fixtures");
    let mut inputs = vec![
        Input { name: "fixtures/macos".into(), paths: vec![fixtures.join("macos")] },
        Input { name: "fixtures/android".into(), paths: vec![fixtures.join("android")] },
        Input {
            name: "fixtures/browser".into(),
            paths: vec![
                fixtures.join("browser/Extensions"),
                fixtures.join("browser/addon@example.org.xpi"),
            ],
        },
    ];
    let crafted = work.join("corpus");
    let (bundles, packages) = crafted::write(root, &crafted)?;
    inputs.push(Input { name: "crafted/bundles".into(), paths: vec![bundles.clone()] });
    inputs.push(Input { name: "crafted/packages".into(), paths: vec![packages.clone()] });
    inputs.push(Input {
        name: "everything above in one scan".into(),
        paths: vec![fixtures.join("macos"), fixtures.join("android"), bundles, packages],
    });
    for path in extra {
        inputs.push(Input { name: path.display().to_string(), paths: vec![path.clone()] });
    }
    Ok(inputs)
}

fn compare_all(
    root: &Path,
    base: &Path,
    new: &Path,
    extra: &[PathBuf],
    work: &Path,
    expect_changes: bool,
) -> Result<()> {
    let inputs = corpus(root, extra, work)?;
    let mut failed = Vec::new();
    println!("{:<44} {:>6} {:>9}  result", "input", "claims", "records");
    for (number, input) in inputs.iter().enumerate() {
        let dir = work.join(format!("input-{number}"));
        private_dir(&dir)?;
        let reference = scan(base, input, Mode::NoCache { threads: None }, &dir, "base")?;
        let reference_value = normalized(&reference, "base")?;
        let (claims, records) = sizes(&reference_value);
        let mut differences = Vec::new();
        for (run, (label, mode)) in NEW_RUNS.iter().enumerate() {
            let report = scan(new, input, *mode, &dir, &format!("new-{run}"))?;
            if report == reference {
                continue;
            }
            let value = normalized(&report, "new")?;
            if value != reference_value {
                differences.push(format!("{label}: {}", describe(&reference_value, &value)));
            }
        }
        if differences.is_empty() {
            println!(
                "{:<44} {claims:>6} {records:>9}  same in {} scans",
                input.name,
                NEW_RUNS.len()
            );
        } else {
            println!("{:<44} {claims:>6} {records:>9}  DIFFERENT", input.name);
            for difference in &differences {
                println!("    {difference}");
            }
            failed.push(input.name.clone());
        }
    }
    if failed.is_empty() {
        println!("ok: every report of the new build equals the base build's");
        Ok(())
    } else if expect_changes {
        println!(
            "ok: the reports differ on {}, as --expect-changes says they may",
            failed.join(", ")
        );
        Ok(())
    } else {
        Err(format!("the reports differ on: {}", failed.join(", ")))
    }
}

/// Runs one scan of `input` and returns the JSON report it wrote.
fn scan(binary: &Path, input: &Input, mode: Mode, dir: &Path, label: &str) -> Result<Vec<u8>> {
    let report = dir.join(format!("{label}.json"));
    let home = dir.join(format!("home-{}", if label == "base" { "base" } else { "new" }));
    private_dir(&home)?;
    let mut command = Command::new(binary);
    command.arg("scan").arg("--no-open").arg("--json").arg(&report);
    match mode {
        Mode::NoCache { threads } => {
            command.arg("--no-cache");
            if let Some(threads) = threads {
                command.arg("--threads").arg(threads.to_string());
            }
        }
        Mode::Cache => {}
    }
    command.arg("--").args(&input.paths);
    let output = command
        .env("HOME", &home)
        .env_remove("XDG_CACHE_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .map_err(|error| format!("cannot run {}: {error}", binary.display()))?;
    // 3 is a finding that meets a --fail-on condition; none is given.
    if !output.status.success() {
        return Err(format!(
            "{label} scan of {} failed: {}",
            input.name,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    crate::read(&report)
}

/// The report as a JSON value, with the one field that may differ removed.
fn normalized(report: &[u8], label: &str) -> Result<Value> {
    let mut value: Value = serde_json::from_slice(report)
        .map_err(|error| format!("the {label} report does not parse: {error}"))?;
    if let Some(scanner) = value.get_mut("scanner").and_then(Value::as_object_mut) {
        scanner.remove("version");
    }
    Ok(value)
}

fn sizes(report: &Value) -> (usize, usize) {
    let claims = report.get("claims").and_then(Value::as_array).map_or(0, Vec::len);
    let records = report.get("evidence").and_then(Value::as_object).map_or(0, |map| map.len());
    (claims, records)
}

/// Which parts of two reports differ, in a few lines.
fn describe(base: &Value, new: &Value) -> String {
    let mut out = String::new();
    let empty = serde_json::Map::new();
    let evidence = |report: &Value| -> BTreeMap<String, Value> {
        report
            .get("evidence")
            .and_then(Value::as_object)
            .unwrap_or(&empty)
            .iter()
            .map(|(id, record)| (id.clone(), record.clone()))
            .collect()
    };
    let (old, now) = (evidence(base), evidence(new));
    let only_base: Vec<&String> = old.keys().filter(|id| !now.contains_key(*id)).collect();
    let only_new: Vec<&String> = now.keys().filter(|id| !old.contains_key(*id)).collect();
    if !only_base.is_empty() {
        let _ = write!(
            out,
            "{} records only in base, such as {}; ",
            only_base.len(),
            sample(&old, &only_base)
        );
    }
    if !only_new.is_empty() {
        let _ = write!(
            out,
            "{} records only in new, such as {}; ",
            only_new.len(),
            sample(&now, &only_new)
        );
    }
    for key in ["claims", "headline", "scope", "packs", "schema"] {
        if base.get(key) != new.get(key) {
            let _ = write!(out, "{key} differ; ");
        }
    }
    if out.is_empty() {
        out.push_str("the reports differ in their bytes only");
    }
    out
}

fn sample(records: &BTreeMap<String, Value>, ids: &[&String]) -> String {
    ids.first().and_then(|id| records.get(*id)).map_or_else(String::new, |record| {
        let text = record.to_string();
        text.chars().take(300).collect()
    })
}

/// The corpus this command writes: apps made of the rule pack's own tokens,
/// laid out to reach the scanner's edges rather than to look real.
pub(crate) mod crafted {
    use super::*;

    /// The window the scanner reads files in, and the size below which a
    /// file is read on the small lane. Files are written on both sides of
    /// each, and literals across window edges.
    const WINDOW: usize = 1 << 20;
    const SMALL: usize = 256 << 10;

    fn put(path: &Path, bytes: impl AsRef<[u8]>) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        crate::write(path, bytes.as_ref())
    }

    /// Every token of the built-in pack, by the kind of matcher it is for.
    fn tokens(root: &Path) -> Result<BTreeMap<MatcherKind, Vec<Token>>> {
        let pack_bytes = crate::read(&root.join("rules/dist/core.pack.json"))?;
        let signature = crate::read_text(&root.join("rules/dist/core.pack.json.minisig"))?;
        let pack: Pack = xs_rules::load_pack(
            &[xs_rules::SignedLayer { bytes: &pack_bytes, signature: &signature }],
            xs_rules::TRUSTED_KEYS,
        )
        .map_err(|error| format!("cannot load the rule pack: {error}"))?;
        let mut tokens: BTreeMap<MatcherKind, Vec<Token>> = BTreeMap::new();
        for rule in pack.rules() {
            for (kind, listed) in &rule.matchers {
                tokens.entry(*kind).or_default().extend(listed.iter().cloned());
            }
        }
        Ok(tokens)
    }

    /// A value a token of its boundary hits, as the canary test plants it.
    fn value(token: &Token) -> String {
        match token.at {
            Boundary::Prefix if token.lit.ends_with('.') => format!("{}Plant", token.lit),
            Boundary::Prefix => format!("{}.Plant", token.lit),
            _ => token.lit.clone(),
        }
    }

    fn in_text(token: &Token) -> String {
        match token.at {
            Boundary::Host => format!("https://{}/v1/plant", token.lit),
            _ => format!("\"{}\"", value(token)),
        }
    }

    /// Filler that is not text and holds no literal: a counter, spread out.
    fn filler(len: usize, seed: usize) -> Vec<u8> {
        (0..len)
            .map(|index| (index.wrapping_mul(31).wrapping_add(seed) % 251) as u8 | 0x80)
            .collect()
    }

    /// `literal` placed so that it straddles every window edge in `bytes`.
    fn straddle(bytes: &mut [u8], literal: &[u8]) {
        let mut edge = WINDOW;
        while edge + literal.len() < bytes.len() {
            let at = edge - literal.len() / 2;
            if let Some(slot) = bytes.get_mut(at..at + literal.len()) {
                slot.copy_from_slice(literal);
            }
            edge += WINDOW;
        }
    }

    fn info_plist(id: &str, index: usize) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleShortVersionString</key><string>1.{index}</string>
<key>CFBundleName</key><string>Plant {index}</string>
<key>CFBundleExecutable</key><string>Plant</string>
<key>NSCameraUsageDescription</key><string>To take a photo.</string>
<key>NSMicrophoneUsageDescription</key><string>To record a note.</string>
</dict></plist>"#
        )
    }

    /// The bytes of an asar archive that holds `files`.
    fn asar(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
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
                    .and_then(Value::as_object_mut)
                    .ok_or("an asar folder that is not one")?;
            }
            let offset = data.len().to_string();
            data.extend_from_slice(content);
            folder.insert(
                name.to_string(),
                serde_json::json!({"offset": offset, "size": content.len()}),
            );
        }
        let json = serde_json::json!({"files": tree}).to_string();
        let len = u32::try_from(json.len()).map_err(|error| error.to_string())?;
        let padded = len.div_ceil(4) * 4;
        let mut bytes = Vec::new();
        for word in [4, padded + 8, padded + 4, len] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(json.as_bytes());
        bytes.resize(16 + padded as usize, 0);
        bytes.extend_from_slice(&data);
        Ok(bytes)
    }

    /// Writes the corpus into `dir` and returns its folder of bundles and
    /// its folder of packages.
    pub(crate) fn write(root: &Path, dir: &Path) -> Result<(PathBuf, PathBuf)> {
        let tokens = tokens(root)?;
        let of = |kind: MatcherKind| tokens.get(&kind).cloned().unwrap_or_default();
        let bundles = dir.join("bundles");
        let packages = dir.join("packages");
        write_bundles(&bundles, &of)?;
        write_packages(&packages, &of)?;
        Ok((bundles, packages))
    }

    fn write_bundles(dir: &Path, of: &dyn Fn(MatcherKind) -> Vec<Token>) -> Result<()> {
        let script_tokens = of(MatcherKind::ContentLiteral);
        let macho_tokens = of(MatcherKind::MachoToken);
        let classes = of(MatcherKind::MachoObjcClass);
        let frameworks = of(MatcherKind::AppleFramework);
        let npm = of(MatcherKind::NpmPackage);
        let privacy = of(MatcherKind::PrivacyManifest);
        for index in 0..6usize {
            let id = format!("org.example.difftest.app{index}");
            let app = dir.join(format!("Plant{index}.app")).join("Contents");
            put(&app.join("Info.plist"), info_plist(&id, index))?;

            // The main executable: class names and strings in their
            // sections, and a large data section with literals across
            // every window edge.
            let mut names = Vec::new();
            for token in classes.iter().skip(index).step_by(3) {
                names.extend_from_slice(value(token).as_bytes());
                names.push(0);
            }
            let mut cstrings = Vec::new();
            for token in macho_tokens.iter().skip(index % 2).step_by(2) {
                cstrings.extend_from_slice(in_text(token).trim_matches('"').as_bytes());
                cstrings.push(0);
            }
            let mut big = filler(3 * WINDOW + index * 4099, index);
            if let Some(token) = macho_tokens.get(index % macho_tokens.len().max(1)) {
                straddle(&mut big, in_text(token).trim_matches('"').as_bytes());
            }
            let main = Binary::new()
                .section(Section::code("__TEXT", "__text", &filler(4096, index)))
                .section(Section::data("__TEXT", "__objc_classname", &names))
                .section(Section::data("__TEXT", "__cstring", &cstrings))
                .section(Section::data("__DATA", "__const", &big))
                .build();
            put(&app.join("MacOS/Plant"), main)?;

            // Frameworks named by tokens, one with a privacy manifest, and
            // an Electron runtime, whose bytes are hashed and not searched.
            for token in frameworks.iter().skip(index).step_by(4) {
                let stem = token.lit.trim_end_matches(".framework");
                let path = app.join("Frameworks").join(&token.lit).join("Versions/A").join(stem);
                put(&path, Binary::new().trailer(&filler(SMALL + index, index)).build())?;
            }
            if index % 2 == 0 {
                let listed: String =
                    privacy.iter().map(|token| format!("<string>{}</string>", token.lit)).collect();
                put(
                    &app.join("Frameworks/PlantKit.framework/Resources/PrivacyInfo.xcprivacy"),
                    format!(
                        "<plist version=\"1.0\"><dict><key>NSPrivacyTracking</key><true/>\
                         <key>NSPrivacyTrackingDomains</key><array>{listed}</array></dict></plist>"
                    ),
                )?;
            }
            let mut runtime = filler(2 * WINDOW + 17, index);
            if let Some(token) = script_tokens.first() {
                // A runtime that names a company is not evidence of it.
                straddle(&mut runtime, in_text(token).as_bytes());
            }
            put(
                &app.join("Frameworks/Electron Framework.framework/Versions/A/Electron Framework"),
                Binary::new().trailer(&runtime).build(),
            )?;

            // A loose code root: many small scripts, a few on either side
            // of the small-lane and window sizes, and packages by name.
            let code = app.join("Resources/app");
            put(&code.join("package.json"), "{\"name\":\"plant\",\"main\":\"main.js\"}")?;
            for (number, token) in npm.iter().enumerate().skip(index).step_by(3) {
                put(&code.join("node_modules").join(&token.lit).join("package.json"), "{}")?;
                put(
                    &code.join("node_modules").join(&token.lit).join(format!("i{number}.js")),
                    "x();",
                )?;
            }
            for number in 0..400usize {
                let token = script_tokens.get((number + index) % script_tokens.len().max(1));
                let mut body = format!("var n{number}=function(a){{return a+{number}}};\n")
                    .repeat(1 + number % 9);
                if number % 7 == 0
                    && let Some(token) = token
                {
                    body.push_str(&format!("const host={};\n", in_text(token)));
                }
                let folder = if number % 3 == 0 { "node_modules/vendor/lib" } else { "src" };
                put(&code.join(folder).join(format!("m{number:03}.js")), body)?;
            }
            for (number, size) in
                [SMALL - 1, SMALL, SMALL + 1, WINDOW - 1, WINDOW, WINDOW + 1].iter().enumerate()
            {
                let mut body = vec![b' '; *size];
                if let Some(token) = script_tokens.get(number % script_tokens.len().max(1)) {
                    let text = in_text(token);
                    straddle(&mut body, text.as_bytes());
                    let at = size.saturating_sub(text.len() + 1);
                    if let Some(slot) = body.get_mut(at..at + text.len()) {
                        slot.copy_from_slice(text.as_bytes());
                    }
                }
                put(&code.join(format!("src/edge{number}.js")), body)?;
            }
            // An archive beside the loose root, as some apps ship both.
            if index % 3 == 1 {
                let mut files = vec![
                    (String::from("package.json"), b"{\"name\":\"plant-asar\"}".to_vec()),
                    (String::from("main.js"), b"boot();".to_vec()),
                ];
                for token in script_tokens.iter().skip(index).step_by(5) {
                    files.push((
                        format!("lib/{}.js", files.len()),
                        format!("send({});", in_text(token)).into_bytes(),
                    ));
                }
                put(&app.join("Resources/app.asar"), asar(&files)?)?;
            }
            // Files that are not code: pictures, data, an empty file, and a
            // link, which is never followed.
            for number in 0..300usize {
                put(
                    &app.join(format!("Resources/assets/a{number:03}.png")),
                    filler(100 + number * 37, number),
                )?;
            }
            put(&app.join("Resources/empty.dat"), b"")?;
            #[cfg(unix)]
            {
                let link = app.join("Resources/link-to-main");
                let _ = fs::remove_file(&link);
                std::os::unix::fs::symlink("../MacOS/Plant", &link)
                    .map_err(|error| format!("cannot link {}: {error}", link.display()))?;
            }
        }
        Ok(())
    }

    fn write_packages(dir: &Path, of: &dyn Fn(MatcherKind) -> Vec<Token>) -> Result<()> {
        let components: Vec<String> =
            of(MatcherKind::ManifestComponent).iter().map(value).collect();
        let classes: Vec<String> = of(MatcherKind::AndroidClassPrefix).iter().map(value).collect();
        let strings: Vec<String> = of(MatcherKind::DexString)
            .iter()
            .map(|token| in_text(token).trim_matches('"').to_string())
            .collect();
        let files: Vec<String> = of(MatcherKind::ApkFile).iter().map(value).collect();

        let manifest = |id: &str, components: &[String]| {
            let mut builder = AxmlBuilder::new()
                .start(
                    "manifest",
                    &[
                        Attr::int(testkit::ANDROID_VERSION_CODE, "versionCode", 7),
                        Attr::android(testkit::ANDROID_VERSION_NAME, "versionName", "7.0"),
                        Attr::plain("package", id),
                    ],
                )
                .start(
                    "uses-permission",
                    &[Attr::android(testkit::ANDROID_NAME, "name", "android.permission.CAMERA")],
                )
                .end()
                .start("application", &[Attr::android(testkit::ANDROID_LABEL, "label", "Plant")]);
            for name in components {
                builder = builder
                    .start("service", &[Attr::android(testkit::ANDROID_NAME, "name", name)])
                    .end();
            }
            builder.end().end().finish()
        };
        let dex = |classes: &[String], strings: &[String], pad: usize| {
            let mut builder = DexBuilder::new();
            for class in classes {
                builder = builder.class(class);
            }
            for string in strings {
                builder = builder.string(string);
            }
            for number in 0..pad {
                builder = builder.string(&format!("org.example.filler.String{number:06}"));
            }
            builder.finish()
        };

        // Packages that are well formed, with what each witness reads.
        for index in 0..4usize {
            let id = format!("org.example.difftest.pkg{index}");
            let pick = |list: &[String]| -> Vec<String> {
                list.iter().skip(index).step_by(2).cloned().collect()
            };
            let mut zip = ZipBuilder::new()
                .deflated("AndroidManifest.xml", &manifest(&id, &pick(&components)))
                .deflated("classes.dex", &dex(&pick(&classes), &pick(&strings), 2000 * index));
            if index % 2 == 1 {
                zip = zip.stored("classes2.dex", &dex(&classes, &[], 10));
            }
            for name in pick(&files) {
                zip = zip.stored(&name, b"x");
            }
            put(&dir.join(format!("pkg{index}.apk")), zip.finish())?;
        }
        // The same app as a bundle for Google Play.
        put(
            &dir.join("bundle.aab"),
            ZipBuilder::new()
                .deflated("base/manifest/AndroidManifest.xml", &[0x0a, 0x00])
                .deflated("base/dex/classes.dex", &dex(&classes, &strings, 0))
                .finish(),
        )?;
        // Packages that are damaged or made to mislead a reader, as the
        // hardening review found them: an "encrypted" manifest, unknown
        // methods, a local header that disagrees with the directory, a cut
        // archive, a DEX file that inflates past what one entry may hold,
        // and a package that holds nothing a scanner can use.
        let good_manifest = manifest("org.example.difftest.damaged", &components);
        let good_dex = dex(&classes, &strings, 0);
        let deflated = |bytes: &[u8]| miniz_oxide::deflate::compress_to_vec(bytes, 6);
        let len = |bytes: &[u8]| u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "manifest-encrypted-flag.apk",
                ZipBuilder::new()
                    .raw(
                        "AndroidManifest.xml",
                        8,
                        1,
                        &deflated(&good_manifest),
                        len(&good_manifest),
                    )
                    .deflated("classes.dex", &good_dex)
                    .finish(),
            ),
            (
                "manifest-method-99.apk",
                ZipBuilder::new()
                    .raw("AndroidManifest.xml", 99, 0, &good_manifest, len(&good_manifest))
                    .deflated("classes.dex", &good_dex)
                    .finish(),
            ),
            (
                "dex-method-99.apk",
                ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &good_manifest)
                    .raw("classes.dex", 99, 0, &good_dex, len(&good_dex))
                    .finish(),
            ),
            (
                "dex-inflates-past-its-size.apk",
                ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &good_manifest)
                    .raw("classes.dex", 8, 0, &deflated(&vec![0u8; 40 << 20]), 1 << 10)
                    .finish(),
            ),
            (
                "dex-bomb.apk",
                ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &good_manifest)
                    .raw("classes.dex", 8, 0, &deflated(&vec![0u8; 40 << 20]), 40 << 20)
                    .raw("classes2.dex", 8, 0, &deflated(&vec![0u8; 40 << 20]), 40 << 20)
                    .finish(),
            ),
            ("cut.apk", {
                let mut whole = ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &good_manifest)
                    .deflated("classes.dex", &good_dex)
                    .finish();
                whole.truncate(whole.len() / 2);
                whole
            }),
            ("dex-empty-header-then-nothing.apk", {
                let mut dex = DexBuilder::new().finish();
                dex.resize(40 << 20, 0);
                ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &good_manifest)
                    .deflated("classes.dex", &dex)
                    .finish()
            }),
            ("dex-version-041-then-nothing.apk", {
                let mut dex = DexBuilder::new().finish();
                dex.resize(40 << 20, 0);
                if let Some(version) = dex.get_mut(4..7) {
                    version.copy_from_slice(b"041");
                }
                ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &good_manifest)
                    .deflated("classes.dex", &dex)
                    .finish()
            }),
            ("dex-large-with-strings.apk", {
                let mut dex = good_dex.clone();
                dex.resize(40 << 20, 0);
                ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &good_manifest)
                    .deflated("classes.dex", &dex)
                    .finish()
            }),
            (
                "dex-inflates-past-what-it-declares.apk",
                ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &good_manifest)
                    .raw("classes.dex", 8, 0, &deflated(&DexBuilder::new().finish()), 0x70)
                    .finish(),
            ),
            ("not-a-zip.apk", filler(5000, 3)),
            ("empty.apk", Vec::new()),
            ("no-manifest.apk", ZipBuilder::new().deflated("classes.dex", &good_dex).finish()),
        ];
        for (name, bytes) in cases {
            put(&dir.join(name), bytes)?;
        }
        // The app's name, which the manifest points at in the resource
        // table: a table after the manifest, before it, one that does not
        // hold the string, one that is not a table, and the same in a
        // bundle, whose table is a protocol buffer.
        const LABEL: u32 = 0x7f0f_0001;
        let labelled = |id: &str, label: u32| {
            AxmlBuilder::new()
                .start("manifest", &[Attr::plain("package", id)])
                .start("application", &[Attr::reference(testkit::ANDROID_LABEL, "label", label)])
                .end()
                .end()
                .finish()
        };
        let table = testkit::ArscBuilder::new()
            .string(LABEL, &[(None, "Plant Name"), (Some(*b"de"), "Pflanze")])
            .finish();
        let named: Vec<(&str, Vec<u8>)> = vec![
            ("name-table-after.apk", {
                ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &labelled("org.example.difftest.after", LABEL))
                    .deflated("classes.dex", &good_dex)
                    .stored("resources.arsc", &table)
                    .finish()
            }),
            ("name-table-before.apk", {
                ZipBuilder::new()
                    .stored("resources.arsc", &table)
                    .deflated(
                        "AndroidManifest.xml",
                        &labelled("org.example.difftest.before", LABEL),
                    )
                    .deflated("classes.dex", &good_dex)
                    .finish()
            }),
            ("name-not-in-table.apk", {
                ZipBuilder::new()
                    .deflated(
                        "AndroidManifest.xml",
                        &labelled("org.example.difftest.missing", LABEL + 1),
                    )
                    .deflated("resources.arsc", &table)
                    .finish()
            }),
            ("name-table-unreadable.apk", {
                ZipBuilder::new()
                    .deflated(
                        "AndroidManifest.xml",
                        &labelled("org.example.difftest.unreadable", LABEL),
                    )
                    .stored("resources.arsc", b"not a resource table")
                    .finish()
            }),
            ("name-table-unreadable-unneeded.apk", {
                ZipBuilder::new()
                    .deflated("AndroidManifest.xml", &good_manifest)
                    .stored("resources.arsc", b"not a resource table")
                    .finish()
            }),
            ("name-bundle.aab", {
                let manifest = testkit::ProtoXml::new()
                    .start("manifest", &[Attr::plain("package", "org.example.difftest.bundle")])
                    .start(
                        "application",
                        &[Attr::reference(testkit::ANDROID_LABEL, "label", LABEL)],
                    )
                    .end()
                    .end()
                    .finish();
                let resources = testkit::ProtoResources::new()
                    .string(LABEL, &[(None, "Plant Bundle")])
                    .finish();
                ZipBuilder::new()
                    .deflated("base/manifest/AndroidManifest.xml", &manifest)
                    .deflated("base/dex/classes.dex", &good_dex)
                    .deflated("base/resources.pb", &resources)
                    .finish()
            }),
        ];
        for (name, bytes) in named {
            put(&dir.join(name), bytes)?;
        }
        // A local header that names another entry than the directory does.
        let mut mismatched = ZipBuilder::new()
            .deflated("AndroidManifest.xml", &good_manifest)
            .deflated("classes.dex", &good_dex)
            .finish();
        if let Some(at) = find(&mismatched, b"classes.dex")
            && let Some(byte) = mismatched.get_mut(at)
        {
            *byte = b'C';
        }
        put(&dir.join("local-header-mismatch.apk"), mismatched)?;
        Ok(())
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|window| window == needle)
    }
}
