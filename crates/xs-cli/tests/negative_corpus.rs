//! Property 2, "does not cry wolf": the negative-control corpus (design
//! report, section 7).
//!
//! Real apps that ship no code of another company are scanned, and any
//! channel to a company other than the app's own publisher, at any grade
//! and any confidence, fails the test. One channel is expected and allowed:
//! the update feed the app's own property list names, which is the app's
//! own even when another company, such as GitHub, hosts it (build plan,
//! task 6: "Maccy reports no SDK and a graded update feed"). The corpus holds hard negatives on
//! purpose: a web browser, an ad blocker, apps that embed Chromium, and
//! apps whose bundled documentation names SDKs.
//!
//! The apps are never stored in this repository. They are pinned by hash
//! and download address in `tests/fixtures/negative-apps.txt`, fetched into
//! a cache folder, and read from there:
//!
//! ```console
//! $ cargo xtask fixtures negatives --dir DIR [--all]
//! $ EXPOSURE_NEGATIVE_CACHE=DIR [EXPOSURE_NEGATIVE_SET=all] cargo test -p exposure --test negative_corpus
//! ```
//!
//! Without `EXPOSURE_NEGATIVE_CACHE` the test has nothing to scan and passes
//! after saying so. With it, the apps of the set `every-change` are scanned,
//! or every app when `EXPOSURE_NEGATIVE_SET` is `all`; one that is missing
//! from the folder or has another hash fails the test. CI scans the first
//! set on every change and the whole corpus nightly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::print_stderr,
    reason = "tests run the binary, read the environment and say when they are skipped"
)]

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use xs_model::record::{EdgeType, Record, declared};
use xs_model::{Party, Report, Sha256Stream, SubjectDigest};

const PINS: &str = include_str!("../../../tests/fixtures/negative-apps.txt");

/// One pinned app.
struct Negative<'a> {
    sha256: &'a str,
    file: &'a str,
    every_change: bool,
    /// For a zip, the app inside it.
    app: Option<&'a str>,
}

fn negatives() -> Vec<Negative<'static>> {
    PINS.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| match line.split_whitespace().collect::<Vec<_>>()[..] {
            [sha256, file, _url, set, app] => Negative {
                sha256,
                file,
                every_change: set == "every-change",
                app: (app != "-").then_some(app),
            },
            _ => panic!("tests/fixtures/negative-apps.txt: cannot read {line:?}"),
        })
        .collect()
}

fn sha256_of(path: &Path) -> String {
    let mut reader = File::open(path).unwrap_or_else(|error| {
        panic!(
            "{}: {error}. Run: cargo xtask fixtures negatives --dir <cache> [--all]",
            path.display()
        )
    });
    let mut hasher = Sha256Stream::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let count = reader.read(&mut buffer).unwrap();
        if count == 0 {
            return hasher.finish().to_hex();
        }
        hasher.update(&buffer[..count]);
    }
}

#[test]
fn the_pinned_corpus_is_large_and_holds_both_platforms() {
    let negatives = negatives();
    let files: BTreeSet<&str> = negatives.iter().map(|negative| negative.file).collect();
    assert_eq!(files.len(), negatives.len(), "an app is pinned once");
    assert!(negatives.len() >= 20, "the corpus grows toward 30 apps; it has {}", negatives.len());
    let every_change = negatives.iter().filter(|negative| negative.every_change).count();
    assert!((6..=10).contains(&every_change), "a subset of 6 to 10 apps runs on every change");
    assert!(negatives.iter().any(|negative| negative.app.is_some()), "macOS apps");
    assert!(negatives.iter().any(|negative| negative.app.is_none()), "Android apps");
}

#[test]
fn no_negative_control_app_has_a_channel_to_another_company() {
    let Some(cache) = std::env::var_os("EXPOSURE_NEGATIVE_CACHE") else {
        eprintln!(
            "skipped: set EXPOSURE_NEGATIVE_CACHE to scan the negative corpus \
             (see tests/fixtures/README.md)"
        );
        return;
    };
    let cache = PathBuf::from(cache);
    let all = std::env::var("EXPOSURE_NEGATIVE_SET").is_ok_and(|set| set == "all");
    let chosen: Vec<Negative<'_>> =
        negatives().into_iter().filter(|negative| all || negative.every_change).collect();

    let mut paths = Vec::new();
    for negative in &chosen {
        let file = cache.join(negative.file);
        assert_eq!(sha256_of(&file), negative.sha256, "{} is not the pinned file", file.display());
        paths.push(match negative.app {
            Some(app) => cache.join(format!("{}.d", negative.file)).join(app),
            None => file,
        });
    }

    let output = Command::new(env!("CARGO_BIN_EXE_exposure"))
        .args(["scan", "--no-cache", "--json", "-", "--"])
        .args(&paths)
        .output()
        .unwrap();
    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{summary}");
    let report: Report = serde_json::from_slice(&output.stdout).unwrap();
    eprintln!("{summary}");

    // Every app was read: a scan that could not read one proves nothing of
    // it.
    let mut read = BTreeSet::new();
    for (_, record) in &report.evidence {
        if let Record::Artifact(artifact) = record {
            assert_ne!(artifact.subject.digest, SubjectDigest::Unread, "{:?}", artifact.subject);
            read.insert(&artifact.subject.digest);
        }
    }
    assert!(read.len() >= paths.len(), "{} apps read of {}", read.len(), paths.len());

    let update_feed = declared::category(declared::UPDATE_FEED);
    assert!(update_feed.is_some());
    let wolves: Vec<String> = report
        .claims
        .iter()
        .filter(|claim| {
            claim.edge == EdgeType::Channel
                && claim.company.is_some()
                && claim.party != Party::First
                && Some(claim.category.as_str()) != update_feed
        })
        .map(|claim| {
            format!(
                "{} {}: {} ({:?}, {:?})",
                claim.subject.id, claim.object.id, claim.category, claim.grade, claim.confidence
            )
        })
        .collect();
    assert!(wolves.is_empty(), "a negative-control app has a channel to a company: {wolves:#?}");
}
