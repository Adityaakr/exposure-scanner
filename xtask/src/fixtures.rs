//! Fetching the real apps the tests scan.
//!
//! Real artifacts are never stored in the repository. They are pinned in
//! `tests/fixtures/real-apps.txt`, one per line, by the SHA-256 of the
//! file, the name it has in the cache, and the address its publisher offers
//! it at. This command downloads the ones a cache folder does not hold yet
//! and refuses any file whose hash is not the pinned one. The tests that
//! scan them read the same list and check the same hashes.
//!
//! The download is done by `curl`, which this tool may run and the scanner
//! may not: no crate that can open a socket is allowed into the workspace.
//!
//! The negative-control corpus (design report, section 7, property 2) is
//! pinned the same way in `tests/fixtures/negative-apps.txt`, with two
//! more columns: the set an app is in (`every-change`, the subset CI scans
//! on every change, or `nightly`) and, for a macOS app that is published
//! as a zip, the path of the bundle inside it. `fixtures negatives` fetches
//! them and unpacks each zip, with `unzip`, into a folder of its own beside
//! it.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use xs_model::{Sha256Digest, Sha256Stream};

use crate::{Result, read_text, repo_root};

const PINS: &str = "tests/fixtures/real-apps.txt";
const NEGATIVES: &str = "tests/fixtures/negative-apps.txt";

/// Which part of the negative corpus to fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Set {
    /// The apps CI scans on every change.
    EveryChange,
    /// Every app, which CI scans nightly.
    All,
}

/// One app of the negative corpus.
#[derive(Debug, PartialEq, Eq)]
struct Negative<'a> {
    pin: Pin<'a>,
    /// Whether CI scans it on every change, and not only nightly.
    every_change: bool,
    /// For a zip, the path of the app inside it.
    app: Option<&'a str>,
}

/// One pinned artifact.
#[derive(Debug, PartialEq, Eq)]
struct Pin<'a> {
    sha256: Sha256Digest,
    file: &'a str,
    url: &'a str,
}

/// Parses the pin list. Lines that are empty or start with `#` are skipped.
fn pins(text: &str) -> Result<Vec<Pin<'_>>> {
    let mut pins: Vec<Pin<'_>> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fail = |what: &str| format!("{PINS}, line {}: {what}", index + 1);
        let [sha256, file, url] = line.split_whitespace().collect::<Vec<_>>()[..] else {
            return Err(fail("expected a SHA-256, a file name and an address"));
        };
        let pin = pin(sha256, file, url).map_err(|what| fail(&what))?;
        if pins.iter().any(|known| known.file == file) {
            return Err(fail("the file name is pinned twice"));
        }
        pins.push(pin);
    }
    Ok(pins)
}

/// Parses the negative corpus: a pin, its set, and the app inside a zip.
fn negatives(text: &str) -> Result<Vec<Negative<'_>>> {
    let mut negatives: Vec<Negative<'_>> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fail = |what: &str| format!("{NEGATIVES}, line {}: {what}", index + 1);
        let [sha256, file, url, set, app] = line.split_whitespace().collect::<Vec<_>>()[..] else {
            return Err(fail(
                "expected a SHA-256, a file name, an address, a set and the app in a zip",
            ));
        };
        let pin = pin(sha256, file, url).map_err(|what| fail(&what))?;
        let every_change = match set {
            "every-change" => true,
            "nightly" => false,
            _ => return Err(fail("the set is every-change or nightly")),
        };
        let app = match (app, file.ends_with(".zip")) {
            ("-", false) => None,
            (path, true) if path != "-" => {
                // Joined to the folder the zip is unpacked in: it must stay
                // inside it.
                let inside = !path.starts_with('/')
                    && path.ends_with(".app")
                    && path.split('/').all(|part| !part.is_empty() && part != "." && part != "..");
                if !inside {
                    return Err(fail("the app is a relative path to a .app inside the zip"));
                }
                Some(path)
            }
            _ => return Err(fail("a zip names the app inside it, and only a zip does")),
        };
        if negatives.iter().any(|known| known.pin.file == file) {
            return Err(fail("the file name is pinned twice"));
        }
        negatives.push(Negative { pin, every_change, app });
    }
    Ok(negatives)
}

/// Checks the three columns every pin has.
fn pin<'a>(sha256: &str, file: &'a str, url: &'a str) -> std::result::Result<Pin<'a>, String> {
    let sha256 =
        Sha256Digest::from_hex(sha256).ok_or("the hash is not 64 lowercase hex characters")?;
    // The name is joined to the cache folder, so it must be a plain file
    // name and nothing that could leave the folder.
    let plain = !file.starts_with('.')
        && file.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    if !plain {
        return Err(String::from(
            "the file name may hold letters, digits, dots, dashes and underscores",
        ));
    }
    if !url.starts_with("https://") {
        return Err(String::from("the address must start with https://"));
    }
    Ok(Pin { sha256, file, url })
}

fn sha256_of(path: &Path) -> Result<Sha256Digest> {
    let fail = |error| format!("cannot read {}: {error}", path.display());
    let mut file = std::fs::File::open(path).map_err(fail)?;
    let mut hasher = Sha256Stream::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let count = file.read(&mut buffer).map_err(fail)?;
        if count == 0 {
            return Ok(hasher.finish());
        }
        hasher.update(buffer.get(..count).unwrap_or_default());
    }
}

/// The cache folder, made if need be and refused inside the repository.
fn cache_folder(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    let dir =
        dir.canonicalize().map_err(|error| format!("cannot resolve {}: {error}", dir.display()))?;
    let repo = repo_root()
        .canonicalize()
        .map_err(|error| format!("cannot resolve the repository: {error}"))?;
    if dir.starts_with(&repo) {
        return Err(format!(
            "{} is inside the repository. Real apps are never stored in it; name a folder outside",
            dir.display()
        ));
    }
    Ok(dir)
}

/// `fixtures fetch --dir DIR`
pub(crate) fn fetch(dir: &Path) -> Result<()> {
    let dir = cache_folder(dir)?;
    let text = read_text(&repo_root().join(PINS))?;
    for pin in pins(&text)? {
        download(&dir, &pin)?;
    }
    Ok(())
}

/// `fixtures negatives --dir DIR [--all]`
pub(crate) fn fetch_negatives(dir: &Path, set: Set) -> Result<()> {
    let dir = cache_folder(dir)?;
    let text = read_text(&repo_root().join(NEGATIVES))?;
    for negative in negatives(&text)? {
        if set == Set::EveryChange && !negative.every_change {
            continue;
        }
        download(&dir, &negative.pin)?;
        if let Some(app) = negative.app {
            unpack(&dir, negative.pin.file, app)?;
        }
    }
    Ok(())
}

/// Unpacks the zip `file` in `dir` into the folder `<file>.d` beside it,
/// unless that folder already holds `app`. The zip is unpacked into a
/// folder of another name first, so a folder of the final name is always
/// complete.
fn unpack(dir: &Path, file: &str, app: &str) -> Result<()> {
    let target = dir.join(format!("{file}.d"));
    if target.join(app).is_dir() {
        println!("ok       {file} ({app})");
        return Ok(());
    }
    let partial = dir.join(format!("{file}.d.part"));
    for stale in [&partial, &target] {
        if stale.exists() {
            std::fs::remove_dir_all(stale)
                .map_err(|error| format!("cannot remove {}: {error}", stale.display()))?;
        }
    }
    let status = Command::new("unzip")
        .args(["-q", "-o"])
        .arg(dir.join(file))
        .arg("-d")
        .arg(&partial)
        .status()
        .map_err(|error| format!("cannot run unzip: {error}"))?;
    if !status.success() || !partial.join(app).is_dir() {
        let _ = std::fs::remove_dir_all(&partial);
        return Err(format!("unpacking {file} did not give {app}"));
    }
    std::fs::rename(&partial, &target)
        .map_err(|error| format!("cannot write {}: {error}", target.display()))?;
    println!("unpacked {file} ({app})");
    Ok(())
}

/// Downloads `pin` into `dir` unless it is there, and checks its hash.
fn download(dir: &Path, pin: &Pin<'_>) -> Result<()> {
    let target = dir.join(pin.file);
    if target.exists() {
        if sha256_of(&target)? != pin.sha256 {
            return Err(format!(
                "{} is not the pinned file (expected sha256 {}). Remove it to fetch it again",
                target.display(),
                pin.sha256
            ));
        }
        println!("ok       {}", pin.file);
        return Ok(());
    }
    // Downloaded under another name and renamed only once the hash is
    // right, so an interrupted or wrong download never stands in for the
    // pinned file.
    let partial = dir.join(format!("{}.part", pin.file));
    let status = Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--location"])
        .args(["--proto", "=https", "--proto-redir", "=https", "--output"])
        .arg(&partial)
        .arg(pin.url)
        .status()
        .map_err(|error| format!("cannot run curl: {error}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&partial);
        return Err(format!("downloading {} failed", pin.url));
    }
    let actual = sha256_of(&partial)?;
    if actual != pin.sha256 {
        let _ = std::fs::remove_file(&partial);
        return Err(format!(
            "{} has sha256 {actual}, not the pinned {}; nothing was kept",
            pin.url, pin.sha256
        ));
    }
    std::fs::rename(&partial, &target)
        .map_err(|error| format!("cannot write {}: {error}", target.display()))?;
    println!("fetched  {}", pin.file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "8aa0e5bf089ace014976eb8cae42a857ceb0604a7d2f00870419a3f03c588293";

    #[test]
    fn the_committed_pin_list_parses() {
        let text = read_text(&repo_root().join(PINS)).unwrap();
        let pins = pins(&text).unwrap();
        assert!(pins.iter().any(|pin| pin.file == "bitwarden-android-2026.9.1-play.apk"));
        assert!(pins.iter().all(|pin| pin.url.starts_with("https://github.com/")));
    }

    #[test]
    fn the_committed_negative_corpus_parses() {
        let text = read_text(&repo_root().join(NEGATIVES)).unwrap();
        let negatives = negatives(&text).unwrap();
        assert!(negatives.iter().filter(|negative| negative.every_change).count() >= 6);
        assert!(negatives.iter().all(|negative| negative.pin.url.starts_with("https://")));
    }

    #[test]
    fn a_negative_names_its_set_and_the_app_in_a_zip() {
        let line = format!("{HASH} a.zip https://example.org/a.zip nightly Example.app\n");
        let parsed = negatives(&line).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].app, Some("Example.app"));
        assert!(!parsed[0].every_change);
        let line = format!("{HASH} a.apk https://example.org/a.apk every-change -\n");
        assert_eq!(negatives(&line).unwrap()[0].app, None);
        for bad in [
            format!("{HASH} a.apk https://example.org/a.apk every-change"),
            format!("{HASH} a.apk https://example.org/a.apk weekly -"),
            format!("{HASH} a.apk https://example.org/a.apk nightly A.app"),
            format!("{HASH} a.zip https://example.org/a.zip nightly -"),
            format!("{HASH} a.zip https://example.org/a.zip nightly ../A.app"),
            format!("{HASH} a.zip https://example.org/a.zip nightly /A.app"),
            format!("{HASH} a.zip https://example.org/a.zip nightly A/../../B.app"),
            format!("{HASH} a.zip https://example.org/a.zip nightly README.md"),
        ] {
            assert!(negatives(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_pin_is_a_hash_a_plain_file_name_and_an_https_address() {
        let line = format!("# comment\n\n{HASH}  app.apk  https://example.org/app.apk\n");
        assert_eq!(
            pins(&line).unwrap(),
            [Pin {
                sha256: Sha256Digest::from_hex(HASH).unwrap(),
                file: "app.apk",
                url: "https://example.org/app.apk"
            }]
        );
        for bad in [
            format!("{HASH} app.apk"),
            format!("{HASH} app.apk https://example.org/a extra"),
            format!("{} app.apk https://example.org/a", &HASH[..63]),
            format!("{} app.apk https://example.org/a", HASH.to_uppercase()),
            format!("{HASH} ../app.apk https://example.org/a"),
            format!("{HASH} dir/app.apk https://example.org/a"),
            format!("{HASH} .hidden https://example.org/a"),
            format!("{HASH} app.apk http://example.org/a"),
            format!("{HASH} app.apk file:///etc/passwd"),
            format!("{HASH} a.apk https://example.org/a\n{HASH} a.apk https://example.org/b"),
        ] {
            assert!(pins(&bad).is_err(), "{bad}");
        }
    }
}
