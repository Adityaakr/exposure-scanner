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

use std::io::Read as _;
use std::path::Path;
use std::process::Command;

use xs_model::{Sha256Digest, Sha256Stream};

use crate::{Result, read_text, repo_root};

const PINS: &str = "tests/fixtures/real-apps.txt";

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
        let sha256 = Sha256Digest::from_hex(sha256)
            .ok_or_else(|| fail("the hash is not 64 lowercase hex characters"))?;
        // The name is joined to the cache folder, so it must be a plain
        // file name and nothing that could leave the folder.
        let plain = !file.starts_with('.')
            && file.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
        if !plain {
            return Err(fail(
                "the file name may hold letters, digits, dots, dashes and underscores",
            ));
        }
        if !url.starts_with("https://") {
            return Err(fail("the address must start with https://"));
        }
        if pins.iter().any(|pin| pin.file == file) {
            return Err(fail("the file name is pinned twice"));
        }
        pins.push(Pin { sha256, file, url });
    }
    Ok(pins)
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

/// `fixtures fetch --dir DIR`
pub(crate) fn fetch(dir: &Path) -> Result<()> {
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

    let text = read_text(&repo.join(PINS))?;
    for pin in pins(&text)? {
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
            continue;
        }
        // Downloaded under another name and renamed only once the hash is
        // right, so an interrupted or wrong download never stands in for
        // the pinned file.
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
    }
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
