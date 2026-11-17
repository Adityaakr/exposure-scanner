//! Proving that the guardrails bite.
//!
//! A guardrail that has never been seen to stop anything is a hope. This
//! command breaks each rule on purpose, in a throwaway copy of the
//! workspace, and requires the build to fail for the right reason:
//!
//! * the pure crates are `no_std`, so using the file system in them does not
//!   compile (build plan, task 1: "using `std::fs` in `xs-derive` fails to
//!   compile");
//! * the parser and rule-pack crates may not touch files, and no shipped
//!   crate may open a socket, run a process or use a randomly seeded map:
//!   the lint lists refuse them;
//! * a crate that can open a socket may not become a dependency: `cargo deny`
//!   refuses it (build plan, task 1: "adding `ureq` to `xs-cli` fails the
//!   deny check").

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, cargo, repo_root};

/// One deliberate violation and how its refusal must look.
struct Probe {
    /// What is being proven.
    claim: &'static str,
    /// The file to append to, relative to the workspace root.
    file: &'static str,
    /// What to append.
    addition: &'static str,
    /// The cargo arguments that must fail.
    cargo: &'static [&'static str],
    /// Text the failure output must contain, all of it: the right reason.
    expect: &'static [&'static str],
}

const USE_FS: &str = "\npub fn guardrail_probe() -> bool { std::fs::metadata(\"x\").is_ok() }\n";

const PROBES: &[Probe] = &[
    Probe {
        claim: "xs-model cannot use the file system (no_std)",
        file: "crates/xs-model/src/lib.rs",
        addition: USE_FS,
        cargo: &["check", "--offline", "--package", "xs-model"],
        expect: &["E0433"],
    },
    Probe {
        claim: "xs-match cannot use the file system (no_std)",
        file: "crates/xs-match/src/lib.rs",
        addition: USE_FS,
        cargo: &["check", "--offline", "--package", "xs-match"],
        expect: &["E0433"],
    },
    Probe {
        claim: "xs-derive cannot use the file system (no_std)",
        file: "crates/xs-derive/src/lib.rs",
        addition: USE_FS,
        cargo: &["check", "--offline", "--package", "xs-derive"],
        expect: &["E0433"],
    },
    Probe {
        claim: "xs-render cannot use the file system (no_std)",
        file: "crates/xs-render/src/lib.rs",
        addition: USE_FS,
        cargo: &["check", "--offline", "--package", "xs-render"],
        expect: &["E0433"],
    },
    Probe {
        claim: "xs-formats may not touch files (lint list)",
        file: "crates/xs-formats/src/lib.rs",
        addition: USE_FS,
        cargo: &["clippy", "--offline", "--package", "xs-formats"],
        expect: &["use of a disallowed method `std::fs::metadata`"],
    },
    Probe {
        claim: "xs-rules may not touch files (lint list)",
        file: "crates/xs-rules/src/lib.rs",
        addition: USE_FS,
        cargo: &["clippy", "--offline", "--package", "xs-rules"],
        expect: &["use of a disallowed method `std::fs::metadata`"],
    },
    Probe {
        claim: "xs-collect may not open a socket (lint list)",
        file: "crates/xs-collect/src/lib.rs",
        addition: "\npub fn guardrail_probe() -> bool { std::net::TcpStream::connect(\"127.0.0.1:9\").is_ok() }\n",
        cargo: &["clippy", "--offline", "--package", "xs-collect"],
        expect: &["use of a disallowed type `std::net::TcpStream`"],
    },
    Probe {
        claim: "xs-collect may not use a randomly seeded map (lint list)",
        file: "crates/xs-collect/src/lib.rs",
        addition: "\npub fn guardrail_probe() -> usize { std::collections::HashMap::<u8, u8>::new().len() }\n",
        cargo: &["clippy", "--offline", "--package", "xs-collect"],
        expect: &["use of a disallowed type `std::collections::HashMap`"],
    },
    Probe {
        claim: "xs-cli may not read the clock (lint list)",
        file: "crates/xs-cli/src/commands.rs",
        addition: "\npub(crate) fn guardrail_probe() -> bool { std::time::SystemTime::now().elapsed().is_ok() }\n",
        cargo: &["clippy", "--offline", "--package", "xs-cli"],
        expect: &["use of a disallowed type `std::time::SystemTime`"],
    },
    Probe {
        claim: "xs-cli may not run a process (lint list)",
        file: "crates/xs-cli/src/commands.rs",
        addition: "\npub(crate) fn guardrail_probe() -> bool { std::process::Command::new(\"true\").status().is_ok() }\n",
        cargo: &["clippy", "--offline", "--package", "xs-cli"],
        expect: &["use of a disallowed type `std::process::Command`"],
    },
    Probe {
        claim: "a crate that can open a socket cannot become a dependency (cargo deny)",
        file: "crates/xs-cli/Cargo.toml",
        addition: "\n[dependencies.ureq]\nversion = \"3\"\n",
        cargo: &["deny", "check", "bans"],
        expect: &["ureq", "banned"],
    },
];

/// `guardrails`
pub(crate) fn run() -> Result<()> {
    let root = repo_root();
    let work = root.join("target/guardrails");
    let copy = work.join("workspace");
    copy_workspace(&root, &copy)?;
    let target = work.join("target");

    let mut failures = 0;
    for probe in PROBES {
        match run_probe(probe, &copy, &target) {
            Ok(()) => println!("ok    {}", probe.claim),
            Err(reason) => {
                failures += 1;
                println!("FAIL  {}\n      {reason}", probe.claim);
            }
        }
    }
    match shipped_tooling(&root) {
        Ok(found) if found.is_empty() => {
            println!("ok    the exposure binary links no developer-only crate")
        }
        Ok(found) => {
            failures += 1;
            println!("FAIL  the exposure binary links developer-only crates: {}", found.join(", "));
        }
        Err(reason) => {
            failures += 1;
            println!("FAIL  cannot list the exposure binary's dependencies: {reason}");
        }
    }
    if failures > 0 {
        return Err(format!("{failures} guardrail(s) did not hold"));
    }
    println!("{} guardrails hold", PROBES.len() + 1);
    Ok(())
}

/// Crates that belong to tooling and tests only. The rule-pack compiler
/// (`toml`, `psl`) matters most: the shipped scanner must only ever read a
/// compiled, signed pack.
const TOOLING_ONLY: &[&str] =
    &["toml", "psl", "minisign", "object", "proptest", "tempfile", "serde_json_canonicalizer"];

/// The tooling-only crates among the normal dependencies of `xs-cli`, which
/// must be none.
fn shipped_tooling(root: &Path) -> Result<Vec<String>> {
    let output = Command::new(cargo())
        .args([
            "tree",
            "--locked",
            "--package",
            "xs-cli",
            "--edges",
            "normal",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run cargo tree: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    let mut found: Vec<String> = listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| TOOLING_ONLY.contains(name))
        .map(str::to_string)
        .collect();
    found.sort();
    found.dedup();
    Ok(found)
}

/// Applies one violation, runs cargo, and restores the file.
fn run_probe(probe: &Probe, workspace: &Path, target: &Path) -> Result<()> {
    let file = workspace.join(probe.file);
    let original = std::fs::read_to_string(&file)
        .map_err(|error| format!("cannot read {}: {error}", probe.file))?;
    std::fs::write(&file, format!("{original}{}", probe.addition))
        .map_err(|error| format!("cannot write {}: {error}", probe.file))?;

    let outcome = Command::new(cargo())
        .args(probe.cargo)
        .current_dir(workspace)
        .env("CARGO_TARGET_DIR", target)
        .env_remove("RUSTFLAGS")
        .output();
    std::fs::write(&file, original)
        .map_err(|error| format!("cannot restore {}: {error}", probe.file))?;

    let output =
        outcome.map_err(|error| format!("cannot run cargo {}: {error}", probe.cargo.join(" ")))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        return Err(format!(
            "`cargo {}` succeeded; the violation was not refused",
            probe.cargo.join(" ")
        ));
    }
    if let Some(missing) = probe.expect.iter().find(|expected| !text.contains(**expected)) {
        let tail: Vec<&str> = text.lines().rev().take(12).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        return Err(format!(
            "`cargo {}` failed, but not with `{missing}`:\n      {}",
            probe.cargo.join(" "),
            tail.join("\n      ")
        ));
    }
    Ok(())
}

/// Copies every file git tracks or would track into `to`, keeping symbolic
/// links as links. Build output and ignored files stay behind.
fn copy_workspace(root: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        std::fs::remove_dir_all(to)
            .map_err(|error| format!("cannot clear {}: {error}", to.display()))?;
    }
    let listing = Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard", "-z"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if !listing.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&listing.stderr).trim()
        ));
    }
    let listing = String::from_utf8(listing.stdout)
        .map_err(|_| String::from("a tracked path is not UTF-8"))?;
    for path in listing.split('\0').filter(|path| !path.is_empty()) {
        let from = root.join(path);
        let target: PathBuf = to.join(path);
        let fail = |error: std::io::Error| format!("cannot copy {path}: {error}");
        // A file deleted from the working tree but still in the index.
        let Ok(metadata) = std::fs::symlink_metadata(&from) else { continue };
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(fail)?;
        }
        if metadata.is_symlink() {
            let link = std::fs::read_link(&from).map_err(fail)?;
            std::os::unix::fs::symlink(link, &target).map_err(fail)?;
        } else if metadata.is_file() {
            std::fs::copy(&from, &target).map_err(fail)?;
        }
    }
    Ok(())
}
