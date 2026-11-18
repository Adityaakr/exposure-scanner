//! The reproducible-build check (design report, task 14): two clean builds
//! of one commit give the same binary, byte for byte.
//!
//! The commit is exported twice with `git archive`, into two folders at
//! different paths, so neither build can lean on the working tree or on
//! anything a build of the other left behind. Each is built in release
//! mode with its own target folder, `--locked`, by the toolchain that
//! `rust-toolchain.toml` pins, and the two `exposure` binaries are hashed.
//!
//! What makes this hold: cargo names the files of workspace crates relative
//! to the workspace, so the path of a checkout does not reach the binary;
//! dependencies come from the same registry folder; the release profile
//! strips debug information; and nothing in the scanner reads a clock or
//! the environment at build time. A build on another machine gives the same
//! bytes with the same toolchain, target and cargo home folder. The path of
//! the cargo home is in the file names of dependencies, which stable Rust
//! cannot yet trim (`trim-paths` is unstable in 1.97).

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{Result, cargo, repo_root};

/// `repro [REV]`
pub(crate) fn run(rev: &str) -> Result<()> {
    let root = repo_root();
    let commit = git(&root, &["rev-parse", "--verify", &format!("{rev}^{{commit}}")])?;
    let work = std::env::temp_dir().join(format!("exposure-repro-{}", std::process::id()));
    fs::create_dir_all(&work)
        .map_err(|error| format!("cannot create {}: {error}", work.display()))?;
    let outcome = check(&root, &commit, &work);
    match &outcome {
        Ok(()) => {
            let _ = fs::remove_dir_all(&work);
        }
        Err(_) => println!("the two builds are kept for comparison in {}", work.display()),
    }
    outcome
}

fn check(root: &Path, commit: &str, work: &Path) -> Result<()> {
    let archive = work.join("source.tar");
    git(root, &["archive", "--format=tar", "--output", path_text(&archive)?, commit])?;
    // Two paths of different lengths and names, so that a path that
    // reached the binary would show.
    let mut hashes = Vec::new();
    for name in ["a", "second-build-at-a-longer-path"] {
        let source = work.join(name).join("exposure-scanner");
        fs::create_dir_all(&source)
            .map_err(|error| format!("cannot create {}: {error}", source.display()))?;
        run_tool(Command::new("tar").arg("-xf").arg(&archive).arg("-C").arg(&source), "tar")?;
        let target = source.join("target");
        println!("building {} in {}", short(commit), source.display());
        run_tool(
            Command::new(cargo())
                .args(["build", "--release", "--locked", "--quiet", "--package", "exposure"])
                .current_dir(&source)
                .env("CARGO_TARGET_DIR", &target)
                .env_remove("RUSTFLAGS")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("CARGO_BUILD_RUSTFLAGS"),
            "cargo build",
        )?;
        let binary = target.join("release/exposure");
        let digest = xs_model::Sha256Digest::of(&crate::read(&binary)?).to_hex();
        println!("sha256 {digest}  {}", binary.display());
        hashes.push(digest);
    }
    match hashes.as_slice() {
        [first, second] if first == second => {
            println!("ok: two clean builds of {} give one binary, sha256 {first}", short(commit));
            Ok(())
        }
        _ => Err(format!("two clean builds of {} gave different binaries", short(commit))),
    }
}

fn short(commit: &str) -> &str {
    commit.get(..12).unwrap_or(commit)
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| format!("{} is not UTF-8", path.display()))
}

/// Runs git in `root` and returns what it printed, trimmed.
fn git(root: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn run_tool(command: &mut Command, name: &str) -> Result<()> {
    let status = command.status().map_err(|error| format!("cannot run {name}: {error}"))?;
    if status.success() { Ok(()) } else { Err(format!("{name} failed")) }
}
