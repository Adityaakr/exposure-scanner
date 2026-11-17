//! Building, signing and checking the built-in rule pack.
//!
//! ```text
//! rules/core/*.toml ──compile──▶ rules/dist/core.pack.json ──sign──▶ core.pack.json.minisig
//!   (edited by people)             (canonical JSON, committed)         (committed)
//! ```
//!
//! The compiled pack and its signature are committed because the secret key
//! exists only on the maintainer's machine: CI cannot sign, it can only
//! check. `pack check` is that check.

use std::io::Cursor;
use std::path::{Path, PathBuf};

use xs_model::Sha256Digest;
use xs_rules::compile::{Compiled, Options, SourceFile, compile};
use xs_rules::{SignedLayer, TRUSTED_KEYS};

use crate::{Result, read, read_text, repo_root, write};

const LAYER: &str = "core";

fn source_dir() -> PathBuf {
    repo_root().join("rules").join(LAYER)
}

fn dist_file() -> PathBuf {
    repo_root().join("rules/dist").join(format!("{LAYER}.pack.json"))
}

fn signature_file() -> PathBuf {
    repo_root().join("rules/dist").join(format!("{LAYER}.pack.json.minisig"))
}

/// Reads the layer's source files: `pack.toml`, `entities.toml` and
/// `sdk/*.toml`, as (path relative to the layer, text).
fn sources() -> Result<Vec<(String, String)>> {
    let dir = source_dir();
    let mut files = Vec::new();
    for name in ["pack.toml", "entities.toml"] {
        files.push((name.to_string(), read_text(&dir.join(name))?));
    }
    let sdk = dir.join("sdk");
    let entries = std::fs::read_dir(&sdk)
        .map_err(|error| format!("cannot list {}: {error}", sdk.display()))?;
    for entry in entries {
        let path = entry.map_err(|error| format!("cannot list {}: {error}", sdk.display()))?.path();
        if path.extension().is_some_and(|extension| extension == "toml") {
            let name = path.file_name().and_then(|name| name.to_str()).unwrap_or_default();
            files.push((format!("sdk/{name}"), read_text(&path)?));
        }
    }
    Ok(files)
}

fn compile_sources(files: &[(String, String)]) -> Result<Compiled> {
    let files: Vec<SourceFile<'_>> =
        files.iter().map(|(path, text)| SourceFile { path, text }).collect();
    compile(&files, Options::default()).map_err(|problems| {
        let mut message = format!("the rule sources have {} problem(s):", problems.len());
        for problem in problems {
            message.push_str(&format!("\n  rules/{LAYER}/{problem}"));
        }
        message
    })
}

/// `pack compile`: writes the compiled layer.
pub(crate) fn compile_to_dist() -> Result<()> {
    let compiled = compile_sources(&sources()?)?;
    write(&dist_file(), &compiled.bytes)?;
    println!(
        "compiled layer `{}` version {}: {} rule(s), {} bytes, sha256 {}",
        compiled.layer.layer,
        compiled.layer.version,
        compiled.layer.rules.len(),
        compiled.bytes.len(),
        Sha256Digest::of(&compiled.bytes)
    );
    println!("wrote {}", dist_file().display());
    println!("next: cargo xtask pack sign --key <secret key>");
    Ok(())
}

/// `pack sign`: signs the compiled layer with a minisign secret key.
pub(crate) fn sign(key_file: &Path) -> Result<()> {
    let compiled = compile_sources(&sources()?)?;
    let bytes = read(&dist_file())?;
    if bytes != compiled.bytes {
        return Err(String::from(
            "rules/dist is stale: it does not match the rule sources. Run `cargo xtask pack compile` first.",
        ));
    }
    let secret = minisign::SecretKeyBox::from_string(&read_text(key_file)?)
        .and_then(minisign::SecretKeyBox::into_unencrypted_secret_key)
        .map_err(|error| format!("cannot load the secret key {}: {error}", key_file.display()))?;
    let trusted_comment = format!(
        "exposure rule pack layer={} version={} sha256={}",
        compiled.layer.layer,
        compiled.layer.version,
        Sha256Digest::of(&bytes)
    );
    let signature = minisign::sign(
        None,
        &secret,
        Cursor::new(&bytes),
        Some(&trusted_comment),
        Some("signature of an exposure rule pack"),
    )
    .map_err(|error| format!("signing failed: {error}"))?;
    let text = signature.into_string();

    // Refuse to write a signature the scanner would not accept, such as one
    // made with a key that is not compiled in.
    xs_rules::verify_signature(&bytes, &text, TRUSTED_KEYS).map_err(|error| {
        format!("{error}. Is rules/keys/ holding the public half of {}?", key_file.display())
    })?;
    write(&signature_file(), text.as_bytes())?;
    println!("signed: {trusted_comment}");
    println!("wrote {}", signature_file().display());
    Ok(())
}

/// `pack check`: what CI runs. The committed pack must be exactly what the
/// sources compile to, compilation must be reproducible, and the committed
/// signature must verify against a key compiled into the scanner.
pub(crate) fn check() -> Result<()> {
    let mut files = sources()?;
    let first = compile_sources(&files)?;
    files.reverse();
    let second = compile_sources(&files)?;
    if first.bytes != second.bytes {
        return Err(String::from(
            "compiling twice gave different bytes; the compiler is not deterministic",
        ));
    }

    let committed = read(&dist_file())?;
    if committed != first.bytes {
        return Err(String::from(
            "rules/dist is stale: it does not match the rule sources. Run `cargo xtask pack compile`, \
             then `cargo xtask pack sign --key <secret key>`, and commit both files.",
        ));
    }
    let signature = read_text(&signature_file())?;
    let pack = xs_rules::load_pack(
        &[SignedLayer { bytes: &committed, signature: &signature }],
        TRUSTED_KEYS,
    )
    .map_err(|error| format!("the committed pack does not load: {error}"))?;

    for layer in pack.refs() {
        println!("layer `{}` version {} sha256 {}", layer.layer, layer.version, layer.sha256);
    }
    println!("{} rule(s); sources, compiled pack and signature agree", pack.rule_count());
    Ok(())
}
