//! Creating the rule-pack signing key.
//!
//! The secret key must never enter the repository. This command writes it to
//! a directory outside the repository, readable by its owner only, and
//! prints the public half for `rules/keys/`.
//!
//! The key is not password-protected, so that signing can be scripted. Its
//! protection is the file mode and the disk it sits on. To add a password
//! later, re-create the key with the `minisign` tool and replace the public
//! key in `rules/keys/`.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

use crate::{Result, repo_root};

const NAME: &str = "exposure-pack-1";

/// `key generate --dir DIR`
pub(crate) fn generate(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    let dir =
        dir.canonicalize().map_err(|error| format!("cannot resolve {}: {error}", dir.display()))?;
    let repo = repo_root()
        .canonicalize()
        .map_err(|error| format!("cannot resolve the repository: {error}"))?;
    if dir.starts_with(&repo) {
        return Err(format!(
            "{} is inside the repository. The secret key must live outside it, for example in ~/.exposure/keys",
            dir.display()
        ));
    }

    let secret_file = dir.join(format!("{NAME}.key"));
    let public_file = dir.join(format!("{NAME}.pub"));
    let pair = minisign::KeyPair::generate_unencrypted_keypair()
        .map_err(|error| format!("key generation failed: {error}"))?;
    let secret = pair
        .sk
        .to_box(Some(&format!("{NAME} secret key. Never commit this file.")))
        .map_err(|error| format!("cannot encode the secret key: {error}"))?
        .into_string();
    let public = format!(
        "untrusted comment: {NAME} public key of the exposure rule pack\n{}\n",
        pair.pk.to_base64()
    );

    // `create_new` refuses to overwrite: an existing key is never replaced.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&secret_file)
        .map_err(|error| format!("cannot create {}: {error}", secret_file.display()))?;
    file.write_all(secret.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|error| format!("cannot write {}: {error}", secret_file.display()))?;
    std::fs::write(&public_file, &public)
        .map_err(|error| format!("cannot write {}: {error}", public_file.display()))?;

    println!("secret key: {} (mode 0600; keep it out of every repository)", secret_file.display());
    println!("public key: {}", public_file.display());
    println!("copy the public key to rules/keys/{NAME}.pub and commit it:\n\n{public}");
    Ok(())
}
