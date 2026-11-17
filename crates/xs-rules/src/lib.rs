//! Loading and checking rule packs.
//!
//! A rule pack reaches the scanner as **compiled layers**: canonical JSON
//! files, each with a detached [minisign] (Ed25519) signature. This crate
//! turns those bytes into a validated [`Pack`], in this order:
//!
//! 1. The signature is checked against the public keys compiled into the
//!    binary. A layer nobody trusted signed is refused before a single byte
//!    of it is parsed.
//! 2. The bytes are parsed and must be exactly the canonical form of what
//!    they contain, so a layer has one byte representation and one hash.
//! 3. The layers are validated together ([`Pack::new`]).
//!
//! The crate takes bytes and returns values. It never opens a file; the lint
//! lists in `clippy.toml` ban the file-system API here, so the trust decision
//! cannot be influenced by anything but its arguments.
//!
//! The source compiler ([`compile`]) turns the TOML rule files a person
//! edits into a compiled layer. It sits behind the `compile` feature, which
//! only developer tooling enables, so the shipped scanner contains no TOML
//! parser and cannot be handed unsigned rules.
//!
//! [minisign]: https://jedisct1.github.io/minisign/

#[cfg(feature = "compile")]
pub mod compile;

use std::fmt;

use minisign_verify::{PublicKey, Signature};
use xs_model::pack::{Layer, LoadedLayer, PackError};
use xs_model::{Pack, Sha256Digest, canon};

/// A public key the scanner accepts rule-pack signatures from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedKey {
    /// A name for messages, such as `exposure-pack-1`.
    pub name: &'static str,
    /// The key file in minisign format: a comment line, then the key in
    /// base64.
    pub minisign: &'static str,
}

/// The keys compiled into this build.
///
/// The matching secret key never enters the repository. It lives on the
/// maintainer's machine (by default `~/.exposure/keys/`, mode 0600) and is
/// only used by `cargo xtask pack sign`.
pub const TRUSTED_KEYS: &[TrustedKey] = &[TrustedKey {
    name: "exposure-pack-1",
    minisign: include_str!("../../../rules/keys/exposure-pack-1.pub"),
}];

/// The bytes of a compiled layer and the text of its detached signature.
#[derive(Debug, Clone, Copy)]
pub struct SignedLayer<'a> {
    /// The compiled layer.
    pub bytes: &'a [u8],
    /// The content of the `.minisig` file.
    pub signature: &'a str,
}

/// Why a rule pack was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// The signature file is not a minisign signature.
    BadSignatureFile,
    /// A key compiled into the binary is not a minisign public key.
    BadTrustedKey(&'static str),
    /// No trusted key made this signature over these bytes. Either the layer
    /// was changed after signing or someone else signed it.
    Untrusted,
    /// The signed bytes are not a layer file.
    Parse(String),
    /// The signed bytes are a layer, but not in canonical form.
    NotCanonical,
    /// The layers do not form a valid pack.
    Pack(PackError),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSignatureFile => f.write_str("the signature file is not a minisign signature"),
            Self::BadTrustedKey(name) => {
                write!(f, "built-in key `{name}` is not a minisign public key")
            }
            Self::Untrusted => f.write_str(
                "the rule pack is not signed by a trusted key, or was changed after it was signed",
            ),
            Self::Parse(message) => write!(f, "the rule pack is not a layer file: {message}"),
            Self::NotCanonical => f.write_str("the rule pack is not in canonical form"),
            Self::Pack(error) => write!(f, "the rule pack is invalid: {error}"),
        }
    }
}

impl std::error::Error for LoadError {}

impl From<PackError> for LoadError {
    fn from(error: PackError) -> Self {
        Self::Pack(error)
    }
}

/// Checks that one of `keys` signed `bytes`, and returns that key's name.
///
/// Only prehashed signatures are accepted, the format every current minisign
/// implementation writes. The legacy format is refused.
///
/// # Errors
///
/// [`LoadError::Untrusted`] if no key in `keys` made the signature over
/// exactly these bytes.
pub fn verify_signature(
    bytes: &[u8],
    signature: &str,
    keys: &[TrustedKey],
) -> Result<&'static str, LoadError> {
    let signature = Signature::decode(signature).map_err(|_| LoadError::BadSignatureFile)?;
    for key in keys {
        let public =
            PublicKey::decode(key.minisign).map_err(|_| LoadError::BadTrustedKey(key.name))?;
        if public.verify(bytes, &signature, false).is_ok() {
            return Ok(key.name);
        }
    }
    Err(LoadError::Untrusted)
}

/// Verifies and parses one layer.
///
/// # Errors
///
/// See [`LoadError`]. The signature is checked first; nothing is parsed from
/// bytes that fail it.
pub fn load_layer(signed: SignedLayer<'_>, keys: &[TrustedKey]) -> Result<LoadedLayer, LoadError> {
    verify_signature(signed.bytes, signed.signature, keys)?;
    let layer: Layer = serde_json::from_slice(signed.bytes)
        .map_err(|error| LoadError::Parse(error.to_string()))?;
    let canonical = canon::to_vec(&layer).map_err(|error| LoadError::Parse(error.to_string()))?;
    if canonical != signed.bytes {
        return Err(LoadError::NotCanonical);
    }
    Ok(LoadedLayer { layer, sha256: Sha256Digest::of(signed.bytes) })
}

/// Verifies, parses and validates a whole pack. The order of `layers` is the
/// order they are consulted in.
///
/// # Errors
///
/// See [`LoadError`].
pub fn load_pack(layers: &[SignedLayer<'_>], keys: &[TrustedKey]) -> Result<Pack, LoadError> {
    let loaded =
        layers.iter().map(|&signed| load_layer(signed, keys)).collect::<Result<Vec<_>, _>>()?;
    Ok(Pack::new(loaded)?)
}
