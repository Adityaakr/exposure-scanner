//! SHA-256 digests and the digest that identifies a subject.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use sha2::{Digest as _, Sha256};

use crate::canon;
use crate::path::RelPath;
use crate::serde_str::impl_serde_str;

/// A SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Digest of a whole buffer.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut stream = Sha256Stream::new();
        stream.update(bytes);
        stream.finish()
    }

    /// The raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Lowercase hexadecimal form, 64 characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::with_capacity(64);
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{self}");
        out
    }

    /// Parses 64 lowercase hexadecimal characters.
    ///
    /// Uppercase is rejected so that a digest has exactly one text form.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.as_bytes();
        if hex.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (slot, pair) in bytes.iter_mut().zip(hex.chunks_exact(2)) {
            let [high, low] = pair else { return None };
            *slot = (nibble(*high)? << 4) | nibble(*low)?;
        }
        Some(Self(bytes))
    }
}

const fn nibble(character: u8) -> Option<u8> {
    match character {
        b'0'..=b'9' => Some(character - b'0'),
        b'a'..=b'f' => Some(character - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({self})")
    }
}

/// Incremental SHA-256, so a file can be hashed in the same pass that feeds
/// the matcher (design report, section 6.2 decision 3).
#[derive(Clone, Default)]
pub struct Sha256Stream(Sha256);

impl Sha256Stream {
    /// A fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self(Sha256::new())
    }

    /// Feeds more bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// The digest of everything fed so far.
    #[must_use]
    pub fn finish(self) -> Sha256Digest {
        Sha256Digest(self.0.finalize().into())
    }
}

impl fmt::Debug for Sha256Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256Stream")
    }
}

/// A digest in its `sha256:<hex>` text form, the shape of every id in a
/// report. The error type of the string parsers in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestParseError {
    expected: &'static str,
}

impl DigestParseError {
    pub(crate) const fn new(expected: &'static str) -> Self {
        Self { expected }
    }
}

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expected {}", self.expected)
    }
}

impl core::error::Error for DigestParseError {}

/// What identifies an artifact: the hash of its file, or the bundle digest of
/// a directory artifact.
///
/// Two builds that share one app id are two subjects, because their digests
/// differ. That is rule 1 of the evidence format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubjectDigest {
    /// `sha256:` — the SHA-256 of a single-file artifact such as an APK.
    Sha256(Sha256Digest),
    /// `bd1:` — bundle digest, version 1. See [`BundleManifest`].
    Bundle(Sha256Digest),
}

impl fmt::Display for SubjectDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256(digest) => write!(f, "sha256:{digest}"),
            Self::Bundle(digest) => write!(f, "bd1:{digest}"),
        }
    }
}

impl FromStr for SubjectDigest {
    type Err = DigestParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        const EXPECTED: &str = "\"sha256:\" or \"bd1:\" followed by 64 lowercase hex characters";
        let parse = |hex| Sha256Digest::from_hex(hex).ok_or(DigestParseError::new(EXPECTED));
        if let Some(hex) = text.strip_prefix("sha256:") {
            parse(hex).map(Self::Sha256)
        } else if let Some(hex) = text.strip_prefix("bd1:") {
            parse(hex).map(Self::Bundle)
        } else {
            Err(DigestParseError::new(EXPECTED))
        }
    }
}

impl_serde_str!(SubjectDigest, "a subject digest such as \"sha256:…\" or \"bd1:…\"");

/// The inputs a collector read from a directory artifact, from which the
/// bundle digest `bd1` is computed.
///
/// Evidence about a bundle can only come from what the collector read. So the
/// digest covers exactly that: every file it read, by content hash, and every
/// directory listing it consulted, by the hash of the sorted entry names. Two
/// bundles with equal digests therefore yield equal evidence, which is the
/// property that makes a `contains` record reproducible by anyone holding the
/// same artifact.
///
/// The digest is the SHA-256 of the canonical JSON of
/// `["bd1", [[path, entry], …]]` with paths in byte order, where `entry` is
/// `"sha256:<hex>"` for a file and `"names:<hex>"` for a directory listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleManifest {
    entries: BTreeMap<RelPath, ManifestEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManifestEntry {
    File(Sha256Digest),
    Listing(Sha256Digest),
}

impl BundleManifest {
    /// An empty manifest.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a file the collector read, by the hash of its content.
    pub fn file(&mut self, path: RelPath, content: Sha256Digest) {
        self.entries.insert(path, ManifestEntry::File(content));
    }

    /// Records a directory listing the collector consulted.
    ///
    /// The names are hashed as a sorted, de-duplicated list (the canonical
    /// JSON array of the names), so the order the file system returned them
    /// in cannot matter.
    pub fn listing<'a>(&mut self, path: RelPath, names: impl IntoIterator<Item = &'a str>) {
        let mut sorted: Vec<&str> = names.into_iter().collect();
        sorted.sort_unstable();
        sorted.dedup();
        let mut preimage = Vec::with_capacity(64);
        preimage.push(b'[');
        for (index, name) in sorted.into_iter().enumerate() {
            if index > 0 {
                preimage.push(b',');
            }
            canon::write_string(&mut preimage, name);
        }
        preimage.push(b']');
        self.entries.insert(path, ManifestEntry::Listing(Sha256Digest::of(&preimage)));
    }

    /// Number of entries recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `bd1` digest of this manifest.
    #[must_use]
    pub fn digest(&self) -> SubjectDigest {
        // Canonical JSON written by hand: the shape is fixed and holds only
        // strings, so there is nothing that could fail.
        let mut preimage = Vec::with_capacity(32 + self.entries.len() * 128);
        preimage.extend_from_slice(b"[\"bd1\",[");
        for (index, (path, entry)) in self.entries.iter().enumerate() {
            if index > 0 {
                preimage.push(b',');
            }
            let value = match entry {
                ManifestEntry::File(digest) => alloc::format!("sha256:{digest}"),
                ManifestEntry::Listing(digest) => alloc::format!("names:{digest}"),
            };
            preimage.push(b'[');
            canon::write_string(&mut preimage, path.as_str());
            preimage.push(b',');
            canon::write_string(&mut preimage, &value);
            preimage.push(b']');
        }
        preimage.extend_from_slice(b"]]");
        SubjectDigest::Bundle(Sha256Digest::of(&preimage))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn matches_the_published_test_vectors() {
        assert_eq!(Sha256Digest::of(b"").to_hex(), EMPTY);
        assert_eq!(Sha256Digest::of(b"abc").to_hex(), ABC);
    }

    #[test]
    fn streaming_equals_one_shot_at_any_split() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        for split in [0, 1, 63, 64, 65, 500, 999, 1000] {
            let mut stream = Sha256Stream::new();
            stream.update(&data[..split]);
            stream.update(&data[split..]);
            assert_eq!(stream.finish(), Sha256Digest::of(&data));
        }
    }

    #[test]
    fn hex_round_trips_and_rejects_other_forms() {
        let digest = Sha256Digest::from_hex(ABC).unwrap();
        assert_eq!(digest.to_hex(), ABC);
        assert!(Sha256Digest::from_hex(&ABC.to_uppercase()).is_none());
        assert!(Sha256Digest::from_hex(&ABC[1..]).is_none());
        assert!(Sha256Digest::from_hex(&ABC.replace('b', "g")).is_none());
    }

    #[test]
    fn subject_digest_keeps_its_scheme() {
        let file: SubjectDigest = alloc::format!("sha256:{ABC}").parse().unwrap();
        let bundle: SubjectDigest = alloc::format!("bd1:{ABC}").parse().unwrap();
        assert_ne!(file, bundle);
        assert_eq!(file.to_string(), alloc::format!("sha256:{ABC}"));
        assert_eq!(bundle.to_string(), alloc::format!("bd1:{ABC}"));
        assert!(ABC.parse::<SubjectDigest>().is_err());
        assert!(alloc::format!("md5:{ABC}").parse::<SubjectDigest>().is_err());
    }

    fn path(text: &str) -> RelPath {
        RelPath::new(text).unwrap()
    }

    #[test]
    fn bundle_digest_ignores_the_order_inputs_were_recorded_in() {
        let mut forward = BundleManifest::new();
        forward.file(path("Contents/Info.plist"), Sha256Digest::of(b"plist"));
        forward.file(path("Contents/MacOS/App"), Sha256Digest::of(b"binary"));
        forward.listing(path("Contents/Frameworks"), ["B.framework", "A.framework"]);

        let mut backward = BundleManifest::new();
        backward.listing(path("Contents/Frameworks"), ["A.framework", "B.framework"]);
        backward.file(path("Contents/MacOS/App"), Sha256Digest::of(b"binary"));
        backward.file(path("Contents/Info.plist"), Sha256Digest::of(b"plist"));

        assert_eq!(forward.digest(), backward.digest());
    }

    #[test]
    fn bundle_digest_changes_with_any_input() {
        let base = || {
            let mut manifest = BundleManifest::new();
            manifest.file(path("Contents/Info.plist"), Sha256Digest::of(b"plist"));
            manifest.listing(path("Contents/Frameworks"), ["A.framework"]);
            manifest
        };
        let reference = base().digest();

        let mut changed_content = base();
        changed_content.file(path("Contents/Info.plist"), Sha256Digest::of(b"other"));
        assert_ne!(changed_content.digest(), reference);

        let mut changed_listing = base();
        changed_listing.listing(path("Contents/Frameworks"), ["A.framework", "B.framework"]);
        assert_ne!(changed_listing.digest(), reference);

        let mut extra_file = base();
        extra_file.file(path("Contents/MacOS/App"), Sha256Digest::of(b"binary"));
        assert_ne!(extra_file.digest(), reference);
    }

    #[test]
    fn a_file_and_a_listing_with_the_same_hash_differ() {
        let names = ["A.framework"];
        let listing_hash = Sha256Digest::of(&canon::to_vec(&names).unwrap());

        let mut as_listing = BundleManifest::new();
        as_listing.listing(path("x"), names);
        let mut as_file = BundleManifest::new();
        as_file.file(path("x"), listing_hash);

        assert_ne!(as_listing.digest(), as_file.digest());
    }

    #[test]
    fn the_hand_written_preimage_is_the_canonical_json_of_its_structure() {
        // Names that need escaping and names that sort differently as bytes.
        let names = ["b\"quote", "a\\slash", "é.framework", "Z.framework"];
        let mut manifest = BundleManifest::new();
        manifest.file(path("Contents/Info.plist"), Sha256Digest::of(b"x"));
        manifest.file(path("Contents/MacOS/a \"b\""), Sha256Digest::of(b"y"));
        manifest.listing(path("Contents/Frameworks"), names);

        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        let listing = Sha256Digest::of(&canon::to_vec(&sorted).unwrap());
        let rows = [
            ("Contents/Frameworks", alloc::format!("names:{listing}")),
            ("Contents/Info.plist", alloc::format!("sha256:{}", Sha256Digest::of(b"x"))),
            ("Contents/MacOS/a \"b\"", alloc::format!("sha256:{}", Sha256Digest::of(b"y"))),
        ];
        let expected = Sha256Digest::of(&canon::to_vec(&("bd1", rows)).unwrap());
        assert_eq!(manifest.digest(), SubjectDigest::Bundle(expected));
    }

    #[test]
    fn bundle_digest_is_pinned() {
        // Guards the bd1 preimage against accidental change: a different
        // digest for the same inputs would silently split every subject.
        let mut manifest = BundleManifest::new();
        manifest.file(path("Contents/Info.plist"), Sha256Digest::of(b""));
        manifest.listing(path("Contents/Frameworks"), ["Sentry.framework"]);
        let names = Sha256Digest::of(br#"["Sentry.framework"]"#);
        let preimage = alloc::format!(
            r#"["bd1",[["Contents/Frameworks","names:{names}"],["Contents/Info.plist","sha256:{EMPTY}"]]]"#
        );
        assert_eq!(manifest.digest(), SubjectDigest::Bundle(Sha256Digest::of(preimage.as_bytes())));
    }
}
