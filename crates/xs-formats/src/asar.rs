//! The header of an asar archive, the format Electron apps ship their code in.
//!
//! An archive is a 16-byte prefix, a JSON header that lists every file with
//! its place in the archive, and then the files' bytes back to back:
//!
//! ```text
//! | 4 | header size | payload size | JSON length | JSON … padding | file bytes … |
//!   └── four little-endian u32 ──────────────────┘                 └ data start
//! ```
//!
//! The four numbers are two Chromium pickles, one wrapped around the other.
//! A file's `offset` in the header counts from the data start.
//!
//! This module reads the prefix and the header and nothing else. It never
//! sees the files' bytes; the collector reads those, at the places the header
//! names.
//!
//! **Strict on purpose.** Electron's own reader is lenient in ways a writer
//! never needs, such as a pickle whose sizes disagree or an entry that is a
//! folder and a file at once. An archive built that way could show Electron
//! one tree and a scanner another. So anything a writer does not produce is
//! refused as malformed, and the collector reports the archive as not
//! understood instead of reporting on a tree the app may not run. The one
//! exception is a name that appears twice in a folder: Electron would run
//! the last, both are kept, and a scanner that reads both misses nothing.
//!
//! **Bounded.** The header is consumed as a stream and stored as one string
//! of names plus a fixed-size node per entry, so memory is a small multiple
//! of the header's own size whatever its shape. A path is only put together
//! when one is asked for.

use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, Error as _, IgnoredAny, MapAccess, Visitor};

use crate::{Budget, FormatError};

/// How many leading bytes [`prefix`] needs.
pub const PREFIX_BYTES: usize = 16;
/// Largest header the reader accepts, in bytes (design report, 4.8). The
/// largest seen in a real app was 4.5 MB.
pub const MAX_HEADER_BYTES: usize = 64 * 1024 * 1024;
/// Most entries, files and folders alike, the reader accepts.
pub const MAX_ENTRIES: usize = 1_000_000;
/// Deepest path the reader accepts, in components. The JSON reader stops at
/// 127 nested objects and a folder costs two of them, so this budget is
/// always reached first and a header that is too deep is reported as such.
pub const MAX_DEPTH: usize = 60;
/// Longest name of one entry, in bytes: what a file system allows.
pub const MAX_NAME_BYTES: usize = 255;

/// What the first [`PREFIX_BYTES`] bytes of an archive say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    /// Length of the JSON header in bytes. It starts right after the prefix.
    pub json_len: usize,
    /// Where the files' bytes start, counted from the start of the archive.
    pub data_start: u64,
}

/// Reads the prefix of an archive from its first [`PREFIX_BYTES`] bytes.
///
/// # Errors
///
/// [`FormatError::Malformed`] if fewer bytes are given or the sizes are not
/// the ones a writer produces. [`FormatError::OverBudget`] if the header is
/// larger than [`MAX_HEADER_BYTES`].
pub fn prefix(head: &[u8]) -> Result<Prefix, FormatError> {
    let (words, _) = head.split_first_chunk::<PREFIX_BYTES>().ok_or(FormatError::Malformed)?;
    let [a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3] = *words;
    let size_payload = u32::from_le_bytes([a0, a1, a2, a3]);
    let header_size = u32::from_le_bytes([b0, b1, b2, b3]);
    let payload_size = u32::from_le_bytes([c0, c1, c2, c3]);
    let json_len = u32::from_le_bytes([d0, d1, d2, d3]);

    // The first pickle holds one u32, the size of the second.
    if size_payload != 4 {
        return Err(FormatError::Malformed);
    }
    // The second pickle is its own payload size and then the payload: the
    // JSON's length, the JSON, and padding to a multiple of four bytes.
    if payload_size.checked_add(4) != Some(header_size) {
        return Err(FormatError::Malformed);
    }
    let room = payload_size.checked_sub(4).ok_or(FormatError::Malformed)?;
    if json_len > room {
        return Err(FormatError::Malformed);
    }
    let json_len = usize::try_from(json_len).map_err(|_| FormatError::OverBudget(Budget::Bytes))?;
    if json_len > MAX_HEADER_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    Ok(Prefix { json_len, data_start: u64::from(header_size).saturating_add(8) })
}

/// What one entry of an archive is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A folder.
    Dir,
    /// A file whose bytes are in the archive.
    File {
        /// Where its bytes start, counted from the archive's data start.
        offset: u64,
        /// How many bytes it has.
        size: u64,
    },
    /// A file kept out of the archive. Its bytes are in the folder beside
    /// the archive whose name is the archive's plus `.unpacked`.
    Unpacked {
        /// How many bytes it has.
        size: u64,
    },
    /// A symbolic link. Its target is not read.
    Link,
}

/// One entry of a [`Header`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    /// The entry's position in [`Header::entries`].
    pub index: usize,
    /// The folder that holds it, or `None` at the top of the archive.
    pub parent: Option<usize>,
    /// Its name inside that folder.
    pub name: &'a str,
    /// What it is.
    pub kind: Kind,
}

const NO_PARENT: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Node {
    parent: u32,
    name_start: u32,
    name_len: u16,
    kind: Kind,
}

/// The file table of an archive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    /// Every name, one after the other.
    names: String,
    nodes: Vec<Node>,
    unusable: u32,
}

impl Header {
    /// Number of entries, files and folders alike.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the archive holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// How many entries were left out because their name is not a path
    /// component: empty, `.`, `..`, longer than [`MAX_NAME_BYTES`], or
    /// holding a `/` or a NUL. Such an entry cannot be reached by a path, so
    /// it and everything below it is not part of the tree. Each counts once,
    /// whatever it holds.
    #[must_use]
    pub fn unusable(&self) -> u32 {
        self.unusable
    }

    fn entry_of(&self, index: usize, node: &Node) -> Entry<'_> {
        let start = usize::try_from(node.name_start).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::from(node.name_len));
        Entry {
            index,
            parent: usize::try_from(node.parent).ok().filter(|_| node.parent != NO_PARENT),
            name: self.names.get(start..end).unwrap_or_default(),
            kind: node.kind,
        }
    }

    /// The entry at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<Entry<'_>> {
        self.nodes.get(index).map(|node| self.entry_of(index, node))
    }

    /// Every entry, in the order of the header. A folder comes before what
    /// it holds.
    pub fn entries(&self) -> impl Iterator<Item = Entry<'_>> {
        self.nodes.iter().enumerate().map(|(index, node)| self.entry_of(index, node))
    }

    /// The path of the entry at `index` inside the archive, with `/` between
    /// components. Empty if there is no such entry.
    #[must_use]
    pub fn path(&self, index: usize) -> String {
        let mut parts: Vec<&str> = Vec::new();
        let mut next = self.get(index);
        // A parent always comes before its child, so the walk ends; the
        // bound only keeps that from being an assumption.
        while let Some(entry) = next.filter(|_| parts.len() <= MAX_DEPTH) {
            parts.push(entry.name);
            next = entry.parent.filter(|parent| *parent < entry.index).and_then(|p| self.get(p));
        }
        parts.reverse();
        parts.join("/")
    }
}

/// The budgets of one parse. Tests lower them to reach the limits with small
/// inputs.
#[derive(Debug, Clone, Copy)]
struct Limits {
    entries: usize,
    depth: usize,
}

/// Parses the JSON header of an archive.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the header is larger than
/// [`MAX_HEADER_BYTES`], lists more than [`MAX_ENTRIES`] entries or nests
/// deeper than [`MAX_DEPTH`]. [`FormatError::Malformed`] if it is not JSON in
/// the shape an archive writer produces.
pub fn parse_header(json: &[u8]) -> Result<Header, FormatError> {
    parse_with(json, Limits { entries: MAX_ENTRIES, depth: MAX_DEPTH })
}

fn parse_with(json: &[u8], limits: Limits) -> Result<Header, FormatError> {
    if json.len() > MAX_HEADER_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let mut builder = Builder { header: Header::default(), limits, over: None };
    let mut reader = serde_json::Deserializer::from_slice(json);
    let parsed = Root(&mut builder).deserialize(&mut reader).and_then(|()| reader.end());
    match (builder.over, parsed) {
        (Some(budget), _) => Err(FormatError::OverBudget(budget)),
        (None, Err(_)) => Err(FormatError::Malformed),
        (None, Ok(())) => Ok(builder.header),
    }
}

struct Builder {
    header: Header,
    limits: Limits,
    /// The budget that stopped the parse. The JSON reader only carries its
    /// own error type, so the reason travels here.
    over: Option<Budget>,
}

impl Builder {
    fn over<E: serde::de::Error>(&mut self, budget: Budget) -> E {
        self.over = Some(budget);
        E::custom("over budget")
    }
}

/// Whether `name` can be one component of a path.
fn is_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name != "."
        && name != ".."
        && !name.bytes().any(|byte| byte == b'/' || byte == 0)
}

/// The header itself: an object whose `files` key holds the top folder.
struct Root<'b>(&'b mut Builder);

impl<'de> DeserializeSeed<'de> for Root<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Root<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an asar header object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = false;
        while let Some(key) = map.next_key::<Key>()? {
            if matches!(key, Key::Files) {
                if seen {
                    return Err(A::Error::custom("two `files` keys"));
                }
                seen = true;
                map.next_value_seed(Folder { builder: &mut *self.0, parent: NO_PARENT, depth: 1 })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        if seen { Ok(()) } else { Err(A::Error::custom("no `files` key")) }
    }
}

/// The keys of an entry that say what it is. Every other key, such as
/// `executable` and `integrity`, is skipped.
enum Key {
    Files,
    Offset,
    Size,
    Unpacked,
    Link,
    Other,
}

impl<'de> serde::Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;

        impl Visitor<'_> for KeyVisitor {
            type Value = Key;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a key")
            }

            fn visit_str<E: serde::de::Error>(self, key: &str) -> Result<Key, E> {
                Ok(match key {
                    "files" => Key::Files,
                    "offset" => Key::Offset,
                    "size" => Key::Size,
                    "unpacked" => Key::Unpacked,
                    "link" => Key::Link,
                    _ => Key::Other,
                })
            }
        }

        deserializer.deserialize_str(KeyVisitor)
    }
}

/// A name, appended to the string that holds them all.
struct Name<'b>(&'b mut String);

impl<'de> DeserializeSeed<'de> for Name<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for Name<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a name")
    }

    fn visit_str<E: serde::de::Error>(self, name: &str) -> Result<(), E> {
        self.0.push_str(name);
        Ok(())
    }
}

/// An `offset`: a string of decimal digits.
struct Offset;

impl<'de> DeserializeSeed<'de> for Offset {
    type Value = u64;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<u64, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for Offset {
    type Value = u64;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string of decimal digits")
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<u64, E> {
        // `parse` alone would accept a leading plus sign.
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(E::custom("an offset is decimal digits"));
        }
        text.parse().map_err(|_| E::custom("an offset fits 64 bits"))
    }
}

/// A `link`: a string, which is not kept.
struct Target;

impl<'de> DeserializeSeed<'de> for Target {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for Target {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a link target")
    }

    fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
}

/// The value of a `files` key: the entries of one folder, by name.
struct Folder<'b> {
    builder: &'b mut Builder,
    parent: u32,
    /// How many components the paths of this folder's entries have.
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Folder<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Folder<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object of entries")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let Self { builder, parent, depth } = self;
        loop {
            let start = builder.header.names.len();
            if map.next_key_seed(Name(&mut builder.header.names))?.is_none() {
                return Ok(());
            }
            let name = builder.header.names.get(start..).unwrap_or_default();
            if !is_component(name) {
                builder.header.names.truncate(start);
                builder.header.unusable = builder.header.unusable.saturating_add(1);
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            if depth > builder.limits.depth {
                return Err(builder.over(Budget::Depth));
            }
            if builder.header.nodes.len() >= builder.limits.entries {
                return Err(builder.over(Budget::Items));
            }
            // The header is at most 64 MiB and a name at most 255 bytes, so
            // these fit; a header that large would have been refused.
            let (Ok(name_start), Ok(name_len), Ok(index)) = (
                u32::try_from(start),
                u16::try_from(name.len()),
                u32::try_from(builder.header.nodes.len()),
            ) else {
                return Err(builder.over(Budget::Bytes));
            };
            builder.header.nodes.push(Node { parent, name_start, name_len, kind: Kind::Dir });
            let kind = map.next_value_seed(EntrySeed { builder: &mut *builder, index, depth })?;
            if let Some(node) =
                usize::try_from(index).ok().and_then(|index| builder.header.nodes.get_mut(index))
            {
                node.kind = kind;
            }
        }
    }
}

/// One entry: an object whose keys say whether it is a folder, a file, an
/// unpacked file or a link.
struct EntrySeed<'b> {
    builder: &'b mut Builder,
    index: u32,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for EntrySeed<'_> {
    type Value = Kind;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Kind, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for EntrySeed<'_> {
    type Value = Kind;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an entry object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Kind, A::Error> {
        let Self { builder, index, depth } = self;
        let twice = || A::Error::custom("a key appears twice in one entry");
        let mut folder = false;
        let mut link = false;
        let mut offset: Option<u64> = None;
        let mut size: Option<u64> = None;
        let mut unpacked: Option<bool> = None;
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Files if folder => return Err(twice()),
                Key::Files => {
                    folder = true;
                    map.next_value_seed(Folder {
                        builder: &mut *builder,
                        parent: index,
                        depth: depth.saturating_add(1),
                    })?;
                }
                Key::Link if link => return Err(twice()),
                Key::Link => {
                    link = true;
                    map.next_value_seed(Target)?;
                }
                Key::Offset if offset.is_some() => return Err(twice()),
                Key::Offset => offset = Some(map.next_value_seed(Offset)?),
                Key::Size if size.is_some() => return Err(twice()),
                Key::Size => size = Some(map.next_value::<u64>()?),
                Key::Unpacked if unpacked.is_some() => return Err(twice()),
                Key::Unpacked => unpacked = Some(map.next_value::<bool>()?),
                Key::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        // A writer marks folders and links as unpacked too, so that flag
        // may accompany any kind. Every other mix is one no writer makes.
        match (folder, link, offset, size, unpacked.unwrap_or(false)) {
            (true, false, None, None, _) => Ok(Kind::Dir),
            (false, true, None, None, _) => Ok(Kind::Link),
            (false, false, None, Some(size), true) => Ok(Kind::Unpacked { size }),
            (false, false, Some(offset), Some(size), false) => Ok(Kind::File { offset, size }),
            _ => Err(A::Error::custom("an entry is one of folder, file, unpacked file or link")),
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const DEFAULT: Limits = Limits { entries: MAX_ENTRIES, depth: MAX_DEPTH };

    /// The 16 bytes a writer puts before a header of `json_len` bytes.
    fn prefix_bytes(json_len: u32) -> [u8; 16] {
        let padded = json_len.div_ceil(4) * 4;
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(&4u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&(padded + 8).to_le_bytes());
        bytes[8..12].copy_from_slice(&(padded + 4).to_le_bytes());
        bytes[12..].copy_from_slice(&json_len.to_le_bytes());
        bytes
    }

    fn with_word(mut bytes: [u8; 16], word: usize, value: u32) -> [u8; 16] {
        bytes[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    /// The numbers are the ones of Logseq 2.0.2's `app.asar`, read with a
    /// hex dump: `04000000 e02a0c00 dc2a0c00 d52a0c00`.
    #[test]
    fn the_prefix_of_a_real_archive_is_read() {
        let bytes = [4, 0, 0, 0, 0xe0, 0x2a, 0x0c, 0, 0xdc, 0x2a, 0x0c, 0, 0xd5, 0x2a, 0x0c, 0];
        assert_eq!(prefix(&bytes), Ok(Prefix { json_len: 797_397, data_start: 797_416 }));
        assert_eq!(prefix_bytes(797_397), bytes);
        // Longer input is fine: only the first sixteen bytes are looked at.
        let mut longer = bytes.to_vec();
        longer.extend_from_slice(b"{\"files\":{}}");
        assert_eq!(prefix(&longer), prefix(&bytes));
    }

    #[test]
    fn a_header_that_needs_no_padding_and_an_empty_one_are_read() {
        assert_eq!(prefix(&prefix_bytes(12)), Ok(Prefix { json_len: 12, data_start: 28 }));
        assert_eq!(prefix(&prefix_bytes(13)), Ok(Prefix { json_len: 13, data_start: 32 }));
        assert_eq!(prefix(&prefix_bytes(0)), Ok(Prefix { json_len: 0, data_start: 16 }));
    }

    #[test]
    fn sizes_no_writer_produces_are_refused() {
        let good = prefix_bytes(100);
        assert!(prefix(&good).is_ok());
        for short in 0..PREFIX_BYTES {
            assert_eq!(prefix(&good[..short]), Err(FormatError::Malformed), "{short} bytes");
        }
        // The first pickle does not hold exactly one number.
        assert_eq!(prefix(&with_word(good, 0, 8)), Err(FormatError::Malformed));
        assert_eq!(prefix(&with_word(good, 0, 0)), Err(FormatError::Malformed));
        // The two sizes of the second pickle disagree, which would make
        // Electron look for the JSON somewhere else.
        assert_eq!(prefix(&with_word(good, 1, 112)), Err(FormatError::Malformed));
        assert_eq!(prefix(&with_word(good, 2, 100)), Err(FormatError::Malformed));
        // The JSON does not fit the pickle that holds it.
        assert_eq!(prefix(&with_word(good, 3, 101)), Err(FormatError::Malformed));
        assert_eq!(prefix(&with_word(good, 3, u32::MAX)), Err(FormatError::Malformed));
        // Sizes that would overflow.
        let wrapped = with_word(with_word(good, 1, 3), 2, u32::MAX);
        assert_eq!(prefix(&wrapped), Err(FormatError::Malformed));
        assert_eq!(prefix(&with_word(with_word(good, 1, 4), 2, 0)), Err(FormatError::Malformed));
    }

    #[test]
    fn a_header_over_the_byte_budget_is_refused_as_such() {
        let limit = u32::try_from(MAX_HEADER_BYTES).unwrap();
        assert!(prefix(&prefix_bytes(limit)).is_ok());
        assert_eq!(prefix(&prefix_bytes(limit + 1)), Err(FormatError::OverBudget(Budget::Bytes)));
        assert_eq!(
            parse_header(&vec![b' '; MAX_HEADER_BYTES + 1]),
            Err(FormatError::OverBudget(Budget::Bytes))
        );
    }

    /// The shape `@electron/asar` writes, taken from its README, with the
    /// extra keys real archives carry.
    const SAMPLE: &str = r#"{"files":{
        "tmp":{"files":{}},
        "usr":{"files":{"bin":{"files":{
            "ls":{"offset":"0","size":100,"executable":true,
                  "integrity":{"algorithm":"SHA256","hash":"ab","blockSize":4194304,"blocks":["ab"]}},
            "cd":{"offset":"100","size":100,"executable":true}}}}},
        "etc":{"files":{"hosts":{"offset":"200","size":32}}},
        "node_modules":{"unpacked":true,"files":{"keytar":{"files":{
            "keytar.node":{"size":4096,"unpacked":true},
            "current":{"link":"build/Release","unpacked":true}}}}},
        "empty.js":{"offset":"232","size":0}
    }}"#;

    fn listing(header: &Header) -> Vec<(String, Kind)> {
        header.entries().map(|entry| (header.path(entry.index), entry.kind)).collect()
    }

    #[test]
    fn the_tree_a_writer_produces_is_read_in_header_order() {
        let header = parse_header(SAMPLE.as_bytes()).unwrap();
        let file = |offset, size| Kind::File { offset, size };
        let expected: Vec<(&str, Kind)> = vec![
            ("tmp", Kind::Dir),
            ("usr", Kind::Dir),
            ("usr/bin", Kind::Dir),
            ("usr/bin/ls", file(0, 100)),
            ("usr/bin/cd", file(100, 100)),
            ("etc", Kind::Dir),
            ("etc/hosts", file(200, 32)),
            ("node_modules", Kind::Dir),
            ("node_modules/keytar", Kind::Dir),
            ("node_modules/keytar/keytar.node", Kind::Unpacked { size: 4096 }),
            ("node_modules/keytar/current", Kind::Link),
            ("empty.js", file(232, 0)),
        ];
        let found = listing(&header);
        let found: Vec<(&str, Kind)> =
            found.iter().map(|(path, kind)| (path.as_str(), *kind)).collect();
        assert_eq!(found, expected);
        assert_eq!(header.len(), 12);
        assert!(!header.is_empty());
        assert_eq!(header.unusable(), 0);

        // Entries name their folder, and a folder comes first.
        let ls = header.get(3).unwrap();
        assert_eq!((ls.name, ls.parent), ("ls", Some(2)));
        assert_eq!(header.get(0).unwrap().parent, None);
        for entry in header.entries() {
            assert!(entry.parent.is_none_or(|parent| parent < entry.index));
        }
        assert_eq!(header.get(12), None);
        assert_eq!(header.path(12), "");
    }

    #[test]
    fn an_empty_archive_and_extra_keys_at_the_top_are_fine() {
        let header = parse_header(br#"{"files":{}}"#).unwrap();
        assert!(header.is_empty());
        let header = parse_header(br#" {"version":2,"files":{"a":{"files":{}}},"x":[1,{}]} "#);
        assert_eq!(listing(&header.unwrap()), [(String::from("a"), Kind::Dir)]);
    }

    #[test]
    fn names_are_unescaped_and_kept_as_they_are() {
        let json = r#"{"files":{"café 😀.js":{"offset":"0","size":1},
            "a\\b":{"files":{"tab\there":{"offset":"1","size":1}}}}}"#;
        let header = parse_header(json.as_bytes()).unwrap();
        let paths: Vec<String> = listing(&header).into_iter().map(|(path, _)| path).collect();
        assert_eq!(paths, ["café 😀.js", "a\\b", "a\\b/tab\there"]);
    }

    #[test]
    fn a_name_that_appears_twice_in_a_folder_is_kept_twice() {
        let json = r#"{"files":{"main.js":{"offset":"0","size":4},"main.js":{"offset":"4","size":9},
            "lib":{"files":{"a.js":{"offset":"13","size":1}}},"lib":{"files":{}}}}"#;
        let header = parse_header(json.as_bytes()).unwrap();
        let file = |offset, size| Kind::File { offset, size };
        let expected = [
            ("main.js", file(0, 4)),
            ("main.js", file(4, 9)),
            ("lib", Kind::Dir),
            ("lib/a.js", file(13, 1)),
            ("lib", Kind::Dir),
        ];
        let found = listing(&header);
        let found: Vec<(&str, Kind)> =
            found.iter().map(|(path, kind)| (path.as_str(), *kind)).collect();
        assert_eq!(found, expected);
    }

    #[test]
    fn a_name_that_is_not_a_path_component_is_left_out_with_all_below_it() {
        let long = "n".repeat(MAX_NAME_BYTES + 1);
        let fits = "n".repeat(MAX_NAME_BYTES);
        let json = format!(
            r#"{{"files":{{
                "":{{"offset":"0","size":1}},
                ".":{{"files":{{"hidden.js":{{"offset":"1","size":1}}}}}},
                "..":{{"files":{{}}}},
                "a/b.js":{{"offset":"2","size":1}},
                "nul\u0000.js":{{"offset":"3","size":1}},
                "{long}":{{"offset":"4","size":1}},
                "{fits}":{{"offset":"5","size":1}},
                "..js":{{"offset":"6","size":1}},
                "kept":{{"files":{{"..":{{"link":"x"}},"main.js":{{"offset":"7","size":1}}}}}}
            }}}}"#
        );
        let header = parse_header(json.as_bytes()).unwrap();
        let paths: Vec<String> = listing(&header).into_iter().map(|(path, _)| path).collect();
        assert_eq!(paths, [fits.as_str(), "..js", "kept", "kept/main.js"]);
        assert_eq!(header.unusable(), 7);
        // What is left out is still checked to be JSON.
        assert_eq!(
            parse_header(br#"{"files":{"":{"offset":"0","size":1,}}}"#),
            Err(FormatError::Malformed)
        );
    }

    #[test]
    fn shapes_no_writer_produces_are_malformed() {
        let entry = |body: &str| format!(r#"{{"files":{{"x":{body}}}}}"#);
        for body in [
            // A folder that is also a file, an unpacked file or a link.
            r#"{"files":{},"offset":"0","size":1}"#,
            r#"{"files":{},"size":1,"unpacked":true}"#,
            r#"{"files":{},"link":"y"}"#,
            // A file that is not all there, or is in two places at once.
            r#"{}"#,
            r#"{"offset":"0"}"#,
            r#"{"size":1}"#,
            r#"{"size":1,"unpacked":false}"#,
            r#"{"offset":"0","size":1,"unpacked":true}"#,
            r#"{"link":"y","offset":"0","size":1}"#,
            // A key twice: the last one would win in Electron.
            r#"{"offset":"0","size":1,"offset":"9"}"#,
            r#"{"offset":"0","size":1,"size":9}"#,
            r#"{"files":{},"files":{}}"#,
            r#"{"link":"a","link":"b"}"#,
            r#"{"size":1,"unpacked":true,"unpacked":true}"#,
            // Values of the wrong type or form.
            r#"{"offset":0,"size":1}"#,
            r#"{"offset":"","size":1}"#,
            r#"{"offset":"+1","size":1}"#,
            r#"{"offset":" 1","size":1}"#,
            r#"{"offset":"0x10","size":1}"#,
            r#"{"offset":"18446744073709551616","size":1}"#,
            r#"{"offset":"0","size":"1"}"#,
            r#"{"offset":"0","size":-1}"#,
            r#"{"offset":"0","size":1.5}"#,
            r#"{"offset":"0","size":1e2}"#,
            r#"{"offset":"0","size":18446744073709551616}"#,
            r#"{"size":1,"unpacked":"true"}"#,
            r#"{"link":1}"#,
            r#"{"files":[]}"#,
            r#"[]"#,
            r#""file""#,
            r#"null"#,
        ] {
            assert_eq!(parse_header(entry(body).as_bytes()), Err(FormatError::Malformed), "{body}");
        }
        // The largest values that do fit are read.
        let header = parse_header(
            entry(r#"{"offset":"18446744073709551615","size":18446744073709551615}"#).as_bytes(),
        );
        assert_eq!(
            header.unwrap().get(0).unwrap().kind,
            Kind::File { offset: u64::MAX, size: u64::MAX }
        );
    }

    #[test]
    fn input_that_is_not_one_header_object_is_malformed() {
        for json in [
            &b""[..],
            b"{}",
            br#"{"files":{}"#,
            br#"{"files":{}} trailing"#,
            br#"{"files":{}}{"files":{}}"#,
            br#"{"files":{},"files":{}}"#,
            br#"{"files":null}"#,
            br#"["files"]"#,
            b"\xff\xfe",
            br#"{"files":{"\ud800":{"files":{}}}}"#,
            b"{\"files\":{\"a\xff\":{\"files\":{}}}}",
        ] {
            assert_eq!(parse_header(json), Err(FormatError::Malformed), "{json:?}");
        }
    }

    /// `depth` folders `d`, one inside the other.
    fn nested(depth: usize) -> String {
        let mut json = String::from(r#"{"files":{"#);
        for _ in 0..depth {
            json.push_str(r#""d":{"files":{"#);
        }
        json.push_str(&"}}".repeat(depth));
        json.push_str("}}");
        json
    }

    #[test]
    fn the_depth_budget_is_a_count_of_path_components() {
        let limits = Limits { entries: MAX_ENTRIES, depth: 3 };
        assert_eq!(parse_with(nested(3).as_bytes(), limits).unwrap().len(), 3);
        assert_eq!(
            parse_with(nested(4).as_bytes(), limits),
            Err(FormatError::OverBudget(Budget::Depth))
        );
        // The real budget is reached before the JSON reader's own limit, also
        // for a file at the bottom that carries an `integrity` object.
        let deepest = nested(MAX_DEPTH).replace(
            r#""d":{"files":{}}"#,
            r#""f":{"offset":"0","size":1,"integrity":{"blocks":["ab"]}}"#,
        );
        let header = parse_with(deepest.as_bytes(), DEFAULT).unwrap();
        assert_eq!(header.len(), MAX_DEPTH);
        assert_eq!(header.path(MAX_DEPTH - 1).split('/').count(), MAX_DEPTH);
        assert_eq!(
            parse_header(nested(MAX_DEPTH + 1).as_bytes()),
            Err(FormatError::OverBudget(Budget::Depth))
        );
        // A value that is skipped is skipped without recursion, so its own
        // nesting costs no stack and needs no budget.
        let deep = 100_000;
        let skipped = format!(r#"{{"x":{}{},"files":{{}}}}"#, "[".repeat(deep), "]".repeat(deep));
        assert!(parse_header(skipped.as_bytes()).unwrap().is_empty());
    }

    #[test]
    fn the_entry_budget_counts_files_and_folders() {
        let json = r#"{"files":{"a":{"files":{"b":{"offset":"0","size":1}}},"c":{"link":"a"}}}"#;
        let limits = |entries| Limits { entries, depth: MAX_DEPTH };
        assert_eq!(parse_with(json.as_bytes(), limits(3)).unwrap().len(), 3);
        assert_eq!(
            parse_with(json.as_bytes(), limits(2)),
            Err(FormatError::OverBudget(Budget::Items))
        );
        // An entry that is left out does not count.
        let json = r#"{"files":{"a":{"files":{}},"":{"files":{}},"b":{"files":{}}}}"#;
        assert_eq!(parse_with(json.as_bytes(), limits(2)).unwrap().len(), 2);
    }

    /// A random tree, as the header JSON a writer would produce for it and
    /// as the list of paths it holds, in header order.
    fn tree() -> impl Strategy<Value = (String, Vec<String>)> {
        let name = "[a-z.@_-]{1,6}".prop_filter("a path component", |name| is_component(name));
        let leaf = (0u64..1000, 0u64..1000)
            .prop_map(|(offset, size)| format!(r#"{{"offset":"{offset}","size":{size}}}"#));
        let node = leaf.prop_map(|json| (json, Vec::<String>::new())).prop_recursive(
            4,
            40,
            6,
            move |inner| {
                prop::collection::btree_map(name.clone(), inner, 0..6).prop_map(|children| {
                    let mut json = String::from(r#"{"files":{"#);
                    let mut paths = Vec::new();
                    for (index, (name, (child, below))) in children.into_iter().enumerate() {
                        if index > 0 {
                            json.push(',');
                        }
                        json.push_str(&format!("{}:{child}", serde_json::json!(name)));
                        paths.extend(below.iter().map(|path| format!("{name}/{path}")));
                        paths.insert(paths.len() - below.len(), name);
                    }
                    json.push_str("}}");
                    (json, paths)
                })
            },
        );
        node.prop_filter("the top is a folder", |(json, _)| json.starts_with(r#"{"files""#))
    }

    proptest! {
        #[test]
        fn a_generated_tree_reads_back_as_its_paths((json, paths) in tree()) {
            let header = parse_header(json.as_bytes()).unwrap();
            let found: Vec<String> = listing(&header).into_iter().map(|(path, _)| path).collect();
            prop_assert_eq!(found, paths);
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
            let _ = prefix(&bytes);
            let _ = parse_header(&bytes);
        }

        /// A valid header with some bytes changed is read or refused, and
        /// what is read holds together: every path can be put together and
        /// no entry names a folder that comes after it.
        #[test]
        fn a_damaged_header_is_read_or_refused(
            edits in prop::collection::vec((0..SAMPLE.len(), any::<u8>()), 1..6),
        ) {
            let mut json = SAMPLE.as_bytes().to_vec();
            for (at, byte) in edits {
                json[at] = byte;
            }
            if let Ok(header) = parse_header(&json) {
                for entry in header.entries() {
                    prop_assert!(entry.parent.is_none_or(|parent| parent < entry.index));
                    prop_assert!(is_component(entry.name));
                    prop_assert!(header.path(entry.index).ends_with(entry.name));
                }
            }
        }
    }
}
