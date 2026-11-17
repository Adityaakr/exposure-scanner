//! Writers for small synthetic artifacts: zip archives, DEX files and
//! compiled Android manifests.
//!
//! Real apps are never stored in the repository, so tests build what they
//! scan. These writers produce files that are well formed enough for the
//! standard tools (`unzip -t` accepts the archives), and whose every byte is
//! decided by the test, so a test can also damage one deliberately.
//!
//! This module is test support. It is compiled for this crate's own tests
//! and, behind the `testkit` feature, for the tests of the crates that
//! build on the parsers. No shipped code enables that feature.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "writers of test fixtures work on sizes they chose themselves"
)]

use std::collections::{BTreeMap, BTreeSet};

/// `android:name`, the resource id of the attribute that names a component.
pub const ANDROID_NAME: u32 = 0x0101_0003;
/// `android:label`.
pub const ANDROID_LABEL: u32 = 0x0101_0001;
/// `android:versionCode`.
pub const ANDROID_VERSION_CODE: u32 = 0x0101_021b;
/// `android:versionName`.
pub const ANDROID_VERSION_NAME: u32 = 0x0101_021c;

const NO_INDEX: u32 = u32::MAX;

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// A length the formats store in 32 bits. Fixtures are small.
fn len32(length: usize) -> u32 {
    u32::try_from(length).unwrap_or(u32::MAX)
}

/// A length the formats store in 16 bits.
fn len16(length: usize) -> u16 {
    u16::try_from(length).unwrap_or(u16::MAX)
}

/// CRC-32 as zip uses it, bit by bit.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 { crc >> 1 } else { (crc >> 1) ^ 0xedb8_8320 };
        }
    }
    !crc
}

/// Writes a zip archive entry by entry.
#[derive(Debug, Clone, Default)]
pub struct ZipBuilder {
    /// Local headers and data.
    body: Vec<u8>,
    directory: Vec<u8>,
    entries: u16,
}

impl ZipBuilder {
    /// An archive with no entries yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an entry whose content is stored as it is.
    #[must_use]
    pub fn stored(self, name: &str, content: &[u8]) -> Self {
        self.stored_padded(name, content, 0)
    }

    /// Adds a stored entry whose local header carries `padding` bytes of
    /// extra field, the way packages are aligned.
    #[must_use]
    pub fn stored_padded(self, name: &str, content: &[u8], padding: usize) -> Self {
        self.entry(name, 0, 0, content, len32(content.len()), crc32(content), padding)
    }

    /// Adds an entry whose content is compressed with DEFLATE.
    #[must_use]
    pub fn deflated(self, name: &str, content: &[u8]) -> Self {
        let data = miniz_oxide::deflate::compress_to_vec(content, 6);
        self.entry(name, 8, 0, &data, len32(content.len()), crc32(content), 0)
    }

    /// Adds an entry exactly as given: any method, any flags, any declared
    /// size, whatever the data really holds.
    #[must_use]
    pub fn raw(self, name: &str, method: u16, flags: u16, data: &[u8], declared: u32) -> Self {
        self.entry(name, method, flags, data, declared, 0, 0)
    }

    #[expect(clippy::too_many_arguments, reason = "the fields of one zip entry")]
    fn entry(
        mut self,
        name: &str,
        method: u16,
        flags: u16,
        data: &[u8],
        declared: u32,
        crc: u32,
        padding: usize,
    ) -> Self {
        let offset = len32(self.body.len());
        // What the local header and the directory entry share: version
        // needed, flags, method, time, date (1980-01-01), checksum, sizes.
        let mut shared = Vec::new();
        put16(&mut shared, 20);
        put16(&mut shared, flags);
        put16(&mut shared, method);
        put16(&mut shared, 0);
        put16(&mut shared, 0x0021);
        put32(&mut shared, crc);
        put32(&mut shared, len32(data.len()));
        put32(&mut shared, declared);
        put16(&mut shared, len16(name.len()));

        self.body.extend_from_slice(b"PK\x03\x04");
        self.body.extend_from_slice(&shared);
        put16(&mut self.body, len16(padding));
        self.body.extend_from_slice(name.as_bytes());
        self.body.resize(self.body.len() + padding, 0);
        self.body.extend_from_slice(data);

        self.directory.extend_from_slice(b"PK\x01\x02");
        put16(&mut self.directory, 20);
        self.directory.extend_from_slice(&shared);
        // Extra length, comment length, disk, internal and external
        // attributes.
        self.directory.extend_from_slice(&[0; 12]);
        put32(&mut self.directory, offset);
        self.directory.extend_from_slice(name.as_bytes());
        self.entries += 1;
        self
    }

    /// The finished archive.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.finish_with_comment(b"")
    }

    /// The finished archive, with a comment after its end record.
    #[must_use]
    pub fn finish_with_comment(self, comment: &[u8]) -> Vec<u8> {
        let mut out = self.body;
        let directory_offset = len32(out.len());
        out.extend_from_slice(&self.directory);
        out.extend_from_slice(b"PK\x05\x06");
        put16(&mut out, 0);
        put16(&mut out, 0);
        put16(&mut out, self.entries);
        put16(&mut out, self.entries);
        put32(&mut out, len32(self.directory.len()));
        put32(&mut out, directory_offset);
        put16(&mut out, len16(comment.len()));
        out.extend_from_slice(comment);
        out
    }
}

/// Writes a DEX file that holds a string table, a type table and class
/// definitions, and no code.
#[derive(Debug, Clone, Default)]
pub struct DexBuilder {
    strings: BTreeSet<Vec<u8>>,
    types: BTreeSet<Vec<u8>>,
    /// Descriptors of the classes the file defines, in the order added.
    classes: Vec<Vec<u8>>,
}

impl DexBuilder {
    /// A file with empty tables.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Defines the class `name`, given the way reports write it:
    /// `com.example.Main`.
    #[must_use]
    pub fn class(self, name: &str) -> Self {
        self.class_descriptor(&format!("L{};", name.replace('.', "/")))
    }

    /// Defines a class by its raw type descriptor, which need not be one a
    /// class can have.
    #[must_use]
    pub fn class_descriptor(mut self, descriptor: &str) -> Self {
        self.types.insert(descriptor.as_bytes().to_vec());
        self.classes.push(descriptor.as_bytes().to_vec());
        self
    }

    /// Adds a type the file refers to and does not define.
    #[must_use]
    pub fn referenced_type(mut self, descriptor: &str) -> Self {
        self.types.insert(descriptor.as_bytes().to_vec());
        self
    }

    /// Adds a string constant.
    #[must_use]
    pub fn string(mut self, string: &str) -> Self {
        self.strings.insert(string.as_bytes().to_vec());
        self
    }

    /// The finished file: header, `string_ids`, `type_ids`, `class_defs`,
    /// then the string data.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        const HEADER: usize = 0x70;
        // Both tables are sorted, as the format requires.
        let strings: Vec<&Vec<u8>> = self.strings.union(&self.types).collect();
        let index_of =
            |wanted: &Vec<u8>| len32(strings.iter().position(|s| *s == wanted).unwrap_or(0));
        let types: Vec<u32> = self.types.iter().map(index_of).collect();
        let type_of = |descriptor: &Vec<u8>| {
            let string = index_of(descriptor);
            len32(types.iter().position(|index| *index == string).unwrap_or(0))
        };

        let string_ids_at = HEADER;
        let type_ids_at = string_ids_at + strings.len() * 4;
        let class_defs_at = type_ids_at + types.len() * 4;
        let data_at = class_defs_at + self.classes.len() * 32;

        let mut data = Vec::new();
        let mut string_ids = Vec::new();
        for string in &strings {
            put32(&mut string_ids, len32(data_at + data.len()));
            // The length in UTF-16 code units, as ULEB128.
            let mut units = String::from_utf8_lossy(string).encode_utf16().count();
            loop {
                let low = (units & 0x7f) as u8;
                units >>= 7;
                data.push(if units == 0 { low } else { low | 0x80 });
                if units == 0 {
                    break;
                }
            }
            data.extend_from_slice(string);
            data.push(0);
        }

        let mut out = b"dex\n035\0".to_vec();
        out.resize(0x20, 0); // checksum and signature, which nothing here reads
        put32(&mut out, len32(data_at + data.len()));
        put32(&mut out, len32(HEADER));
        put32(&mut out, 0x1234_5678);
        out.resize(0x38, 0); // link and map
        let table = |out: &mut Vec<u8>, count: usize, at: usize| {
            put32(out, len32(count));
            put32(out, if count == 0 { 0 } else { len32(at) });
        };
        table(&mut out, strings.len(), string_ids_at);
        table(&mut out, types.len(), type_ids_at);
        out.resize(0x60, 0); // protos, fields, methods
        table(&mut out, self.classes.len(), class_defs_at);
        table(&mut out, data.len(), data_at);
        debug_assert_eq!(out.len(), HEADER);

        out.extend_from_slice(&string_ids);
        for index in &types {
            put32(&mut out, *index);
        }
        for class in &self.classes {
            put32(&mut out, type_of(class));
            put32(&mut out, 1); // public
            put32(&mut out, NO_INDEX); // no superclass
            put32(&mut out, 0);
            put32(&mut out, NO_INDEX); // no source file
            out.extend_from_slice(&[0; 12]);
        }
        out.extend_from_slice(&data);
        out
    }
}

/// The value of an attribute in a compiled manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AttrValue {
    Text(String),
    Int(u32),
    Reference(u32),
}

/// One attribute of an element in a compiled manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    /// The resource id of the attribute's name, for an `android:` attribute.
    resource: Option<u32>,
    name: String,
    value: AttrValue,
}

impl Attr {
    /// An attribute without a namespace or a resource id, such as `package`.
    #[must_use]
    pub fn plain(name: &str, value: &str) -> Self {
        Self { resource: None, name: name.into(), value: AttrValue::Text(value.into()) }
    }

    /// An `android:` attribute with a text value. `name` is the name string
    /// the file carries, which the platform does not look at.
    #[must_use]
    pub fn android(resource: u32, name: &str, value: &str) -> Self {
        Self { resource: Some(resource), name: name.into(), value: AttrValue::Text(value.into()) }
    }

    /// An `android:` attribute with an integer value.
    #[must_use]
    pub fn int(resource: u32, name: &str, value: u32) -> Self {
        Self { resource: Some(resource), name: name.into(), value: AttrValue::Int(value) }
    }

    /// An `android:` attribute whose value points at a resource, such as
    /// `@string/app_name`.
    #[must_use]
    pub fn reference(resource: u32, name: &str, id: u32) -> Self {
        Self { resource: Some(resource), name: name.into(), value: AttrValue::Reference(id) }
    }
}

/// The string pool of a document while it is written.
struct Pool<'a> {
    strings: Vec<&'a str>,
    /// Where each string that is not a resource-backed attribute name went.
    /// Those names are never shared: their index is their resource id's.
    plain: BTreeMap<&'a str, u32>,
}

impl<'a> Pool<'a> {
    /// The index of `text`, adding it if it is new.
    fn intern(&mut self, text: &'a str) -> u32 {
        *self.plain.entry(text).or_insert_with(|| {
            self.strings.push(text);
            len32(self.strings.len() - 1)
        })
    }
}

#[derive(Debug, Clone)]
enum Event {
    Start(String, Vec<Attr>),
    End(String),
}

/// Writes Android binary XML, the compiled form of a manifest.
#[derive(Debug, Clone, Default)]
pub struct AxmlBuilder {
    utf8: bool,
    events: Vec<Event>,
    open: Vec<String>,
}

impl AxmlBuilder {
    /// A document with a UTF-16 string pool and no elements yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores the string pool as UTF-8.
    #[must_use]
    pub fn utf8(mut self) -> Self {
        self.utf8 = true;
        self
    }

    /// Opens an element.
    #[must_use]
    pub fn start(mut self, name: &str, attributes: &[Attr]) -> Self {
        self.open.push(name.into());
        self.events.push(Event::Start(name.into(), attributes.to_vec()));
        self
    }

    /// Closes the element opened last. With none open, it still writes an
    /// end chunk, which a reader must cope with.
    #[must_use]
    pub fn end(mut self) -> Self {
        let name = self.open.pop().unwrap_or_default();
        self.events.push(Event::End(name));
        self
    }

    /// The finished document. Elements still open stay unclosed.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        // Attribute names with a resource id come first in the pool, in
        // step with the resource map, as the build tool writes them.
        let mut resources: Vec<(u32, &str)> = Vec::new();
        for event in &self.events {
            let Event::Start(_, attributes) = event else { continue };
            for attribute in attributes {
                if let Some(id) = attribute.resource
                    && !resources.contains(&(id, attribute.name.as_str()))
                {
                    resources.push((id, attribute.name.as_str()));
                }
            }
        }
        let mut strings = Pool {
            strings: resources.iter().map(|(_, name)| *name).collect(),
            plain: BTreeMap::new(),
        };
        let android = strings.intern("http://schemas.android.com/apk/res/android");

        let mut nodes = Vec::new();
        for event in &self.events {
            match event {
                Event::Start(name, attributes) => {
                    put16(&mut nodes, 0x0102);
                    put16(&mut nodes, 16);
                    put32(&mut nodes, len32(16 + 20 + attributes.len() * 20));
                    put32(&mut nodes, 0); // line
                    put32(&mut nodes, NO_INDEX); // comment
                    put32(&mut nodes, NO_INDEX); // namespace
                    put32(&mut nodes, strings.intern(name.as_str()));
                    put16(&mut nodes, 20); // where the attributes start
                    put16(&mut nodes, 20); // size of one
                    put16(&mut nodes, len16(attributes.len()));
                    nodes.extend_from_slice(&[0; 6]); // id, class, style
                    for attribute in attributes {
                        let (namespace, name) = match attribute.resource {
                            Some(id) => {
                                let key = (id, attribute.name.as_str());
                                let at = resources.iter().position(|entry| *entry == key);
                                (android, len32(at.unwrap_or(0)))
                            }
                            None => (NO_INDEX, strings.intern(attribute.name.as_str())),
                        };
                        let (raw, kind, data) = match &attribute.value {
                            AttrValue::Text(text) => {
                                let index = strings.intern(text.as_str());
                                (index, 0x03, index)
                            }
                            AttrValue::Int(value) => (NO_INDEX, 0x10, *value),
                            AttrValue::Reference(id) => (NO_INDEX, 0x01, *id),
                        };
                        put32(&mut nodes, namespace);
                        put32(&mut nodes, name);
                        put32(&mut nodes, raw);
                        put16(&mut nodes, 8);
                        nodes.push(0);
                        nodes.push(kind);
                        put32(&mut nodes, data);
                    }
                }
                Event::End(name) => {
                    put16(&mut nodes, 0x0103);
                    put16(&mut nodes, 16);
                    put32(&mut nodes, 24);
                    put32(&mut nodes, 0);
                    put32(&mut nodes, NO_INDEX);
                    put32(&mut nodes, NO_INDEX);
                    put32(&mut nodes, strings.intern(name.as_str()));
                }
            }
        }

        let pool = strings.strings;
        let mut offsets = Vec::new();
        let mut data = Vec::new();
        for text in &pool {
            put32(&mut offsets, len32(data.len()));
            if self.utf8 {
                // Both lengths take one byte, or two with the top bit set.
                for length in [text.encode_utf16().count(), text.len()] {
                    if length > 0x7f {
                        data.push(0x80 | (length >> 8) as u8);
                    }
                    data.push(length as u8);
                }
                data.extend_from_slice(text.as_bytes());
                data.push(0);
            } else {
                let units: Vec<u16> = text.encode_utf16().collect();
                if units.len() > 0x7fff {
                    put16(&mut data, 0x8000 | (units.len() >> 16) as u16);
                }
                put16(&mut data, units.len() as u16);
                for unit in units {
                    put16(&mut data, unit);
                }
                put16(&mut data, 0);
            }
        }
        data.resize(data.len().next_multiple_of(4), 0);

        let mut out = Vec::new();
        put16(&mut out, 0x0003);
        put16(&mut out, 8);
        put32(&mut out, 0); // patched below

        put16(&mut out, 0x0001);
        put16(&mut out, 28);
        put32(&mut out, len32(28 + offsets.len() + data.len()));
        put32(&mut out, len32(pool.len()));
        put32(&mut out, 0); // styles
        put32(&mut out, if self.utf8 { 1 << 8 } else { 0 });
        put32(&mut out, len32(28 + offsets.len()));
        put32(&mut out, 0);
        out.extend_from_slice(&offsets);
        out.extend_from_slice(&data);

        put16(&mut out, 0x0180);
        put16(&mut out, 8);
        put32(&mut out, len32(8 + resources.len() * 4));
        for (id, _) in &resources {
            put32(&mut out, *id);
        }

        out.extend_from_slice(&nodes);
        let size = len32(out.len());
        out[4..8].copy_from_slice(&size.to_le_bytes());
        out
    }
}

/// A compiled manifest of the usual shape: a package, a version, and the
/// given elements directly inside `<application>`, each with its
/// `android:name`. `elements` pairs an element name such as `service` or
/// `meta-data` with that name.
#[must_use]
pub fn manifest(package: &str, version: &str, elements: &[(&str, &str)]) -> Vec<u8> {
    let mut builder = AxmlBuilder::new()
        .start(
            "manifest",
            &[
                Attr::android(ANDROID_VERSION_NAME, "versionName", version),
                Attr::plain("package", package),
            ],
        )
        .start("application", &[]);
    for (element, name) in elements {
        builder = builder.start(element, &[Attr::android(ANDROID_NAME, "name", name)]).end();
    }
    builder.end().end().finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check value every CRC-32 implementation is tested against.
    #[test]
    fn the_checksum_is_the_standard_crc32() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn the_writers_are_deterministic() {
        let zip = || ZipBuilder::new().deflated("a", b"aaaa").stored("b", b"bb").finish();
        assert_eq!(zip(), zip());
        let dex = || DexBuilder::new().class("b.B").class("a.A").string("z").finish();
        assert_eq!(dex(), dex());
        let xml = || manifest("com.example", "1.0", &[("service", ".S")]);
        assert_eq!(xml(), xml());
    }
}
