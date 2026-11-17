//! Reading the identity and the components of an Android app from its
//! `AndroidManifest.xml`.
//!
//! Inside a package the manifest is not text. The build tool compiles it to
//! Android's binary XML: a string pool, a table that maps attribute names to
//! resource ids, and a flat list of element chunks. This module reads that
//! list once, front to back, and keeps what the scanner needs:
//!
//! * the package name and version, which identify the app;
//! * the name of every component (`activity`, `activity-alias`, `service`,
//!   `receiver`, `provider`) and of every `meta-data` entry;
//! * the name of every permission the app asks for (`uses-permission` and
//!   `uses-permission-sdk-23`), with the highest API level it asks on when
//!   the manifest limits it (`android:maxSdkVersion`).
//!
//! Component names are the witness that survives full obfuscation. The
//! build tool keeps every class the manifest names, because the system
//! starts them by name, and an SDK that registers itself (Firebase's
//! `com.google.firebase.components:<Registrar>` entries, for one) does so
//! through the manifest that is merged into the app's.
//!
//! The reader takes names the way the platform takes them, so that it sees
//! what Android would run and nothing else:
//!
//! * An `android:` attribute is recognised by its **resource id**, never by
//!   its name. A manifest whose attribute names were stripped or changed
//!   still means the same to Android, and to this reader.
//! * A component counts where Android looks for one: directly inside
//!   `<application>`. A `meta-data` entry counts inside `<application>` or
//!   inside a component. A permission counts directly inside `<manifest>`.
//! * A class name that starts with a dot, or has none, is relative to the
//!   package.
//!
//! Budgets: at most [`MAX_BYTES`] of input, [`MAX_DEPTH`] nested elements,
//! and [`MAX_BYTES`] of text in the result in total, so a file whose every
//! attribute points at one huge string costs no more than an honest one.
//! Text is charged before it is made, at the most it can come to: three
//! bytes for each byte or code unit in the pool, and the package once more
//! for each class name that is relative to it.

use crate::le::{u16_at, u32_at, usize_at};
use crate::{Budget, FormatError};

/// Largest manifest the reader accepts, in bytes. Real ones are tens of
/// kilobytes.
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
/// Deepest element nesting the reader accepts. A manifest nests five deep.
pub const MAX_DEPTH: usize = 64;

/// Chunk types (`ResourceTypes.h`).
const XML: u16 = 0x0003;
const STRING_POOL: u16 = 0x0001;
const RESOURCE_MAP: u16 = 0x0180;
const START_ELEMENT: u16 = 0x0102;
const END_ELEMENT: u16 = 0x0103;

/// Length of the header every chunk starts with: type, header size, size.
const CHUNK_HEADER_BYTES: usize = 8;
/// Length of the fixed part of an attribute.
const ATTRIBUTE_BYTES: usize = 20;
/// String pool flag: strings are UTF-8 rather than UTF-16.
const UTF8_FLAG: u32 = 1 << 8;
/// "No string": the value of an absent namespace or raw value.
const NO_INDEX: u32 = u32::MAX;

/// Typed value kinds (`Res_value`).
const TYPE_STRING: u8 = 0x03;
/// The range of integer kinds (`TYPE_FIRST_INT` to `TYPE_LAST_INT`).
const TYPE_INTS: core::ops::RangeInclusive<u8> = 0x10..=0x1f;

/// Resource ids of the `android:` attributes the reader wants
/// (`android.R.attr`).
const ATTR_LABEL: u32 = 0x0101_0001;
const ATTR_NAME: u32 = 0x0101_0003;
const ATTR_VERSION_NAME: u32 = 0x0101_021c;
const ATTR_MAX_SDK_VERSION: u32 = 0x0101_0271;

/// What a package says about itself.
///
/// Every text field is whatever the file declares, unchecked and uncut. The
/// caller cleans it before it enters a record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// The `package` attribute: the app id, such as `com.x8bit.bitwarden`.
    pub package: Option<String>,
    /// `android:versionName`, the version shown to users.
    pub version_name: Option<String>,
    /// `android:label` of the application, when the manifest holds it as
    /// text. Most apps point at a string resource instead, which this
    /// reader does not resolve.
    pub label: Option<String>,
    /// The components and `meta-data` entries, in document order.
    pub components: Vec<Component>,
    /// Every `uses-permission` and `uses-permission-sdk-23` element that
    /// asks on some API level, in document order. A name may appear twice.
    pub permissions: Vec<UsesPermission>,
}

/// One permission a manifest asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsesPermission {
    /// Its `android:name` as written, such as `android.permission.CAMERA`.
    pub name: String,
    /// Its `android:maxSdkVersion`: the highest API level the app asks on.
    /// `None` when it asks on every level, as it does for a value of 0.
    pub max_sdk: Option<u32>,
}

/// One component or `meta-data` entry of a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// Its `android:name`. For a component this is the fully qualified
    /// class name; for `meta-data` it is the key as written.
    pub name: String,
}

/// What the `android:name` of a collected element is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Named {
    /// A class name, which may be relative to the package.
    Class,
    /// The key of a `meta-data` entry, taken as written.
    Key,
}

/// What an open element is, as far as the reader cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Manifest,
    Application,
    Component,
    Other,
}

/// One chunk: its type, its header and its whole extent.
struct Chunk<'a> {
    kind: u16,
    header_bytes: usize,
    bytes: &'a [u8],
}

impl<'a> Chunk<'a> {
    /// The chunk at the start of `bytes`.
    fn read(bytes: &'a [u8]) -> Result<Self, FormatError> {
        let kind = u16_at(bytes, 0).ok_or(FormatError::Malformed)?;
        let header_bytes = usize::from(u16_at(bytes, 2).ok_or(FormatError::Malformed)?);
        let size = usize_at(bytes, 4).ok_or(FormatError::Malformed)?;
        if header_bytes < CHUNK_HEADER_BYTES || size < header_bytes {
            return Err(FormatError::Malformed);
        }
        let bytes = bytes.get(..size).ok_or(FormatError::Malformed)?;
        Ok(Self { kind, header_bytes, bytes })
    }

    /// What follows the chunk's header.
    fn body(&self) -> &'a [u8] {
        self.bytes.get(self.header_bytes..).unwrap_or_default()
    }
}

/// The string pool of the document.
struct Pool<'a> {
    /// The offsets of the strings, four bytes each.
    offsets: &'a [u8],
    /// The string data the offsets point into.
    data: &'a [u8],
    utf8: bool,
}

/// A string as the pool stores it.
enum Encoded<'a> {
    Utf8(&'a [u8]),
    /// UTF-16 code units, little-endian, two bytes each.
    Utf16(&'a [u8]),
}

impl<'a> Pool<'a> {
    fn read(chunk: &Chunk<'a>) -> Result<Self, FormatError> {
        let field = |at| usize_at(chunk.bytes, at).ok_or(FormatError::Malformed);
        let (count, strings_start) = (field(8)?, field(20)?);
        let flags = u32_at(chunk.bytes, 16).ok_or(FormatError::Malformed)?;
        let offsets = count
            .checked_mul(4)
            .and_then(|length| chunk.body().get(..length))
            .ok_or(FormatError::Malformed)?;
        let data = if count == 0 {
            &[]
        } else {
            chunk.bytes.get(strings_start..).ok_or(FormatError::Malformed)?
        };
        Ok(Self { offsets, data, utf8: flags & UTF8_FLAG != 0 })
    }

    /// A length in a UTF-8 pool: one byte, or two when the top bit of the
    /// first is set. Returns the length and what follows it.
    fn length8(bytes: &'a [u8]) -> Option<(usize, &'a [u8])> {
        let first = usize::from(*bytes.first()?);
        if first & 0x80 == 0 {
            return Some((first, bytes.get(1..)?));
        }
        let high = (first & 0x7f).checked_shl(8)?;
        Some((high | usize::from(*bytes.get(1)?), bytes.get(2..)?))
    }

    /// A length in a UTF-16 pool: one code unit, or two when the top bit of
    /// the first is set. Returns the length and what follows it.
    fn length16(bytes: &'a [u8]) -> Option<(usize, &'a [u8])> {
        let first = usize::from(u16_at(bytes, 0)?);
        if first & 0x8000 == 0 {
            return Some((first, bytes.get(2..)?));
        }
        let high = (first & 0x7fff).checked_shl(16)?;
        Some((high | usize::from(u16_at(bytes, 2)?), bytes.get(4..)?))
    }

    /// String `index` as stored, or `None` if the pool has no such string or
    /// it does not lie inside the pool.
    fn encoded(&self, index: u32) -> Option<Encoded<'a>> {
        let offset = usize_at(self.offsets, usize::try_from(index).ok()?.checked_mul(4)?)?;
        let item = self.data.get(offset..)?;
        if self.utf8 {
            // The length in UTF-16 code units comes first and is not needed.
            let (_, rest) = Self::length8(item)?;
            let (length, rest) = Self::length8(rest)?;
            rest.get(..length).map(Encoded::Utf8)
        } else {
            let (length, rest) = Self::length16(item)?;
            rest.get(..length.checked_mul(2)?).map(Encoded::Utf16)
        }
    }

    /// Whether string `index` is exactly the ASCII text `name`. Nothing is
    /// decoded or allocated, so element names cost no text budget.
    fn is(&self, index: u32, name: &str) -> bool {
        match self.encoded(index) {
            Some(Encoded::Utf8(bytes)) => bytes == name.as_bytes(),
            Some(Encoded::Utf16(units)) => {
                units.len() == name.len().saturating_mul(2)
                    && units
                        .chunks_exact(2)
                        .zip(name.bytes())
                        .all(|(unit, byte)| matches!(unit, [low, 0] if *low == byte))
            }
            None => false,
        }
    }

    /// String `index` as text, charged against `budget`. Bytes that are not
    /// valid in their encoding become U+FFFD.
    fn text(&self, index: u32, budget: &mut usize) -> Result<Option<String>, FormatError> {
        let Some(encoded) = self.encoded(index) else { return Ok(None) };
        let text = match encoded {
            Encoded::Utf8(bytes) => {
                // A byte that is not valid becomes the three of U+FFFD.
                charge(budget, bytes.len().saturating_mul(3))?;
                String::from_utf8_lossy(bytes).into_owned()
            }
            Encoded::Utf16(units) => {
                // A code unit becomes at most three bytes of UTF-8.
                charge(budget, units.len().saturating_mul(3) / 2)?;
                let units = units.chunks_exact(2).filter_map(|unit| u16_at(unit, 0));
                char::decode_utf16(units)
                    .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect()
            }
        };
        Ok(Some(text))
    }
}

/// Takes `bytes` out of the text budget.
fn charge(budget: &mut usize, bytes: usize) -> Result<(), FormatError> {
    *budget = budget.checked_sub(bytes).ok_or(FormatError::OverBudget(Budget::Bytes))?;
    Ok(())
}

/// One attribute of an element.
struct Attribute {
    namespace: u32,
    name: u32,
    raw: u32,
    kind: u8,
    data: u32,
}

impl Attribute {
    /// The string the typed value refers to, if it is a string. This is what
    /// the platform reads an `android:` attribute through.
    fn typed_string(&self) -> Option<u32> {
        (self.kind == TYPE_STRING).then_some(self.data)
    }

    /// The integer of the typed value, if it is one.
    fn typed_int(&self) -> Option<i32> {
        TYPE_INTS.contains(&self.kind).then_some(self.data.cast_signed())
    }
}

/// The attributes of a start-element chunk.
fn attributes<'a>(chunk: &Chunk<'a>) -> Result<impl Iterator<Item = Attribute> + 'a, FormatError> {
    let body = chunk.body();
    let field = |at| u16_at(body, at).map(usize::from).ok_or(FormatError::Malformed);
    let (start, size, count) = (field(8)?, field(10)?, field(12)?);
    let table = if count == 0 {
        &[]
    } else if size < ATTRIBUTE_BYTES {
        return Err(FormatError::Malformed);
    } else {
        count
            .checked_mul(size)
            .and_then(|length| body.get(start..start.checked_add(length)?))
            .ok_or(FormatError::Malformed)?
    };
    Ok(table.chunks_exact(size.max(ATTRIBUTE_BYTES)).filter_map(|bytes| {
        Some(Attribute {
            namespace: u32_at(bytes, 0)?,
            name: u32_at(bytes, 4)?,
            raw: u32_at(bytes, 8)?,
            kind: *bytes.get(15)?,
            data: u32_at(bytes, 16)?,
        })
    }))
}

/// Makes a component's class name absolute, as the platform does: a name
/// that starts with a dot or holds none is relative to the package. The
/// package put in front of a name is charged against `budget`.
fn class_name(
    package: Option<&str>,
    name: String,
    budget: &mut usize,
) -> Result<String, FormatError> {
    let Some(package) = package else { return Ok(name) };
    let separator = if name.starts_with('.') {
        ""
    } else if name.contains('.') {
        return Ok(name);
    } else {
        "."
    };
    charge(budget, package.len().saturating_add(separator.len()))?;
    Ok(format!("{package}{separator}{name}"))
}

/// Extracts the identity and the component names from the bytes of a
/// compiled `AndroidManifest.xml`.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the input is larger than [`MAX_BYTES`],
/// nests deeper than [`MAX_DEPTH`] or takes more than [`MAX_BYTES`] of text
/// out of its string pool. [`FormatError::Malformed`] if it is not binary
/// XML whose root element is `manifest`.
pub fn parse(bytes: &[u8]) -> Result<Manifest, FormatError> {
    if bytes.len() > MAX_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let document = Chunk::read(bytes)?;
    if document.kind != XML {
        return Err(FormatError::Malformed);
    }

    let mut manifest = Manifest::default();
    let mut pool: Option<Pool<'_>> = None;
    let mut resource_ids: &[u8] = &[];
    let mut open: Vec<Tag> = Vec::new();
    let mut text_budget = MAX_BYTES;
    let mut rest = document.body();

    while !rest.is_empty() {
        let chunk = Chunk::read(rest)?;
        rest = rest.get(chunk.bytes.len()..).unwrap_or_default();
        match chunk.kind {
            STRING_POOL => {
                // Elements refer to strings by index, so a second pool would
                // make every name ambiguous.
                if pool.is_some() {
                    return Err(FormatError::Malformed);
                }
                pool = Some(Pool::read(&chunk)?);
            }
            RESOURCE_MAP => resource_ids = chunk.body(),
            START_ELEMENT => {
                let pool = pool.as_ref().ok_or(FormatError::Malformed)?;
                let name = u32_at(chunk.body(), 4).ok_or(FormatError::Malformed)?;
                let parent = open.last().copied();
                if open.len() >= MAX_DEPTH {
                    return Err(FormatError::OverBudget(Budget::Depth));
                }
                // The resource id of an attribute's name, if it has one.
                let resource = |attribute: &Attribute| {
                    usize::try_from(attribute.name)
                        .ok()
                        .and_then(|index| u32_at(resource_ids, index.checked_mul(4)?))
                };
                let asks = parent == Some(Tag::Manifest)
                    && ["uses-permission", "uses-permission-sdk-23"]
                        .iter()
                        .any(|element| pool.is(name, element));
                let mut android_name = None;
                let mut permission = None;
                let mut max_sdk = None;
                for attribute in attributes(&chunk)? {
                    // The package is the one attribute read by its name: it
                    // has no namespace and no resource id.
                    if parent.is_none()
                        && attribute.namespace == NO_INDEX
                        && manifest.package.is_none()
                        && pool.is(attribute.name, "package")
                    {
                        let value = if attribute.raw == NO_INDEX {
                            attribute.typed_string()
                        } else {
                            Some(attribute.raw)
                        };
                        if let Some(index) = value {
                            manifest.package = pool.text(index, &mut text_budget)?;
                        }
                        continue;
                    }
                    match (parent, resource(&attribute)) {
                        (None, Some(ATTR_VERSION_NAME)) => {
                            if let Some(index) = attribute.typed_string() {
                                manifest.version_name = pool.text(index, &mut text_budget)?;
                            }
                        }
                        (Some(Tag::Manifest), Some(ATTR_LABEL))
                            if manifest.label.is_none() && pool.is(name, "application") =>
                        {
                            if let Some(index) = attribute.typed_string() {
                                manifest.label = pool.text(index, &mut text_budget)?;
                            }
                        }
                        (Some(Tag::Application | Tag::Component), Some(ATTR_NAME)) => {
                            android_name = attribute.typed_string();
                        }
                        (Some(Tag::Manifest), Some(ATTR_NAME)) if asks => {
                            permission = attribute.typed_string();
                        }
                        (Some(Tag::Manifest), Some(ATTR_MAX_SDK_VERSION)) if asks => {
                            max_sdk = attribute.typed_int();
                        }
                        _ => {}
                    }
                }

                let (tag, named) = match parent {
                    None if pool.is(name, "manifest") => (Tag::Manifest, None),
                    // The root element must be the manifest.
                    None => return Err(FormatError::Malformed),
                    Some(Tag::Manifest) if pool.is(name, "application") => (Tag::Application, None),
                    Some(Tag::Application)
                        if ["activity", "activity-alias", "service", "receiver", "provider"]
                            .iter()
                            .any(|element| pool.is(name, element)) =>
                    {
                        (Tag::Component, Some(Named::Class))
                    }
                    Some(Tag::Application | Tag::Component) if pool.is(name, "meta-data") => {
                        (Tag::Other, Some(Named::Key))
                    }
                    Some(_) => (Tag::Other, None),
                };
                open.push(tag);
                // The platform takes 0 for no limit, and grants a permission
                // whose limit is below every level on none.
                let max_sdk = match max_sdk {
                    None | Some(0) => Some(None),
                    Some(level) => u32::try_from(level).ok().map(Some),
                };
                if let (Some(index), Some(max_sdk)) = (permission, max_sdk)
                    && let Some(name) = pool.text(index, &mut text_budget)?
                    && !name.is_empty()
                {
                    manifest.permissions.push(UsesPermission { name, max_sdk });
                }
                if let (Some(named), Some(index)) = (named, android_name)
                    && let Some(name) = pool.text(index, &mut text_budget)?
                    && !name.is_empty()
                {
                    let name = match named {
                        Named::Key => name,
                        Named::Class => {
                            class_name(manifest.package.as_deref(), name, &mut text_budget)?
                        }
                    };
                    manifest.components.push(Component { name });
                }
            }
            END_ELEMENT => {
                if open.pop().is_none() {
                    return Err(FormatError::Malformed);
                }
                if open.is_empty() {
                    // The root element closed. Anything after it is not ours.
                    return Ok(manifest);
                }
            }
            // Namespaces, character data and chunk types this reader does
            // not know carry no names.
            _ => {}
        }
    }
    // The platform reads to the end of the chunks and does not ask that
    // every element was closed. Without a root element there is no manifest.
    if open.is_empty() { Err(FormatError::Malformed) } else { Ok(manifest) }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::testkit::{Attr, AxmlBuilder};

    fn names(manifest: &Manifest) -> Vec<&str> {
        manifest.components.iter().map(|c| c.name.as_str()).collect()
    }

    /// The bytes of all the text in a manifest.
    fn text_bytes(manifest: &Manifest) -> usize {
        [&manifest.package, &manifest.version_name, &manifest.label]
            .into_iter()
            .flatten()
            .chain(manifest.components.iter().map(|component| &component.name))
            .chain(manifest.permissions.iter().map(|permission| &permission.name))
            .map(String::len)
            .sum()
    }

    /// A manifest shaped like the merged manifest of a real app.
    fn document(builder: AxmlBuilder) -> Vec<u8> {
        builder
            .start(
                "manifest",
                &[
                    Attr::android(ATTR_VERSION_NAME, "versionName", "2026.9.1"),
                    Attr::plain("package", "com.example.app"),
                ],
            )
            .start("uses-permission", &[Attr::android(ATTR_NAME, "name", "android.permission.INTERNET")])
            .end()
            .start(
                "application",
                &[
                    Attr::reference(ATTR_LABEL, "label", 0x7f0f_0001),
                    Attr::android(ATTR_NAME, "name", ".App"),
                ],
            )
            .start("activity", &[Attr::android(ATTR_NAME, "name", ".MainActivity")])
            .start("intent-filter", &[])
            .start("action", &[Attr::android(ATTR_NAME, "name", "android.intent.action.MAIN")])
            .end()
            .end()
            .start("meta-data", &[Attr::android(ATTR_NAME, "name", "android.app.shortcuts")])
            .end()
            .end()
            .start("activity-alias", &[Attr::android(ATTR_NAME, "name", "Launcher")])
            .end()
            .start(
                "service",
                &[Attr::android(
                    ATTR_NAME,
                    "name",
                    "com.google.firebase.components.ComponentDiscoveryService",
                )],
            )
            .start(
                "meta-data",
                &[Attr::android(
                    ATTR_NAME,
                    "name",
                    "com.google.firebase.components:com.google.firebase.crashlytics.CrashlyticsRegistrar",
                )],
            )
            .end()
            .end()
            .start("receiver", &[Attr::android(ATTR_NAME, "name", "com.example.lib.Receiver")])
            .end()
            .start("provider", &[Attr::android(ATTR_NAME, "name", "io.sentry.android.core.SentryInitProvider")])
            .end()
            .start("meta-data", &[Attr::android(ATTR_NAME, "name", "com.google.android.play.billingclient.version")])
            .end()
            .start("uses-library", &[Attr::android(ATTR_NAME, "name", "org.apache.http.legacy")])
            .end()
            .end()
            .end()
            .finish()
    }

    fn expected() -> Manifest {
        Manifest {
            package: Some("com.example.app".into()),
            version_name: Some("2026.9.1".into()),
            label: None,
            components: [
                "com.example.app.MainActivity",
                "android.app.shortcuts",
                "com.example.app.Launcher",
                "com.google.firebase.components.ComponentDiscoveryService",
                "com.google.firebase.components:com.google.firebase.crashlytics.CrashlyticsRegistrar",
                "com.example.lib.Receiver",
                "io.sentry.android.core.SentryInitProvider",
                "com.google.android.play.billingclient.version",
            ]
            .map(|name| Component { name: name.into() })
            .into(),
            permissions: vec![UsesPermission {
                name: "android.permission.INTERNET".into(),
                max_sdk: None,
            }],
        }
    }

    #[test]
    fn reads_a_manifest_with_utf16_strings() {
        assert_eq!(parse(&document(AxmlBuilder::new())), Ok(expected()));
    }

    #[test]
    fn reads_a_manifest_with_utf8_strings() {
        assert_eq!(parse(&document(AxmlBuilder::new().utf8())), Ok(expected()));
    }

    /// The permission, the intent action and the library all carry an
    /// `android:name`, and none of them is a component.
    #[test]
    fn only_components_and_meta_data_are_collected() {
        let manifest = parse(&document(AxmlBuilder::new())).unwrap();
        for name in names(&manifest) {
            assert!(!name.starts_with("android.permission"), "{name:?}");
            assert!(!name.starts_with("android.intent"), "{name:?}");
            assert!(!name.starts_with("org.apache"), "{name:?}");
        }
    }

    /// Android finds a component directly inside `<application>` and
    /// nowhere else, so nowhere else counts here.
    /// A permission is asked for directly inside `<manifest>`, by either of
    /// the two elements Android reads, under the attribute with the resource
    /// id of `android:name`.
    #[test]
    fn permissions_are_collected_where_android_looks_for_them() {
        let name = |value| [Attr::android(ATTR_NAME, "name", value)];
        let bytes = AxmlBuilder::new()
            .start("manifest", &[Attr::plain("package", "com.example.app")])
            .start("uses-permission", &name("android.permission.CAMERA"))
            .end()
            .start("uses-permission-sdk-23", &name("android.permission.RECORD_AUDIO"))
            .end()
            .start("uses-permission", &name("android.permission.CAMERA"))
            .end()
            // What the app defines or merely mentions is not what it asks for.
            .start("permission", &name("com.example.app.permission.OWN"))
            .end()
            .start("uses-feature", &name("android.hardware.camera"))
            .end()
            .start("uses-permission", &[Attr::plain("name", "android.permission.READ_SMS")])
            .end()
            .start("uses-permission", &name(""))
            .end()
            .start("application", &[])
            .start("uses-permission", &name("android.permission.READ_CONTACTS"))
            .end()
            .start("activity", &name(".Main"))
            .end()
            .end()
            .end()
            .finish();
        let manifest = parse(&bytes).unwrap();
        assert_eq!(
            manifest
                .permissions
                .iter()
                .map(|permission| permission.name.as_str())
                .collect::<Vec<_>>(),
            [
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA"
            ]
        );
        assert!(manifest.permissions.iter().all(|permission| permission.max_sdk.is_none()));
        assert_eq!(names(&manifest), ["com.example.app.Main"]);
    }

    /// `android:maxSdkVersion` (`android.R.attr.maxSdkVersion`, 0x01010271)
    /// is the highest API level a permission is asked on. The platform reads
    /// it as an integer by resource id, takes 0 for no limit and grants a
    /// permission whose limit is below every level on no device.
    #[test]
    fn the_highest_api_level_of_a_permission_is_kept() {
        let asks = |name: &str, max: Attr| [Attr::android(ATTR_NAME, "name", name), max];
        let bytes = AxmlBuilder::new()
            .start("manifest", &[Attr::plain("package", "com.example.app")])
            .start(
                "uses-permission",
                &asks(
                    "android.permission.WRITE_EXTERNAL_STORAGE",
                    Attr::int(ATTR_MAX_SDK_VERSION, "maxSdkVersion", 28),
                ),
            )
            .end()
            .start(
                "uses-permission-sdk-23",
                &asks(
                    "android.permission.READ_EXTERNAL_STORAGE",
                    Attr::int(ATTR_MAX_SDK_VERSION, "maxSdkVersion", 32),
                ),
            )
            .end()
            .start(
                "uses-permission",
                &asks(
                    "android.permission.CAMERA",
                    Attr::int(ATTR_MAX_SDK_VERSION, "maxSdkVersion", 0),
                ),
            )
            .end()
            .start(
                "uses-permission",
                &asks(
                    "android.permission.READ_SMS",
                    Attr::int(ATTR_MAX_SDK_VERSION, "maxSdkVersion", u32::MAX),
                ),
            )
            .end()
            .start(
                "uses-permission",
                &asks("android.permission.RECORD_AUDIO", Attr::plain("maxSdkVersion", "28")),
            )
            .end()
            .start(
                "uses-permission",
                &asks(
                    "android.permission.READ_CONTACTS",
                    Attr::android(ATTR_MAX_SDK_VERSION, "maxSdkVersion", "28"),
                ),
            )
            .end()
            .end()
            .finish();
        let manifest = parse(&bytes).unwrap();
        let permissions: Vec<(&str, Option<u32>)> = manifest
            .permissions
            .iter()
            .map(|permission| (permission.name.as_str(), permission.max_sdk))
            .collect();
        assert_eq!(
            permissions,
            [
                ("android.permission.WRITE_EXTERNAL_STORAGE", Some(28)),
                ("android.permission.READ_EXTERNAL_STORAGE", Some(32)),
                ("android.permission.CAMERA", None),
                ("android.permission.RECORD_AUDIO", None),
                ("android.permission.READ_CONTACTS", None),
            ]
        );
    }

    #[test]
    fn a_component_outside_the_application_does_not_count() {
        let service = [Attr::android(ATTR_NAME, "name", "com.example.Misplaced")];
        let bytes = AxmlBuilder::new()
            .start("manifest", &[Attr::plain("package", "com.example.app")])
            .start("service", &service)
            .end()
            .start("meta-data", &service)
            .end()
            .start("application", &[])
            .start("activity", &[Attr::android(ATTR_NAME, "name", "com.example.Real")])
            .start("service", &service)
            .end()
            .end()
            .start("unknown", &[])
            .start("receiver", &service)
            .end()
            .end()
            .end()
            .end()
            .finish();
        let manifest = parse(&bytes).unwrap();
        assert_eq!(names(&manifest), ["com.example.Real"]);
    }

    /// The platform resolves `android:` attributes by resource id. A name
    /// string that says "name" without the id is some other attribute, and
    /// the id without the string still is `android:name`.
    #[test]
    fn attributes_are_recognised_by_resource_id_not_by_name() {
        let bytes = AxmlBuilder::new()
            .start("manifest", &[Attr::plain("package", "com.example.app")])
            .start("application", &[])
            .start("service", &[Attr::plain("name", "com.example.NotAndroidName")])
            .end()
            .start("service", &[Attr::android(ATTR_NAME, "", "com.example.Stripped")])
            .end()
            .start("receiver", &[Attr::android(ATTR_LABEL, "name", "com.example.ALabel")])
            .end()
            .end()
            .end()
            .finish();
        let manifest = parse(&bytes).unwrap();
        assert_eq!(names(&manifest), ["com.example.Stripped"]);
    }

    #[test]
    fn values_that_are_not_text_are_absent() {
        let bytes = AxmlBuilder::new()
            .start(
                "manifest",
                &[
                    Attr::plain("package", "com.example.app"),
                    Attr::reference(ATTR_VERSION_NAME, "versionName", 0x7f0f_0002),
                ],
            )
            .start("application", &[Attr::android(ATTR_LABEL, "label", "Example")])
            .start("activity", &[Attr::reference(ATTR_NAME, "name", 0x7f0f_0003)])
            .end()
            .start("activity", &[Attr::android(ATTR_NAME, "name", "")])
            .end()
            .start("activity", &[])
            .end()
            .end()
            .end()
            .finish();
        let manifest = parse(&bytes).unwrap();
        assert_eq!(manifest.version_name, None);
        assert_eq!(manifest.label.as_deref(), Some("Example"));
        assert!(manifest.components.is_empty());
    }

    #[test]
    fn class_names_are_made_absolute_the_way_the_platform_does() {
        let absolute = |package, name: &str| {
            let mut budget = usize::MAX;
            class_name(package, name.into(), &mut budget).unwrap()
        };
        let package = Some("com.example");
        assert_eq!(absolute(package, ".Main"), "com.example.Main");
        assert_eq!(absolute(package, ".ui.Main"), "com.example.ui.Main");
        assert_eq!(absolute(package, "Main"), "com.example.Main");
        assert_eq!(absolute(package, "org.other.Main"), "org.other.Main");
        assert_eq!(absolute(None, ".Main"), ".Main");
    }

    #[test]
    fn a_manifest_without_a_package_or_components_is_fine() {
        let bytes = AxmlBuilder::new().start("manifest", &[]).end().finish();
        assert_eq!(parse(&bytes), Ok(Manifest::default()));
    }

    #[test]
    fn an_unclosed_document_is_read_as_far_as_it_goes() {
        let bytes = AxmlBuilder::new()
            .start("manifest", &[Attr::plain("package", "com.example.app")])
            .start("application", &[])
            .start("service", &[Attr::android(ATTR_NAME, "name", ".Sync")])
            .finish();
        let manifest = parse(&bytes).unwrap();
        assert_eq!(names(&manifest), ["com.example.app.Sync"]);
    }

    #[test]
    fn rejects_what_is_not_a_manifest() {
        assert_eq!(parse(b""), Err(FormatError::Malformed));
        assert_eq!(parse(b"<?xml version=\"1.0\"?><manifest/>"), Err(FormatError::Malformed));
        // Binary XML of some other document.
        let layout = AxmlBuilder::new().start("LinearLayout", &[]).end().finish();
        assert_eq!(parse(&layout), Err(FormatError::Malformed));
        // No element at all.
        assert_eq!(parse(&AxmlBuilder::new().finish()), Err(FormatError::Malformed));
        // An end without a start.
        let unbalanced = AxmlBuilder::new().start("manifest", &[]).end().end().finish();
        assert_eq!(parse(&unbalanced), Ok(Manifest::default()), "ends after the root are not read");
        // A chunk that claims to be longer than the file.
        let good = document(AxmlBuilder::new());
        assert_eq!(parse(&good[..good.len() - 1]), Err(FormatError::Malformed));
        // A string pool after the first.
        let mut twice = good[..CHUNK_HEADER_BYTES].to_vec();
        let pool = Chunk::read(&good[CHUNK_HEADER_BYTES..]).unwrap();
        assert_eq!(pool.kind, STRING_POOL);
        twice.extend_from_slice(pool.bytes);
        twice.extend_from_slice(&good[CHUNK_HEADER_BYTES..]);
        let size = twice.len() as u32;
        twice[4..8].copy_from_slice(&size.to_le_bytes());
        assert_eq!(parse(&twice), Err(FormatError::Malformed));
    }

    #[test]
    fn an_element_before_the_string_pool_is_malformed() {
        let good = AxmlBuilder::new().start("manifest", &[]).end().finish();
        let pool = Chunk::read(&good[CHUNK_HEADER_BYTES..]).unwrap();
        let after_pool = CHUNK_HEADER_BYTES + pool.bytes.len();
        let mut swapped = good[..CHUNK_HEADER_BYTES].to_vec();
        swapped.extend_from_slice(&good[after_pool..]);
        swapped.extend_from_slice(pool.bytes);
        assert_eq!(parse(&swapped), Err(FormatError::Malformed));
    }

    #[test]
    fn enforces_the_byte_and_depth_budgets() {
        let big = vec![0u8; MAX_BYTES + 1];
        assert_eq!(parse(&big), Err(FormatError::OverBudget(Budget::Bytes)));

        let nested = |depth: usize| {
            let mut builder = AxmlBuilder::new().start("manifest", &[]);
            for _ in 1..depth {
                builder = builder.start("layer", &[]);
            }
            for _ in 0..depth {
                builder = builder.end();
            }
            builder.finish()
        };
        assert_eq!(parse(&nested(MAX_DEPTH)), Ok(Manifest::default()));
        assert_eq!(parse(&nested(MAX_DEPTH + 1)), Err(FormatError::OverBudget(Budget::Depth)));
    }

    /// Every attribute may point at the same string, so the text taken out
    /// of the pool is budgeted on its own: a small file cannot make the
    /// reader copy a large string a hundred thousand times.
    #[test]
    fn text_taken_from_the_pool_is_budgeted() {
        let long = "x".repeat(1 << 20);
        let service = [Attr::android(ATTR_NAME, "name", long.as_str())];
        let build = |count: usize| {
            let mut builder = AxmlBuilder::new().start("manifest", &[]).start("application", &[]);
            for _ in 0..count {
                builder = builder.start("service", &service).end();
            }
            builder.end().end().finish()
        };
        // A UTF-16 code unit is charged as the three bytes it can become, so
        // a megabyte of them costs three: five copies fit in sixteen, and
        // the sixth does not.
        let within = build(5);
        assert!(within.len() < 3 << 20, "the string is stored once");
        assert_eq!(parse(&within).unwrap().components.len(), 5);
        assert_eq!(parse(&build(6)), Err(FormatError::OverBudget(Budget::Bytes)));
    }

    /// A UTF-8 pool is charged the same way. Its longest string is 32 767
    /// bytes, and when none of them is valid UTF-8 each becomes the three
    /// bytes of U+FFFD, 98 301 in all: 170 copies fit in sixteen mebibytes
    /// and the next does not.
    #[test]
    fn invalid_utf8_is_charged_as_the_text_it_becomes() {
        const LENGTH: usize = 0x7fff;
        let long = "x".repeat(LENGTH);
        let service = [Attr::android(ATTR_NAME, "name", long.as_str())];
        let build = |count: usize| {
            let mut builder =
                AxmlBuilder::new().utf8().start("manifest", &[]).start("application", &[]);
            for _ in 0..count {
                builder = builder.start("service", &service).end();
            }
            let mut bytes = builder.end().end().finish();
            let at = bytes.windows(LENGTH).position(|run| run == long.as_bytes()).unwrap();
            bytes[at..at + LENGTH].fill(0xff);
            bytes
        };
        let manifest = parse(&build(170)).unwrap();
        assert_eq!(manifest.components.len(), 170);
        assert_eq!(manifest.components[0].name, "\u{fffd}".repeat(LENGTH));
        assert!(text_bytes(&manifest) <= MAX_BYTES);
        assert_eq!(parse(&build(171)), Err(FormatError::OverBudget(Budget::Bytes)));
    }

    /// A relative class name is given the package, so the package is
    /// charged again for each one: a megabyte of UTF-16 package costs three
    /// to read, and twelve names relative to it fit in the thirteen left.
    #[test]
    fn the_package_put_before_a_class_name_is_budgeted() {
        let package = "p".repeat(1 << 20);
        let build = |count: usize| {
            let mut builder = AxmlBuilder::new()
                .start("manifest", &[Attr::plain("package", package.as_str())])
                .start("application", &[]);
            for _ in 0..count {
                builder = builder.start("service", &[Attr::android(ATTR_NAME, "name", "S")]).end();
            }
            builder.end().end().finish()
        };
        let manifest = parse(&build(12)).unwrap();
        assert_eq!(manifest.components.len(), 12);
        assert_eq!(manifest.components[0].name.len(), package.len() + 2);
        assert!(text_bytes(&manifest) <= MAX_BYTES);
        assert_eq!(parse(&build(13)), Err(FormatError::OverBudget(Budget::Bytes)));
    }

    #[test]
    fn long_strings_use_the_two_unit_length() {
        // 40 000 UTF-16 units need the two-unit form; so do 400 UTF-8 bytes.
        for (builder, count) in [(AxmlBuilder::new(), 40_000), (AxmlBuilder::new().utf8(), 200)] {
            let long = format!("com.example.{}", "é".repeat(count));
            let bytes =
                builder.start("manifest", &[Attr::plain("package", long.as_str())]).end().finish();
            assert_eq!(parse(&bytes).unwrap().package.as_deref(), Some(long.as_str()));
        }
    }

    #[test]
    fn broken_text_is_replaced_not_refused() {
        let bytes = AxmlBuilder::new()
            .start("manifest", &[Attr::plain("package", "com.example.\u{d7ff}app")])
            .end()
            .finish();
        // Turn the code unit D7FF into the unpaired surrogate D800.
        let at = bytes.windows(2).position(|unit| unit == [0xff, 0xd7]).unwrap();
        let mut broken = bytes;
        broken[at..at + 2].copy_from_slice(&[0x00, 0xd8]);
        assert_eq!(parse(&broken).unwrap().package.as_deref(), Some("com.example.\u{fffd}app"));
    }

    proptest! {
        #[test]
        fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
            let _ = parse(&bytes);
        }

        /// A valid manifest with a few bytes changed still reads or is
        /// refused; it never panics.
        #[test]
        fn a_damaged_manifest_never_panics(
            utf8 in any::<bool>(),
            edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
            cut in any::<prop::sample::Index>(),
            truncate in any::<bool>(),
        ) {
            let builder = if utf8 { AxmlBuilder::new().utf8() } else { AxmlBuilder::new() };
            let mut bytes = document(builder);
            for (at, value) in edits {
                let at = at.index(bytes.len());
                bytes[at] = value;
            }
            if truncate {
                bytes.truncate(cut.index(bytes.len()));
            }
            let _ = parse(&bytes);
        }
    }
}
