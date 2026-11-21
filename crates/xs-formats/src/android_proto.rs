//! Reading the manifest and the resource table of an Android App Bundle.
//!
//! An app bundle (`.aab`) is what a developer uploads to Google Play: a zip
//! archive with one folder per module, `base/` first, from which Play builds
//! the APKs it serves. Its manifest and its resource table are not in the
//! binary XML and `resources.arsc` of an APK but in the protocol buffer
//! form of the build tool, aapt2 (`Resources.proto`):
//!
//! | File | Message |
//! |---|---|
//! | `base/manifest/AndroidManifest.xml` | `XmlNode`: the root element, with its attributes and children |
//! | `base/resources.pb` | `ResourceTable`: packages, types, entries, a value per configuration |
//!
//! [`manifest`] reads the first into the same [`Manifest`] the binary
//! reader gives, by the same rules: an `android:` attribute is recognised by
//! its resource id, a component counts directly inside `<application>`, a
//! permission directly inside `<manifest>`, and a relative class name is
//! made absolute. [`string`] looks up one string in the second, in the
//! default configuration, as [`android_resources::string`] does for an APK.
//!
//! Only the fields named here are decoded; every other field is skipped by
//! its wire type. Budgets: at most [`MAX_BYTES`] of input, [`MAX_DEPTH`]
//! nested elements (each nested message is one level more of the
//! protocol buffer as well), and the text budgets of the binary readers.
//!
//! [`android_resources::string`]: crate::android_resources::string

use crate::android_manifest::{Component, MAX_DEPTH, Manifest, UsesPermission};
use crate::{Budget, FormatError};

/// Largest manifest or resource table the reader accepts, in bytes.
pub const MAX_BYTES: usize = crate::android_resources::MAX_BYTES;

/// Resource ids of the `android:` attributes the reader wants.
const ATTR_LABEL: u32 = 0x0101_0001;
const ATTR_NAME: u32 = 0x0101_0003;
const ATTR_VERSION_NAME: u32 = 0x0101_021c;
const ATTR_MAX_SDK_VERSION: u32 = 0x0101_0271;

/// One field of a message, with its value as the wire carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    /// A fixed-width value, which none of the fields read here is.
    Fixed,
}

/// The fields of one message, in the order they are written.
struct Fields<'a> {
    rest: &'a [u8],
}

fn fields(bytes: &[u8]) -> Fields<'_> {
    Fields { rest: bytes }
}

/// A varint at the start of `bytes`, and what follows it.
fn varint(bytes: &[u8]) -> Result<(u64, &[u8]), FormatError> {
    let mut value: u64 = 0;
    for (at, &byte) in bytes.iter().enumerate().take(10) {
        let bits = u64::from(byte & 0x7f);
        let shift = u32::try_from(at.saturating_mul(7)).map_err(|_| FormatError::Malformed)?;
        value |= bits.checked_shl(shift).ok_or(FormatError::Malformed)?;
        if byte & 0x80 == 0 {
            let rest = bytes.get(at.saturating_add(1)..).ok_or(FormatError::Malformed)?;
            return Ok((value, rest));
        }
    }
    Err(FormatError::Malformed)
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<(u64, Wire<'a>), FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let field = (|| {
            let (key, rest) = varint(self.rest)?;
            let number = key >> 3;
            if number == 0 {
                return Err(FormatError::Malformed);
            }
            let (wire, rest) = match key & 7 {
                0 => {
                    let (value, rest) = varint(rest)?;
                    (Wire::Varint(value), rest)
                }
                1 => (Wire::Fixed, rest.get(8..).ok_or(FormatError::Malformed)?),
                2 => {
                    let (length, rest) = varint(rest)?;
                    let length = usize::try_from(length).map_err(|_| FormatError::Malformed)?;
                    let bytes = rest.get(..length).ok_or(FormatError::Malformed)?;
                    (Wire::Bytes(bytes), rest.get(length..).ok_or(FormatError::Malformed)?)
                }
                5 => (Wire::Fixed, rest.get(4..).ok_or(FormatError::Malformed)?),
                // Groups are not used by these messages.
                _ => return Err(FormatError::Malformed),
            };
            self.rest = rest;
            Ok((number, wire))
        })();
        if field.is_err() {
            self.rest = &[];
        }
        Some(field)
    }
}

/// The last value of field `number` that is a length-delimited value, as
/// the protocol buffer rules have a repeated scalar field: the last one
/// wins.
fn bytes_of(message: &[u8], number: u64) -> Result<Option<&[u8]>, FormatError> {
    let mut found = None;
    for field in fields(message) {
        if let (at, Wire::Bytes(bytes)) = field?
            && at == number
        {
            found = Some(bytes);
        }
    }
    Ok(found)
}

/// The last varint of field `number`.
fn varint_of(message: &[u8], number: u64) -> Result<Option<u64>, FormatError> {
    let mut found = None;
    for field in fields(message) {
        if let (at, Wire::Varint(value)) = field?
            && at == number
        {
            found = Some(value);
        }
    }
    Ok(found)
}

/// Takes `bytes` out of the text budget.
fn charge(budget: &mut usize, bytes: usize) -> Result<(), FormatError> {
    *budget = budget.checked_sub(bytes).ok_or(FormatError::OverBudget(Budget::Bytes))?;
    Ok(())
}

/// Text from a string field, charged against `budget`. A byte that is not
/// valid UTF-8 becomes the three of U+FFFD, so that is what is charged.
fn text(bytes: &[u8], budget: &mut usize) -> Result<String, FormatError> {
    charge(budget, bytes.len().saturating_mul(3))?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// The compiled value of an attribute (`Item`), as far as it matters here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item<'a> {
    /// `str`: a string.
    Str(&'a [u8]),
    /// `ref`: a reference to a resource, by id.
    Ref(u32),
    /// `prim`: an integer, decimal or hexadecimal.
    Int(i64),
    /// Anything else.
    Other,
}

/// Reads an `Item` message.
fn item(message: &[u8]) -> Result<Item<'_>, FormatError> {
    let mut found = Item::Other;
    for field in fields(message) {
        match field? {
            (1, Wire::Bytes(reference)) => {
                let id = varint_of(reference, 2)?.unwrap_or(0);
                found = Item::Ref(u32::try_from(id).unwrap_or(0));
            }
            (2, Wire::Bytes(string)) => found = Item::Str(bytes_of(string, 1)?.unwrap_or(&[])),
            (7, Wire::Bytes(primitive)) => {
                found = Item::Other;
                for field in fields(primitive) {
                    match field? {
                        // `int_decimal_value` is an int32 and comes as the
                        // varint of its sign-extended 64 bits.
                        (6, Wire::Varint(value)) => {
                            let value = i64::from_ne_bytes(value.to_ne_bytes());
                            found = Item::Int(value);
                        }
                        (7, Wire::Varint(value)) => {
                            found = Item::Int(i64::from(u32::try_from(value).unwrap_or(0)));
                        }
                        _ => {}
                    }
                }
            }
            (3..=6, Wire::Bytes(_)) => found = Item::Other,
            _ => {}
        }
    }
    Ok(found)
}

/// One attribute of an element (`XmlAttribute`).
#[derive(Default)]
struct Attribute<'a> {
    namespace: &'a [u8],
    name: &'a [u8],
    /// The value as written.
    value: Option<&'a [u8]>,
    resource_id: u32,
    /// The value as compiled.
    item: Option<Item<'a>>,
}

impl<'a> Attribute<'a> {
    fn read(message: &'a [u8]) -> Result<Self, FormatError> {
        let mut attribute = Self::default();
        for field in fields(message) {
            match field? {
                (1, Wire::Bytes(bytes)) => attribute.namespace = bytes,
                (2, Wire::Bytes(bytes)) => attribute.name = bytes,
                (3, Wire::Bytes(bytes)) => attribute.value = Some(bytes),
                (5, Wire::Varint(id)) => attribute.resource_id = u32::try_from(id).unwrap_or(0),
                (6, Wire::Bytes(bytes)) => attribute.item = Some(item(bytes)?),
                _ => {}
            }
        }
        Ok(attribute)
    }

    /// The attribute's string: the compiled string, or the value as
    /// written when nothing was compiled.
    fn string(&self) -> Option<&'a [u8]> {
        match self.item {
            Some(Item::Str(bytes)) => Some(bytes),
            Some(_) => None,
            None => self.value,
        }
    }

    /// The attribute's integer: the compiled one, or the value as written
    /// when nothing was compiled and it is a decimal number.
    fn int(&self) -> Option<i64> {
        match self.item {
            Some(Item::Int(value)) => Some(value),
            Some(_) => None,
            None => core::str::from_utf8(self.value?).ok()?.trim().parse().ok(),
        }
    }
}

/// What an open element is, as far as the reader cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tag {
    Manifest,
    Application,
    Component,
    Other,
}

/// Makes a component's class name absolute, as the platform does.
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

/// A manifest while it is read.
struct Reader {
    manifest: Manifest,
    budget: usize,
}

impl Reader {
    /// Reads the element `message` (`XmlElement`), whose parent is
    /// `parent`, `depth` elements deep, and then its children.
    fn element(
        &mut self,
        message: &[u8],
        parent: Option<Tag>,
        depth: usize,
    ) -> Result<(), FormatError> {
        if depth >= MAX_DEPTH {
            return Err(FormatError::OverBudget(Budget::Depth));
        }
        let name = bytes_of(message, 3)?.unwrap_or(&[]);
        let is = |wanted: &[&str]| wanted.iter().any(|element| name == element.as_bytes());
        let asks =
            parent == Some(Tag::Manifest) && is(&["uses-permission", "uses-permission-sdk-23"]);

        // The attributes first, wherever they are written: a class name is
        // relative to a package that may be written after it.
        let mut android_name = None;
        let mut permission = None;
        let mut max_sdk = None;
        for field in fields(message) {
            let (4, Wire::Bytes(bytes)) = field? else { continue };
            let attribute = Attribute::read(bytes)?;
            if parent.is_none()
                && attribute.namespace.is_empty()
                && attribute.resource_id == 0
                && attribute.name == b"package"
            {
                if self.manifest.package.is_none()
                    && let Some(value) = attribute.string()
                {
                    self.manifest.package = Some(text(value, &mut self.budget)?);
                }
                continue;
            }
            match (parent, attribute.resource_id) {
                (None, ATTR_VERSION_NAME) => {
                    if let Some(value) = attribute.string() {
                        self.manifest.version_name = Some(text(value, &mut self.budget)?);
                    }
                }
                (Some(Tag::Manifest), ATTR_LABEL)
                    if is(&["application"])
                        && self.manifest.label.is_none()
                        && self.manifest.label_ref.is_none() =>
                {
                    match attribute.item {
                        Some(Item::Ref(id)) if id != 0 => self.manifest.label_ref = Some(id),
                        _ => {
                            if let Some(value) = attribute.string() {
                                self.manifest.label = Some(text(value, &mut self.budget)?);
                            }
                        }
                    }
                }
                (Some(Tag::Application | Tag::Component), ATTR_NAME) => {
                    android_name = attribute.string();
                }
                (Some(Tag::Manifest), ATTR_NAME) if asks => permission = attribute.string(),
                (Some(Tag::Manifest), ATTR_MAX_SDK_VERSION) if asks => max_sdk = attribute.int(),
                _ => {}
            }
        }

        let (tag, class) = match parent {
            None if is(&["manifest"]) => (Tag::Manifest, None),
            None => return Err(FormatError::Malformed),
            Some(Tag::Manifest) if is(&["application"]) => (Tag::Application, None),
            Some(Tag::Application)
                if is(&["activity", "activity-alias", "service", "receiver", "provider"]) =>
            {
                (Tag::Component, Some(true))
            }
            Some(Tag::Application | Tag::Component) if is(&["meta-data"]) => {
                (Tag::Other, Some(false))
            }
            Some(_) => (Tag::Other, None),
        };
        // The platform takes 0 for no limit, and grants a permission whose
        // limit is below every level on none.
        let max_sdk = match max_sdk {
            None | Some(0) => Some(None),
            Some(level) => u32::try_from(level).ok().map(Some),
        };
        if let (Some(value), Some(max_sdk)) = (permission, max_sdk) {
            let name = text(value, &mut self.budget)?;
            if !name.is_empty() {
                self.manifest.permissions.push(UsesPermission { name, max_sdk });
            }
        }
        if let (Some(class), Some(value)) = (class, android_name) {
            let name = text(value, &mut self.budget)?;
            if !name.is_empty() {
                let name = if class {
                    class_name(self.manifest.package.as_deref(), name, &mut self.budget)?
                } else {
                    name
                };
                self.manifest.components.push(Component { name });
            }
        }

        // Then the children (`XmlNode`), each an element or text.
        for field in fields(message) {
            let (5, Wire::Bytes(node)) = field? else { continue };
            if let Some(child) = bytes_of(node, 1)? {
                self.element(child, Some(tag), depth.saturating_add(1))?;
            }
        }
        Ok(())
    }
}

/// Extracts the identity, the components and the permissions from the
/// protocol buffer form of `AndroidManifest.xml`, a serialized `XmlNode`.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the input is larger than [`MAX_BYTES`],
/// nests deeper than [`MAX_DEPTH`] or takes more text than the binary
/// reader allows. [`FormatError::Malformed`] if it is not a protocol buffer
/// whose root element is `manifest`.
pub fn manifest(bytes: &[u8]) -> Result<Manifest, FormatError> {
    if bytes.len() > crate::android_manifest::MAX_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let root = bytes_of(bytes, 1)?.ok_or(FormatError::Malformed)?;
    let mut reader =
        Reader { manifest: Manifest::default(), budget: crate::android_manifest::MAX_BYTES };
    reader.element(root, None, 0)?;
    Ok(reader.manifest)
}

/// The id inside a `PackageId`, `TypeId` or `EntryId` message: absent means
/// zero, as the protocol buffer rules have it.
fn id_of(message: Option<&[u8]>) -> Result<u64, FormatError> {
    match message {
        Some(message) => Ok(varint_of(message, 1)?.unwrap_or(0)),
        None => Ok(0),
    }
}

/// Whether a `Configuration` message is the default one: every field it
/// holds is zero or empty.
fn is_default(config: &[u8]) -> Result<bool, FormatError> {
    for field in fields(config) {
        match field? {
            (_, Wire::Varint(0)) => {}
            (_, Wire::Bytes([])) => {}
            _ => return Ok(false),
        }
    }
    Ok(true)
}

/// The value (`Item`) of resource `id` in the default configuration.
fn value(table: &[u8], id: u32) -> Result<Option<Item<'_>>, FormatError> {
    let [package_id, type_id, entry_high, entry_low] = id.to_be_bytes();
    let entry_id = u16::from_be_bytes([entry_high, entry_low]);
    for package in fields(table) {
        let (2, Wire::Bytes(package)) = package? else { continue };
        if id_of(bytes_of(package, 1)?)? != u64::from(package_id) {
            continue;
        }
        for kind in fields(package) {
            let (3, Wire::Bytes(kind)) = kind? else { continue };
            if id_of(bytes_of(kind, 1)?)? != u64::from(type_id) {
                continue;
            }
            for entry in fields(kind) {
                let (3, Wire::Bytes(entry)) = entry? else { continue };
                if id_of(bytes_of(entry, 1)?)? != u64::from(entry_id) {
                    continue;
                }
                for config_value in fields(entry) {
                    let (6, Wire::Bytes(config_value)) = config_value? else { continue };
                    if !is_default(bytes_of(config_value, 1)?.unwrap_or(&[]))? {
                        continue;
                    }
                    let Some(value) = bytes_of(config_value, 2)? else { return Ok(None) };
                    return match bytes_of(value, 4)? {
                        Some(found) => Ok(Some(item(found)?)),
                        None => Ok(None),
                    };
                }
                return Ok(None);
            }
        }
    }
    Ok(None)
}

/// The value of the resource `id` in the default configuration of a
/// `ResourceTable`, as text, following references as
/// [`android_resources::string`](crate::android_resources::string) does.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the table is larger than [`MAX_BYTES`],
/// a chain is longer than
/// [`android_resources::MAX_HOPS`](crate::android_resources::MAX_HOPS) or
/// the text longer than its budget. [`FormatError::Malformed`] if a message
/// on the way to the value is not well formed.
pub fn string(table: &[u8], id: u32) -> Result<Option<String>, FormatError> {
    if table.len() > MAX_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let mut wanted = id;
    for _ in 0..=crate::android_resources::MAX_HOPS {
        match value(table, wanted)? {
            Some(Item::Str(bytes)) => {
                let mut budget = crate::android_resources::MAX_TEXT_BYTES;
                return text(bytes, &mut budget).map(Some);
            }
            Some(Item::Ref(next)) if next != 0 => wanted = next,
            _ => return Ok(None),
        }
    }
    Err(FormatError::OverBudget(Budget::Items))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android_manifest;
    use crate::testkit::{Attr, AxmlBuilder, ProtoResources, ProtoXml};

    /// The same document, built as binary XML and as a protocol buffer.
    fn both(build: impl Fn(Builder) -> Builder) -> (Manifest, Manifest) {
        let binary = build(Builder::Binary(AxmlBuilder::new()));
        let proto = build(Builder::Proto(ProtoXml::new()));
        let (Builder::Binary(binary), Builder::Proto(proto)) = (binary, proto) else {
            unreachable!()
        };
        (android_manifest::parse(&binary.finish()).unwrap(), manifest(&proto.finish()).unwrap())
    }

    enum Builder {
        Binary(AxmlBuilder),
        Proto(ProtoXml),
    }

    impl Builder {
        fn start(self, name: &str, attributes: &[Attr]) -> Self {
            match self {
                Self::Binary(builder) => Self::Binary(builder.start(name, attributes)),
                Self::Proto(builder) => Self::Proto(builder.start(name, attributes)),
            }
        }

        fn end(self) -> Self {
            match self {
                Self::Binary(builder) => Self::Binary(builder.end()),
                Self::Proto(builder) => Self::Proto(builder.end()),
            }
        }
    }

    #[test]
    fn a_bundle_manifest_reads_as_its_binary_twin_does() {
        let (binary, proto) = both(|builder| {
            builder
                .start(
                    "manifest",
                    &[
                        Attr::android(ATTR_VERSION_NAME, "versionName", "2026.9.1"),
                        Attr::plain("package", "com.example.app"),
                    ],
                )
                .start(
                    "uses-permission",
                    &[Attr::android(ATTR_NAME, "name", "android.permission.CAMERA")],
                )
                .end()
                .start(
                    "uses-permission",
                    &[
                        Attr::android(
                            ATTR_NAME,
                            "name",
                            "android.permission.READ_EXTERNAL_STORAGE",
                        ),
                        Attr::int(ATTR_MAX_SDK_VERSION, "maxSdkVersion", 32),
                    ],
                )
                .end()
                .start(
                    "application",
                    &[
                        Attr::reference(ATTR_LABEL, "label", 0x7f0f_0001),
                        Attr::android(ATTR_NAME, "name", ".App"),
                    ],
                )
                .start("activity", &[Attr::android(ATTR_NAME, "name", ".MainActivity")])
                .start("meta-data", &[Attr::android(ATTR_NAME, "name", "android.app.shortcuts")])
                .end()
                .end()
                .start("service", &[Attr::android(ATTR_NAME, "name", "Uploader")])
                .end()
                .start(
                    "provider",
                    &[Attr::android(
                        ATTR_NAME,
                        "name",
                        "io.sentry.android.core.SentryInitProvider",
                    )],
                )
                .end()
                .start(
                    "meta-data",
                    &[Attr::android(
                        ATTR_NAME,
                        "name",
                        "com.google.android.play.billingclient.version",
                    )],
                )
                .end()
                // Not a component where it is: deeper than the application.
                .start("activity", &[Attr::android(ATTR_NAME, "name", ".Outer")])
                .start("service", &[Attr::android(ATTR_NAME, "name", ".Nested")])
                .end()
                .end()
                .end()
                .end()
        });
        assert_eq!(proto, binary);
        assert_eq!(proto.package.as_deref(), Some("com.example.app"));
        assert_eq!(proto.label_ref, Some(0x7f0f_0001));
        assert_eq!(proto.permissions.len(), 2);
        assert_eq!(proto.permissions[1].max_sdk, Some(32));
        assert!(proto.components.iter().any(|c| c.name == "com.example.app.Uploader"));

        let (binary, proto) = both(|builder| {
            builder
                .start("manifest", &[Attr::plain("package", "com.example.app")])
                .start("application", &[Attr::android(ATTR_LABEL, "label", "Example")])
                .end()
                .end()
        });
        assert_eq!(proto, binary);
        assert_eq!(proto.label.as_deref(), Some("Example"));
    }

    #[test]
    fn what_is_not_a_bundle_manifest_is_refused_and_never_panics() {
        assert_eq!(manifest(b""), Err(FormatError::Malformed));
        let other = ProtoXml::new().start("application", &[]).end().finish();
        assert_eq!(manifest(&other), Err(FormatError::Malformed));
        let mut deep = ProtoXml::new().start("manifest", &[]);
        for _ in 0..MAX_DEPTH {
            deep = deep.start("x", &[]);
        }
        assert_eq!(manifest(&deep.finish()), Err(FormatError::OverBudget(Budget::Depth)));

        let bytes = ProtoXml::new()
            .start("manifest", &[Attr::plain("package", "com.example.app")])
            .start("application", &[Attr::android(ATTR_NAME, "name", ".App")])
            .end()
            .end()
            .finish();
        for end in 0..bytes.len() {
            let _ = manifest(&bytes[..end]);
        }
        let mut flipped = bytes;
        for at in 0..flipped.len() {
            flipped[at] ^= 0xff;
            let _ = manifest(&flipped);
            flipped[at] ^= 0xff;
        }
    }

    #[test]
    fn a_string_resource_of_a_bundle_is_read_in_the_default_configuration() {
        const NAME: u32 = 0x7f0f_0001;
        let table = ProtoResources::new()
            .string(NAME, &[(Some("de"), "Beispiel"), (None, "Example")])
            .reference(0x7f0f_0002, NAME)
            .reference(0x7f0f_0003, 0x7f0f_0003)
            .string(0x7f0f_0004, &[(Some("fr"), "Exemple")])
            .string(0x7f0e_0000, &[(None, "Other type")])
            .finish();
        assert_eq!(string(&table, NAME).unwrap().as_deref(), Some("Example"));
        assert_eq!(string(&table, 0x7f0f_0002).unwrap().as_deref(), Some("Example"));
        assert_eq!(string(&table, 0x7f0e_0000).unwrap().as_deref(), Some("Other type"));
        assert_eq!(string(&table, 0x7f0f_0004).unwrap(), None);
        assert_eq!(string(&table, 0x7f0f_0009).unwrap(), None);
        assert_eq!(string(&table, 0x0101_0001).unwrap(), None);
        assert_eq!(string(&table, 0x7f0f_0003), Err(FormatError::OverBudget(Budget::Items)));
        for end in 0..table.len() {
            let _ = string(&table[..end], NAME);
        }
        assert!(string(&[0x0f], NAME).is_err());
    }

    #[test]
    fn varints_are_read_to_ten_bytes_and_no_further() {
        assert_eq!(varint(&[0x96, 0x01, 0xff]), Ok((150, &[0xff][..])));
        assert_eq!(
            varint(&[0xff; 9].iter().copied().chain([0x01]).collect::<Vec<_>>()).map(|v| v.0),
            Ok(u64::MAX)
        );
        assert_eq!(varint(&[0xff; 10]), Err(FormatError::Malformed));
        assert_eq!(varint(&[0x80]), Err(FormatError::Malformed));
        assert_eq!(varint(&[]), Err(FormatError::Malformed));
    }
}
