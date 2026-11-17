//! DEX files: the classes a file defines, and its strings.
//!
//! A DEX file is the compiled code of an Android app. Two of its tables say
//! what the code is made of without anything being executed or decompiled:
//!
//! * `class_defs` lists the classes the file **defines**. A class that is
//!   only referred to (a framework class, say) has a type but no definition,
//!   so matching definitions tells "ships this code" from "calls this code".
//! * `string_ids` lists every string constant, which is where an endpoint
//!   host name survives when class names have been obfuscated away.
//!
//! Only the header and those tables are read, about a hundred lines of
//! parsing; method bodies, fields and annotations are never touched.
//!
//! The format is specified at
//! <https://source.android.com/docs/core/runtime/dex-format>. Versions 035
//! to 040 are read. Version 041, the container format that holds several
//! logical files in one, is experimental ("shouldn't be used for production
//! code") and is reported as unsupported rather than guessed at.
//!
//! **Budget.** A well-formed file stores each string once and no string
//! inside another, so the strings of a table add up to no more than the
//! file. A hostile file can point a million string ids at one long string;
//! each walk over a table therefore stops, as over budget, once it has
//! handed out more string bytes than the file holds. The work is linear in
//! the size of the file whatever the file says.

use crate::le::{u32_at, usize_at};
use crate::{Budget, FormatError, ReadError};

/// Length of the header of versions 035 to 040.
const HEADER_BYTES: usize = 0x70;
const ENDIAN_CONSTANT: u32 = 0x1234_5678;
const REVERSE_ENDIAN_CONSTANT: u32 = 0x7856_3412;
/// The versions this reader knows, as the three digits of the magic number.
const VERSIONS: std::ops::RangeInclusive<u32> = 35..=40;
const STRING_ID_BYTES: usize = 4;
const TYPE_ID_BYTES: usize = 4;
const CLASS_DEF_BYTES: usize = 32;

/// Length of the magic number: `dex\n`, three digits and a NUL.
const MAGIC_BYTES: usize = 8;

/// The version in the magic number, if `header` starts with one.
fn version(header: &[u8]) -> Option<u32> {
    let (magic, _) = header.split_first_chunk::<MAGIC_BYTES>()?;
    let [b'd', b'e', b'x', b'\n', digits @ .., 0] = magic else { return None };
    digits.iter().try_fold(0u32, |number, digit| {
        let value = u32::from(digit.checked_sub(b'0').filter(|value| *value <= 9)?);
        number.checked_mul(10)?.checked_add(value)
    })
}

/// A table of fixed-size items somewhere in the file.
#[derive(Debug, Clone, Copy)]
struct Table<'a> {
    bytes: &'a [u8],
    item_bytes: usize,
}

impl<'a> Table<'a> {
    /// The table of `count` items at `offset`, where the header gives the
    /// count at `header_at` and the offset in the four bytes after it.
    fn read(data: &'a [u8], header_at: usize, item_bytes: usize) -> Result<Self, FormatError> {
        let count = usize_at(data, header_at).ok_or(FormatError::Malformed)?;
        let offset = usize_at(data, header_at.saturating_add(4)).ok_or(FormatError::Malformed)?;
        if count == 0 {
            // An empty table may give any offset, usually zero.
            return Ok(Self { bytes: &[], item_bytes });
        }
        let bytes = count
            .checked_mul(item_bytes)
            .and_then(|length| data.get(offset..offset.checked_add(length)?))
            .ok_or(FormatError::Malformed)?;
        Ok(Self { bytes, item_bytes })
    }

    fn len(&self) -> usize {
        self.bytes.len().checked_div(self.item_bytes).unwrap_or(0)
    }

    /// The first field of item `index`: an index or an offset.
    fn first_field(&self, index: usize) -> Option<usize> {
        usize_at(self.bytes, index.checked_mul(self.item_bytes)?)
    }
}

/// The tables of a DEX file. Borrows the file's bytes; nothing is copied.
#[derive(Debug, Clone, Copy)]
pub struct Dex<'a> {
    data: &'a [u8],
    string_ids: Table<'a>,
    type_ids: Table<'a>,
    class_defs: Table<'a>,
}

impl<'a> Dex<'a> {
    /// Reads the header of a DEX file and locates its tables.
    ///
    /// # Errors
    ///
    /// [`ReadError::Unsupported`] for a version other than 035 to 040 or a
    /// byte-swapped file. [`FormatError::Malformed`] if `data` does not
    /// start with a DEX header or a table does not lie inside it.
    pub fn parse(data: &'a [u8]) -> Result<Self, ReadError> {
        let version = version(data).ok_or(FormatError::Malformed)?;
        if !VERSIONS.contains(&version) {
            return Err(ReadError::Unsupported);
        }
        if data.len() < HEADER_BYTES {
            return Err(FormatError::Malformed.into());
        }
        match u32_at(data, 0x28) {
            Some(ENDIAN_CONSTANT) => {}
            Some(REVERSE_ENDIAN_CONSTANT) => return Err(ReadError::Unsupported),
            _ => return Err(FormatError::Malformed.into()),
        }
        if usize_at(data, 0x24) != Some(HEADER_BYTES) {
            return Err(FormatError::Malformed.into());
        }
        Ok(Self {
            data,
            string_ids: Table::read(data, 0x38, STRING_ID_BYTES)?,
            type_ids: Table::read(data, 0x40, TYPE_ID_BYTES)?,
            class_defs: Table::read(data, 0x60, CLASS_DEF_BYTES)?,
        })
    }

    /// The bytes of string `index`, without the length before them or the
    /// NUL after them.
    ///
    /// The bytes are Modified UTF-8, which is plain UTF-8 for everything a
    /// rule token can hold except characters outside the Basic Multilingual
    /// Plane and U+0000.
    fn string(&self, index: usize) -> Result<&'a [u8], FormatError> {
        let item = self
            .string_ids
            .first_field(index)
            .and_then(|offset| self.data.get(offset..))
            .ok_or(FormatError::Malformed)?;
        // The length in UTF-16 code units, as ULEB128: up to five bytes, the
        // last of which has its top bit clear. It is skipped, because the
        // bytes end at the NUL whatever it says.
        let prefix = item.iter().take(5).position(|byte| byte & 0x80 == 0);
        let text = prefix
            .and_then(|last| item.get(last.checked_add(1)?..))
            .ok_or(FormatError::Malformed)?;
        let end = text.iter().position(|&byte| byte == 0).ok_or(FormatError::Malformed)?;
        text.get(..end).ok_or(FormatError::Malformed)
    }

    /// Every string of the file, in table order.
    ///
    /// The iterator ends after its first error.
    #[must_use]
    pub fn strings(&self) -> Strings<'a> {
        Strings { walk: Walk::new(*self, self.string_ids.len()) }
    }

    /// The type descriptor of every class the file defines, such as
    /// `Lcom/example/Main;`, in table order. See [`class_name`].
    ///
    /// The iterator ends after its first error.
    #[must_use]
    pub fn class_descriptors(&self) -> ClassDescriptors<'a> {
        ClassDescriptors { walk: Walk::new(*self, self.class_defs.len()) }
    }
}

/// The state both iterators share: a position in a table and what is left
/// of the byte budget.
#[derive(Debug, Clone)]
struct Walk<'a> {
    dex: Dex<'a>,
    next: usize,
    len: usize,
    /// String bytes that may still be handed out.
    budget: usize,
}

impl<'a> Walk<'a> {
    fn new(dex: Dex<'a>, len: usize) -> Self {
        Self { dex, next: 0, len, budget: dex.data.len() }
    }

    /// Advances, and resolves the item's index with `string_of`.
    fn step(
        &mut self,
        string_of: impl FnOnce(&Dex<'a>, usize) -> Result<&'a [u8], FormatError>,
    ) -> Option<Result<&'a [u8], FormatError>> {
        if self.next >= self.len {
            return None;
        }
        let index = self.next;
        self.next = self.next.saturating_add(1);
        let result = string_of(&self.dex, index).and_then(|bytes| {
            // The NUL counts, so empty strings cost something too.
            let cost = bytes.len().saturating_add(1);
            self.budget =
                self.budget.checked_sub(cost).ok_or(FormatError::OverBudget(Budget::Bytes))?;
            Ok(bytes)
        });
        if result.is_err() {
            self.next = self.len;
        }
        Some(result)
    }

    fn remaining(&self) -> usize {
        self.len.saturating_sub(self.next)
    }
}

/// Iterator over the strings of a DEX file. See [`Dex::strings`].
#[derive(Debug, Clone)]
pub struct Strings<'a> {
    walk: Walk<'a>,
}

impl<'a> Iterator for Strings<'a> {
    type Item = Result<&'a [u8], FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk.step(Dex::string)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.walk.remaining()))
    }
}

/// Iterator over the descriptors of the classes a DEX file defines. See
/// [`Dex::class_descriptors`].
#[derive(Debug, Clone)]
pub struct ClassDescriptors<'a> {
    walk: Walk<'a>,
}

impl<'a> Iterator for ClassDescriptors<'a> {
    type Item = Result<&'a [u8], FormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.walk.step(|dex, index| {
            // class_def_item.class_idx -> type_id_item.descriptor_idx -> string.
            let descriptor = dex
                .class_defs
                .first_field(index)
                .and_then(|class| dex.type_ids.first_field(class))
                .ok_or(FormatError::Malformed)
                .and_then(|string| dex.string(string))?;
            // A definition must be of a class type. An array or a primitive
            // type here is what Android's verifier rejects the file for.
            match descriptor {
                [b'L', name @ .., b';'] if !name.is_empty() => Ok(descriptor),
                _ => Err(FormatError::Malformed),
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.walk.remaining()))
    }
}

/// Writes the class name a descriptor stands for into `out`, replacing what
/// was there: `Lcom/example/Main$Inner;` becomes `com.example.Main$Inner`,
/// the form rules and reports use.
///
/// Returns `false`, leaving `out` empty, if `descriptor` is not a class
/// descriptor.
pub fn class_name(descriptor: &[u8], out: &mut Vec<u8>) -> bool {
    out.clear();
    let [b'L', name @ .., b';'] = descriptor else { return false };
    if name.is_empty() {
        return false;
    }
    out.extend(name.iter().map(|&byte| if byte == b'/' { b'.' } else { byte }));
    true
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::testkit::DexBuilder;

    const MALFORMED: ReadError = ReadError::Format(FormatError::Malformed);

    fn strings(dex: &Dex<'_>) -> Result<Vec<String>, FormatError> {
        dex.strings().map(|s| s.map(|bytes| String::from_utf8_lossy(bytes).into_owned())).collect()
    }

    fn classes(dex: &Dex<'_>) -> Result<Vec<String>, FormatError> {
        let mut name = Vec::new();
        dex.class_descriptors()
            .map(|descriptor| {
                assert!(class_name(descriptor?, &mut name));
                Ok(String::from_utf8_lossy(&name).into_owned())
            })
            .collect()
    }

    fn sample() -> Vec<u8> {
        DexBuilder::new()
            .class("com.example.Main")
            .class("com.google.firebase.crashlytics.CrashlyticsRegistrar")
            .class("a.b$c")
            .referenced_type("Landroid/app/Activity;")
            .referenced_type("[I")
            .string("https://firebase-settings.crashlytics.com/spi/v2/")
            .string("")
            .string("日本語")
            .finish()
    }

    #[test]
    fn lists_the_classes_a_file_defines_and_not_the_ones_it_refers_to() {
        let bytes = sample();
        let dex = Dex::parse(&bytes).unwrap();
        assert_eq!(
            classes(&dex).unwrap(),
            ["com.example.Main", "com.google.firebase.crashlytics.CrashlyticsRegistrar", "a.b$c"]
        );
        assert_eq!(dex.class_descriptors().size_hint(), (0, Some(3)));
    }

    #[test]
    fn lists_every_string_sorted_as_the_format_stores_them() {
        let bytes = sample();
        let dex = Dex::parse(&bytes).unwrap();
        let found = strings(&dex).unwrap();
        assert_eq!(found.len(), 8, "three strings and five descriptors, each stored once");
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(found, sorted, "the builder writes a sorted table, as the format requires");
        for expected in [
            "",
            "Landroid/app/Activity;",
            "Lcom/example/Main;",
            "[I",
            "https://firebase-settings.crashlytics.com/spi/v2/",
            "日本語",
        ] {
            assert!(found.iter().any(|string| string == expected), "{expected}");
        }
    }

    #[test]
    fn an_empty_file_has_empty_tables() {
        let bytes = DexBuilder::new().finish();
        assert_eq!(bytes.len(), HEADER_BYTES);
        let dex = Dex::parse(&bytes).unwrap();
        assert_eq!(strings(&dex), Ok(Vec::new()));
        assert_eq!(classes(&dex), Ok(Vec::new()));
    }

    #[test]
    fn what_does_not_start_with_the_magic_number_is_malformed() {
        for not in
            [&b"dex\n035"[..], b"dex\n03x\0", b"dey\n035\0", b"DEX\n035\0", b"dex\n035\n", b""]
        {
            assert_eq!(Dex::parse(not).err(), Some(MALFORMED), "{not:?}");
        }
    }

    #[test]
    fn versions_this_reader_does_not_know_are_unsupported_not_malformed() {
        for (version, expected) in [
            (*b"035", None),
            (*b"037", None),
            (*b"038", None),
            (*b"039", None),
            (*b"040", None),
            (*b"041", Some(ReadError::Unsupported)),
            (*b"034", Some(ReadError::Unsupported)),
            (*b"999", Some(ReadError::Unsupported)),
        ] {
            let mut bytes = sample();
            bytes[4..7].copy_from_slice(&version);
            assert_eq!(Dex::parse(&bytes).err(), expected, "{version:?}");
        }
        // A byte-swapped file is a real variant of the format.
        let mut swapped = sample();
        swapped[0x28..0x2c].copy_from_slice(&REVERSE_ENDIAN_CONSTANT.to_le_bytes());
        assert_eq!(Dex::parse(&swapped).err(), Some(ReadError::Unsupported));
    }

    #[test]
    fn what_is_not_a_dex_file_is_malformed() {
        let good = sample();
        assert_eq!(Dex::parse(b"").err(), Some(MALFORMED));
        assert_eq!(Dex::parse(b"PK\x03\x04 a zip file").err(), Some(MALFORMED));
        assert_eq!(Dex::parse(&good[..HEADER_BYTES - 1]).err(), Some(MALFORMED));
        let mut endian = good.clone();
        endian[0x28] = 0;
        assert_eq!(Dex::parse(&endian).err(), Some(MALFORMED));
        let mut header = good.clone();
        header[0x24] = 0x78;
        assert_eq!(Dex::parse(&header).err(), Some(MALFORMED));
        // Each table must lie inside the file.
        for count_at in [0x38, 0x40, 0x60] {
            let mut long = good.clone();
            long[count_at..count_at + 4].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
            assert_eq!(Dex::parse(&long).err(), Some(MALFORMED), "count at {count_at:#x}");
            let mut far = good.clone();
            far[count_at + 4..count_at + 8].copy_from_slice(&u32::MAX.to_le_bytes());
            assert_eq!(Dex::parse(&far).err(), Some(MALFORMED), "offset at {count_at:#x}");
        }
    }

    /// Sets the first field of item `index` of the table whose header entry
    /// is at `header_at`.
    fn patch_item(bytes: &mut [u8], header_at: usize, item_bytes: usize, index: usize, value: u32) {
        let offset = u32::from_le_bytes(bytes[header_at + 4..header_at + 8].try_into().unwrap());
        let at = offset as usize + index * item_bytes;
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn a_dangling_index_ends_the_walk_with_an_error() {
        // A class definition whose type index is past the type table.
        let mut bytes = sample();
        patch_item(&mut bytes, 0x60, CLASS_DEF_BYTES, 1, 9999);
        let dex = Dex::parse(&bytes).unwrap();
        let walked: Vec<_> = dex.class_descriptors().collect();
        assert_eq!(walked.len(), 2, "the walk stops at the first error");
        assert!(walked[0].is_ok());
        assert_eq!(walked[1], Err(FormatError::Malformed));

        // A string id that points past the end of the file.
        let mut bytes = sample();
        patch_item(&mut bytes, 0x38, STRING_ID_BYTES, 2, u32::MAX);
        let dex = Dex::parse(&bytes).unwrap();
        assert_eq!(strings(&dex), Err(FormatError::Malformed));
        assert_eq!(dex.strings().count(), 3);
    }

    #[test]
    fn a_definition_of_something_that_is_not_a_class_is_malformed() {
        for descriptor in ["[I", "I", "L;", "Lcom/example/Main", "com.example.Main", ""] {
            let bytes = DexBuilder::new().class_descriptor(descriptor).finish();
            let dex = Dex::parse(&bytes).unwrap();
            assert_eq!(classes(&dex), Err(FormatError::Malformed), "{descriptor:?}");
            let mut out = b"left over".to_vec();
            assert!(!class_name(descriptor.as_bytes(), &mut out));
            assert!(out.is_empty());
        }
    }

    #[test]
    fn a_string_without_its_terminator_is_malformed() {
        let mut bytes = DexBuilder::new().string("the last string in the file").finish();
        assert_eq!(bytes.pop(), Some(0));
        let dex = Dex::parse(&bytes).unwrap();
        assert_eq!(strings(&dex), Err(FormatError::Malformed));
    }

    #[test]
    fn a_long_length_prefix_is_skipped_and_an_endless_one_is_malformed() {
        // 300 code units need a two-byte ULEB128 length.
        let long = "x".repeat(300);
        let bytes = DexBuilder::new().string(&long).finish();
        let dex = Dex::parse(&bytes).unwrap();
        assert_eq!(strings(&dex).unwrap(), [long]);

        // Five bytes with the top bit set never end the length.
        let mut bytes = DexBuilder::new().string("abcdefgh").finish();
        let at = bytes.len() - 10;
        bytes[at..at + 5].fill(0x80);
        let dex = Dex::parse(&bytes).unwrap();
        assert_eq!(strings(&dex), Err(FormatError::Malformed));
    }

    /// The budget that keeps the work linear: every string id may point at
    /// the same long string, and the walk stops once it has handed out more
    /// bytes than the file holds.
    #[test]
    fn string_ids_that_share_one_string_run_into_the_byte_budget() {
        let long = "y".repeat(1000);
        let mut builder = DexBuilder::new().string(&long);
        for index in 0..200 {
            builder = builder.string(&format!("filler {index:03}"));
        }
        let mut bytes = builder.finish();
        let honest = Dex::parse(&bytes).unwrap().strings().count();
        assert_eq!(honest, 201);
        assert!(Dex::parse(&bytes).unwrap().strings().all(|string| string.is_ok()));

        // Point every id at the long string: 201 000 bytes out of a file of
        // about 4 000.
        let offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let last = bytes[offset + 200 * 4..offset + 201 * 4].to_vec();
        for index in 0..200 {
            bytes[offset + index * 4..offset + index * 4 + 4].copy_from_slice(&last);
        }
        let dex = Dex::parse(&bytes).unwrap();
        let walked: Vec<_> = dex.strings().collect();
        assert_eq!(walked.last(), Some(&Err(FormatError::OverBudget(Budget::Bytes))));
        let handed_out: usize = walked.iter().flatten().map(|string| string.len() + 1).sum();
        assert!(handed_out <= bytes.len(), "{handed_out} bytes from a file of {}", bytes.len());
        assert!(walked.len() < 10);
    }

    proptest! {
        #[test]
        fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
            if let Ok(dex) = Dex::parse(&bytes) {
                let _ = dex.strings().count();
                let _ = dex.class_descriptors().count();
            }
        }

        /// A valid file with a few bytes changed still reads or is refused.
        /// It never panics, and no walk hands out more than the file holds.
        #[test]
        fn a_damaged_file_never_panics(
            edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
            cut in any::<prop::sample::Index>(),
            truncate in any::<bool>(),
        ) {
            let mut bytes = sample();
            for (at, value) in edits {
                let at = at.index(bytes.len());
                bytes[at] = value;
            }
            if truncate {
                bytes.truncate(cut.index(bytes.len()));
            }
            if let Ok(dex) = Dex::parse(&bytes) {
                let strings: usize = dex.strings().flatten().map(|s| s.len() + 1).sum();
                let classes: usize = dex.class_descriptors().flatten().map(|s| s.len() + 1).sum();
                prop_assert!(strings <= bytes.len() && classes <= bytes.len());
            }
        }

        #[test]
        fn class_names_round_trip(name in "[a-z]{1,8}(\\.[a-zA-Z$]{1,8}){0,4}") {
            let descriptor = format!("L{};", name.replace('.', "/"));
            let mut out = Vec::new();
            prop_assert!(class_name(descriptor.as_bytes(), &mut out));
            prop_assert_eq!(out, name.as_bytes());
        }
    }
}
