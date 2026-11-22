//! Looking up one string in the resource table of an Android package.
//!
//! An app's manifest rarely holds its name as text. `android:label` points
//! at a string resource, `@string/app_name`, and the package's compiled
//! resource table, `resources.arsc`, holds the value for each configuration
//! (language, screen size and so on) the app provides. This module answers
//! one question of that table: what is the value of the resource with this
//! id, in the default configuration? That is the name the app declares
//! before any translation, so it is the same on every device.
//!
//! The table is binary, in the chunk format of the binary XML of the
//! manifest (`ResourceTypes.h`):
//!
//! ```text
//! table ─┬─ string pool (the values of string resources)
//!        └─ package (id 0x7f for the app's own) ─┬─ type and key names
//!                                               └─ type chunks, one per
//!                                                  configuration, each a
//!                                                  table of entries
//! ```
//!
//! A resource id is `0xPPTTEEEE`: package, type and entry. The reader walks
//! the chunk headers to the package and the type chunks of the type, takes
//! the entry from the type chunk of the default configuration, and reads its
//! value. A value that is itself a reference is followed, at most
//! [`MAX_HOPS`] times. Nothing else of the table is decoded.
//!
//! Budgets: at most [`MAX_BYTES`] of input, [`MAX_HOPS`] references, and
//! [`MAX_TEXT_BYTES`] of text in the result. A chunk walk takes at least
//! eight bytes a step, so its cost is bounded by the input.

use crate::android_manifest::{Chunk, Pool, TYPE_REFERENCE, TYPE_STRING};
use crate::le::{u16_at, u32_at, usize_at};
use crate::{Budget, FormatError};

/// Largest resource table the reader accepts, in bytes. Large apps ship
/// tables of 10 to 30 MiB.
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
/// Most references followed from the id asked for to a value.
pub const MAX_HOPS: usize = 8;
/// Most text the result may take: an app's name is a few words.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

/// Chunk types (`ResourceTypes.h`).
const TABLE: u16 = 0x0002;
const STRING_POOL: u16 = 0x0001;
const PACKAGE: u16 = 0x0200;
const TYPE: u16 = 0x0201;

/// Offsets in a package chunk's header.
const PACKAGE_ID_AT: usize = 8;
/// Offsets in a type chunk's header.
const TYPE_ID_AT: usize = 8;
const TYPE_FLAGS_AT: usize = 9;
const TYPE_COUNT_AT: usize = 12;
const TYPE_ENTRIES_AT: usize = 16;
const TYPE_CONFIG_AT: usize = 20;
/// Type chunk flags: entries are listed as (index, offset) pairs, or their
/// offsets are 16 bits wide.
const FLAG_SPARSE: u8 = 0x01;
const FLAG_OFFSET16: u8 = 0x02;
/// Entry flags: the entry is a map (a style, an array), or it is the
/// eight-byte compact form that holds its value in place.
const ENTRY_COMPLEX: u16 = 0x0001;
const ENTRY_COMPACT: u16 = 0x0008;
/// The offset of an entry a configuration does not provide.
const NO_ENTRY: u32 = u32::MAX;
const NO_ENTRY16: u16 = u16::MAX;

/// The value of the resource `id` in the default configuration, as text:
/// the string it holds, or the string a chain of references from it ends
/// at. `None` when the table holds no such resource, when the default
/// configuration does not provide it, or when its value is not a string.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the table is larger than [`MAX_BYTES`],
/// a chain is longer than [`MAX_HOPS`], or the text is longer than
/// [`MAX_TEXT_BYTES`]. [`FormatError::Malformed`] if the table, or a chunk
/// on the way to the value, is not well formed.
pub fn string(table: &[u8], id: u32) -> Result<Option<String>, FormatError> {
    if table.len() > MAX_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let document = Chunk::read(table)?;
    if document.kind != TABLE {
        return Err(FormatError::Malformed);
    }
    let mut pool = None;
    let mut packages = Vec::new();
    let mut rest = document.body();
    while !rest.is_empty() {
        let chunk = Chunk::read(rest)?;
        rest = rest.get(chunk.bytes.len()..).unwrap_or_default();
        match chunk.kind {
            // One pool: values refer to strings by index.
            STRING_POOL if pool.is_none() => pool = Some(Pool::read(&chunk)?),
            STRING_POOL => return Err(FormatError::Malformed),
            PACKAGE => packages.push(chunk),
            _ => {}
        }
    }
    let pool = pool.ok_or(FormatError::Malformed)?;

    let mut wanted = id;
    for _ in 0..=MAX_HOPS {
        let Some((kind, data)) = value(&packages, wanted)? else { return Ok(None) };
        match kind {
            TYPE_STRING => {
                let mut budget = MAX_TEXT_BYTES;
                return pool.text(data, &mut budget);
            }
            TYPE_REFERENCE if data != 0 => wanted = data,
            _ => return Ok(None),
        }
    }
    Err(FormatError::OverBudget(Budget::Items))
}

/// The typed value of resource `id` in the default configuration: its kind
/// and its data.
fn value(packages: &[Chunk<'_>], id: u32) -> Result<Option<(u8, u32)>, FormatError> {
    let [package_id, type_id, entry_high, entry_low] = id.to_be_bytes();
    let entry = u16::from_be_bytes([entry_high, entry_low]);
    if type_id == 0 {
        return Ok(None);
    }
    for package in packages {
        let id = u32_at(package.bytes, PACKAGE_ID_AT).ok_or(FormatError::Malformed)?;
        if id != u32::from(package_id) {
            continue;
        }
        let mut rest = package.body();
        while !rest.is_empty() {
            let chunk = Chunk::read(rest)?;
            rest = rest.get(chunk.bytes.len()..).unwrap_or_default();
            if chunk.kind != TYPE
                || chunk.bytes.get(TYPE_ID_AT) != Some(&type_id)
                || !is_default(&chunk)?
            {
                continue;
            }
            return entry_value(&chunk, entry);
        }
        return Ok(None);
    }
    Ok(None)
}

/// Whether a type chunk is of the default configuration: every field of its
/// configuration after the size is zero.
fn is_default(chunk: &Chunk<'_>) -> Result<bool, FormatError> {
    let size = usize_at(chunk.bytes, TYPE_CONFIG_AT).ok_or(FormatError::Malformed)?;
    let end = TYPE_CONFIG_AT.checked_add(size).ok_or(FormatError::Malformed)?;
    if size < 4 || end > chunk.header_bytes {
        return Err(FormatError::Malformed);
    }
    let fields = chunk.bytes.get(TYPE_CONFIG_AT.saturating_add(4)..end);
    Ok(fields.ok_or(FormatError::Malformed)?.iter().all(|&byte| byte == 0))
}

/// The typed value of entry `entry` of a type chunk, if the chunk provides
/// it and it is a single value rather than a map.
fn entry_value(chunk: &Chunk<'_>, entry: u16) -> Result<Option<(u8, u32)>, FormatError> {
    let bytes = chunk.bytes;
    let flags = *bytes.get(TYPE_FLAGS_AT).ok_or(FormatError::Malformed)?;
    let count = usize_at(bytes, TYPE_COUNT_AT).ok_or(FormatError::Malformed)?;
    let entries_start = usize_at(bytes, TYPE_ENTRIES_AT).ok_or(FormatError::Malformed)?;
    let offsets = bytes.get(chunk.header_bytes..).ok_or(FormatError::Malformed)?;
    let index = usize::from(entry);

    let offset = if flags & FLAG_SPARSE != 0 {
        // Pairs of (entry index, offset / 4), sorted by index.
        let pairs = offsets
            .get(..count.checked_mul(4).ok_or(FormatError::Malformed)?)
            .ok_or(FormatError::Malformed)?;
        let found = pairs
            .chunks_exact(4)
            .find(|pair| u16_at(pair, 0) == Some(entry))
            .and_then(|pair| u16_at(pair, 2));
        match found {
            Some(quarter) => usize::from(quarter).checked_mul(4),
            None => return Ok(None),
        }
    } else if index >= count {
        return Ok(None);
    } else if flags & FLAG_OFFSET16 != 0 {
        match u16_at(offsets, index.saturating_mul(2)).ok_or(FormatError::Malformed)? {
            NO_ENTRY16 => return Ok(None),
            quarter => usize::from(quarter).checked_mul(4),
        }
    } else {
        match u32_at(offsets, index.saturating_mul(4)).ok_or(FormatError::Malformed)? {
            NO_ENTRY => return Ok(None),
            offset => usize::try_from(offset).ok(),
        }
    };
    let at = offset
        .and_then(|offset| entries_start.checked_add(offset))
        .ok_or(FormatError::Malformed)?;
    let record = bytes.get(at..).ok_or(FormatError::Malformed)?;
    let size = usize::from(u16_at(record, 0).ok_or(FormatError::Malformed)?);
    let entry_flags = u16_at(record, 2).ok_or(FormatError::Malformed)?;
    if entry_flags & ENTRY_COMPACT != 0 {
        // Key index, flags with the value's kind in the high byte, data.
        let [_, kind] = entry_flags.to_le_bytes();
        let data = u32_at(record, 4).ok_or(FormatError::Malformed)?;
        return Ok(Some((kind, data)));
    }
    if entry_flags & ENTRY_COMPLEX != 0 {
        return Ok(None);
    }
    // A `Res_value` follows the entry: size, a zero byte, kind, data.
    let value = record.get(size..).ok_or(FormatError::Malformed)?;
    let kind = *value.get(3).ok_or(FormatError::Malformed)?;
    let data = u32_at(value, 4).ok_or(FormatError::Malformed)?;
    Ok(Some((kind, data)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{ArscBuilder, ArscValue};

    const NAME: u32 = 0x7f0f_0001;

    fn table() -> ArscBuilder {
        ArscBuilder::new()
            .string(NAME, &[(None, "Bitwarden"), (Some(*b"de"), "Bitwarden-DE")])
            .string(0x7f0f_0000, &[(None, "Other")])
            .value(0x7f0f_0002, &[(None, ArscValue::Reference(NAME))])
            .value(0x7f0f_0003, &[(None, ArscValue::Int(7))])
            .string(0x7f0f_0004, &[(Some(*b"fr"), "Seulement en français")])
    }

    #[test]
    fn a_string_resource_is_read_in_the_default_configuration() {
        for builder in [table(), table().offset16(), table().sparse(), table().compact()] {
            let bytes = builder.finish();
            assert_eq!(string(&bytes, NAME).unwrap().as_deref(), Some("Bitwarden"));
            assert_eq!(string(&bytes, 0x7f0f_0000).unwrap().as_deref(), Some("Other"));
            // A reference is followed to the string it ends at.
            assert_eq!(string(&bytes, 0x7f0f_0002).unwrap().as_deref(), Some("Bitwarden"));
            // Not a string, not in the default configuration, not there.
            assert_eq!(string(&bytes, 0x7f0f_0003).unwrap(), None);
            assert_eq!(string(&bytes, 0x7f0f_0004).unwrap(), None);
            assert_eq!(string(&bytes, 0x7f0f_0009).unwrap(), None);
            assert_eq!(string(&bytes, 0x7f0e_0001).unwrap(), None);
            assert_eq!(string(&bytes, 0x0101_0001).unwrap(), None);
            assert_eq!(string(&bytes, 0x7f00_0001).unwrap(), None);
        }
    }

    #[test]
    fn a_chain_of_references_stops_at_its_budget() {
        let bytes = ArscBuilder::new()
            .value(0x7f0f_0000, &[(None, ArscValue::Reference(0x7f0f_0001))])
            .value(0x7f0f_0001, &[(None, ArscValue::Reference(0x7f0f_0000))])
            .finish();
        assert_eq!(string(&bytes, 0x7f0f_0000), Err(FormatError::OverBudget(Budget::Items)));
    }

    #[test]
    fn a_truncated_or_foreign_table_is_refused_and_never_panics() {
        let bytes = table().finish();
        assert_eq!(string(b"", NAME), Err(FormatError::Malformed));
        assert_eq!(string(&bytes[..4], NAME), Err(FormatError::Malformed));
        let mut foreign = bytes.clone();
        foreign[0] = 0x03;
        assert_eq!(string(&foreign, NAME), Err(FormatError::Malformed));
        for end in 0..bytes.len() {
            let _ = string(&bytes[..end], NAME);
        }
        let mut flipped = bytes;
        for at in 0..flipped.len() {
            flipped[at] ^= 0xff;
            let _ = string(&flipped, NAME);
            flipped[at] ^= 0xff;
        }
    }
}
