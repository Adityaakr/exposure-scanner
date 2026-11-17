//! Zip archives: the table of contents, and the content of single entries.
//!
//! An Android package is a zip archive. The scanner needs two things from
//! it: the names of its entries, and the bytes of a few of them (the manifest
//! and the DEX files). So this reader never walks the archive from its
//! start. It works from the end, the way Android does:
//!
//! 1. [`locate`] finds the end-of-central-directory record in the last bytes
//!    of the file and says where the central directory is.
//! 2. [`directory`] parses the central directory into [`Entry`] values.
//! 3. [`data`] finds an entry's bytes behind its local header, and
//!    [`content`] gives them back as stored or inflates them.
//!
//! The central directory is the only table of contents that counts. Local
//! headers are read for the two lengths that say where the data starts and
//! for nothing else, so an archive whose local headers tell a different
//! story than its directory cannot show the scanner one thing and Android
//! another.
//!
//! Where a rule decides whether an archive is accepted, it is the rule of
//! Android's own reader (`libziparchive`): the end record is the last one in
//! the file and its comment must reach exactly to the end, no entry may
//! start inside the directory, names hold no NUL and are not repeated, and a
//! local header must carry the name the directory gives. An archive Android
//! refuses to install is refused here too, for the same reason.
//!
//! Budgets: the directory is at most [`MAX_DIRECTORY_BYTES`] long (an
//! archive without the 64-bit extension has at most 65 534 entries), and an
//! entry inflates to at most the budget the caller passes to [`content`],
//! never to more than its directory entry declares.

use std::borrow::Cow;

use miniz_oxide::inflate::decompress_to_vec_with_limit;

use crate::le::{u16_at, u32_at};
use crate::{Budget, FormatError, ReadError};

/// Length of the end-of-central-directory record without its comment.
pub const END_RECORD_BYTES: usize = 22;
/// The longest tail of a file that can hold the end record: the record and
/// the longest comment.
pub const MAX_TAIL_BYTES: usize = END_RECORD_BYTES + 0xffff;
/// Largest central directory the reader accepts: 64 MiB, a thousand bytes
/// for each of the most entries an archive can have. Real packages need a
/// hundred bytes per entry.
pub const MAX_DIRECTORY_BYTES: usize = 64 << 20;
/// Length of the fixed part of a local file header.
pub const LOCAL_HEADER_BYTES: usize = 30;

/// Length of the fixed part of a central directory entry.
const DIRECTORY_ENTRY_BYTES: usize = 46;
const END_SIGNATURE: [u8; 4] = *b"PK\x05\x06";
const DIRECTORY_SIGNATURE: [u8; 4] = *b"PK\x01\x02";
const LOCAL_SIGNATURE: [u8; 4] = *b"PK\x03\x04";
/// General purpose bit 0: the entry is encrypted.
const FLAG_ENCRYPTED: u16 = 1;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATED: u16 = 8;

const MALFORMED: ReadError = ReadError::Format(FormatError::Malformed);

/// Where the central directory of an archive is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct End {
    /// Offset of the central directory from the start of the file.
    pub directory_offset: u64,
    /// Length of the central directory in bytes, at most
    /// [`MAX_DIRECTORY_BYTES`].
    pub directory_bytes: usize,
    /// Number of entries the directory holds.
    pub entries: u16,
}

/// Finds the end-of-central-directory record.
///
/// `tail` is the end of the file: all of it, or its last [`MAX_TAIL_BYTES`]
/// bytes if it is longer. `file_bytes` is the length of the whole file.
///
/// # Errors
///
/// [`ReadError::Unsupported`] for an archive that spans several disks or
/// uses the 64-bit extension. [`FormatError::OverBudget`] if the directory
/// is longer than [`MAX_DIRECTORY_BYTES`]. [`FormatError::Malformed`] if
/// there is no end record, if bytes follow its comment, or if the directory
/// it names does not lie before it.
pub fn locate(tail: &[u8], file_bytes: u64) -> Result<End, ReadError> {
    let tail_bytes = u64::try_from(tail.len()).map_err(|_| MALFORMED)?;
    // The caller must have read to the end of the file.
    let tail_offset = file_bytes.checked_sub(tail_bytes).ok_or(MALFORMED)?;
    if tail_offset > 0 && tail.len() < MAX_TAIL_BYTES {
        return Err(MALFORMED);
    }

    // The last signature in the file is the record, as for Android. A
    // signature inside the comment of a record further back is therefore
    // taken for the record, and refused below unless its own comment fits.
    let last_start = tail.len().checked_sub(END_RECORD_BYTES).ok_or(MALFORMED)?;
    let at = (0..=last_start)
        .rev()
        .find(|&at| tail.get(at..).is_some_and(|rest| rest.starts_with(&END_SIGNATURE)))
        .ok_or(MALFORMED)?;
    let record = tail.get(at..).ok_or(MALFORMED)?;
    let field16 = |offset| u16_at(record, offset).ok_or(MALFORMED);
    let field32 = |offset| u32_at(record, offset).ok_or(MALFORMED);

    let comment_bytes = usize::from(field16(20)?);
    if record.len().checked_sub(END_RECORD_BYTES) != Some(comment_bytes) {
        return Err(MALFORMED);
    }
    let (disk, directory_disk) = (field16(4)?, field16(6)?);
    let (entries_here, entries) = (field16(8)?, field16(10)?);
    let (directory_bytes, directory_offset) = (field32(12)?, field32(16)?);
    // The 64-bit extension marks the fields it replaces with all ones.
    if entries == u16::MAX || directory_bytes == u32::MAX || directory_offset == u32::MAX {
        return Err(ReadError::Unsupported);
    }
    if disk != 0 || directory_disk != 0 || entries_here != entries {
        return Err(ReadError::Unsupported);
    }

    let record_offset =
        tail_offset.checked_add(u64::try_from(at).map_err(|_| MALFORMED)?).ok_or(MALFORMED)?;
    let directory_offset = u64::from(directory_offset);
    let directory_end = directory_offset.checked_add(u64::from(directory_bytes));
    if directory_end.is_none_or(|end| end > record_offset) {
        return Err(MALFORMED);
    }
    let directory_bytes = usize::try_from(directory_bytes).map_err(|_| MALFORMED)?;
    if directory_bytes > MAX_DIRECTORY_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes).into());
    }
    // Every entry takes at least its fixed part.
    if usize::from(entries).saturating_mul(DIRECTORY_ENTRY_BYTES) > directory_bytes {
        return Err(MALFORMED);
    }
    Ok(End { directory_offset, directory_bytes, entries })
}

/// How the bytes of an entry are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// As they are.
    Stored,
    /// Compressed with DEFLATE.
    Deflated,
    /// Any other method, by its number. The scanner has no reader for these;
    /// Android has none either.
    Other(u16),
}

/// One entry of the central directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    /// The entry's name, as stored. A zip name is bytes; nothing says they
    /// are UTF-8, a relative path, or free of `..`.
    pub name: &'a [u8],
    /// How the entry's bytes are stored.
    pub method: Method,
    /// Whether the entry is marked as encrypted.
    pub encrypted: bool,
    /// Length of the entry's data in the archive.
    pub compressed_bytes: u32,
    /// Length of the entry's content once inflated.
    pub bytes: u32,
    /// Offset of the entry's local header from the start of the file.
    pub offset: u32,
}

impl Entry<'_> {
    /// Whether the entry stands for a directory: its name ends in a slash.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.name.ends_with(b"/")
    }
}

/// Parses the central directory.
///
/// `bytes` is the directory, [`End::directory_bytes`] long, read from
/// [`End::directory_offset`]. The entries come back in the order the
/// directory lists them.
///
/// # Errors
///
/// [`ReadError::Unsupported`] if an entry uses the 64-bit extension.
/// [`FormatError::Malformed`] if `bytes` is not the directory `end`
/// describes, if an entry starts at or after the directory, or if a name
/// holds a NUL or occurs twice.
pub fn directory<'a>(bytes: &'a [u8], end: &End) -> Result<Vec<Entry<'a>>, ReadError> {
    if bytes.len() != end.directory_bytes {
        return Err(MALFORMED);
    }
    let mut entries = Vec::with_capacity(usize::from(end.entries));
    let mut rest = bytes;
    for _ in 0..end.entries {
        let field16 = |offset| u16_at(rest, offset).ok_or(MALFORMED);
        let field32 = |offset| u32_at(rest, offset).ok_or(MALFORMED);
        if !rest.starts_with(&DIRECTORY_SIGNATURE) {
            return Err(MALFORMED);
        }
        let flags = field16(8)?;
        let method = match field16(10)? {
            METHOD_STORED => Method::Stored,
            METHOD_DEFLATED => Method::Deflated,
            other => Method::Other(other),
        };
        let (compressed_bytes, inflated_bytes, offset) = (field32(20)?, field32(24)?, field32(42)?);
        if compressed_bytes == u32::MAX || inflated_bytes == u32::MAX || offset == u32::MAX {
            return Err(ReadError::Unsupported);
        }
        if u64::from(offset) >= end.directory_offset {
            return Err(MALFORMED);
        }
        let name_bytes = usize::from(field16(28)?);
        let after_name = DIRECTORY_ENTRY_BYTES.saturating_add(name_bytes);
        let name = rest.get(DIRECTORY_ENTRY_BYTES..after_name).ok_or(MALFORMED)?;
        if name.contains(&0) {
            return Err(MALFORMED);
        }
        // The extra field and the comment are skipped unread.
        let next = after_name
            .saturating_add(usize::from(field16(30)?))
            .saturating_add(usize::from(field16(32)?));
        rest = rest.get(next..).ok_or(MALFORMED)?;
        entries.push(Entry {
            name,
            method,
            encrypted: flags & FLAG_ENCRYPTED != 0,
            compressed_bytes,
            bytes: inflated_bytes,
            offset,
        });
    }

    let mut names: Vec<&[u8]> = entries.iter().map(|entry| entry.name).collect();
    names.sort_unstable();
    if names.windows(2).any(|pair| matches!(pair, [one, other] if one == other)) {
        return Err(MALFORMED);
    }
    Ok(entries)
}

/// How many bytes lie between the start of an entry's local header and the
/// first byte of its data: the header's fixed part, its name and its extra
/// field.
///
/// `header` holds at least the [`LOCAL_HEADER_BYTES`] bytes of the fixed
/// part.
///
/// # Errors
///
/// [`FormatError::Malformed`] if `header` is shorter than that or does not
/// start a local header.
pub fn data_offset(header: &[u8]) -> Result<usize, FormatError> {
    if !header.starts_with(&LOCAL_SIGNATURE) {
        return Err(FormatError::Malformed);
    }
    let name_bytes = u16_at(header, 26).ok_or(FormatError::Malformed)?;
    let extra_bytes = u16_at(header, 28).ok_or(FormatError::Malformed)?;
    Ok(LOCAL_HEADER_BYTES
        .saturating_add(usize::from(name_bytes))
        .saturating_add(usize::from(extra_bytes)))
}

/// The data of `entry`, still as the archive stores it.
///
/// `local` is the archive from the entry's local header on. It may run on
/// past the entry's data.
///
/// # Errors
///
/// [`FormatError::Malformed`] if `local` does not start with a local header
/// that carries the entry's name, or ends before the data does.
pub fn data<'a>(entry: &Entry<'_>, local: &'a [u8]) -> Result<&'a [u8], FormatError> {
    let start = data_offset(local)?;
    let name = start
        .checked_sub(usize::from(u16_at(local, 28).ok_or(FormatError::Malformed)?))
        .and_then(|name_end| local.get(LOCAL_HEADER_BYTES..name_end));
    if name != Some(entry.name) {
        return Err(FormatError::Malformed);
    }
    let length = usize::try_from(entry.compressed_bytes).map_err(|_| FormatError::Malformed)?;
    local.get(start..start.saturating_add(length)).ok_or(FormatError::Malformed)
}

/// The content of `entry`, inflated if it is stored deflated.
///
/// `data` is what [`data`] returned for the entry. `budget` is the most
/// bytes the content may have.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the entry declares more than `budget`
/// bytes; nothing is inflated then. [`ReadError::Unsupported`] if the entry
/// is encrypted or uses a method other than stored and DEFLATE.
/// [`FormatError::Malformed`] if the data is not a DEFLATE stream or does
/// not come to exactly the length the entry declares.
pub fn content<'a>(
    entry: &Entry<'_>,
    data: &'a [u8],
    budget: usize,
) -> Result<Cow<'a, [u8]>, ReadError> {
    let declared = usize::try_from(entry.bytes).map_err(|_| MALFORMED)?;
    if declared > budget {
        return Err(FormatError::OverBudget(Budget::Bytes).into());
    }
    if entry.encrypted {
        return Err(ReadError::Unsupported);
    }
    match entry.method {
        Method::Stored if data.len() == declared => Ok(Cow::Borrowed(data)),
        Method::Stored => Err(MALFORMED),
        Method::Deflated => {
            // The limit stops a stream that inflates to more than it
            // declares, so the declared size, which is within budget, bounds
            // the memory used whatever the stream holds.
            let inflated = decompress_to_vec_with_limit(data, declared).map_err(|_| MALFORMED)?;
            if inflated.len() == declared { Ok(Cow::Owned(inflated)) } else { Err(MALFORMED) }
        }
        Method::Other(_) => Err(ReadError::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::testkit::ZipBuilder;

    const OVER_BUDGET: ReadError = ReadError::Format(FormatError::OverBudget(Budget::Bytes));

    /// Reads an archive held in memory the way a collector reads a file.
    fn read(archive: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ReadError> {
        let tail = &archive[archive.len().saturating_sub(MAX_TAIL_BYTES)..];
        let end = locate(tail, archive.len() as u64)?;
        let start = usize::try_from(end.directory_offset).unwrap();
        let entries = directory(&archive[start..start + end.directory_bytes], &end)?;
        entries
            .iter()
            .map(|entry| {
                let stored = data(entry, &archive[entry.offset as usize..])?;
                let content = content(entry, stored, 1 << 20)?;
                Ok((String::from_utf8_lossy(entry.name).into_owned(), content.into_owned()))
            })
            .collect()
    }

    fn text(len: usize) -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog. ".iter().copied().cycle().take(len).collect()
    }

    fn sample() -> Vec<u8> {
        ZipBuilder::new()
            .stored("AndroidManifest.xml", b"manifest")
            .deflated("classes.dex", &text(5000))
            .stored("lib/", b"")
            .deflated("empty.txt", b"")
            .finish()
    }

    #[test]
    fn reads_stored_and_deflated_entries_in_directory_order() {
        let entries = read(&sample()).unwrap();
        let names: Vec<&str> = entries.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["AndroidManifest.xml", "classes.dex", "lib/", "empty.txt"]);
        assert_eq!(entries[0].1, b"manifest");
        assert_eq!(entries[1].1, text(5000));
        assert!(entries[2].1.is_empty() && entries[3].1.is_empty());
    }

    #[test]
    fn the_directory_says_how_each_entry_is_stored() {
        let archive = sample();
        let end = locate(&archive, archive.len() as u64).unwrap();
        assert_eq!(end.entries, 4);
        let start = usize::try_from(end.directory_offset).unwrap();
        let entries = directory(&archive[start..start + end.directory_bytes], &end).unwrap();
        assert_eq!(entries[0].method, Method::Stored);
        assert_eq!((entries[0].bytes, entries[0].compressed_bytes, entries[0].offset), (8, 8, 0));
        assert_eq!(entries[1].method, Method::Deflated);
        assert_eq!(entries[1].bytes, 5000);
        assert!(entries[1].compressed_bytes < 200, "repetitive text compresses");
        assert!(entries[2].is_directory() && !entries[1].is_directory());
        assert!(entries.iter().all(|entry| !entry.encrypted));
    }

    #[test]
    fn an_empty_archive_has_no_entries() {
        let archive = ZipBuilder::new().finish();
        assert_eq!(archive.len(), END_RECORD_BYTES);
        assert_eq!(read(&archive), Ok(Vec::new()));
    }

    #[test]
    fn a_comment_is_allowed_and_must_reach_the_end_of_the_file() {
        let archive = ZipBuilder::new().stored("a", b"1").finish_with_comment(b"signed by nobody");
        assert_eq!(read(&archive).unwrap().len(), 1);

        // Bytes after the comment: Android refuses the file, so does this.
        let mut longer = archive.clone();
        longer.push(0);
        assert_eq!(read(&longer), Err(MALFORMED));
        // A comment cut short.
        assert_eq!(read(&archive[..archive.len() - 1]), Err(MALFORMED));
    }

    #[test]
    fn the_last_end_record_in_the_file_is_the_one_that_counts() {
        // The comment holds what looks like another end record. It is the
        // last signature in the file, and its comment length (zero) does not
        // reach the end of the file, so the archive is refused rather than
        // read through whichever record suits.
        let mut decoy = END_SIGNATURE.to_vec();
        decoy.extend_from_slice(&[0; 18]);
        decoy.extend_from_slice(b"tail");
        let archive = ZipBuilder::new().stored("a", b"1").finish_with_comment(&decoy);
        assert_eq!(read(&archive), Err(MALFORMED));

        // The same decoy with nothing after it is a well-formed record of an
        // empty archive whose directory "ends" where it says: offset zero.
        let decoy_only = &decoy[..END_RECORD_BYTES];
        let archive = ZipBuilder::new().stored("a", b"1").finish_with_comment(decoy_only);
        assert_eq!(read(&archive), Ok(Vec::new()));
    }

    #[test]
    fn a_long_file_is_read_from_its_last_bytes_only() {
        let archive = ZipBuilder::new().stored("big", &text(200_000)).deflated("b", b"x").finish();
        let tail = &archive[archive.len() - MAX_TAIL_BYTES..];
        let end = locate(tail, archive.len() as u64).unwrap();
        assert_eq!(end.entries, 2);
        assert!(end.directory_offset > 200_000);
        // A tail that is neither the whole file nor the full tail length
        // cannot be searched reliably.
        assert_eq!(locate(&tail[1..], archive.len() as u64), Err(MALFORMED));
        // A tail longer than the file is a caller's mistake, not a panic.
        assert_eq!(locate(&archive, 10), Err(MALFORMED));
    }

    #[test]
    fn what_is_not_an_archive_is_malformed() {
        for bytes in [&b""[..], b"PK", b"not a zip file at all, just some text", &[0u8; 21]] {
            assert_eq!(locate(bytes, bytes.len() as u64), Err(MALFORMED), "{bytes:?}");
        }
    }

    /// Overwrites `width` bytes at `offset` in the end record of `archive`.
    fn patch_end(archive: &mut [u8], offset: usize, value: u32, width: usize) {
        let at = archive.len() - END_RECORD_BYTES + offset;
        archive[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }

    #[test]
    fn archives_on_several_disks_or_with_the_64_bit_extension_are_unsupported() {
        for (offset, value, width) in [
            (4, 1, 2),         // this disk
            (6, 1, 2),         // disk of the directory
            (8, 0, 2),         // entries on this disk differ from the total
            (10, 0xffff, 2),   // 64-bit marker: entries
            (12, u32::MAX, 4), // 64-bit marker: directory size
            (16, u32::MAX, 4), // 64-bit marker: directory offset
        ] {
            let mut archive = sample();
            patch_end(&mut archive, offset, value, width);
            assert_eq!(read(&archive), Err(ReadError::Unsupported), "field at {offset}");
        }
    }

    #[test]
    fn a_directory_that_does_not_lie_before_the_end_record_is_malformed() {
        let archive = sample();
        let end = locate(&archive, archive.len() as u64).unwrap();
        let (offset, size) = (end.directory_offset as u32, end.directory_bytes as u32);
        for (field, value) in [(16, offset + 1), (12, size + 1), (16, u32::MAX - 1)] {
            let mut moved = archive.clone();
            patch_end(&mut moved, field, value, 4);
            assert_eq!(read(&moved), Err(MALFORMED), "field {field} = {value}");
        }
        // More entries than the directory has room for.
        let mut crowded = archive.clone();
        patch_end(&mut crowded, 8, 5000, 2);
        patch_end(&mut crowded, 10, 5000, 2);
        assert_eq!(read(&crowded), Err(MALFORMED));
        // One more entry than the directory holds.
        let mut one_more = archive;
        patch_end(&mut one_more, 8, 5, 2);
        patch_end(&mut one_more, 10, 5, 2);
        assert_eq!(read(&one_more), Err(MALFORMED));
    }

    #[test]
    fn a_directory_over_the_budget_is_not_read() {
        // Only the end record is needed to tell.
        let mut record = END_SIGNATURE.to_vec();
        record.extend_from_slice(&[0; 18]);
        let size = MAX_DIRECTORY_BYTES as u32 + 1;
        record[12..16].copy_from_slice(&size.to_le_bytes());
        let file_bytes = u64::from(size) + END_RECORD_BYTES as u64;
        assert_eq!(locate(&record, file_bytes), Err(MALFORMED), "the tail must be complete");
        let mut tail = vec![0; MAX_TAIL_BYTES - END_RECORD_BYTES];
        tail.extend_from_slice(&record);
        assert_eq!(locate(&tail, file_bytes), Err(OVER_BUDGET));
    }

    #[test]
    fn repeated_names_and_names_with_a_nul_are_malformed() {
        let twice = ZipBuilder::new().stored("classes.dex", b"1").stored("classes.dex", b"2");
        assert_eq!(read(&twice.finish()), Err(MALFORMED));
        let nul = ZipBuilder::new().stored("classes.dex\0.txt", b"1").finish();
        assert_eq!(read(&nul), Err(MALFORMED));
    }

    #[test]
    fn an_entry_that_starts_inside_the_directory_is_malformed() {
        let archive = ZipBuilder::new().stored("a", b"1").finish();
        let end = locate(&archive, archive.len() as u64).unwrap();
        let start = usize::try_from(end.directory_offset).unwrap();
        let mut moved = archive.clone();
        moved[start + 42..start + 46].copy_from_slice(&(start as u32).to_le_bytes());
        assert_eq!(read(&moved), Err(MALFORMED));
        // The 64-bit marker in an entry.
        let mut marked = archive;
        marked[start + 42..start + 46].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(read(&marked), Err(ReadError::Unsupported));
    }

    #[test]
    fn a_local_header_must_carry_the_name_the_directory_gives() {
        let archive = ZipBuilder::new().stored("classes.dex", b"dex").finish();
        // The local header's name is the first place the name occurs.
        let at = archive.windows(11).position(|window| window == b"classes.dex").unwrap();
        assert_eq!(at, LOCAL_HEADER_BYTES);
        let mut renamed = archive.clone();
        renamed[at] = b'k';
        assert_eq!(read(&renamed), Err(MALFORMED));
        let mut unsigned = archive;
        unsigned[0] = b'Q';
        assert_eq!(read(&unsigned), Err(MALFORMED));
    }

    #[test]
    fn the_extra_field_of_a_local_header_is_skipped_by_its_own_length() {
        // Packages are aligned with padding in the local extra field, which
        // the directory does not repeat.
        let archive = ZipBuilder::new().stored_padded("classes.dex", b"dex bytes", 13).finish();
        assert_eq!(data_offset(&archive), Ok(LOCAL_HEADER_BYTES + 11 + 13));
        assert_eq!(read(&archive).unwrap()[0].1, b"dex bytes");
        assert_eq!(data_offset(&archive[..LOCAL_HEADER_BYTES - 1]), Err(FormatError::Malformed));
    }

    #[test]
    fn data_that_ends_early_is_malformed() {
        let archive = ZipBuilder::new().stored("a", b"0123456789").finish();
        let end = locate(&archive, archive.len() as u64).unwrap();
        let start = usize::try_from(end.directory_offset).unwrap();
        let entries = directory(&archive[start..], &end);
        assert_eq!(entries, Err(MALFORMED), "the directory slice must be exact");
        let entries = directory(&archive[start..start + end.directory_bytes], &end).unwrap();
        assert_eq!(
            data(&entries[0], &archive[..LOCAL_HEADER_BYTES + 1 + 9]),
            Err(FormatError::Malformed)
        );
        assert_eq!(
            data(&entries[0], &archive[..LOCAL_HEADER_BYTES + 1 + 10]).unwrap(),
            b"0123456789"
        );
    }

    fn entry(method: Method, bytes: u32, compressed_bytes: u32) -> Entry<'static> {
        Entry { name: b"e", method, encrypted: false, compressed_bytes, bytes, offset: 0 }
    }

    /// The inflate budget (design report, section 4.8): an entry that
    /// declares more than the budget is refused before a byte is inflated,
    /// and one that inflates to more than it declares is cut off at what it
    /// declared.
    #[test]
    fn nothing_inflates_past_the_budget_or_past_the_declared_size() {
        let original = vec![0u8; 1 << 20];
        let deflated = miniz_oxide::deflate::compress_to_vec(&original, 6);
        assert!(deflated.len() < 2000, "a megabyte of zeros is a small bomb");
        let size = original.len() as u32;
        let honest = entry(Method::Deflated, size, deflated.len() as u32);

        assert_eq!(content(&honest, &deflated, 1 << 20).unwrap(), original);
        assert_eq!(content(&honest, &deflated, (1 << 20) - 1), Err(OVER_BUDGET));

        // The entry understates its size to get under the budget.
        let liar = entry(Method::Deflated, 1000, deflated.len() as u32);
        assert_eq!(content(&liar, &deflated, 1 << 20), Err(MALFORMED));
        // And overstates it.
        let padded = entry(Method::Deflated, size + 1, deflated.len() as u32);
        assert_eq!(content(&padded, &deflated, 1 << 21), Err(MALFORMED));
        // A stored entry is held to the budget too.
        let stored = entry(Method::Stored, 10, 10);
        assert_eq!(content(&stored, &[0; 10], 9), Err(OVER_BUDGET));
        assert_eq!(content(&stored, &[0; 10], 10).unwrap(), vec![0; 10]);
        assert_eq!(content(&stored, &[0; 9], 10), Err(MALFORMED));
    }

    #[test]
    fn damaged_streams_encrypted_entries_and_other_methods_are_told_apart() {
        let deflated = miniz_oxide::deflate::compress_to_vec(&text(4000), 6);
        let honest = entry(Method::Deflated, 4000, deflated.len() as u32);
        assert_eq!(content(&honest, &deflated, 4000).unwrap(), text(4000));
        assert_eq!(content(&honest, &deflated[..deflated.len() / 2], 4000), Err(MALFORMED));
        assert_eq!(content(&honest, b"\xff\xff\xff\xff", 4000), Err(MALFORMED));
        assert_eq!(content(&honest, b"", 4000), Err(MALFORMED));

        let encrypted = Entry { encrypted: true, ..honest };
        assert_eq!(content(&encrypted, &deflated, 4000), Err(ReadError::Unsupported));
        // Method 12 is bzip2, 93 is Zstandard.
        for method in [12, 93] {
            let other = entry(Method::Other(method), 4000, deflated.len() as u32);
            assert_eq!(content(&other, &deflated, 4000), Err(ReadError::Unsupported));
        }
    }

    #[test]
    fn the_builder_marks_what_it_is_told_to() {
        let archive = ZipBuilder::new().raw("secret", 99, 1, b"????", 4).finish();
        let end = locate(&archive, archive.len() as u64).unwrap();
        let start = usize::try_from(end.directory_offset).unwrap();
        let entries = directory(&archive[start..start + end.directory_bytes], &end).unwrap();
        assert_eq!(entries[0].method, Method::Other(99));
        assert!(entries[0].encrypted);
    }

    proptest! {
        #[test]
        fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
            let _ = read(&bytes);
            let _ = data_offset(&bytes);
            let honest = entry(Method::Deflated, 64, bytes.len() as u32);
            let _ = content(&honest, &bytes, 64);
        }

        /// A valid archive with a few bytes changed either still reads or
        /// is refused; it never panics and never yields more than the
        /// budget allows.
        #[test]
        fn a_damaged_archive_never_panics(
            edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
            cut in any::<prop::sample::Index>(),
            truncate in any::<bool>(),
        ) {
            let mut archive = sample();
            for (at, value) in edits {
                let at = at.index(archive.len());
                archive[at] = value;
            }
            if truncate {
                archive.truncate(cut.index(archive.len()));
            }
            if let Ok(entries) = read(&archive) {
                prop_assert!(entries.iter().all(|(_, content)| content.len() <= 1 << 20));
            }
        }
    }
}
