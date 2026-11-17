//! Reading the Team ID and the entitlements out of an embedded code
//! signature.
//!
//! A signed Mach-O image carries a signature blob, named by its
//! `LC_CODE_SIGNATURE` load command. The blob is a table of contents (a
//! "super blob") followed by its parts. One part is the code directory,
//! which names the signing identity: an identifier and, for anything signed
//! with a developer certificate, the ten-character Apple Team ID (design
//! report, M5).
//!
//! Another part holds the entitlements: a property list of the
//! capabilities the signer asks the system for, such as the camera or the
//! App Sandbox. It lies after the code directory and its page hashes, which
//! can be megabytes.
//!
//! This reads that string and that list and nothing else. It does **not**
//! verify the signature: both are what the file claims, which is all a
//! scanner that executes nothing can say. A [`Reader`] takes the signature
//! as it goes by, in pieces of any size, and keeps two bounded parts of it:
//! the first [`PREFIX_BYTES`] bytes, which hold the table of contents, the
//! fixed part of the code directory and its strings, and the entitlements
//! part, of which it keeps at most [`MAX_ENTITLEMENTS_BYTES`].
//!
//! Layout, all integers big-endian (Apple's `cs_blobs.h`):
//!
//! ```text
//! super blob:     magic 0xfade0cc0, length, count, then count × (slot, offset)
//! code directory: magic 0xfade0c02, length, version, …, teamOffset at byte 48
//!                 (present from version 0x20200), then the strings
//! entitlements:   magic 0xfade7171, length, then an XML property list
//! ```

use std::collections::BTreeSet;
use std::io::Cursor;

use plist::stream::{Event, Reader as Events};

use crate::{Budget, FormatError, ReadError, info_plist};

/// How many leading bytes of a signature blob [`team_id`] needs at most.
pub const PREFIX_BYTES: usize = 64 * 1024;

/// Most parts a signature may list. Real ones have fewer than ten.
pub const MAX_PARTS: u32 = 64;

/// Longest Team ID accepted, in bytes. Apple's are ten characters.
pub const MAX_TEAM_ID_BYTES: usize = 32;

/// Largest entitlements property list the reader accepts, in bytes. Real
/// ones are a few kilobytes.
pub const MAX_ENTITLEMENTS_BYTES: usize = 256 * 1024;
/// Most entitlements one signature may grant.
pub const MAX_ENTITLEMENTS: usize = 4096;
/// Longest entitlement key kept, in bytes. A longer one is not a key anyone
/// knows, and is left out.
pub const MAX_KEY_BYTES: usize = 255;

const SUPER_BLOB: u32 = 0xfade_0cc0;
const CODE_DIRECTORY: u32 = 0xfade_0c02;
const ENTITLEMENTS: u32 = 0xfade_7171;
/// The slot of the code directory in the table of contents.
const SLOT_CODE_DIRECTORY: u32 = 0;
/// The slot of the entitlements, as a property list.
const SLOT_ENTITLEMENTS: u32 = 5;
/// The slot of the entitlements in their DER form, which this build does
/// not read. Signing tools write both forms.
const SLOT_DER_ENTITLEMENTS: u32 = 7;
/// Length of the header every part starts with: magic and length.
const PART_HEADER_BYTES: usize = 8;
/// The first version of the code directory that has a team field.
const VERSION_WITH_TEAM: u32 = 0x2_0200;
/// Where the team field is in the code directory.
const TEAM_OFFSET_AT: usize = 48;

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(*bytes.get(at..)?.first_chunk::<4>()?))
}

/// Where the part in `slot` starts, counted from the start of the signature
/// whose first bytes are `prefix`, or `None` if the table of contents lists
/// no such part. The first entry for a slot counts. `beyond` is the error
/// for an entry that `prefix` does not hold.
fn part_offset(prefix: &[u8], slot: u32, beyond: FormatError) -> Result<Option<u32>, FormatError> {
    if u32_at(prefix, 0).ok_or(FormatError::Malformed)? != SUPER_BLOB {
        return Err(FormatError::Malformed);
    }
    let count = u32_at(prefix, 8).ok_or(FormatError::Malformed)?;
    if count > MAX_PARTS {
        return Err(FormatError::OverBudget(Budget::Items));
    }
    let mut entry: usize = 12;
    for _ in 0..count {
        let listed = u32_at(prefix, entry).ok_or(beyond)?;
        let offset = u32_at(prefix, entry.saturating_add(4)).ok_or(beyond)?;
        if listed == slot {
            return Ok(Some(offset));
        }
        entry = entry.saturating_add(8);
    }
    Ok(None)
}

/// How many bytes the table of contents of the signature that starts with
/// `prefix` takes, or `None` while `prefix` is too short to say, or is no
/// signature a reader goes on with.
fn contents_len(prefix: &[u8]) -> Option<usize> {
    let count = u32_at(prefix, 8).filter(|&count| count <= MAX_PARTS)?;
    usize::try_from(count).ok()?.checked_mul(8)?.checked_add(12)
}

/// One entitlement a signature grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entitlement {
    /// The key, such as `com.apple.security.device.camera`.
    pub key: String,
    /// One for a key that is set to true or to a text that is not empty.
    /// For a key that holds a list or a dictionary, the number of its
    /// entries. The entries are not kept.
    pub count: u32,
}

/// Reads the entitlements a property list grants: the keys of its top-level
/// dictionary that are set to true, to a text that is not empty, or to a
/// list or dictionary that is not empty. A key that is set to false, or to
/// a number, grants nothing and is left out, as is a key longer than
/// [`MAX_KEY_BYTES`]. A key that appears more than once keeps its first
/// value. The result is in document order.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the input is larger than
/// [`MAX_ENTITLEMENTS_BYTES`], nests deeper than
/// [`info_plist::MAX_DEPTH`], holds more than [`info_plist::MAX_ITEMS`]
/// values or grants more than [`MAX_ENTITLEMENTS`] entitlements.
/// [`FormatError::Malformed`] if it is not a property list whose root is a
/// dictionary.
pub fn entitlements(plist: &[u8]) -> Result<Vec<Entitlement>, FormatError> {
    if plist.len() > MAX_ENTITLEMENTS_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let mut events = Events::new(Cursor::new(plist));
    match events.next() {
        Some(Ok(Event::StartDictionary(_))) => {}
        _ => return Err(FormatError::Malformed),
    }

    let mut granted: Vec<Entitlement> = Vec::new();
    // Every key whose first value has begun. Later values of it are read
    // past, whatever the first one was.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    // The key whose value comes next at depth 1, if the last event there
    // was a key.
    let mut pending: Option<String> = None;
    // The key of the collection being read at depth 2 and below, with the
    // number of values directly inside it so far, and whether it is a
    // dictionary, where two values make one entry.
    let mut collection: Option<(String, u32, bool)> = None;
    let mut depth: u32 = 1;
    let mut items: u32 = 0;
    let mut grant = |key: String, count: u32| {
        if count == 0 || key.len() > MAX_KEY_BYTES {
            return Ok(());
        }
        if granted.len() >= MAX_ENTITLEMENTS {
            return Err(FormatError::OverBudget(Budget::Items));
        }
        granted.push(Entitlement { key, count });
        Ok(())
    };

    for event in events {
        let event = event.map_err(|_| FormatError::Malformed)?;
        items = items.saturating_add(1);
        if items > info_plist::MAX_ITEMS {
            return Err(FormatError::OverBudget(Budget::Items));
        }
        if depth == 2
            && !matches!(event, Event::EndCollection)
            && let Some((_, inside, _)) = &mut collection
        {
            *inside = inside.saturating_add(1);
        }
        // A value at depth 1 consumes the pending key, whatever its type.
        // Only the first value of a key counts.
        let key = if depth == 1 { pending.take() } else { None };
        let is_key = depth == 1 && key.is_none();
        let key = key.filter(|key| seen.insert(key.clone()));
        match event {
            Event::StartArray(_) | Event::StartDictionary(_) => {
                if is_key {
                    // A collection where a key belongs is no dictionary.
                    return Err(FormatError::Malformed);
                }
                if depth == 1 {
                    let pairs = matches!(event, Event::StartDictionary(_));
                    collection = key.map(|key| (key, 0, pairs));
                }
                depth = depth.saturating_add(1);
                if depth > info_plist::MAX_DEPTH {
                    return Err(FormatError::OverBudget(Budget::Depth));
                }
            }
            Event::EndCollection => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    // End of the root dictionary. Anything after it is not ours.
                    return Ok(granted);
                }
                if depth == 1
                    && let Some((key, inside, pairs)) = collection.take()
                {
                    grant(key, if pairs { inside / 2 } else { inside })?;
                }
            }
            Event::String(text) if is_key => pending = Some(text.into_owned()),
            // A scalar that is no text where a key belongs is no dictionary.
            _ if is_key => return Err(FormatError::Malformed),
            _ if depth == 1 => {
                let on = match &event {
                    Event::Boolean(on) => *on,
                    Event::String(text) => !text.is_empty(),
                    _ => false,
                };
                if let Some(key) = key {
                    grant(key, u32::from(on))?;
                }
            }
            _ => {}
        }
    }
    // The stream ended before the root dictionary closed.
    Err(FormatError::Malformed)
}

/// Reads the entitlements from the part of a signature that holds them:
/// `part` starts at the part's header and holds as much of the part as the
/// reader kept.
fn entitlements_part(part: &[u8]) -> Result<Vec<Entitlement>, FormatError> {
    if u32_at(part, 0).ok_or(FormatError::Malformed)? != ENTITLEMENTS {
        return Err(FormatError::Malformed);
    }
    let length =
        usize::try_from(u32_at(part, 4).ok_or(FormatError::Malformed)?).unwrap_or(usize::MAX);
    let body = length.checked_sub(PART_HEADER_BYTES).ok_or(FormatError::Malformed)?;
    if body > MAX_ENTITLEMENTS_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    // A part that claims more than was there ends with the signature.
    entitlements(part.get(PART_HEADER_BYTES..length).ok_or(FormatError::Malformed)?)
}

/// What a [`Reader`] made of one signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// The Team ID, as [`team_id`] reads it.
    pub team_id: Result<Option<String>, FormatError>,
    /// The entitlements the signature grants, or `None` if it carries no
    /// entitlements part. A signature that carries them in their DER form
    /// only is a variant this build cannot read. A signature whose table of
    /// contents could not be read has `None` here: `team_id` holds the
    /// error, once.
    pub entitlements: Result<Option<Vec<Entitlement>>, ReadError>,
}

/// Reads one embedded signature as it goes by.
///
/// The signature is handed over in pieces, in order, with [`push`]; the
/// pieces may be cut anywhere. [`finish`] says what the signature holds and
/// makes the reader ready for the next one. Whatever the size of the
/// signature, the reader keeps at most [`PREFIX_BYTES`] plus
/// [`MAX_ENTITLEMENTS_BYTES`] of it.
///
/// [`push`]: Reader::push
/// [`finish`]: Reader::finish
#[derive(Debug, Default)]
pub struct Reader {
    /// The first bytes of the signature, at most [`PREFIX_BYTES`].
    head: Vec<u8>,
    /// How many bytes of the signature have gone by.
    seen: u64,
    /// Where the entitlements part starts, once the table of contents has
    /// gone by: `Some(None)` if it lists none.
    wanted: Option<Option<u64>>,
    /// The entitlements part from its start, as far as it is kept.
    part: Vec<u8>,
}

impl Reader {
    /// A reader at the start of a signature.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many bytes of the entitlements part are wanted, as far as is
    /// known: all the part claims to hold, up to the budget and its header.
    fn part_limit(&self) -> usize {
        let most = MAX_ENTITLEMENTS_BYTES.saturating_add(PART_HEADER_BYTES);
        match u32_at(&self.part, 4) {
            Some(length) => usize::try_from(length).unwrap_or(most).clamp(PART_HEADER_BYTES, most),
            None => most,
        }
    }

    /// Keeps what `bytes`, which start `start` bytes into the signature,
    /// hold of the entitlements part beyond what is kept already.
    fn keep(&mut self, bytes: &[u8], start: u64) {
        let Some(Some(part_start)) = self.wanted else { return };
        // The header first: it says how long the part is.
        for stop in [PART_HEADER_BYTES, usize::MAX] {
            let next = part_start.saturating_add(self.part.len() as u64);
            let Some(skip) = next.checked_sub(start).and_then(|skip| usize::try_from(skip).ok())
            else {
                return;
            };
            let room = self.part_limit().min(stop).saturating_sub(self.part.len());
            let fresh = bytes.get(skip..).unwrap_or_default();
            self.part.extend_from_slice(fresh.get(..room).unwrap_or(fresh));
        }
    }

    /// Takes in the next piece of the signature.
    pub fn push(&mut self, piece: &[u8]) {
        let start = self.seen;
        self.seen = self.seen.saturating_add(piece.len() as u64);
        let room = PREFIX_BYTES.saturating_sub(self.head.len());
        self.head.extend_from_slice(piece.get(..room).unwrap_or(piece));

        if self.wanted.is_none() {
            // The table of contents is a few hundred bytes at most, so it
            // has gone by long before the kept prefix is full.
            if contents_len(&self.head).is_none_or(|length| self.head.len() < length) {
                return;
            }
            let Ok(offset) = part_offset(&self.head, SLOT_ENTITLEMENTS, FormatError::Malformed)
            else {
                return;
            };
            self.wanted = Some(offset.map(u64::from));
            // What went by before this piece is all in the kept prefix.
            let earlier = usize::try_from(start).unwrap_or(usize::MAX).min(self.head.len());
            let head = std::mem::take(&mut self.head);
            self.keep(head.get(..earlier).unwrap_or_default(), 0);
            self.head = head;
        }
        self.keep(piece, start);
    }

    /// What the signature that has gone by holds. The reader is then at the
    /// start of the next signature.
    pub fn finish(&mut self) -> Signature {
        // Whole unless the signature was longer than what was kept.
        let whole = self.seen == self.head.len() as u64;
        let team_id = team_id(&self.head, whole);
        let entitlements = match self.wanted {
            Some(Some(_)) => entitlements_part(&self.part).map(Some).map_err(ReadError::Format),
            // The table of contents has gone by whole, so every entry is
            // in the kept prefix.
            Some(None) => {
                match part_offset(&self.head, SLOT_DER_ENTITLEMENTS, FormatError::Malformed) {
                    Ok(Some(_)) => Err(ReadError::Unsupported),
                    _ => Ok(None),
                }
            }
            None => Ok(None),
        };
        self.head.clear();
        self.part.clear();
        self.seen = 0;
        self.wanted = None;
        Signature { team_id, entitlements }
    }
}

/// Reads the Team ID from the first bytes of an embedded signature.
///
/// `prefix` is the start of the blob and `whole` says whether it is all of
/// it. Returns `Ok(None)` for a signature that names no team, which is what
/// an ad-hoc signature looks like.
///
/// # Errors
///
/// [`FormatError::Malformed`] if the bytes are not a signature blob, or the
/// Team ID is not a short run of ASCII letters and digits.
/// [`FormatError::OverBudget`] if the blob lists more than [`MAX_PARTS`]
/// parts, or the Team ID lies beyond a `prefix` that is not the whole blob.
pub fn team_id(prefix: &[u8], whole: bool) -> Result<Option<String>, FormatError> {
    // What the prefix does not hold is either past the budget or missing.
    let beyond =
        if whole { FormatError::Malformed } else { FormatError::OverBudget(Budget::Bytes) };

    // A signature without a code directory signs nothing.
    let start = part_offset(prefix, SLOT_CODE_DIRECTORY, beyond)?
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or(FormatError::Malformed)?;
    let directory = prefix.get(start..).ok_or(beyond)?;

    if u32_at(directory, 0).ok_or(beyond)? != CODE_DIRECTORY {
        return Err(FormatError::Malformed);
    }
    let length =
        usize::try_from(u32_at(directory, 4).ok_or(beyond)?).map_err(|_| FormatError::Malformed)?;
    if u32_at(directory, 8).ok_or(beyond)? < VERSION_WITH_TEAM {
        return Ok(None);
    }
    let offset = u32_at(directory, TEAM_OFFSET_AT).ok_or(beyond)?;
    if offset == 0 {
        return Ok(None);
    }
    let offset = usize::try_from(offset).map_err(|_| FormatError::Malformed)?;
    if offset >= length {
        return Err(FormatError::Malformed);
    }
    // The string must end inside the directory, and inside what was read.
    let declared = directory.get(offset..length.min(directory.len())).ok_or(beyond)?;
    let Some(end) = declared.iter().position(|&byte| byte == 0) else {
        return Err(if length > directory.len() { beyond } else { FormatError::Malformed });
    };
    let team = declared.get(..end).unwrap_or_default();
    if team.is_empty()
        || team.len() > MAX_TEAM_ID_BYTES
        || !team.iter().all(u8::is_ascii_alphanumeric)
    {
        return Err(FormatError::Malformed);
    }
    Ok(Some(String::from_utf8_lossy(team).into_owned()))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::macho_build::{
        SLOT_DER_ENTITLEMENTS as DER, entitlements_part as part, entitlements_plist, signature,
        signature_with,
    };

    /// Reads `blob` through a [`Reader`], `piece` bytes at a time.
    fn read(blob: &[u8], piece: usize) -> Signature {
        let mut reader = Reader::new();
        for piece in blob.chunks(piece) {
            reader.push(piece);
        }
        reader.finish()
    }

    fn granted(keys: &[(&str, u32)]) -> Result<Option<Vec<Entitlement>>, ReadError> {
        Ok(Some(keys.iter().map(|&(key, count)| Entitlement { key: key.into(), count }).collect()))
    }

    const CAMERA: &str = "com.apple.security.device.camera";
    const SANDBOX: &str = "com.apple.security.app-sandbox";

    #[test]
    fn reads_the_entitlements_a_property_list_grants() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
    <key>com.apple.security.app-sandbox</key><true/>
    <key>com.apple.security.device.camera</key><true/>
    <key>com.apple.security.device.usb</key><false/>
    <key>com.apple.application-identifier</key><string>ABCDE12345.com.example.app</string>
    <key>empty.text</key><string></string>
    <key>keychain-access-groups</key>
    <array><string>ABCDE12345.one</string><string>ABCDE12345.two</string></array>
    <key>empty.list</key><array/>
    <key>nested</key>
    <dict>
        <key>com.apple.security.device.audio-input</key><true/>
        <key>list</key><array><string>a</string><string>b</string><string>c</string></array>
    </dict>
    <key>a.number</key><integer>3</integer>
    <key>com.apple.security.device.camera</key><false/>
    <key>com.apple.security.device.usb</key><true/>
    <key>empty.list</key><array><string>later</string></array>
</dict></plist>"#;
        let found: Vec<(String, u32)> = entitlements(plist.as_bytes())
            .unwrap()
            .into_iter()
            .map(|entitlement| (entitlement.key, entitlement.count))
            .collect();
        let expected = [
            (SANDBOX, 1),
            (CAMERA, 1),
            ("com.apple.application-identifier", 1),
            ("keychain-access-groups", 2),
            ("nested", 2),
        ];
        assert_eq!(found, expected.map(|(key, count)| (key.to_string(), count)));
    }

    #[test]
    fn rejects_entitlements_that_are_no_dictionary_and_stops_at_its_budgets() {
        assert_eq!(entitlements(b""), Err(FormatError::Malformed));
        assert_eq!(entitlements(b"not a plist"), Err(FormatError::Malformed));
        let list = r#"<plist version="1.0"><array><string>x</string></array></plist>"#;
        assert_eq!(entitlements(list.as_bytes()), Err(FormatError::Malformed));
        let unclosed = r#"<plist version="1.0"><dict><key>a</key><true/>"#;
        assert_eq!(entitlements(unclosed.as_bytes()), Err(FormatError::Malformed));
        let keyless = r#"<plist version="1.0"><dict><true/></dict></plist>"#;
        assert_eq!(entitlements(keyless.as_bytes()), Err(FormatError::Malformed));

        let oversized = vec![b' '; MAX_ENTITLEMENTS_BYTES + 1];
        assert_eq!(entitlements(&oversized), Err(FormatError::OverBudget(Budget::Bytes)));
        let many = |count: usize| {
            let keys: Vec<String> = (0..count).map(|index| format!("k{index}")).collect();
            let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
            entitlements(entitlements_plist(&keys).as_bytes())
        };
        assert_eq!(many(MAX_ENTITLEMENTS).map(|found| found.len()), Ok(MAX_ENTITLEMENTS));
        assert_eq!(many(MAX_ENTITLEMENTS + 1), Err(FormatError::OverBudget(Budget::Items)));
        let deep = format!(
            r#"<plist version="1.0"><dict><key>k</key>{}{}</dict></plist>"#,
            "<array>".repeat(64),
            "</array>".repeat(64)
        );
        assert_eq!(entitlements(deep.as_bytes()), Err(FormatError::OverBudget(Budget::Depth)));
        // A key too long to be one anybody knows is left out, not refused.
        let long = "k".repeat(MAX_KEY_BYTES + 1);
        assert_eq!(
            entitlements(entitlements_plist(&[&long, "short"]).as_bytes()).unwrap().len(),
            1
        );
    }

    /// The entitlements lie after the code directory. However the signature
    /// is cut into pieces, and however far in they lie, the reader finds
    /// them, and the Team ID with them.
    #[test]
    fn a_reader_finds_the_entitlements_wherever_the_pieces_are_cut() {
        let plist = entitlements_plist(&[SANDBOX, CAMERA]);
        let expected = granted(&[(SANDBOX, 1), (CAMERA, 1)]);
        let blob = signature_with("com.example.app", Some("ABCDE12345"), &[part(&plist)]);
        for piece in [1, 2, 7, 8, 13, 27, 28, 29, 64, blob.len() - 1, blob.len(), blob.len() + 9] {
            let read = read(&blob, piece);
            assert_eq!(read.team_id, Ok(Some("ABCDE12345".into())), "piece {piece}");
            assert_eq!(read.entitlements, expected, "piece {piece}");
        }

        // Megabytes of hashes first, as in a real signature.
        let far = signature_with(
            "com.example.app",
            Some("ABCDE12345"),
            &[(0x1000, vec![0xAA; PREFIX_BYTES * 3 + 5]), part(&plist), (0x1_0000, vec![0xBB; 77])],
        );
        for piece in [4096, PREFIX_BYTES - 1, PREFIX_BYTES + 1, far.len()] {
            let read = read(&far, piece);
            assert_eq!(read.team_id, Ok(Some("ABCDE12345".into())), "piece {piece}");
            assert_eq!(read.entitlements, expected, "piece {piece}");
        }
    }

    #[test]
    fn a_reader_starts_afresh_after_each_signature() {
        let mut reader = Reader::new();
        let with = signature_with("a", Some("ABCDE12345"), &[part(&entitlements_plist(&[CAMERA]))]);
        reader.push(&with);
        assert_eq!(reader.finish().entitlements, granted(&[(CAMERA, 1)]));
        reader.push(&signature("b", None));
        assert_eq!(reader.finish(), Signature { team_id: Ok(None), entitlements: Ok(None) });
        // Nothing went by at all.
        assert_eq!(reader.finish().team_id, Err(FormatError::Malformed));
    }

    #[test]
    fn a_signature_without_readable_entitlements_says_which_way() {
        let sign = |parts: &[(u32, Vec<u8>)]| {
            read(&signature_with("com.example.app", None, parts), 16).entitlements
        };
        // None at all: an ad-hoc signature of a command-line tool.
        assert_eq!(sign(&[]), Ok(None));
        // An empty list grants nothing, which is not the same.
        assert_eq!(sign(&[part(&entitlements_plist(&[]))]), granted(&[]));
        // Only the DER form.
        assert_eq!(sign(&[(DER, vec![0x70, 0x00])]), Err(ReadError::Unsupported));
        // Both forms, as signing tools write them.
        let both = [part(&entitlements_plist(&[CAMERA])), (DER, vec![0x70, 0x00])];
        assert_eq!(sign(&both), granted(&[(CAMERA, 1)]));

        let malformed = Err(ReadError::Format(FormatError::Malformed));
        // The slot holds something else.
        assert_eq!(sign(&[(5, vec![0xfa, 0xde, 0x0c, 0x01, 0, 0, 0, 8])]), malformed);
        // The part claims to be shorter than its own header, or longer than
        // the signature.
        let (slot, mut short) = part(&entitlements_plist(&[CAMERA]));
        short[4..8].copy_from_slice(&4u32.to_be_bytes());
        assert_eq!(sign(&[(slot, short)]), malformed);
        let (slot, mut long) = part(&entitlements_plist(&[CAMERA]));
        long[4..8].copy_from_slice(&4096u32.to_be_bytes());
        assert_eq!(sign(&[(slot, long)]), malformed);
        // The property list is damaged.
        assert_eq!(sign(&[part("<plist><dict><key>")]), malformed);
        // A part over the budget is not kept, and says so.
        let (slot, mut huge) = part(&entitlements_plist(&[CAMERA]));
        huge[4..8].copy_from_slice(&((MAX_ENTITLEMENTS_BYTES + 9) as u32).to_be_bytes());
        huge.resize(MAX_ENTITLEMENTS_BYTES + 9, b' ');
        assert_eq!(
            sign(&[(slot, huge)]),
            Err(ReadError::Format(FormatError::OverBudget(Budget::Bytes)))
        );
        // The offset points back into the table of contents.
        let mut inside = signature_with("com.example.app", None, &[part(&entitlements_plist(&[]))]);
        inside[24..28].copy_from_slice(&4u32.to_be_bytes());
        assert_eq!(read(&inside, 16).entitlements, malformed);
        // What is no signature has its error once, with the Team ID.
        let garbage = read(b"not a signature blob", 16);
        assert_eq!(garbage.team_id, Err(FormatError::Malformed));
        assert_eq!(garbage.entitlements, Ok(None));
    }

    #[test]
    fn reads_the_team_a_signature_names() {
        let blob = signature("com.example.app", Some("ABCDE12345"));
        assert_eq!(team_id(&blob, true), Ok(Some("ABCDE12345".into())));
        // The strings come before the hashes, so a prefix is enough.
        let mut long = blob.clone();
        long.resize(PREFIX_BYTES * 4, 0xAA);
        assert_eq!(team_id(&long[..PREFIX_BYTES], false), Ok(Some("ABCDE12345".into())));
    }

    #[test]
    fn an_ad_hoc_signature_names_no_team() {
        assert_eq!(team_id(&signature("Example-55554944", None), true), Ok(None));
        // A code directory from before the team field existed.
        let mut old = signature("com.example.app", Some("ABCDE12345"));
        old[20 + 8..20 + 12].copy_from_slice(&0x2_0100u32.to_be_bytes());
        assert_eq!(team_id(&old, true), Ok(None));
    }

    #[test]
    fn rejects_what_is_not_a_signature() {
        let good = signature("com.example.app", Some("ABCDE12345"));
        assert_eq!(team_id(b"", true), Err(FormatError::Malformed));
        assert_eq!(team_id(b"not a signature blob", true), Err(FormatError::Malformed));

        let edit = |at: usize, value: u32| {
            let mut blob = good.clone();
            blob[at..at + 4].copy_from_slice(&value.to_be_bytes());
            team_id(&blob, true)
        };
        // No code directory among the parts.
        assert_eq!(edit(12, 5), Err(FormatError::Malformed));
        // The part in slot zero is something else.
        assert_eq!(edit(20, 0xfade_7171), Err(FormatError::Malformed));
        // The team string claims to lie outside the directory.
        assert_eq!(edit(20 + TEAM_OFFSET_AT, 1 << 20), Err(FormatError::Malformed));
        // More parts than any signature has.
        assert_eq!(edit(8, MAX_PARTS + 1), Err(FormatError::OverBudget(Budget::Items)));

        // A team that is not letters and digits is not a Team ID.
        for bad in ["TEAM ID", "<script>", "T\u{202e}EAM", &"A".repeat(MAX_TEAM_ID_BYTES + 1)] {
            let blob = signature("com.example.app", Some(bad));
            assert_eq!(team_id(&blob, true), Err(FormatError::Malformed), "{bad:?}");
        }
        // No zero byte ends the string.
        let mut unterminated = good.clone();
        unterminated.pop();
        let length = (unterminated.len() - 20) as u32;
        unterminated[24..28].copy_from_slice(&length.to_be_bytes());
        assert_eq!(team_id(&unterminated, true), Err(FormatError::Malformed));
    }

    /// A blob cut short is over budget when the cut was the reader's own,
    /// and malformed when the file itself ends there.
    #[test]
    fn a_cut_blob_is_told_apart_from_a_damaged_one() {
        let blob = signature("com.example.app", Some("ABCDE12345"));
        // Up to twelve bytes, there is no table of contents to speak of.
        for keep in 12..blob.len() {
            assert_eq!(
                team_id(&blob[..keep], false),
                Err(FormatError::OverBudget(Budget::Bytes)),
                "keep {keep}"
            );
            assert_eq!(team_id(&blob[..keep], true), Err(FormatError::Malformed), "keep {keep}");
        }
    }

    proptest! {
        #[test]
        fn never_panics_on_arbitrary_bytes(
            bytes in prop::collection::vec(any::<u8>(), 0..256),
            whole in any::<bool>(),
            piece in 1usize..64,
        ) {
            let _ = team_id(&bytes, whole);
            let _ = entitlements(&bytes);
            let _ = read(&bytes, piece);
        }

        /// How a signature is cut into pieces changes nothing, damaged or
        /// not, and the entitlements kept stay within their budgets.
        #[test]
        fn the_pieces_of_a_signature_do_not_matter(
            edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..6),
            cut in any::<prop::sample::Index>(),
            piece in 1usize..200,
        ) {
            let plist = entitlements_plist(&[SANDBOX, CAMERA]);
            let mut blob = signature_with("com.example.app", Some("ABCDE12345"), &[part(&plist)]);
            for (at, value) in edits {
                let at = at.index(blob.len());
                blob[at] = value;
            }
            let blob = &blob[..cut.index(blob.len() + 1)];
            let whole = read(blob, blob.len().max(1));
            prop_assert_eq!(&read(blob, piece), &whole);
            if let Ok(Some(found)) = whole.entitlements {
                prop_assert!(found.len() <= MAX_ENTITLEMENTS);
                prop_assert!(found.iter().all(|e| e.count > 0 && e.key.len() <= MAX_KEY_BYTES));
            }
        }

        #[test]
        fn never_panics_on_damaged_signatures(
            edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
            cut in any::<prop::sample::Index>(),
            whole in any::<bool>(),
        ) {
            let mut blob = signature("com.example.app", Some("ABCDE12345"));
            for (at, value) in edits {
                let at = at.index(blob.len());
                blob[at] = value;
            }
            let keep = cut.index(blob.len() + 1);
            if let Ok(Some(team)) = team_id(&blob[..keep], whole) {
                prop_assert!(!team.is_empty() && team.len() <= MAX_TEAM_ID_BYTES);
                prop_assert!(team.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            }
        }
    }
}
