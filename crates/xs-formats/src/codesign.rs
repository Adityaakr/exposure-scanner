//! Reading the Team ID out of an embedded code signature.
//!
//! A signed Mach-O image carries a signature blob, named by its
//! `LC_CODE_SIGNATURE` load command. The blob is a table of contents (a
//! "super blob") followed by its parts. One part is the code directory,
//! which names the signing identity: an identifier and, for anything signed
//! with a developer certificate, the ten-character Apple Team ID (design
//! report, M5).
//!
//! This reads that one string and nothing else. It does **not** verify the
//! signature: the Team ID is what the file claims, which is all a scanner
//! that executes nothing can say. A blob can be megabytes of page hashes;
//! the table of contents, the fixed part of the code directory and its
//! strings come first, so the caller hands over only the first
//! [`PREFIX_BYTES`] bytes.
//!
//! Layout, all integers big-endian (Apple's `cs_blobs.h`):
//!
//! ```text
//! super blob:     magic 0xfade0cc0, length, count, then count × (slot, offset)
//! code directory: magic 0xfade0c02, length, version, …, teamOffset at byte 48
//!                 (present from version 0x20200), then the strings
//! ```

use crate::{Budget, FormatError};

/// How many leading bytes of a signature blob [`team_id`] needs at most.
pub const PREFIX_BYTES: usize = 64 * 1024;

/// Most parts a signature may list. Real ones have fewer than ten.
pub const MAX_PARTS: u32 = 64;

/// Longest Team ID accepted, in bytes. Apple's are ten characters.
pub const MAX_TEAM_ID_BYTES: usize = 32;

const SUPER_BLOB: u32 = 0xfade_0cc0;
const CODE_DIRECTORY: u32 = 0xfade_0c02;
/// The slot of the code directory in the table of contents.
const SLOT_CODE_DIRECTORY: u32 = 0;
/// The first version of the code directory that has a team field.
const VERSION_WITH_TEAM: u32 = 0x2_0200;
/// Where the team field is in the code directory.
const TEAM_OFFSET_AT: usize = 48;

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(*bytes.get(at..)?.first_chunk::<4>()?))
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

    if u32_at(prefix, 0).ok_or(FormatError::Malformed)? != SUPER_BLOB {
        return Err(FormatError::Malformed);
    }
    let count = u32_at(prefix, 8).ok_or(FormatError::Malformed)?;
    if count > MAX_PARTS {
        return Err(FormatError::OverBudget(Budget::Items));
    }
    let mut directory = None;
    let mut entry: usize = 12;
    for _ in 0..count {
        let slot = u32_at(prefix, entry).ok_or(beyond)?;
        let offset = u32_at(prefix, entry.saturating_add(4)).ok_or(beyond)?;
        if slot == SLOT_CODE_DIRECTORY {
            directory = Some(offset);
            break;
        }
        entry = entry.saturating_add(8);
    }
    // A signature without a code directory signs nothing.
    let start =
        directory.and_then(|offset| usize::try_from(offset).ok()).ok_or(FormatError::Malformed)?;
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
    use crate::macho_build::signature;

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
        ) {
            let _ = team_id(&bytes, whole);
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
