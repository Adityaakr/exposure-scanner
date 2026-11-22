//! Hygiene for text that comes out of hostile files.
//!
//! App names, versions and class names are chosen by whoever built the
//! artifact. Before such text enters a record it is cut to a fixed budget and
//! stripped of characters that could disturb a terminal or reorder what a
//! reader sees. Escaping for a particular output format is the renderer's
//! job; this module only makes the stored value safe to carry.

use alloc::string::String;

/// Longest app or SDK identifier a record carries, in bytes.
pub const MAX_ID_BYTES: usize = 255;
/// Longest version string a record carries, in bytes.
pub const MAX_VERSION_BYTES: usize = 64;
/// Longest display name a record carries, in bytes.
pub const MAX_NAME_BYTES: usize = 255;
/// Longest rule token a record carries, in bytes.
pub const MAX_TOKEN_BYTES: usize = 255;
/// Longest proof example a record carries, in bytes (design report, 4.3).
pub const MAX_EXAMPLE_BYTES: usize = 160;

/// Longest host name a record carries, in bytes: the limit of the DNS.
pub const MAX_HOST_BYTES: usize = 253;
/// Longest Apple Team ID a record carries, in bytes.
pub const MAX_TEAM_ID_BYTES: usize = 32;

/// What an unprintable character is replaced with.
const REPLACEMENT: char = '\u{fffd}';
/// Appended when text was cut, so a reader can tell.
const ELLIPSIS: char = '…';

/// Whether a character may appear in stored text.
///
/// Control characters are out, and so are the Unicode bidirectional controls,
/// which can make text render in a different order than it is stored.
#[must_use]
pub fn is_storable(character: char) -> bool {
    !(character.is_control()
        || matches!(
            character,
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        ))
}

/// Whether `text` could have come out of [`clean`] with the same budget.
#[must_use]
pub fn is_clean(text: &str, max_bytes: usize) -> bool {
    text.len() <= max_bytes && text.chars().all(is_storable)
}

/// Whether `text` is a host name in the one form a record stores: lowercase
/// ASCII labels of letters, digits, hyphens and underscores, joined by single
/// dots, at most [`MAX_HOST_BYTES`] long. No scheme, port, path or trailing
/// dot, so two records that name one host always agree byte for byte.
///
/// An IPv4 address has this shape and is accepted. A bracketed IPv6 address
/// and a name that is not ASCII are not.
#[must_use]
pub fn is_host(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_HOST_BYTES
        && text.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
        })
}

/// Makes hostile text safe to store: unprintable characters become U+FFFD and
/// the result is at most `max_bytes` long, ending in `…` if it was cut.
///
/// The function is idempotent, and its output always satisfies [`is_clean`]
/// for the same budget. A budget smaller than the ellipsis (three bytes)
/// yields an empty string for over-long input.
#[must_use]
pub fn clean(text: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(text.len().min(max_bytes));
    for character in text.chars() {
        let character = if is_storable(character) { character } else { REPLACEMENT };
        if out.len() + character.len_utf8() > max_bytes {
            // Over budget: back off until the ellipsis fits, then mark the cut.
            while out.len() + ELLIPSIS.len_utf8() > max_bytes {
                if out.pop().is_none() {
                    return out;
                }
            }
            out.push(ELLIPSIS);
            return out;
        }
        out.push(character);
    }
    out
}

/// Whether `character` is an implicit directional mark: U+200E LEFT-TO-RIGHT
/// MARK, U+200F RIGHT-TO-LEFT MARK or U+061C ARABIC LETTER MARK. A mark is an
/// invisible letter of one direction. Unlike the embeddings, overrides and
/// isolates it opens no run, so taking it out of a name leaves nothing to
/// reorder.
const fn is_implicit_mark(character: char) -> bool {
    matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}')
}

/// [`clean`] for a display name, such as an app's or an extension's.
///
/// Publishers put directional marks in names to keep them in order next to
/// text of the other direction: WhatsApp's `CFBundleDisplayName` starts with
/// U+200E. A mark cannot reorder what a reader sees, so it is dropped rather
/// than shown as U+FFFD, and the name reads as the publisher wrote it. The
/// controls that can reorder text (U+202A to U+202E, U+2066 to U+2069) are
/// still replaced, as is every control character. Identifiers are never
/// cleaned this way: two ids that differ by a mark stay two ids.
#[must_use]
pub fn clean_name(text: &str, max_bytes: usize) -> String {
    if !text.chars().any(is_implicit_mark) {
        return clean(text, max_bytes);
    }
    let kept: String = text.chars().filter(|&character| !is_implicit_mark(character)).collect();
    clean(&kept, max_bytes)
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn leaves_ordinary_text_alone() {
        assert_eq!(clean("Bitwarden 2026.9.1 – “日本語”", 255), "Bitwarden 2026.9.1 – “日本語”");
    }

    #[test]
    fn replaces_control_and_bidi_characters() {
        assert_eq!(clean("a\u{0}b\nc\u{1b}[31m", 255), "a\u{fffd}b\u{fffd}c\u{fffd}[31m");
        assert_eq!(clean("evil\u{202e}txt.exe", 255), "evil\u{fffd}txt.exe");
        // Every code point with the Unicode Bidi_Control property
        // (PropList.txt): U+061C, U+200E..200F, U+202A..202E, U+2066..2069.
        let bidi_controls = ('\u{061c}'..='\u{061c}')
            .chain('\u{200e}'..='\u{200f}')
            .chain('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}');
        for control in bidi_controls {
            assert!(!is_storable(control), "U+{:04X}", control as u32);
            assert_eq!(clean(&alloc::format!("Safe{control}1.0"), 255), "Safe\u{fffd}1.0");
        }
    }

    /// Security review S1: WhatsApp's name starts with a left-to-right mark.
    #[test]
    fn a_name_loses_its_directional_marks_and_keeps_its_overrides_replaced() {
        assert_eq!(clean_name("\u{200e}WhatsApp", 255), "WhatsApp");
        assert_eq!(clean_name("Notes\u{200f}\u{061c}", 255), "Notes");
        assert_eq!(clean_name("evil\u{202e}txt.exe", 255), "evil\u{fffd}txt.exe");
        assert_eq!(clean_name("a\u{2066}b\u{2069}\u{1b}[2J", 255), "a\u{fffd}b\u{fffd}\u{fffd}[2J");
        assert_eq!(clean_name("\u{200e}", 255), "");
        // The budget is counted after the marks are gone.
        assert_eq!(clean_name("\u{200e}abcdef", 6), "abcdef");
        // An identifier keeps the mark visible.
        assert_eq!(clean("\u{200e}WhatsApp", 255), "\u{fffd}WhatsApp");
    }

    #[test]
    fn cuts_on_a_character_boundary_and_marks_the_cut() {
        assert_eq!(clean("abcdefghij", 8), "abcde…");
        // Each character is three bytes; six bytes hold one of them plus the mark.
        assert_eq!(clean("日本語日本語", 6), "日…");
        assert_eq!(clean("abcdef", 6), "abcdef");
        assert_eq!(clean("abcdef", 2), "");
    }

    #[test]
    fn a_host_is_lowercase_labels_and_nothing_else() {
        for host in
            ["ranchero.com", "raw.githubusercontent.com", "a", "x_y.z-1.example", "10.0.0.1"]
        {
            assert!(is_host(host), "{host}");
        }
        let long_label = alloc::format!("{}.example", "a".repeat(64));
        let long_name = alloc::vec!["abcdefgh"; 29].join(".");
        assert_eq!(long_name.len(), 260);
        for not in [
            "",
            "Ranchero.com",
            "ranchero.com.",
            ".ranchero.com",
            "ranchero..com",
            "ranchero.com:443",
            "ranchero.com/feed.xml",
            "https://ranchero.com",
            "user@ranchero.com",
            "[::1]",
            "b\u{fc}cher.example",
            long_label.as_str(),
            long_name.as_str(),
        ] {
            assert!(!is_host(not), "{not}");
        }
    }

    proptest! {
        #[test]
        fn output_is_clean_and_stable(text in any::<String>(), max in 0usize..64) {
            let once = clean(&text, max);
            prop_assert!(is_clean(&once, max));
            prop_assert_eq!(clean(&once, max), once);
        }

        #[test]
        fn a_cleaned_name_is_clean_and_stable(text in any::<String>(), max in 0usize..64) {
            let once = clean_name(&text, max);
            prop_assert!(is_clean(&once, max));
            prop_assert_eq!(clean_name(&once, max), once.clone());
            prop_assert_eq!(clean(&once, max), once);
        }
    }
}
