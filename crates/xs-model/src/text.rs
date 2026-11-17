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

    #[test]
    fn cuts_on_a_character_boundary_and_marks_the_cut() {
        assert_eq!(clean("abcdefghij", 8), "abcde…");
        // Each character is three bytes; six bytes hold one of them plus the mark.
        assert_eq!(clean("日本語日本語", 6), "日…");
        assert_eq!(clean("abcdef", 6), "abcdef");
        assert_eq!(clean("abcdef", 2), "");
    }

    proptest! {
        #[test]
        fn output_is_clean_and_stable(text in any::<String>(), max in 0usize..64) {
            let once = clean(&text, max);
            prop_assert!(is_clean(&once, max));
            prop_assert_eq!(clean(&once, max), once);
        }
    }
}
