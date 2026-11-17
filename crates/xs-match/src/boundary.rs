//! Boundary rules: how a literal must sit in its surroundings to count.
//!
//! A rule token is a literal plus one [`Boundary`]. This module is the whole
//! meaning of the five boundaries (design report, section 5.2 control 2). On
//! 16 real app bundles, naive substring matching of 1,181 literals gave 3,439
//! hits; anchoring them on boundaries left 665.
//!
//! The rules look at bytes, not characters, and only ASCII bytes count as
//! word or hostname bytes. That keeps a rule re-checkable with `grep -F` and
//! a hex dump, and it makes the answer independent of any text encoding.
//!
//! A rule may look at one byte before the literal and two bytes after it.
//! The edges of the haystack count as boundaries: nothing comes before the
//! first byte or after the last.

use xs_model::matcher::Boundary;

/// How many bytes before a literal a boundary rule may look at.
pub(crate) const LOOKBEHIND: usize = 1;
/// How many bytes after a literal a boundary rule may look at. The `host`
/// rule needs two: a dot continues a hostname only if a label follows it.
pub(crate) const LOOKAHEAD: usize = 2;

/// Whether `byte` can be part of an identifier: an ASCII letter, a digit or
/// an underscore.
const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Whether `byte` can be part of one label of a hostname: an ASCII letter, a
/// digit or a hyphen. The underscore is included as well. It is not valid in
/// a hostname, but it is in a DNS name (`_dmarc.example.com`), and a literal
/// glued to one is part of a different name.
const fn is_label_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Whether the literal found at `start..end` of `haystack` sits on
/// `boundary`.
///
/// `haystack` must be the complete value, or a window of a stream that holds
/// [`LOOKBEHIND`] bytes before `start` and [`LOOKAHEAD`] bytes after `end`
/// wherever the stream has them.
pub(crate) fn holds(boundary: Boundary, haystack: &[u8], start: usize, end: usize) -> bool {
    let before = start.checked_sub(1).and_then(|index| haystack.get(index)).copied();
    let after = haystack.get(end).copied();
    match boundary {
        Boundary::None => true,
        Boundary::Prefix => start == 0,
        Boundary::Exact => start == 0 && end == haystack.len(),
        // Not inside a longer identifier, on either side.
        Boundary::Word => !before.is_some_and(is_word_byte) && !after.is_some_and(is_word_byte),
        Boundary::Host => {
            // `us.i.posthog.com` holds `i.posthog.com` as a parent domain,
            // which is a hit. `xi.posthog.com` is a different name.
            let starts_a_label = before.is_none_or(|byte| byte == b'.' || !is_label_byte(byte));
            // `i.posthog.com.evil.example` is a different name. A dot that no
            // label follows ends a sentence or marks a fully qualified name.
            let name_ends = match after {
                None => true,
                Some(b'.') => !end
                    .checked_add(1)
                    .and_then(|index| haystack.get(index))
                    .copied()
                    .is_some_and(is_label_byte),
                Some(byte) => !is_label_byte(byte),
            };
            starts_a_label && name_ends
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Finds `literal` once in `haystack` and applies the rule there.
    fn check(boundary: Boundary, haystack: &str, literal: &str) -> bool {
        let start = haystack.find(literal).expect("the literal occurs in the haystack");
        assert_eq!(haystack.matches(literal).count(), 1, "{haystack}");
        holds(boundary, haystack.as_bytes(), start, start + literal.len())
    }

    #[test]
    fn word_rejects_a_literal_inside_a_longer_identifier() {
        let literal = "sentry.javascript.";
        for hit in [
            "sentry.javascript.",
            "\"sentry.javascript.\"",
            "name:`sentry.javascript.${e}`",
            " sentry.javascript. ",
            "(sentry.javascript.)",
            "\u{e9}sentry.javascript.\u{e9}",
            "-sentry.javascript.-",
        ] {
            assert!(check(Boundary::Word, hit, literal), "{hit}");
        }
        for miss in [
            "sentry.javascript.browser",
            "xsentry.javascript.",
            "_sentry.javascript.",
            "sentry.javascript._",
            "9sentry.javascript.",
            "sentry.javascript.9",
        ] {
            assert!(!check(Boundary::Word, miss, literal), "{miss}");
        }
    }

    #[test]
    fn host_accepts_the_name_and_its_subdomains_only() {
        let literal = "i.posthog.com";
        for hit in [
            "i.posthog.com",
            "us.i.posthog.com",
            "https://i.posthog.com/capture",
            "\"i.posthog.com\"",
            "host=i.posthog.com:443",
            "see i.posthog.com.",
            "i.posthog.com. ",
            "i.posthog.com..",
            "i.posthog.com./",
            "@i.posthog.com",
            "..i.posthog.com",
        ] {
            assert!(check(Boundary::Host, hit, literal), "{hit}");
        }
        for miss in [
            "xi.posthog.com",
            "api-i.posthog.com",
            "_i.posthog.com",
            "9i.posthog.com",
            "i.posthog.community",
            "i.posthog.com-x",
            "i.posthog.com_x",
            "i.posthog.com.evil.example",
            "i.posthog.com.9",
            "i.posthog.com.-",
        ] {
            assert!(!check(Boundary::Host, miss, literal), "{miss}");
        }
    }

    #[test]
    fn prefix_and_exact_are_about_the_whole_value() {
        let value = "com.google.firebase.crashlytics.CrashlyticsRegistrar";
        assert!(check(Boundary::Prefix, value, "com.google.firebase.crashlytics."));
        assert!(!check(Boundary::Prefix, value, "google.firebase.crashlytics."));
        assert!(check(Boundary::Exact, value, value));
        assert!(!check(Boundary::Exact, value, "com.google.firebase.crashlytics."));
        assert!(!check(Boundary::Exact, value, "CrashlyticsRegistrar"));
    }

    #[test]
    fn none_holds_anywhere() {
        assert!(check(Boundary::None, "xxsentryxx", "sentry"));
    }

    #[test]
    fn only_ascii_bytes_are_word_or_label_bytes() {
        for byte in 0..=u8::MAX {
            let word = byte.is_ascii_alphanumeric() || byte == b'_';
            assert_eq!(is_word_byte(byte), word, "{byte}");
            assert_eq!(is_label_byte(byte), word || byte == b'-', "{byte}");
        }
    }
}
