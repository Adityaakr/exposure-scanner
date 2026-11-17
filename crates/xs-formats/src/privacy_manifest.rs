//! Reading the tracking domains a privacy manifest declares.
//!
//! A `PrivacyInfo.xcprivacy` file is a property list an app or an SDK ships
//! to say what it collects. Its `NSPrivacyTrackingDomains` key lists the
//! internet domains it connects to that engage in tracking. That list is the
//! app's own word, which is what the `declares` grade means (design report,
//! section 5.1).
//!
//! Like the bundle's `Info.plist`, the file is consumed as a stream of
//! events and never built into a tree, with the same budgets.

use std::io::Cursor;

use plist::stream::{Event, Reader};

use crate::{Budget, FormatError};

/// Largest privacy manifest the reader accepts, in bytes.
pub const MAX_BYTES: usize = crate::info_plist::MAX_BYTES;
/// Deepest nesting the reader accepts.
pub const MAX_DEPTH: u32 = crate::info_plist::MAX_DEPTH;
/// Most values the reader looks at before giving up.
pub const MAX_ITEMS: u32 = crate::info_plist::MAX_ITEMS;
/// Most tracking domains one manifest may declare. Each becomes a record,
/// so the list has a budget of its own.
pub const MAX_DOMAINS: usize = 1024;

/// The key that lists tracking domains.
pub const TRACKING_DOMAINS_KEY: &str = "NSPrivacyTrackingDomains";

/// What a privacy manifest declares, as far as the scanner reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrivacyManifest {
    /// The entries of `NSPrivacyTrackingDomains`, in file order, as written.
    /// The caller reduces each to a host before it enters a record.
    pub tracking_domains: Vec<String>,
}

/// What the reader expects next in the top-level dictionary.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Position {
    /// A key.
    Key,
    /// The value of a key; `true` for the key that lists tracking domains.
    Value(bool),
}

/// Extracts the tracking domains from the bytes of a privacy manifest.
///
/// Entries of the list that are not strings are passed over. If the key
/// appears more than once, the lists are joined.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the input is larger than [`MAX_BYTES`],
/// nests deeper than [`MAX_DEPTH`], holds more than [`MAX_ITEMS`] values or
/// declares more than [`MAX_DOMAINS`] domains. [`FormatError::Malformed`]
/// if it is not a property list whose root is a dictionary.
pub fn parse(bytes: &[u8]) -> Result<PrivacyManifest, FormatError> {
    if bytes.len() > MAX_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let mut events = Reader::new(Cursor::new(bytes));
    match events.next() {
        Some(Ok(Event::StartDictionary(_))) => {}
        _ => return Err(FormatError::Malformed),
    }

    let mut manifest = PrivacyManifest::default();
    let mut position = Position::Key;
    // Whether the value being read at depth 2 and below is the list of
    // tracking domains. Its own entries are the strings at depth 2.
    let mut in_domains = false;
    let mut depth: u32 = 1;
    let mut items: u32 = 0;

    for event in events {
        let event = event.map_err(|_| FormatError::Malformed)?;
        items = items.saturating_add(1);
        if items > MAX_ITEMS {
            return Err(FormatError::OverBudget(Budget::Items));
        }
        // A value at depth 1 consumes the pending key, whatever its type.
        let pending =
            if depth == 1 { std::mem::replace(&mut position, Position::Key) } else { position };
        match event {
            Event::StartArray(_) | Event::StartDictionary(_) => {
                if depth == 1 {
                    if pending == Position::Key {
                        // A collection where a key belongs.
                        return Err(FormatError::Malformed);
                    }
                    in_domains =
                        pending == Position::Value(true) && matches!(event, Event::StartArray(_));
                }
                depth = depth.saturating_add(1);
                if depth > MAX_DEPTH {
                    return Err(FormatError::OverBudget(Budget::Depth));
                }
            }
            Event::EndCollection => {
                depth = depth.saturating_sub(1);
                match depth {
                    // End of the root dictionary. Anything after it is not ours.
                    0 => return Ok(manifest),
                    1 => in_domains = false,
                    _ => {}
                }
            }
            Event::String(text) if depth == 1 => {
                if pending == Position::Key {
                    position = Position::Value(text == TRACKING_DOMAINS_KEY);
                }
            }
            Event::String(text) if depth == 2 && in_domains => {
                if manifest.tracking_domains.len() >= MAX_DOMAINS {
                    return Err(FormatError::OverBudget(Budget::Items));
                }
                manifest.tracking_domains.push(text.into_owned());
            }
            _ if depth == 1 && pending == Position::Key => {
                // A scalar that is not a string where a key belongs.
                return Err(FormatError::Malformed);
            }
            _ => {}
        }
    }
    // The stream ended before the root dictionary closed.
    Err(FormatError::Malformed)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// The shape Apple documents for the file.
    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSPrivacyTracking</key>
	<true/>
	<key>NSPrivacyTrackingDomains</key>
	<array>
		<string>tracker.example.net</string>
		<string>eu.i.posthog.com</string>
	</array>
	<key>NSPrivacyCollectedDataTypes</key>
	<array>
		<dict>
			<key>NSPrivacyCollectedDataType</key>
			<string>NSPrivacyCollectedDataTypeCrashData</string>
			<key>NSPrivacyTrackingDomains</key>
			<array>
				<string>nested.decoy.example</string>
			</array>
		</dict>
	</array>
	<key>NSPrivacyAccessedAPITypes</key>
	<array/>
</dict>
</plist>
"#;

    fn domains(document: &str) -> Result<Vec<String>, FormatError> {
        parse(document.as_bytes()).map(|manifest| manifest.tracking_domains)
    }

    fn binary() -> Vec<u8> {
        let value = plist::Value::from_reader(Cursor::new(XML.as_bytes())).unwrap();
        let mut out = Vec::new();
        value.to_writer_binary(&mut out).unwrap();
        assert!(out.starts_with(b"bplist00"));
        out
    }

    #[test]
    fn reads_the_declared_domains_in_either_encoding() {
        let expected = ["tracker.example.net", "eu.i.posthog.com"];
        assert_eq!(domains(XML).unwrap(), expected);
        assert_eq!(parse(&binary()).unwrap().tracking_domains, expected);
    }

    #[test]
    fn only_the_top_level_list_counts() {
        assert!(!domains(XML).unwrap().iter().any(|domain| domain.contains("decoy")));
        // The key as a value, or holding something that is not a list.
        let odd = r#"<plist version="1.0"><dict>
            <key>Other</key><string>NSPrivacyTrackingDomains</string>
            <key>Ignored</key><array><string>not.a.tracking.domain.example</string></array>
            <key>NSPrivacyTrackingDomains</key><string>scalar.example</string>
            <key>NSPrivacyTrackingDomains</key><dict><key>k</key><string>dict.example</string></dict>
        </dict></plist>"#;
        assert_eq!(domains(odd).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn entries_that_are_not_strings_are_passed_over_and_repeated_keys_join() {
        let document = r#"<plist version="1.0"><dict>
            <key>NSPrivacyTrackingDomains</key>
            <array><string>a.example</string><integer>7</integer><array><string>deep.example</string></array><string>b.example</string></array>
            <key>NSPrivacyTrackingDomains</key>
            <array><string>c.example</string></array>
        </dict></plist>"#;
        assert_eq!(domains(document).unwrap(), ["a.example", "b.example", "c.example"]);
    }

    #[test]
    fn a_manifest_without_the_key_declares_nothing() {
        assert_eq!(
            domains(r#"<plist version="1.0"><dict/></plist>"#).unwrap(),
            Vec::<String>::new()
        );
        let empty = r#"<plist version="1.0"><dict>
            <key>NSPrivacyTracking</key><false/>
            <key>NSPrivacyTrackingDomains</key><array/>
        </dict></plist>"#;
        assert_eq!(domains(empty).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn rejects_what_is_not_a_privacy_manifest() {
        assert_eq!(parse(b""), Err(FormatError::Malformed));
        assert_eq!(parse(b"not a plist at all"), Err(FormatError::Malformed));
        let array_root = r#"<plist version="1.0"><array><string>x</string></array></plist>"#;
        assert_eq!(parse(array_root.as_bytes()), Err(FormatError::Malformed));
        assert_eq!(parse(&XML.as_bytes()[..XML.len() / 2]), Err(FormatError::Malformed));
        let mut damaged = binary();
        damaged.truncate(damaged.len() - 16);
        assert_eq!(parse(&damaged), Err(FormatError::Malformed));
    }

    #[test]
    fn stops_at_its_budgets() {
        let listing = |count: usize| {
            let mut document = String::from(
                r#"<plist version="1.0"><dict><key>NSPrivacyTrackingDomains</key><array>"#,
            );
            for index in 0..count {
                document.push_str(&format!("<string>t{index}.example</string>"));
            }
            document.push_str("</array></dict></plist>");
            document
        };
        assert_eq!(domains(&listing(MAX_DOMAINS)).unwrap().len(), MAX_DOMAINS);
        assert_eq!(domains(&listing(MAX_DOMAINS + 1)), Err(FormatError::OverBudget(Budget::Items)));

        let nested = |levels: usize| {
            let mut document = String::from(r#"<plist version="1.0"><dict><key>k</key>"#);
            document.push_str(&"<array>".repeat(levels));
            document.push_str(&"</array>".repeat(levels));
            document.push_str("</dict></plist>");
            document
        };
        assert_eq!(domains(&nested(63)).unwrap(), Vec::<String>::new());
        assert_eq!(domains(&nested(64)), Err(FormatError::OverBudget(Budget::Depth)));

        let oversized = vec![b' '; MAX_BYTES + 1];
        assert_eq!(parse(&oversized), Err(FormatError::OverBudget(Budget::Bytes)));
    }

    proptest! {
        #[test]
        fn never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse(&bytes);
        }

        #[test]
        fn never_panics_on_damaged_files(
            use_binary in any::<bool>(),
            position in any::<prop::sample::Index>(),
            value in any::<u8>(),
            cut in any::<prop::sample::Index>(),
        ) {
            let mut bytes = if use_binary { binary() } else { XML.as_bytes().to_vec() };
            let at = position.index(bytes.len());
            bytes[at] = value;
            let keep = cut.index(bytes.len() + 1);
            let _ = parse(&bytes[..keep]);
        }
    }
}
