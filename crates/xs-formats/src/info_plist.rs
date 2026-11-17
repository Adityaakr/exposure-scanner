//! Reading the identity of a macOS bundle from its `Info.plist`, and the
//! permissions it asks for.
//!
//! Only a handful of top-level string values are wanted: the identity keys,
//! and every usage description, which is the sentence macOS shows the user
//! when the app asks for a protected resource such as the camera. Only top
//! level string values are wanted, so the property list
//! is consumed as a stream of events and never built into a tree. That keeps
//! memory flat and lets the reader enforce its own depth and item budgets
//! instead of trusting a recursive builder with a hostile file. XML, binary
//! and old-style ASCII property lists are all accepted.

use std::io::Cursor;

use plist::stream::{Event, Reader};

use crate::{Budget, FormatError};

/// Largest property list the reader accepts, in bytes (design report, 4.8).
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
/// Deepest nesting the reader accepts.
pub const MAX_DEPTH: u32 = 64;
/// Most values the reader looks at before giving up.
pub const MAX_ITEMS: u32 = 1_000_000;
/// Most usage descriptions the reader keeps. Apple defines some sixty keys.
pub const MAX_USAGE_DESCRIPTIONS: usize = 256;
/// What the key of a usage description ends in, such as
/// `NSCameraUsageDescription`.
pub const USAGE_DESCRIPTION_SUFFIX: &str = "UsageDescription";

/// What a bundle says about itself.
///
/// Every field is whatever the file declares, unchecked and uncut. The caller
/// cleans the text before it enters a record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BundleInfo {
    /// `CFBundleIdentifier`, such as `com.lwouis.alt-tab-macos`.
    pub identifier: Option<String>,
    /// `CFBundleShortVersionString`, the version shown to users.
    pub short_version: Option<String>,
    /// `CFBundleVersion`, the build number.
    pub build_version: Option<String>,
    /// `CFBundleDisplayName`.
    pub display_name: Option<String>,
    /// `CFBundleName`.
    pub name: Option<String>,
    /// `CFBundleExecutable`, the file name of the main binary.
    pub executable: Option<String>,
    /// `SUFeedURL`, the address of the update feed the Sparkle updater
    /// reads. The caller keeps only its host.
    pub feed_url: Option<String>,
    /// The usage descriptions: every top-level key that ends in
    /// [`USAGE_DESCRIPTION_SUFFIX`] and holds a string, with that string,
    /// which may be empty. In document order, each key once, at most
    /// [`MAX_USAGE_DESCRIPTIONS`] of them.
    pub usage_descriptions: Vec<(String, String)>,
    /// How many further usage descriptions were left out because the list
    /// was full.
    pub usage_descriptions_dropped: u32,
}

/// The key of the update feed address in an `Info.plist`.
pub const FEED_URL_KEY: &str = "SUFeedURL";

impl BundleInfo {
    fn slot(&mut self, key: &str) -> Option<&mut Option<String>> {
        Some(match key {
            "CFBundleIdentifier" => &mut self.identifier,
            "CFBundleShortVersionString" => &mut self.short_version,
            "CFBundleVersion" => &mut self.build_version,
            "CFBundleDisplayName" => &mut self.display_name,
            "CFBundleName" => &mut self.name,
            "CFBundleExecutable" => &mut self.executable,
            FEED_URL_KEY => &mut self.feed_url,
            _ => return None,
        })
    }
}

/// Where the reader is inside the top-level dictionary.
enum Position {
    /// The next event at depth 1 is a key.
    Key,
    /// The next event at depth 1 is the value of this key.
    Value(String),
}

/// Extracts the identity fields and the usage descriptions from the bytes of
/// an `Info.plist`.
///
/// A key that appears more than once keeps its first string value. A wanted
/// key whose value is not a string is treated as absent.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the input is larger than [`MAX_BYTES`],
/// nests deeper than [`MAX_DEPTH`] or holds more than [`MAX_ITEMS`] values.
/// [`FormatError::Malformed`] if it is not a property list whose root is a
/// dictionary.
pub fn parse(bytes: &[u8]) -> Result<BundleInfo, FormatError> {
    if bytes.len() > MAX_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let mut events = Reader::new(Cursor::new(bytes));
    match events.next() {
        Some(Ok(Event::StartDictionary(_))) => {}
        _ => return Err(FormatError::Malformed),
    }

    let mut info = BundleInfo::default();
    let mut position = Position::Key;
    let mut depth: u32 = 1;
    let mut items: u32 = 0;

    for event in events {
        let event = event.map_err(|_| FormatError::Malformed)?;
        items = items.saturating_add(1);
        if items > MAX_ITEMS {
            return Err(FormatError::OverBudget(Budget::Items));
        }
        // A value at depth 1 consumes the pending key, whatever its type.
        let pending = if depth == 1 {
            match std::mem::replace(&mut position, Position::Key) {
                Position::Value(key) => Some(key),
                Position::Key => None,
            }
        } else {
            None
        };
        match event {
            Event::StartArray(_) | Event::StartDictionary(_) => {
                if depth == 1 && pending.is_none() {
                    // A collection where a key belongs.
                    return Err(FormatError::Malformed);
                }
                depth = depth.saturating_add(1);
                if depth > MAX_DEPTH {
                    return Err(FormatError::OverBudget(Budget::Depth));
                }
            }
            Event::EndCollection => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    // End of the root dictionary. Anything after it is not ours.
                    return Ok(info);
                }
            }
            Event::String(text) if depth == 1 => match pending {
                None => position = Position::Value(text.into_owned()),
                Some(key) => {
                    if let Some(slot) = info.slot(&key) {
                        if slot.is_none() {
                            *slot = Some(text.into_owned());
                        }
                    } else if key.ends_with(USAGE_DESCRIPTION_SUFFIX)
                        && !info.usage_descriptions.iter().any(|(known, _)| *known == key)
                    {
                        if info.usage_descriptions.len() < MAX_USAGE_DESCRIPTIONS {
                            info.usage_descriptions.push((key, text.into_owned()));
                        } else {
                            info.usage_descriptions_dropped =
                                info.usage_descriptions_dropped.saturating_add(1);
                        }
                    }
                }
            },
            _ if depth == 1 && pending.is_none() => {
                // A non-string scalar where a key belongs.
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

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>Example</string>
	<key>CFBundleIdentifier</key>
	<string>com.example.app</string>
	<key>CFBundleName</key>
	<string>Example</string>
	<key>CFBundleShortVersionString</key>
	<string>1.2.3</string>
	<key>CFBundleVersion</key>
	<string>42</string>
	<key>LSMinimumSystemVersion</key>
	<string>13.0</string>
	<key>SUFeedURL</key>
	<string>https://updates.example.com/appcast.xml</string>
	<key>CFBundleDocumentTypes</key>
	<array>
		<dict>
			<key>CFBundleIdentifier</key>
			<string>nested.decoy</string>
		</dict>
	</array>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSCameraUsageDescription</key>
	<string>Example uses the camera for video calls.</string>
	<key>NSMicrophoneUsageDescription</key>
	<string></string>
	<key>NSLocationTemporaryUsageDescriptionDictionary</key>
	<dict>
		<key>NSContactsUsageDescription</key>
		<string>nested decoy</string>
	</dict>
</dict>
</plist>
"#;

    fn expected() -> BundleInfo {
        BundleInfo {
            identifier: Some("com.example.app".into()),
            short_version: Some("1.2.3".into()),
            build_version: Some("42".into()),
            display_name: None,
            name: Some("Example".into()),
            executable: Some("Example".into()),
            feed_url: Some("https://updates.example.com/appcast.xml".into()),
            usage_descriptions: vec![
                (
                    "NSCameraUsageDescription".into(),
                    "Example uses the camera for video calls.".into(),
                ),
                ("NSMicrophoneUsageDescription".into(), String::new()),
            ],
            usage_descriptions_dropped: 0,
        }
    }

    /// The same document as `XML`, as a binary property list.
    fn binary() -> Vec<u8> {
        let value = plist::Value::from_reader(Cursor::new(XML.as_bytes())).unwrap();
        let mut out = Vec::new();
        value.to_writer_binary(&mut out).unwrap();
        assert!(out.starts_with(b"bplist00"));
        out
    }

    #[test]
    fn reads_xml() {
        assert_eq!(parse(XML.as_bytes()), Ok(expected()));
    }

    #[test]
    fn reads_binary() {
        assert_eq!(parse(&binary()), Ok(expected()));
    }

    #[test]
    fn nested_keys_do_not_count() {
        let info = parse(XML.as_bytes()).unwrap();
        assert_ne!(info.identifier.as_deref(), Some("nested.decoy"));
    }

    #[test]
    fn first_value_wins_and_non_strings_are_absent() {
        let doc = r#"<plist version="1.0"><dict>
            <key>CFBundleVersion</key><integer>7</integer>
            <key>CFBundleIdentifier</key><string>first</string>
            <key>CFBundleIdentifier</key><string>second</string>
            <key>CFBundleName</key><array><string>not a name</string></array>
        </dict></plist>"#;
        let info = parse(doc.as_bytes()).unwrap();
        assert_eq!(info.identifier.as_deref(), Some("first"));
        assert_eq!(info.build_version, None);
        assert_eq!(info.name, None);
    }

    /// A usage description is a top-level string under a key with the fixed
    /// ending. Its first value counts, an empty one included.
    #[test]
    fn usage_descriptions_are_top_level_strings_and_each_key_counts_once() {
        let doc = r#"<plist version="1.0"><dict>
            <key>NSCameraUsageDescription</key><string>first</string>
            <key>NSCameraUsageDescription</key><string>second</string>
            <key>NSContactsUsageDescription</key><true/>
            <key>NSContactsUsageDescription</key><string>after a value that is no string</string>
            <key>UsageDescription</key><string>the ending alone</string>
            <key>NSCameraUsageDescriptionX</key><string>not the ending</string>
            <key>CFBundleName</key><string>NSMicrophoneUsageDescription</string>
        </dict></plist>"#;
        let info = parse(doc.as_bytes()).unwrap();
        let found: Vec<(&str, &str)> = info
            .usage_descriptions
            .iter()
            .map(|(key, purpose)| (key.as_str(), purpose.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                ("NSCameraUsageDescription", "first"),
                ("NSContactsUsageDescription", "after a value that is no string"),
                ("UsageDescription", "the ending alone"),
            ]
        );
    }

    #[test]
    fn usage_descriptions_past_the_budget_are_counted_not_kept() {
        let mut doc = String::from(r#"<plist version="1.0"><dict>"#);
        for index in 0..MAX_USAGE_DESCRIPTIONS + 3 {
            doc.push_str(&format!("<key>K{index}UsageDescription</key><string>why</string>"));
        }
        // One that is already in the list is not a further one.
        doc.push_str("<key>K0UsageDescription</key><string>again</string>");
        doc.push_str("</dict></plist>");
        let info = parse(doc.as_bytes()).unwrap();
        assert_eq!(info.usage_descriptions.len(), MAX_USAGE_DESCRIPTIONS);
        assert_eq!(info.usage_descriptions_dropped, 3);
        assert_eq!(info.usage_descriptions[0].0, "K0UsageDescription");
    }

    #[test]
    fn an_empty_dictionary_is_fine() {
        let doc = r#"<plist version="1.0"><dict/></plist>"#;
        assert_eq!(parse(doc.as_bytes()), Ok(BundleInfo::default()));
    }

    #[test]
    fn rejects_what_is_not_a_bundle_property_list() {
        assert_eq!(parse(b""), Err(FormatError::Malformed));
        assert_eq!(parse(b"not a plist at all"), Err(FormatError::Malformed));
        let array_root = r#"<plist version="1.0"><array><string>x</string></array></plist>"#;
        assert_eq!(parse(array_root.as_bytes()), Err(FormatError::Malformed));
        let truncated = &XML.as_bytes()[..XML.len() / 2];
        assert_eq!(parse(truncated), Err(FormatError::Malformed));
        let mut damaged = binary();
        damaged.truncate(damaged.len() - 16);
        assert_eq!(parse(&damaged), Err(FormatError::Malformed));
    }

    #[test]
    fn stops_at_the_depth_budget() {
        let nested = |levels: usize| {
            let mut doc = String::from(r#"<plist version="1.0"><dict><key>k</key>"#);
            doc.push_str(&"<array>".repeat(levels));
            doc.push_str(&"</array>".repeat(levels));
            doc.push_str("</dict></plist>");
            doc
        };
        // The root dictionary is level 1, so 63 arrays reach the limit of 64.
        assert_eq!(parse(nested(63).as_bytes()), Ok(BundleInfo::default()));
        assert_eq!(parse(nested(64).as_bytes()), Err(FormatError::OverBudget(Budget::Depth)));
    }

    #[test]
    fn stops_at_the_byte_budget_before_parsing() {
        let oversized = vec![b' '; MAX_BYTES + 1];
        assert_eq!(parse(&oversized), Err(FormatError::OverBudget(Budget::Bytes)));
    }

    proptest! {
        /// Hostile input may be rejected but must never panic.
        #[test]
        fn never_panics_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse(&bytes);
        }

        /// Damage anywhere in a valid file, of either encoding, never panics.
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
