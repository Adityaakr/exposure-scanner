//! Browser extension manifests: `manifest.json`, the message catalogue a
//! localized name points into, and the site patterns a manifest lists.
//!
//! Chromium-family browsers and Firefox load the same kind of extension. Its
//! `manifest.json` says what the extension asks the browser for, under a few
//! fixed keys, and this reader takes those keys and nothing else:
//!
//! | Key | What is taken |
//! |---|---|
//! | `name`, `version`, `default_locale` | the text |
//! | `author` | the text; the object form that holds an e-mail address is not taken |
//! | `homepage_url` | the text; the caller keeps the host only |
//! | `developer` | `name` and `url`, used where `author` and `homepage_url` are absent |
//! | `permissions`, `optional_permissions` | the text entries: interface names, and site patterns in a version 2 manifest |
//! | `host_permissions`, `optional_host_permissions` | the text entries: site patterns |
//! | `content_scripts` | per script: its `matches`, whether it lists a `js` file, whether `include_globs` narrows it |
//!
//! The reader is lenient where the browser is strict. A key of an
//! unexpected type is passed over, as is an entry of a list that is not
//! text, so one odd key does not hide the rest of a manifest the browser
//! itself has already accepted. Only a file that is not a JSON object is
//! malformed.
//!
//! Both browsers accept comments in a manifest, which JSON does not have, so
//! `//` and `/* */` comments outside of text are blanked out first, and a
//! byte order mark at the start is skipped. Other departures from JSON that
//! a browser tolerates are not: such a manifest is reported as malformed.
//!
//! Budgets: [`MAX_MANIFEST_BYTES`] and [`MAX_MESSAGES_BYTES`] for the two
//! files, [`MAX_ENTRIES`] list entries kept from one manifest, and the JSON
//! reader's own limit on nesting.

use std::borrow::Cow;
use std::fmt;

use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::{Budget, FormatError};

/// Largest `manifest.json` read: 1 MiB. Real ones are a few kilobytes; one
/// that lists a script for each of hundreds of sites reaches a hundred.
pub const MAX_MANIFEST_BYTES: usize = 1 << 20;
/// Largest message catalogue read: 4 MiB.
pub const MAX_MESSAGES_BYTES: usize = 4 << 20;
/// Most list entries kept from one manifest, over all of its lists.
pub const MAX_ENTRIES: usize = 10_000;
/// Longest locale name taken from `default_locale`, in bytes. The longest
/// in use, such as `zh_Hant_TW`, have ten.
const MAX_LOCALE_BYTES: usize = 35;

/// What a manifest says about its extension and what it asks for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    /// `name`, as written. It may be a reference into the message catalogue;
    /// see [`message_key`].
    pub name: Option<String>,
    /// `version`.
    pub version: Option<String>,
    /// `default_locale`: the folder under `_locales` that holds the message
    /// catalogue a reference is looked up in. Only a name that is safe as
    /// one path component is kept.
    pub default_locale: Option<String>,
    /// `author` when it is text, else `developer.name`.
    pub author: Option<String>,
    /// `homepage_url`, else `developer.url`. An address, as written.
    pub homepage_url: Option<String>,
    /// The text entries of `permissions`.
    pub permissions: Vec<String>,
    /// The text entries of `optional_permissions`.
    pub optional_permissions: Vec<String>,
    /// The text entries of `host_permissions`.
    pub host_permissions: Vec<String>,
    /// The text entries of `optional_host_permissions`.
    pub optional_host_permissions: Vec<String>,
    /// The entries of `content_scripts` that are objects.
    pub content_scripts: Vec<ContentScript>,
}

/// One entry of `content_scripts`: files the browser itself puts into the
/// pages its patterns cover.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentScript {
    /// The site patterns under `matches`.
    pub matches: Vec<String>,
    /// Whether `js` lists at least one file. An entry that only lists style
    /// sheets changes how a page looks and cannot read it.
    pub runs_script: bool,
    /// Whether `include_globs` lists at least one pattern, which lets the
    /// script into only those of the matched pages that it also covers.
    pub narrowed: bool,
}

impl Manifest {
    fn entries(&self) -> usize {
        let scripts: usize = self.content_scripts.iter().map(|script| script.matches.len()).sum();
        [
            self.permissions.len(),
            self.optional_permissions.len(),
            self.host_permissions.len(),
            self.optional_host_permissions.len(),
            self.content_scripts.len(),
            scripts,
        ]
        .into_iter()
        .fold(0, usize::saturating_add)
    }
}

/// Parses a `manifest.json`.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the file is larger than
/// [`MAX_MANIFEST_BYTES`] or lists more than [`MAX_ENTRIES`] entries.
/// [`FormatError::Malformed`] if it is not a JSON object, comments aside.
pub fn parse(json: &[u8]) -> Result<Manifest, FormatError> {
    if json.len() > MAX_MANIFEST_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let json = without_comments(json);
    let manifest: Manifest = serde_json::from_slice(&json).map_err(|_| FormatError::Malformed)?;
    if manifest.entries() > MAX_ENTRIES {
        return Err(FormatError::OverBudget(Budget::Items));
    }
    Ok(manifest)
}

/// The name of the message that `text` stands for, if it is a reference
/// into the message catalogue: `appName` for `__MSG_appName__`.
///
/// Only text that is one reference and nothing else counts. The browser
/// also fills in a reference inside longer text; such a name is kept as it
/// is written.
#[must_use]
pub fn message_key(text: &str) -> Option<&str> {
    let key = text.strip_prefix("__MSG_")?.strip_suffix("__")?;
    let is_name_byte = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'@');
    (!key.is_empty() && key.bytes().all(is_name_byte)).then_some(key)
}

/// Looks `key` up in a message catalogue, a `messages.json` file, and gives
/// back its `message`. Message names are compared without regard to ASCII
/// letter case, as the browser compares them; of two that differ in case
/// only, the first in the file is taken.
///
/// # Errors
///
/// [`FormatError::OverBudget`] if the file is larger than
/// [`MAX_MESSAGES_BYTES`]. [`FormatError::Malformed`] if it is not a JSON
/// object, comments aside.
pub fn message(json: &[u8], key: &str) -> Result<Option<String>, FormatError> {
    if json.len() > MAX_MESSAGES_BYTES {
        return Err(FormatError::OverBudget(Budget::Bytes));
    }
    let json = without_comments(json);
    let mut reader = serde_json::Deserializer::from_slice(&json);
    let found = reader.deserialize_map(Catalogue(key)).and_then(|found| {
        reader.end()?;
        Ok(found)
    });
    found.map_err(|_| FormatError::Malformed)
}

/// Blanks out `//` and `/* */` comments outside of JSON text, and a byte
/// order mark at the start. Line breaks inside a comment are kept, so the
/// rest of the file stays where it was.
fn without_comments(json: &[u8]) -> Cow<'_, [u8]> {
    /// Where in the file the reader is.
    #[derive(Clone, Copy)]
    enum At {
        Code,
        /// After a `/` in code, which may open a comment.
        Slash,
        Text,
        /// After a backslash in text.
        Escape,
        LineComment,
        BlockComment,
        /// After a `*` in a block comment, which may close it.
        Star,
    }

    let json = json.strip_prefix(b"\xef\xbb\xbf").unwrap_or(json);
    if !json.contains(&b'/') {
        return Cow::Borrowed(json);
    }
    let blank = |byte: u8| if matches!(byte, b'\n' | b'\r') { byte } else { b' ' };
    let mut out = Vec::with_capacity(json.len());
    let mut at = At::Code;
    for &byte in json {
        let (next, kept) = match (at, byte) {
            (At::Code, b'/') => (At::Slash, byte),
            (At::Code | At::Slash, b'"') => (At::Text, byte),
            (At::Slash, b'/' | b'*') => {
                // The slash before this byte opened a comment after all.
                if let Some(slash) = out.last_mut() {
                    *slash = b' ';
                }
                (if byte == b'/' { At::LineComment } else { At::BlockComment }, b' ')
            }
            (At::Code | At::Slash, _) => (At::Code, byte),
            (At::Text, b'\\') => (At::Escape, byte),
            (At::Text, b'"') => (At::Code, byte),
            (At::Text | At::Escape, _) => (At::Text, byte),
            (At::LineComment, b'\n') => (At::Code, byte),
            (At::LineComment, _) => (At::LineComment, blank(byte)),
            (At::BlockComment | At::Star, b'*') => (At::Star, b' '),
            (At::Star, b'/') => (At::Code, b' '),
            (At::BlockComment | At::Star, _) => (At::BlockComment, blank(byte)),
        };
        at = next;
        out.push(kept);
    }
    Cow::Owned(out)
}

/// Defines what a lenient value makes of every JSON type it does not take:
/// its default. A list or an object is read to its end and dropped.
macro_rules! pass_over {
    ($($method:ident($type:ty)),* $(,)?) => {
        $(
            fn $method<E: serde::de::Error>(self, _: $type) -> Result<Self::Value, E> {
                Ok(Self::Value::default())
            }
        )*

        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(Self::Value::default())
        }
    };
}

/// Passes over a list where something else was expected.
fn drop_seq<'de, A: SeqAccess<'de>>(mut seq: A) -> Result<(), A::Error> {
    while seq.next_element::<IgnoredAny>()?.is_some() {}
    Ok(())
}

/// Passes over an object where something else was expected.
fn drop_map<'de, A: MapAccess<'de>>(mut map: A) -> Result<(), A::Error> {
    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
    Ok(())
}

/// Text, or nothing for a value of any other type.
#[derive(Default)]
struct Text(Option<String>);

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextVisitor;

        impl<'de> Visitor<'de> for TextVisitor {
            type Value = Text;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }

            pass_over!(visit_bool(bool), visit_i64(i64), visit_u64(u64), visit_f64(f64));

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Text, E> {
                Ok(Text(Some(text.to_owned())))
            }

            fn visit_string<E: serde::de::Error>(self, text: String) -> Result<Text, E> {
                Ok(Text(Some(text)))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Text, A::Error> {
                drop_seq(seq).map(|()| Text(None))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Text, A::Error> {
                drop_map(map).map(|()| Text(None))
            }
        }

        deserializer.deserialize_any(TextVisitor)
    }
}

/// The text entries of a list, or none for a value that is not a list.
#[derive(Default)]
struct Texts(Vec<String>);

impl<'de> Deserialize<'de> for Texts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TextsVisitor;

        impl<'de> Visitor<'de> for TextsVisitor {
            type Value = Texts;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }

            pass_over!(
                visit_bool(bool),
                visit_i64(i64),
                visit_u64(u64),
                visit_f64(f64),
                visit_str(&str),
            );

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Texts, A::Error> {
                let mut texts = Vec::new();
                while let Some(Text(entry)) = seq.next_element()? {
                    texts.extend(entry);
                }
                Ok(Texts(texts))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Texts, A::Error> {
                drop_map(map).map(|()| Texts(Vec::new()))
            }
        }

        deserializer.deserialize_any(TextsVisitor)
    }
}

/// One entry of `content_scripts`, or nothing for an entry that is not an
/// object.
#[derive(Default)]
struct Script(Option<ContentScript>);

impl<'de> Deserialize<'de> for Script {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ScriptVisitor;

        impl<'de> Visitor<'de> for ScriptVisitor {
            type Value = Script;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }

            pass_over!(
                visit_bool(bool),
                visit_i64(i64),
                visit_u64(u64),
                visit_f64(f64),
                visit_str(&str),
            );

            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Script, A::Error> {
                drop_seq(seq).map(|()| Script(None))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Script, A::Error> {
                let mut script = ContentScript::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "matches" => script.matches = map.next_value::<Texts>()?.0,
                        "js" => script.runs_script = !map.next_value::<Texts>()?.0.is_empty(),
                        "include_globs" => {
                            script.narrowed = !map.next_value::<Texts>()?.0.is_empty();
                        }
                        _ => drop(map.next_value::<IgnoredAny>()?),
                    }
                }
                Ok(Script(Some(script)))
            }
        }

        deserializer.deserialize_any(ScriptVisitor)
    }
}

/// The entries of `content_scripts` that are objects.
#[derive(Default)]
struct Scripts(Vec<ContentScript>);

impl<'de> Deserialize<'de> for Scripts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ScriptsVisitor;

        impl<'de> Visitor<'de> for ScriptsVisitor {
            type Value = Scripts;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }

            pass_over!(
                visit_bool(bool),
                visit_i64(i64),
                visit_u64(u64),
                visit_f64(f64),
                visit_str(&str),
            );

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Scripts, A::Error> {
                let mut scripts = Vec::new();
                while let Some(Script(entry)) = seq.next_element()? {
                    scripts.extend(entry);
                }
                Ok(Scripts(scripts))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Scripts, A::Error> {
                drop_map(map).map(|()| Scripts(Vec::new()))
            }
        }

        deserializer.deserialize_any(ScriptsVisitor)
    }
}

/// An object of which two keys are taken, each when it is text: `developer`
/// with `name` and `url`, an entry of a message catalogue with `message`.
#[derive(Default)]
struct Pair<const FIRST: char, const SECOND: char>(Option<String>, Option<String>);

/// The keys a [`Pair`] takes, by the letters that stand for them.
const fn pair_key(letter: char) -> &'static str {
    match letter {
        'n' => "name",
        'u' => "url",
        'm' => "message",
        _ => "",
    }
}

impl<'de, const FIRST: char, const SECOND: char> Deserialize<'de> for Pair<FIRST, SECOND> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PairVisitor<const FIRST: char, const SECOND: char>;

        impl<'de, const FIRST: char, const SECOND: char> Visitor<'de> for PairVisitor<FIRST, SECOND> {
            type Value = Pair<FIRST, SECOND>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any value")
            }

            pass_over!(
                visit_bool(bool),
                visit_i64(i64),
                visit_u64(u64),
                visit_f64(f64),
                visit_str(&str),
            );

            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
                drop_seq(seq).map(|()| Pair(None, None))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut pair = Pair(None, None);
                while let Some(key) = map.next_key::<String>()? {
                    if key == pair_key(FIRST) {
                        pair.0 = map.next_value::<Text>()?.0;
                    } else if key == pair_key(SECOND) {
                        pair.1 = map.next_value::<Text>()?.0;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(pair)
            }
        }

        deserializer.deserialize_any(PairVisitor)
    }
}

/// `developer`: its `name` and its `url`.
type Developer = Pair<'n', 'u'>;
/// An entry of a message catalogue: its `message`.
type Message = Pair<'m', 'm'>;

impl<'de> Deserialize<'de> for Manifest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ManifestVisitor;

        impl<'de> Visitor<'de> for ManifestVisitor {
            type Value = Manifest;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an extension manifest object")
            }

            /// A key that occurs twice counts as the browser counts it: the
            /// later one replaces the earlier.
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Manifest, A::Error> {
                let mut manifest = Manifest::default();
                let (mut author, mut homepage) = (None, None);
                let mut developer = Pair(None, None);
                while let Some(key) = map.next_key::<String>()? {
                    let mut text = || map.next_value::<Text>().map(|Text(text)| text);
                    match key.as_str() {
                        "name" => manifest.name = text()?,
                        "version" => manifest.version = text()?,
                        "default_locale" => manifest.default_locale = text()?,
                        "author" => author = text()?,
                        "homepage_url" => homepage = text()?,
                        "developer" => developer = map.next_value::<Developer>()?,
                        "permissions" => manifest.permissions = map.next_value::<Texts>()?.0,
                        "optional_permissions" => {
                            manifest.optional_permissions = map.next_value::<Texts>()?.0;
                        }
                        "host_permissions" => {
                            manifest.host_permissions = map.next_value::<Texts>()?.0;
                        }
                        "optional_host_permissions" => {
                            manifest.optional_host_permissions = map.next_value::<Texts>()?.0;
                        }
                        "content_scripts" => {
                            manifest.content_scripts = map.next_value::<Scripts>()?.0;
                        }
                        _ => drop(map.next_value::<IgnoredAny>()?),
                    }
                }
                manifest.author = author.or(developer.0);
                manifest.homepage_url = homepage.or(developer.1);
                manifest.default_locale = manifest.default_locale.filter(|name| is_locale(name));
                Ok(manifest)
            }
        }

        deserializer.deserialize_map(ManifestVisitor)
    }
}

/// Whether `name` can be a folder under `_locales`: letters, digits,
/// underscores and hyphens only, so it is one path component and nothing
/// else.
fn is_locale(name: &str) -> bool {
    let is_name_byte = |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-');
    !name.is_empty() && name.len() <= MAX_LOCALE_BYTES && name.bytes().all(is_name_byte)
}

/// A message catalogue, searched for the message named by the key.
struct Catalogue<'k>(&'k str);

impl<'de> Visitor<'de> for Catalogue<'_> {
    type Value = Option<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a message catalogue object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Option<String>, A::Error> {
        let mut found: Option<Option<String>> = None;
        while let Some(name) = map.next_key::<String>()? {
            if found.is_none() && name.eq_ignore_ascii_case(self.0) {
                found = Some(map.next_value::<Message>()?.0);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found.flatten())
    }
}

/// The scheme of a site pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `*`: both `http` and `https`.
    Any,
    /// `http` only.
    Http,
    /// `https` only.
    Https,
}

/// The host of a site pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// `*`: every host.
    Any,
    /// `*.example.com`: the named domain and every host under it. The
    /// domain is in lowercase.
    Under(String),
    /// One host.
    Named,
}

/// A site pattern of a manifest (a "match pattern"), as far as it says how
/// much of the web it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SitePattern {
    /// `<all_urls>`: every address of every scheme an extension may reach.
    AllUrls,
    /// `scheme://host/path` for web pages.
    Web {
        /// The scheme.
        scheme: Scheme,
        /// The host.
        host: Host,
        /// Whether the path is `/*`, which covers every page of a site.
        every_path: bool,
        /// Whether the pattern names no port or the port `*`, and so covers
        /// a site on every port.
        every_port: bool,
    },
}

/// Reads an entry of a permission list or of a script's `matches` as a site
/// pattern for web pages.
///
/// Returns `None` for an entry that is not one: the name of a browser
/// interface such as `tabs`, and a pattern for another scheme (`file`,
/// `ftp`, `ws`, `chrome-extension` and so on), which does not cover
/// websites.
#[must_use]
pub fn site_pattern(entry: &str) -> Option<SitePattern> {
    if entry == "<all_urls>" {
        return Some(SitePattern::AllUrls);
    }
    let (scheme, rest) = entry.split_once("://")?;
    let scheme = match scheme {
        "*" => Scheme::Any,
        _ if scheme.eq_ignore_ascii_case("http") => Scheme::Http,
        _ if scheme.eq_ignore_ascii_case("https") => Scheme::Https,
        _ => return None,
    };
    let (authority, path) = match rest.find('/') {
        Some(slash) => rest.split_at_checked(slash)?,
        None => (rest, ""),
    };
    // A port, where a browser accepts one, is digits or `*` after the last
    // colon. An address in brackets is one host whatever follows it.
    let (name, every_port) = match authority.rsplit_once(':') {
        Some((name, port))
            if !name.is_empty()
                && !authority.starts_with('[')
                && (port == "*" || port.bytes().all(|byte| byte.is_ascii_digit())) =>
        {
            (name, port == "*")
        }
        _ => (authority, true),
    };
    let host = match name.strip_prefix("*.") {
        _ if name == "*" => Host::Any,
        Some(domain) if !domain.is_empty() && !domain.contains('*') => {
            Host::Under(domain.to_ascii_lowercase())
        }
        _ => Host::Named,
    };
    Some(SitePattern::Web { scheme, host, every_path: path == "/*", every_port })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn texts(list: &[&str]) -> Vec<String> {
        list.iter().map(|&entry| entry.to_owned()).collect()
    }

    #[test]
    fn takes_the_keys_that_say_what_an_extension_asks_for() {
        let manifest = parse(
            br#"{
              "manifest_version": 3,
              "name": "Example",
              "version": "1.2.3",
              "default_locale": "en",
              "author": "Example Ltd",
              "homepage_url": "https://example.com/extension?ref=store",
              "description": "Not taken",
              "permissions": ["storage", "tabs", "history"],
              "optional_permissions": ["clipboardRead"],
              "host_permissions": ["https://*/*"],
              "optional_host_permissions": ["https://api.example.com/*"],
              "content_scripts": [
                {"matches": ["<all_urls>"], "js": ["content.js"], "all_frames": true},
                {"matches": ["*://*.example.com/*"], "css": ["theme.css"]},
                {"matches": ["*://*/*"], "js": ["pdf.js"], "include_globs": ["*.pdf"]}
              ],
              "background": {"service_worker": "background.js"}
            }"#,
        )
        .unwrap();
        assert_eq!(
            manifest,
            Manifest {
                name: Some("Example".into()),
                version: Some("1.2.3".into()),
                default_locale: Some("en".into()),
                author: Some("Example Ltd".into()),
                homepage_url: Some("https://example.com/extension?ref=store".into()),
                permissions: texts(&["storage", "tabs", "history"]),
                optional_permissions: texts(&["clipboardRead"]),
                host_permissions: texts(&["https://*/*"]),
                optional_host_permissions: texts(&["https://api.example.com/*"]),
                content_scripts: vec![
                    ContentScript {
                        matches: texts(&["<all_urls>"]),
                        runs_script: true,
                        narrowed: false
                    },
                    ContentScript {
                        matches: texts(&["*://*.example.com/*"]),
                        runs_script: false,
                        narrowed: false
                    },
                    ContentScript {
                        matches: texts(&["*://*/*"]),
                        runs_script: true,
                        narrowed: true
                    },
                ],
            }
        );
    }

    #[test]
    fn an_empty_object_is_a_manifest_that_asks_for_nothing() {
        assert_eq!(parse(b"{}").unwrap(), Manifest::default());
        assert_eq!(parse(b" \n{ }\n").unwrap(), Manifest::default());
    }

    /// A key of an unexpected type hides itself and nothing else. The
    /// object form of `author` holds an e-mail address and is not taken.
    #[test]
    fn keys_of_an_unexpected_type_are_passed_over() {
        let manifest = parse(
            br#"{
              "name": ["not", "text"],
              "version": 7,
              "default_locale": null,
              "author": {"email": "someone@example.com"},
              "homepage_url": {"a": {"b": [1, 2, {"c": null}]}},
              "permissions": ["tabs", {"fileSystem": ["write"]}, 3, null, ["nested"], true, 1.5, "history"],
              "optional_permissions": "cookies",
              "host_permissions": {"https://*/*": true},
              "optional_host_permissions": 4,
              "content_scripts": [
                "not an object", 5, [], null,
                {"matches": "https://*/*", "js": "content.js", "include_globs": {}},
                {"matches": [1, "https://example.com/*"], "js": [], "include_globs": []}
              ]
            }"#,
        )
        .unwrap();
        assert_eq!(
            manifest,
            Manifest {
                permissions: texts(&["tabs", "history"]),
                content_scripts: vec![
                    ContentScript::default(),
                    ContentScript {
                        matches: texts(&["https://example.com/*"]),
                        runs_script: false,
                        narrowed: false
                    },
                ],
                ..Manifest::default()
            }
        );
    }

    #[test]
    fn the_developer_key_fills_in_for_author_and_home_page() {
        let both = parse(
            br#"{"author": "A", "homepage_url": "https://a.example/",
                 "developer": {"name": "D", "url": "https://d.example/"}}"#,
        )
        .unwrap();
        assert_eq!(both.author.as_deref(), Some("A"));
        assert_eq!(both.homepage_url.as_deref(), Some("https://a.example/"));

        let developer = parse(
            br#"{"author": {"email": "a@example.com"},
                 "developer": {"name": "D", "url": "https://d.example/", "other": [1]}}"#,
        )
        .unwrap();
        assert_eq!(developer.author.as_deref(), Some("D"));
        assert_eq!(developer.homepage_url.as_deref(), Some("https://d.example/"));

        let odd = parse(br#"{"developer": ["D"]}"#).unwrap();
        assert_eq!((odd.author, odd.homepage_url), (None, None));
    }

    #[test]
    fn a_key_that_occurs_twice_counts_once_as_the_later_one() {
        let manifest = parse(
            br#"{"name": "First", "permissions": ["tabs"], "name": "Second", "permissions": []}"#,
        )
        .unwrap();
        assert_eq!(manifest.name.as_deref(), Some("Second"));
        assert!(manifest.permissions.is_empty());
    }

    #[test]
    fn comments_and_a_byte_order_mark_are_not_part_of_the_manifest() {
        let manifest = parse(
            b"\xef\xbb\xbf// A comment the browser accepts.\n\
              {\n\
                /* a block\n   comment, with a \" quote and a // inside */\n\
                \"name\": \"Slashes // and /* stars */ in text stay\", // trailing\n\
                \"version\": \"1.0\", /**/ \"homepage_url\": \"https://example.com/a\\\\\\\"//b\"\n\
              }\n\
              // the end",
        )
        .unwrap();
        assert_eq!(manifest.name.as_deref(), Some("Slashes // and /* stars */ in text stay"));
        assert_eq!(manifest.version.as_deref(), Some("1.0"));
        assert_eq!(manifest.homepage_url.as_deref(), Some("https://example.com/a\\\"//b"));
        // What is left of a comment is as long as the comment was.
        let stripped = without_comments(b"{/*\xc3\xa9\n*/\"a\":1}//x");
        assert_eq!(&*stripped, b"{    \n  \"a\":1}   ");
        // Without a slash there is nothing to do, and nothing is copied.
        assert!(matches!(without_comments(b"{\"a\": 1}"), Cow::Borrowed(_)));
        // A lone slash is no comment, and is left for the JSON reader to refuse.
        assert_eq!(&*without_comments(b"{\"a\": 1 / 2}"), b"{\"a\": 1 / 2}");
    }

    #[test]
    fn what_is_not_a_json_object_is_malformed() {
        for bad in [
            &b""[..],
            b"null",
            b"[]",
            b"\"manifest\"",
            b"{",
            b"{\"name\": \"x\",}",
            b"{\"name\": \"x\"} trailing",
            b"{\"name\": \"x\"} {}",
            b"{'name': 'x'}",
            b"{\"name\": \"unterminated}",
            b"{\"name\": \"x\" /* never closed }",
            b"\xff\xfe{\x00}\x00",
        ] {
            assert_eq!(parse(bad), Err(FormatError::Malformed), "{}", String::from_utf8_lossy(bad));
        }
    }

    /// What is passed over is skipped without descending into it, so
    /// nesting costs no stack: a manifest cannot be built to overflow it.
    #[test]
    fn deep_nesting_is_passed_over_without_descending() {
        let nest = |open: &str, close: &str| {
            format!("{}null{}", open.repeat(20_000), close.repeat(20_000))
        };
        let lists = nest("[", "]");
        let objects = nest("{\"a\":", "}");
        for value in [&lists, &objects] {
            let json = format!(
                "{{\"other\": {value}, \"name\": {value}, \"permissions\": [{value}, \"tabs\"], \
                 \"content_scripts\": [{{\"matches\": [{value}], \"js\": {value}}}, {value}], \
                 \"developer\": {{\"name\": {value}}}}}"
            );
            assert!(json.len() <= MAX_MANIFEST_BYTES);
            let manifest = parse(json.as_bytes()).unwrap();
            assert_eq!(manifest.name, None);
            assert_eq!(manifest.permissions, ["tabs"]);
        }
        let catalogue = format!("{{\"a\": {lists}, \"appName\": {{\"message\": {objects}}}}}");
        assert_eq!(message(catalogue.as_bytes(), "appName"), Ok(None));
    }

    #[test]
    fn the_budgets_are_counts() {
        let big = format!("{{\"name\": \"{}\"}}", "a".repeat(MAX_MANIFEST_BYTES));
        assert_eq!(parse(big.as_bytes()), Err(FormatError::OverBudget(Budget::Bytes)));

        let list =
            |count: usize| format!("{{\"permissions\": [{}]}}", vec!["\"p\""; count].join(","));
        assert_eq!(parse(list(MAX_ENTRIES).as_bytes()).unwrap().permissions.len(), MAX_ENTRIES);
        assert_eq!(
            parse(list(MAX_ENTRIES + 1).as_bytes()),
            Err(FormatError::OverBudget(Budget::Items))
        );
        // The entries of scripts count too, and so does each script.
        let scripts = format!(
            "{{\"content_scripts\": [{}]}}",
            vec!["{\"matches\": [\"a\", \"b\"]}"; MAX_ENTRIES / 3 + 1].join(",")
        );
        assert_eq!(parse(scripts.as_bytes()), Err(FormatError::OverBudget(Budget::Items)));
    }

    #[test]
    fn only_a_safe_folder_name_is_a_locale() {
        let locale = |name: &str| {
            parse(format!("{{\"default_locale\": {}}}", serde_json::json!(name)).as_bytes())
                .unwrap()
                .default_locale
        };
        for name in ["en", "en_US", "pt-BR", "zh_Hant_TW"] {
            assert_eq!(locale(name).as_deref(), Some(name));
        }
        let long = "a".repeat(MAX_LOCALE_BYTES + 1);
        for name in ["", "..", "en/../..", "en US", "/etc", "en\u{0}", "\u{e9}", long.as_str()] {
            assert_eq!(locale(name), None, "{name:?}");
        }
    }

    #[test]
    fn a_name_that_is_one_reference_names_its_message() {
        assert_eq!(message_key("__MSG_appName__"), Some("appName"));
        assert_eq!(message_key("__MSG_ext_name@2__"), Some("ext_name@2"));
        assert_eq!(message_key("__MSG____"), Some("_"));
        for not in [
            "Example",
            "",
            "__MSG___",
            "__MSG_appName",
            "MSG_appName__",
            "__msg_appName__",
            "My __MSG_appName__",
            "__MSG_app name__",
            "__MSG_app-name__",
            "__MSG_a__ and __MSG_b__",
        ] {
            assert_eq!(message_key(not), None, "{not}");
        }
    }

    #[test]
    fn a_message_is_looked_up_without_regard_to_letter_case() {
        let catalogue = br#"{
          // Catalogues may hold comments too.
          "other": {"message": "Other", "description": "d"},
          "AppName": {"description": "The name", "message": "Example Wallet", "placeholders": {"x": {"content": "$1"}}},
          "appname": {"message": "A later one"},
          "odd": "not an object",
          "empty": {},
          "typed": {"message": 5}
        }"#;
        assert_eq!(message(catalogue, "appName").unwrap().as_deref(), Some("Example Wallet"));
        assert_eq!(message(catalogue, "APPNAME").unwrap().as_deref(), Some("Example Wallet"));
        assert_eq!(message(catalogue, "other").unwrap().as_deref(), Some("Other"));
        for absent in ["missing", "odd", "empty", "typed", ""] {
            assert_eq!(message(catalogue, absent).unwrap(), None, "{absent}");
        }
        assert_eq!(message(b"[]", "appName"), Err(FormatError::Malformed));
        assert_eq!(message(b"{\"appName\": ", "appName"), Err(FormatError::Malformed));
        assert_eq!(message(b"{} {}", "appName"), Err(FormatError::Malformed));
        let big = vec![b' '; MAX_MESSAGES_BYTES + 1];
        assert_eq!(message(&big, "appName"), Err(FormatError::OverBudget(Budget::Bytes)));
    }

    fn web(scheme: Scheme, host: Host, every_path: bool) -> Option<SitePattern> {
        Some(SitePattern::Web { scheme, host, every_path, every_port: true })
    }

    fn web_on_port(scheme: Scheme, host: Host, every_path: bool) -> Option<SitePattern> {
        Some(SitePattern::Web { scheme, host, every_path, every_port: false })
    }

    #[test]
    fn a_site_pattern_says_how_much_of_the_web_it_covers() {
        let under = |domain: &str| Host::Under(domain.to_owned());
        assert_eq!(site_pattern("<all_urls>"), Some(SitePattern::AllUrls));
        assert_eq!(site_pattern("*://*/*"), web(Scheme::Any, Host::Any, true));
        assert_eq!(site_pattern("https://*/*"), web(Scheme::Https, Host::Any, true));
        assert_eq!(site_pattern("HTTP://*/*"), web(Scheme::Http, Host::Any, true));
        assert_eq!(site_pattern("https://*/*.pdf"), web(Scheme::Https, Host::Any, false));
        assert_eq!(site_pattern("https://*/"), web(Scheme::Https, Host::Any, false));
        assert_eq!(site_pattern("https://*"), web(Scheme::Https, Host::Any, false));
        assert_eq!(site_pattern("*://*:*/*"), web(Scheme::Any, Host::Any, true));
        assert_eq!(site_pattern("*://*.com/*"), web(Scheme::Any, under("com"), true));
        assert_eq!(site_pattern("*://*.Co.UK/*"), web(Scheme::Any, under("co.uk"), true));
        assert_eq!(site_pattern("https://*:8443/*"), web_on_port(Scheme::Https, Host::Any, true));
        assert_eq!(
            site_pattern("https://*.example.com:8443/app/*"),
            web_on_port(Scheme::Https, under("example.com"), false)
        );
        for (one_host, every_port) in [
            ("https://example.com/*", true),
            ("http://localhost:8545/", false),
            ("*://connect.trezor.io/9/*", true),
            ("https://[::1]:8080/*", true),
            ("https://*.*/*", true),
            ("https://*./*", true),
            ("https://ex*ample.com/*", true),
            ("https:///*", true),
        ] {
            assert_eq!(site_pattern(one_host), web_scheme_of(one_host, every_port), "{one_host}");
        }
    }

    /// A pattern for one host, whatever its scheme and path.
    fn web_scheme_of(pattern: &str, every_port: bool) -> Option<SitePattern> {
        let scheme = match pattern.split_once("://").unwrap().0 {
            "*" => Scheme::Any,
            "http" => Scheme::Http,
            _ => Scheme::Https,
        };
        let every_path = pattern.ends_with("/*") && pattern.matches('/').count() == 3;
        Some(SitePattern::Web { scheme, host: Host::Named, every_path, every_port })
    }

    #[test]
    fn interface_names_and_other_schemes_are_not_site_patterns() {
        for not in [
            "tabs",
            "history",
            "",
            "<ALL_URLS>",
            "all_urls",
            "file:///*",
            "file://*/*",
            "ftp://*/*",
            "ws://*/*",
            "wss://*/*",
            "chrome://favicon/*",
            "chrome-extension://*/*",
            "*:/*/*",
            "://*/*",
            "urn:*",
        ] {
            assert_eq!(site_pattern(not), None, "{not}");
        }
    }

    proptest! {
        /// Hostile bytes never panic, and what parses is within the budget.
        #[test]
        fn any_bytes_parse_or_are_refused(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            if let Ok(manifest) = parse(&bytes) {
                prop_assert!(manifest.entries() <= MAX_ENTRIES);
            }
            let _ = message(&bytes, "appName");
            let _ = site_pattern(&String::from_utf8_lossy(&bytes));
            // Blanking comments keeps the length, the byte order mark aside.
            let stripped = without_comments(&bytes);
            let mark = if bytes.starts_with(b"\xef\xbb\xbf") { 3 } else { 0 };
            prop_assert_eq!(stripped.len() + mark, bytes.len());
        }

        /// A manifest written by a JSON writer reads back what it was
        /// given, wherever comments are put between its tokens.
        #[test]
        fn a_written_manifest_reads_back(
            name in "[ -~]{0,24}",
            permissions in prop::collection::vec("[a-zA-Z.:/*<>_]{0,16}", 0..8),
            comment in "[ -~]{0,12}",
        ) {
            let comment = comment.replace("*/", "* /");
            let json = format!(
                "/*{comment}*/{{\"name\": {}, // {comment}\n \"permissions\": {}}}",
                serde_json::json!(name),
                serde_json::json!(permissions),
            );
            let manifest = parse(json.as_bytes()).unwrap();
            prop_assert_eq!(manifest.name, Some(name));
            prop_assert_eq!(manifest.permissions, permissions);
        }
    }
}
