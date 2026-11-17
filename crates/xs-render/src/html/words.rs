//! The vocabulary of the HTML report.
//!
//! Every word the report uses for a grade, a kind of evidence or a reason is
//! in this file, so the wording rule can be checked in one place (project
//! spec, "What can be observed, and what cannot"): the report states graded
//! facts, in the words *declares*, *ships*, *may access*, *contacted* and
//! *confirmed*, and never says more than its evidence supports. It never
//! says what an app or a company intends.

use alloc::format;
use alloc::string::String;

use xs_model::Confidence;
use xs_model::matcher::MatcherKind;
use xs_model::record::{CoverageReason, CoverageStatus, Grade, Platform, Region, Scope};

/// The channel ladder, lowest rung first.
pub(crate) const CHANNEL_LADDER: [Grade; 4] =
    [Grade::Declares, Grade::Contains, Grade::Contacts, Grade::Confirmed];
/// The access ladder, lowest rung first.
pub(crate) const ACCESS_LADDER: [Grade; 3] = [Grade::Requested, Grade::Granted, Grade::Used];

/// The name of a grade, as records and the JSON report spell it.
pub(crate) const fn grade_name(grade: Grade) -> &'static str {
    match grade {
        Grade::Declares => "declares",
        Grade::Contains => "contains",
        Grade::Contacts => "contacts",
        Grade::Confirmed => "confirmed",
        Grade::Requested => "requested",
        Grade::Granted => "granted",
        Grade::Used => "used",
    }
}

/// The class that colours the badge of a grade.
pub(crate) const fn grade_class(grade: Grade) -> &'static str {
    match grade {
        Grade::Declares => "grade g-declares",
        Grade::Contains => "grade g-contains",
        Grade::Contacts => "grade g-contacts",
        Grade::Confirmed => "grade g-confirmed",
        Grade::Requested => "grade g-requested",
        Grade::Granted => "grade g-granted",
        Grade::Used => "grade g-used",
    }
}

/// The graded fact in one or two plain words.
pub(crate) const fn grade_verb(grade: Grade) -> &'static str {
    match grade {
        Grade::Declares => "declares",
        Grade::Contains => "ships",
        Grade::Contacts => "contacted",
        Grade::Confirmed => "confirmed",
        Grade::Requested => "may access",
        Grade::Granted => "may access, allowed",
        Grade::Used => "accessed",
    }
}

/// What a grade shows, and what it does not.
pub(crate) const fn grade_meaning(grade: Grade) -> &'static str {
    match grade {
        Grade::Declares => {
            "The app's own files name this endpoint, for example as the address of its update \
             feed or as a domain in its privacy manifest. A declaration is not an observed \
             connection."
        }
        Grade::Contains => {
            "The app ships this code. That shows the code is present, not that it runs or \
             sends anything."
        }
        Grade::Contacts => "The operating system or a capture recorded a connection.",
        Grade::Confirmed => {
            "The receiver's own records list the app as a sender, or a payload was inspected."
        }
        Grade::Requested => "The app asks for this permission.",
        Grade::Granted => "The permission was allowed on this device.",
        Grade::Used => "The operating system logged an access.",
    }
}

/// The graded fact about a thing found in `apps` of the `scanned` apps:
/// `ships in 10 of 16 apps`.
pub(crate) fn found_words(grade: Grade, apps: u64, scanned: u64) -> String {
    let of = format!("{apps} of {}", plural(scanned, "app", "apps"));
    match grade {
        Grade::Declares => format!("declared by {of}"),
        Grade::Contains => format!("ships in {of}"),
        Grade::Contacts => format!("contacted by {of}"),
        Grade::Confirmed => format!("confirmed for {of}"),
        Grade::Requested => format!("{of} may access it"),
        Grade::Granted => format!("{of} may access it, and it was allowed on this device"),
        Grade::Used => format!("accessed by {of}"),
    }
}

pub(crate) const fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

/// Why a finding has the confidence it has.
pub(crate) const fn confidence_meaning(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::High => "a name read from a structured table, or the app's own declaration",
        Confidence::Medium => "text found in the app's own code or in a binary's data",
        Confidence::Low => "text found inside a bundled library or a resource",
    }
}

pub(crate) const fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::Android => "Android",
        Platform::Macos => "macOS",
        Platform::Chromium => "Chromium-family browser",
        Platform::Firefox => "Firefox",
    }
}

/// What kind of evidence a matcher gives, in plain words.
pub(crate) const fn matcher_words(matcher: MatcherKind) -> &'static str {
    match matcher {
        MatcherKind::ManifestComponent => "A component registered in the app's manifest",
        MatcherKind::AndroidClassPrefix => "Classes defined in the app's code",
        MatcherKind::ApkFile => "A file name inside the package",
        MatcherKind::DexString => "A text constant in the app's code",
        MatcherKind::NpmPackage => "An npm package listed in the app's archive",
        MatcherKind::ContentLiteral => "Text in a script",
        MatcherKind::AppleFramework => "A framework folder",
        MatcherKind::MachoDylib => "A library the binary links",
        MatcherKind::MachoObjcClass => "An Objective-C class name in a binary",
        MatcherKind::MachoToken => "Text in a binary's data",
        MatcherKind::PrivacyManifest => "A tracking domain the privacy manifest declares",
        MatcherKind::UpdateFeed => "The update feed the app's property list declares",
        MatcherKind::UsageDescription => "A usage description in the app's property list",
        MatcherKind::Entitlement => "An entitlement in the app's code signature",
        MatcherKind::AndroidPermission => "A permission the app's manifest asks for",
        MatcherKind::ExtensionManifest => "A permission the extension's manifest asks for",
    }
}

/// The table or section a hit is in, in plain words.
pub(crate) const fn region_words(region: Region) -> &'static str {
    match region {
        Region::ClassDefs => "the table of classes the file defines",
        Region::DirEntries => "the names of the entries of the folder",
        Region::AsarHeader => "the file table of the archive",
        Region::Files => "the contents of its files",
        Region::ObjcClassname => "the section of Objective-C class names",
        Region::LoadCommands => "the load commands, which name linked libraries",
        Region::NonCode => "the bytes outside executable code",
        Region::EmbeddedScript => "a section that holds script text",
        Region::PropertyList => "the value under that key",
        Region::Components => "the components the manifest declares",
        Region::StringIds => "the table of text constants",
        Region::ZipEntries => "the names of the archive's entries",
        Region::Entitlements => "the entitlements in the code signature",
        Region::Permissions => "the permissions the manifest asks for",
        Region::ManifestKey => "the entries the manifest lists under that key",
    }
}

/// What kind of code a file holds, in plain words.
pub(crate) const fn scope_words(scope: Scope) -> &'static str {
    match scope {
        Scope::AppCode => "the app's own code",
        Scope::Dependency => "a library shipped with the app",
        Scope::Runtime => "a language runtime or browser engine",
        Scope::Resource => "a data or documentation file",
    }
}

/// How often a marker was found. In the contents of files the count is of
/// files; anywhere else it is of matches.
pub(crate) fn count_words(region: Region, count: u32) -> String {
    match region {
        Region::Files => plural(count.into(), "file", "files"),
        _ => plural(count.into(), "match", "matches"),
    }
}

/// Why something was not covered, in plain words.
pub(crate) const fn reason_words(reason: CoverageReason) -> &'static str {
    match reason {
        CoverageReason::NoPrivilege => "The scanner lacks the permission this needs.",
        CoverageReason::EncryptedBinary => {
            "The binary is encrypted. Its bytes are ciphertext, so they were not searched."
        }
        CoverageReason::OverBudget => "It is over one of the scanner's limits of size or count.",
        CoverageReason::ParseError => "It is damaged, or is not the format its name says.",
        CoverageReason::SupersededVersion => {
            "Older versions of the extension, left for the browser to remove, were not scanned."
        }
        CoverageReason::UnexpectedCase => {
            "Its name differs only in letter case from the one an app's layout fixes, so it \
             was not read as that part of the app."
        }
        CoverageReason::UnrecognizedRecord => {
            "It holds a record of a shape this version does not know."
        }
        CoverageReason::Unreadable => "The file system refused the read.",
        CoverageReason::UnsupportedFormat => "This version has no reader for the format.",
    }
}

pub(crate) const fn status_words(status: CoverageStatus) -> &'static str {
    match status {
        CoverageStatus::Skipped => "Not read",
        CoverageStatus::Unrecognized => "Read, not understood",
    }
}

/// `count` with the right form of a noun: `1 app`, `3 apps`.
pub(crate) fn plural(count: u64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// A size for a reader: `676 bytes`, `4.9 kB`, `68.2 MB`. Decimal units, cut
/// and not rounded, by whole-number arithmetic. The exact number is in the
/// record.
pub(crate) fn size_words(bytes: u64) -> String {
    const UNITS: [(u64, &str); 3] = [(1_000_000_000, "GB"), (1_000_000, "MB"), (1_000, "kB")];
    for (unit, name) in UNITS {
        if bytes >= unit {
            let tenths = bytes / (unit / 10);
            return format!("{}.{} {name}", tenths / 10, tenths % 10);
        }
    }
    plural(bytes, "byte", "bytes")
}

/// `["a"]` as `a`, `["a", "b"]` as `a and b`, `["a", "b", "c"]` as
/// `a, b and c`.
pub(crate) fn list_words(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [only] => String::from(*only),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The first twelve characters of a hex digest, for link text. The whole
/// digest is one click away.
pub(crate) fn short(hex: &str) -> &str {
    hex.get(..12).unwrap_or(hex)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn grade_names_are_the_serialized_names() {
        for grade in CHANNEL_LADDER.into_iter().chain(ACCESS_LADDER) {
            let json = serde_json::to_string(&grade).unwrap();
            assert_eq!(json, format!("\"{}\"", grade_name(grade)));
        }
        assert!(CHANNEL_LADDER.is_sorted() && ACCESS_LADDER.is_sorted());
    }

    #[test]
    fn confidence_names_are_the_serialized_names() {
        for confidence in [Confidence::Low, Confidence::Medium, Confidence::High] {
            let json = serde_json::to_string(&confidence).unwrap();
            assert_eq!(json, format!("\"{}\"", confidence_name(confidence)));
        }
    }

    /// The wording rule: graded facts, in the spec's own words.
    #[test]
    fn the_graded_facts_are_the_spec_s_words() {
        assert_eq!(grade_verb(Grade::Contains), "ships");
        assert_eq!(grade_verb(Grade::Requested), "may access");
        assert_eq!(grade_verb(Grade::Contacts), "contacted");
        assert_eq!(grade_verb(Grade::Confirmed), "confirmed");
    }

    /// What the summary says of a thing found in some of the apps: the same
    /// graded facts, with the count. The words are the project spec's
    /// (declares, ships, may access, contacted, confirmed).
    #[test]
    fn a_thing_found_is_stated_as_a_graded_fact_with_its_count() {
        assert_eq!(found_words(Grade::Declares, 1, 16), "declared by 1 of 16 apps");
        assert_eq!(found_words(Grade::Contains, 10, 16), "ships in 10 of 16 apps");
        assert_eq!(found_words(Grade::Contacts, 2, 3), "contacted by 2 of 3 apps");
        assert_eq!(found_words(Grade::Confirmed, 1, 1), "confirmed for 1 of 1 app");
        assert_eq!(found_words(Grade::Requested, 3, 16), "3 of 16 apps may access it");
        assert_eq!(
            found_words(Grade::Granted, 1, 2),
            "1 of 2 apps may access it, and it was allowed on this device"
        );
        assert_eq!(found_words(Grade::Used, 1, 2), "accessed by 1 of 2 apps");
    }

    /// No word in the vocabulary says what an app or company intends.
    #[test]
    fn nothing_in_the_vocabulary_accuses() {
        let mut words: Vec<String> = Vec::new();
        for grade in CHANNEL_LADDER.into_iter().chain(ACCESS_LADDER) {
            words.push(found_words(grade, 2, 3));
            words.push(grade_verb(grade).to_string());
            words.push(grade_meaning(grade).to_string());
        }
        for matcher in MatcherKind::ALL {
            words.push(matcher_words(matcher).to_string());
        }
        for confidence in [Confidence::Low, Confidence::Medium, Confidence::High] {
            words.push(confidence_meaning(confidence).to_string());
        }
        for text in words {
            let lowercase = text.to_lowercase();
            for banned in ["spy", "spies", "steal", "leak", "surveil", "snoop", "track you"] {
                assert!(!lowercase.contains(banned), "`{banned}` in: {text}");
            }
        }
    }

    #[test]
    fn counts_take_the_right_form_of_the_noun() {
        assert_eq!(plural(0, "app", "apps"), "0 apps");
        assert_eq!(plural(1, "app", "apps"), "1 app");
        assert_eq!(plural(2, "company", "companies"), "2 companies");
        assert_eq!(count_words(Region::Files, 1), "1 file");
        assert_eq!(count_words(Region::ClassDefs, 2), "2 matches");
    }

    #[test]
    fn sizes_are_cut_to_one_decimal() {
        assert_eq!(size_words(0), "0 bytes");
        assert_eq!(size_words(1), "1 byte");
        assert_eq!(size_words(999), "999 bytes");
        assert_eq!(size_words(1_000), "1.0 kB");
        assert_eq!(size_words(4_959), "4.9 kB");
        assert_eq!(size_words(68_219_904), "68.2 MB");
        assert_eq!(size_words(2_147_483_649), "2.1 GB");
        assert_eq!(size_words(u64::MAX), "18446744073.7 GB");
    }

    #[test]
    fn lists_read_as_a_sentence_does() {
        assert_eq!(list_words(&[]), "");
        assert_eq!(list_words(&["a"]), "a");
        assert_eq!(list_words(&["a", "b"]), "a and b");
        assert_eq!(list_words(&["a", "b", "c"]), "a, b and c");
    }

    #[test]
    fn a_short_id_is_a_prefix() {
        assert_eq!(short("0123456789abcdef"), "0123456789ab");
        assert_eq!(short("abc"), "abc");
    }
}
