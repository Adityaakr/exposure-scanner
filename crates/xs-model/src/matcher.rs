//! The vocabulary rules and proofs share: matcher kinds and token boundaries.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::record::Grade;

/// An independent kind of witness for an SDK (design report, section 5.1).
///
/// Each kind looks in a different place, so each survives a different
/// obstacle: obfuscation, bundling or static linking. A claim counts how many
/// distinct kinds agreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatcherKind {
    /// Component and `meta-data` names in an Android binary manifest.
    ManifestComponent,
    /// Names of classes defined in the DEX `class_defs` table.
    AndroidClassPrefix,
    /// Zip entry names inside an APK.
    ApkFile,
    /// Entries of the DEX string data.
    DexString,
    /// `node_modules/<pkg>/package.json` paths in an asar header.
    NpmPackage,
    /// Literals in script text.
    ContentLiteral,
    /// Folder names under `Contents/Frameworks`.
    AppleFramework,
    /// Library names in Mach-O load commands.
    MachoDylib,
    /// Class names in `__TEXT,__objc_classname`.
    MachoObjcClass,
    /// Literals in the non-code sections of a Mach-O file.
    MachoToken,
    /// Tracking domains declared in a `PrivacyInfo.xcprivacy` file.
    PrivacyManifest,
    /// The host of the update feed an app's own property list names.
    UpdateFeed,
}

impl MatcherKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 12] = [
        Self::ManifestComponent,
        Self::AndroidClassPrefix,
        Self::ApkFile,
        Self::DexString,
        Self::NpmPackage,
        Self::ContentLiteral,
        Self::AppleFramework,
        Self::MachoDylib,
        Self::MachoObjcClass,
        Self::MachoToken,
        Self::PrivacyManifest,
        Self::UpdateFeed,
    ];

    /// The name used in rule files and records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManifestComponent => "manifest_component",
            Self::AndroidClassPrefix => "android_class_prefix",
            Self::ApkFile => "apk_file",
            Self::DexString => "dex_string",
            Self::NpmPackage => "npm_package",
            Self::ContentLiteral => "content_literal",
            Self::AppleFramework => "apple_framework",
            Self::MachoDylib => "macho_dylib",
            Self::MachoObjcClass => "macho_objc_class",
            Self::MachoToken => "macho_token",
            Self::PrivacyManifest => "privacy_manifest",
            Self::UpdateFeed => "update_feed",
        }
    }

    /// Whether this kind searches free-form bytes rather than a parsed table.
    ///
    /// Content matchers are the ones that can hit by coincidence, so the pack
    /// compiler holds their tokens to stricter rules.
    #[must_use]
    pub const fn is_content(self) -> bool {
        matches!(self, Self::DexString | Self::ContentLiteral | Self::MachoToken)
    }

    /// The boundaries a token of this kind may use. The first is the default
    /// for kinds whose tokens may be written as bare strings.
    #[must_use]
    pub const fn boundaries(self) -> &'static [Boundary] {
        match self {
            Self::AndroidClassPrefix => &[Boundary::Prefix],
            Self::ApkFile | Self::NpmPackage | Self::AppleFramework | Self::MachoDylib => {
                &[Boundary::Exact]
            }
            Self::ManifestComponent | Self::MachoObjcClass => &[Boundary::Exact, Boundary::Prefix],
            Self::PrivacyManifest | Self::UpdateFeed => &[Boundary::Exact, Boundary::Host],
            Self::DexString => &[Boundary::Host, Boundary::Word, Boundary::Exact, Boundary::None],
            Self::ContentLiteral | Self::MachoToken => {
                &[Boundary::Host, Boundary::Word, Boundary::None]
            }
        }
    }

    /// The boundary a bare-string token gets, or `None` for content matchers,
    /// whose tokens must state their boundary.
    #[must_use]
    pub const fn default_boundary(self) -> Option<Boundary> {
        if self.is_content() {
            return None;
        }
        match self.boundaries() {
            [first, ..] => Some(*first),
            [] => None,
        }
    }

    /// The grade a hit of this kind supports. A privacy manifest and an
    /// update feed are the app's own declarations; everything else shows
    /// that code is shipped.
    #[must_use]
    pub const fn grade(self) -> Grade {
        match self {
            Self::PrivacyManifest | Self::UpdateFeed => Grade::Declares,
            _ => Grade::Contains,
        }
    }
}

impl fmt::Display for MatcherKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a token must sit in its surroundings to count as a hit.
///
/// This fixed list is all the pattern language there is. A rule is a literal
/// plus one of these, which is data rather than a regular expression, so a
/// rule pack cannot run code or stall the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Boundary {
    /// The literal may occur anywhere.
    None,
    /// The value must start with the literal.
    Prefix,
    /// The value must equal the literal.
    Exact,
    /// The byte before and the byte after must not be an ASCII letter, digit
    /// or underscore. So `sentry.javascript.` hits in `"sentry.javascript."`
    /// and in the template `sentry.javascript.${name}`, and not inside a
    /// longer identifier.
    Word,
    /// The literal must sit on hostname boundaries: the byte before is not a
    /// hostname character unless it is a dot, and the byte after does not
    /// continue the hostname.
    Host,
}

impl Boundary {
    /// The name used in rule files.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Prefix => "prefix",
            Self::Exact => "exact",
            Self::Word => "word",
            Self::Host => "host",
        }
    }
}

impl fmt::Display for Boundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn names_match_the_serialized_form() {
        for kind in MatcherKind::ALL {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, alloc::format!("\"{kind}\""));
            assert_eq!(serde_json::from_str::<MatcherKind>(&json).unwrap(), kind);
        }
        for boundary in
            [Boundary::None, Boundary::Prefix, Boundary::Exact, Boundary::Word, Boundary::Host]
        {
            assert_eq!(serde_json::to_string(&boundary).unwrap(), alloc::format!("\"{boundary}\""));
        }
    }

    #[test]
    fn content_matchers_have_no_default_boundary() {
        for kind in MatcherKind::ALL {
            assert!(!kind.boundaries().is_empty(), "{kind}");
            match kind.default_boundary() {
                Some(boundary) => {
                    assert!(!kind.is_content(), "{kind}");
                    assert_eq!(kind.boundaries().first(), Some(&boundary));
                }
                None => assert!(kind.is_content(), "{kind}"),
            }
        }
        assert_eq!(MatcherKind::ContentLiteral.to_string(), "content_literal");
    }

    #[test]
    fn only_the_app_s_own_declarations_declare() {
        for kind in MatcherKind::ALL {
            let declaration =
                matches!(kind, MatcherKind::PrivacyManifest | MatcherKind::UpdateFeed);
            let expected = if declaration { Grade::Declares } else { Grade::Contains };
            assert_eq!(kind.grade(), expected, "{kind}");
            // A declared host is a whole value: it is matched, not searched.
            assert!(!(declaration && kind.is_content()), "{kind}");
        }
    }
}
