//! What a browser extension may be allowed to reach: the objects of the
//! access edges the extension collector emits.
//!
//! An extension says in its manifest what it wants from the browser: the
//! sites it runs on and the browser interfaces it calls. The collector reads
//! those fixed keys, so the list below is part of the scanner and not of the
//! rule pack, like the built-in rules behind declared hosts
//! ([`declared`](crate::record::declared)). A rule pack cannot add to it or
//! take from it.
//!
//! Only what gives an extension a wide view of what a person does in the
//! browser is listed. A manifest names many more permissions (`storage`,
//! `alarms`, `activeTab`), and a site pattern that names single sites is not
//! reported: the report is about breadth, not about every site an extension
//! was written for.
//!
//! **Grade.** A manifest is what the extension asks for, so every edge is
//! graded `requested`. Whether the browser holds the permission now is not
//! read: a key such as `permissions` is granted when the extension is
//! installed, an `optional_` key only once the extension asks while it runs
//! and the person agrees, and a person can narrow site access afterwards.
//! The proof names the key, and a claim that rests on optional keys alone
//! carries the note [`NOTE_OPTIONAL`].

use core::fmt;

use serde::{Deserialize, Serialize};

/// The id of the built-in rule behind every edge to a [`Permission`]. It
/// cannot collide with a pack rule, whose id starts with `sdk/`.
pub const RULE: &str = "declared/extension-permission";

/// The category id of every claim about a [`Permission`]. It is not one of
/// the rule pack's categories: those say what a company's code is for, and
/// rank channels. An access has no company and counts in no headline.
pub const CATEGORY: &str = "extension_permission";

/// The name of [`CATEGORY`], for a reader.
pub const CATEGORY_NAME: &str = "Browser extension permission";

/// The note on a claim whose every record comes from an optional manifest
/// key: the extension does not hold the permission until it asks for it
/// while it runs and the person agrees.
pub const NOTE_OPTIONAL: &str = "optional";

/// Something a browser extension's manifest asks the browser for.
///
/// The variants are declared in the order a report lists them: the two that
/// cover page content first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    /// A site pattern that covers every website: `<all_urls>`, or a pattern
    /// such as `https://*/*` or `*://*/*`.
    AllSites,
    /// A site pattern with a wildcard for the whole host that still covers
    /// less than every website: only `http`, only some paths, only pages a
    /// further filter lets through, or every site under one public suffix
    /// such as `*://*.com/*`.
    BroadSites,
    /// `history`: the browsing history.
    History,
    /// `tabs`: the address and title of every open tab.
    Tabs,
    /// `webNavigation`: the address of each page as it is opened.
    WebNavigation,
    /// `webRequest`, with or without `webRequestBlocking`: the requests
    /// pages make.
    WebRequest,
    /// `cookies`: the cookies of the sites the extension can reach.
    Cookies,
    /// `clipboardRead`: what was copied.
    ClipboardRead,
    /// `clipboardWrite`: what will be pasted.
    ClipboardWrite,
    /// `downloads`, with or without `downloads.open`: downloaded files.
    Downloads,
    /// `nativeMessaging`: a program installed on the computer.
    NativeMessaging,
    /// `management`: the other extensions.
    Management,
    /// `debugger`: the browser's debugger, attached to a page.
    Debugger,
    /// `proxy`: the proxy the browser's traffic goes through.
    Proxy,
}

impl Permission {
    /// Every permission, in declaration order.
    pub const ALL: [Self; 14] = [
        Self::AllSites,
        Self::BroadSites,
        Self::History,
        Self::Tabs,
        Self::WebNavigation,
        Self::WebRequest,
        Self::Cookies,
        Self::ClipboardRead,
        Self::ClipboardWrite,
        Self::Downloads,
        Self::NativeMessaging,
        Self::Management,
        Self::Debugger,
        Self::Proxy,
    ];

    /// The id of the object of an edge to this permission.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::AllSites => "extension/all-sites",
            Self::BroadSites => "extension/broad-sites",
            Self::History => "extension/history",
            Self::Tabs => "extension/tabs",
            Self::WebNavigation => "extension/web-navigation",
            Self::WebRequest => "extension/web-request",
            Self::Cookies => "extension/cookies",
            Self::ClipboardRead => "extension/clipboard-read",
            Self::ClipboardWrite => "extension/clipboard-write",
            Self::Downloads => "extension/downloads",
            Self::NativeMessaging => "extension/native-messaging",
            Self::Management => "extension/management",
            Self::Debugger => "extension/debugger",
            Self::Proxy => "extension/proxy",
        }
    }

    /// The permission with this object id.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|permission| permission.id() == id)
    }

    /// The permission a manifest asks for by this name in `permissions` or
    /// `optional_permissions`. Names are case-sensitive, as they are to the
    /// browser. A name that is not on the list, and a site pattern, give
    /// `None`.
    #[must_use]
    pub fn from_manifest_name(name: &str) -> Option<Self> {
        Some(match name {
            "history" => Self::History,
            "tabs" => Self::Tabs,
            "webNavigation" => Self::WebNavigation,
            "webRequest" | "webRequestBlocking" => Self::WebRequest,
            "cookies" => Self::Cookies,
            "clipboardRead" => Self::ClipboardRead,
            "clipboardWrite" => Self::ClipboardWrite,
            "downloads" | "downloads.open" => Self::Downloads,
            "nativeMessaging" => Self::NativeMessaging,
            "management" => Self::Management,
            "debugger" => Self::Debugger,
            "proxy" => Self::Proxy,
            _ => return None,
        })
    }

    /// What is reached, as the name of a claim's object.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AllSites => "Every website",
            Self::BroadSites => "A broad set of websites",
            Self::History => "Browsing history",
            Self::Tabs => "Open tabs",
            Self::WebNavigation => "Page visits",
            Self::WebRequest => "Network requests",
            Self::Cookies => "Cookies",
            Self::ClipboardRead => "Clipboard, reading",
            Self::ClipboardWrite => "Clipboard, writing",
            Self::Downloads => "Downloads",
            Self::NativeMessaging => "Programs on this computer",
            Self::Management => "Other extensions",
            Self::Debugger => "Page debugger",
            Self::Proxy => "Proxy settings",
        }
    }

    /// What the permission lets an extension do, worded to follow "may":
    /// "This extension may read and change data on every website you visit".
    ///
    /// The words say what the browser allows an extension that holds the
    /// permission, and nothing about what a given extension does with it.
    #[must_use]
    pub const fn allows(self) -> &'static str {
        match self {
            Self::AllSites => "read and change data on every website you visit",
            Self::BroadSites => {
                "read and change data on a broad set of websites: every site under one domain \
                 ending, or part of every site"
            }
            Self::History => "read and change your browsing history",
            Self::Tabs => "see the address and title of every tab you have open",
            Self::WebNavigation => "see the address of each page as you open it",
            Self::WebRequest => "watch the network requests of the sites it can reach",
            Self::Cookies => "read and change the cookies of the sites it can reach",
            Self::ClipboardRead => "read what you copy",
            Self::ClipboardWrite => "replace what is on your clipboard",
            Self::Downloads => "start downloads and see what you have downloaded",
            Self::NativeMessaging => "exchange messages with a program installed on this computer",
            Self::Management => "see, switch on and switch off your other extensions",
            Self::Debugger => {
                "attach the browser's debugger to a page, which can read and change everything \
                 in it"
            }
            Self::Proxy => "route the browser's traffic through a proxy it chooses",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// The key of an extension manifest a permission was read from. It is the
/// `token` of the proof, so a reader can open `manifest.json` and find the
/// entry under that key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestKey {
    /// `permissions`: interface names, and in a version 2 manifest site
    /// patterns too. Granted when the extension is installed.
    Permissions,
    /// `host_permissions`: the site patterns of a version 3 manifest.
    HostPermissions,
    /// `content_scripts`: the `matches` of the scripts the browser runs in
    /// pages by itself.
    ContentScripts,
    /// `optional_permissions`: what the extension may ask for while it runs.
    OptionalPermissions,
    /// `optional_host_permissions`: the site patterns it may ask for while
    /// it runs.
    OptionalHostPermissions,
}

impl ManifestKey {
    /// Every key, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Permissions,
        Self::HostPermissions,
        Self::ContentScripts,
        Self::OptionalPermissions,
        Self::OptionalHostPermissions,
    ];

    /// The key as the manifest spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permissions => "permissions",
            Self::HostPermissions => "host_permissions",
            Self::ContentScripts => "content_scripts",
            Self::OptionalPermissions => "optional_permissions",
            Self::OptionalHostPermissions => "optional_host_permissions",
        }
    }

    /// The key with this spelling.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|key| key.as_str() == name)
    }

    /// Whether the key lists what the extension may ask for while it runs,
    /// which it does not hold until the person agrees.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(self, Self::OptionalPermissions | Self::OptionalHostPermissions)
    }
}

impl fmt::Display for ManifestKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use alloc::format;
    use alloc::string::ToString;

    use super::*;
    use crate::text;

    #[test]
    fn ids_are_distinct_and_round_trip() {
        let ids: BTreeSet<&str> =
            Permission::ALL.iter().map(|permission| permission.id()).collect();
        assert_eq!(ids.len(), Permission::ALL.len());
        for permission in Permission::ALL {
            assert_eq!(Permission::from_id(permission.id()), Some(permission));
            assert_eq!(permission.to_string(), permission.id());
            assert!(permission.id().starts_with("extension/"), "{permission}");
            assert!(text::is_clean(permission.id(), text::MAX_ID_BYTES));
        }
        // An id is not a manifest name, and no id is a rule id of a pack.
        assert_eq!(Permission::from_id("history"), None);
        assert_eq!(Permission::from_id("sdk/sentry"), None);
        assert!(!RULE.starts_with("sdk/"));
    }

    #[test]
    fn manifest_names_are_matched_as_the_browser_spells_them() {
        let named = |name| Permission::from_manifest_name(name);
        assert_eq!(named("history"), Some(Permission::History));
        assert_eq!(named("webRequest"), Some(Permission::WebRequest));
        assert_eq!(named("webRequestBlocking"), Some(Permission::WebRequest));
        assert_eq!(named("downloads.open"), Some(Permission::Downloads));
        assert_eq!(named("nativeMessaging"), Some(Permission::NativeMessaging));
        // Not powerful, a site pattern, or another spelling.
        for other in
            ["storage", "activeTab", "scripting", "<all_urls>", "History", "webrequest", ""]
        {
            assert_eq!(named(other), None, "{other}");
        }
        // Site access is never a manifest name: it is read from patterns.
        let from_names: BTreeSet<Permission> = [
            "history",
            "tabs",
            "webNavigation",
            "webRequest",
            "cookies",
            "clipboardRead",
            "clipboardWrite",
            "downloads",
            "nativeMessaging",
            "management",
            "debugger",
            "proxy",
        ]
        .into_iter()
        .filter_map(Permission::from_manifest_name)
        .collect();
        let expected: BTreeSet<Permission> = Permission::ALL
            .into_iter()
            .filter(|permission| {
                !matches!(permission, Permission::AllSites | Permission::BroadSites)
            })
            .collect();
        assert_eq!(from_names, expected);
    }

    /// The wording rule (project spec): graded facts, never intent. The
    /// words follow "may", so they start with a verb in lower case and
    /// accuse nobody.
    #[test]
    fn the_words_follow_may_and_say_nothing_of_intent() {
        for permission in Permission::ALL {
            let allows = permission.allows();
            assert!(allows.starts_with(|first: char| first.is_ascii_lowercase()), "{allows}");
            assert!(!allows.ends_with('.'), "{allows}");
            let sentence = format!("This extension may {allows}.").to_lowercase();
            for banned in ["spy", "steal", "track", "snoop", "malicious"] {
                assert!(!sentence.contains(banned), "{sentence}");
            }
            assert!(!permission.name().is_empty());
        }
        assert_eq!(
            Permission::AllSites.allows(),
            "read and change data on every website you visit"
        );
    }

    #[test]
    fn manifest_keys_round_trip_and_know_which_are_optional() {
        for key in ManifestKey::ALL {
            assert_eq!(ManifestKey::from_name(key.as_str()), Some(key));
            assert_eq!(serde_json::to_string(&key).unwrap(), format!("\"{key}\""));
            assert_eq!(key.is_optional(), key.as_str().starts_with("optional_"), "{key}");
        }
        assert_eq!(ManifestKey::from_name("Permissions"), None);
        assert_eq!(ManifestKey::from_name("content_scripts.matches"), None);
    }
}
