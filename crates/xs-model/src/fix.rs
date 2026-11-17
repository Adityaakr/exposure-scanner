//! What a person can do about a finding, as data a rule pack carries.
//!
//! The scanner applies no fix (project spec, "Fixes"): a report tells a
//! person what they can do, and they do it. What it tells them comes from
//! two places.
//!
//! * The steps that hold for every app of a platform, such as where macOS
//!   lists the apps allowed to use the camera, are fixed in the renderer,
//!   next to the fixed lists of permissions they are about.
//! * What holds for one app or one SDK is data, here, in the rule pack, so a
//!   change to the advice is a change to a signed, versioned file a report
//!   names, like a change to a rule (spec: "Recipes are data").
//!
//! An [`AppFix`] says what an app's publisher documents about turning off
//! the data the app sends: the setting, and where it is, for each category
//! of service it covers; or, just as useful to a reader, that the publisher
//! documents no such setting. An [`SdkFix`] lists hosts an SDK sends to
//! beyond those its rule already names, so a report can say what an
//! outbound firewall would have to block.
//!
//! Every entry cites the publisher's or vendor's own pages, like every rule.
//! An entry is about what those pages say, never a promise about what the
//! app does: a report words it that way.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::record::Platform;
use crate::text;

/// Longest text of a step or of what a publisher says, in bytes. Steps name
/// a few menus and a switch, which takes more than a name.
pub const MAX_STEP_BYTES: usize = 600;

/// The advice of one layer: about apps, and about SDKs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixes {
    /// What publishers document about their own apps.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<AppFix>,
    /// Hosts of SDKs, beyond those their rules name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sdks: Vec<SdkFix>,
}

impl Fixes {
    /// Whether the layer gives no advice at all. A layer without advice
    /// writes no `fixes` key, so its bytes are those of a layer from before
    /// the key existed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty() && self.sdks.is_empty()
    }
}

/// What a publisher documents about turning off what its app sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppFix {
    /// The id of the entry, a hyphenated lowercase name such as `slack`.
    pub id: String,
    /// The app as a reader knows it, such as `Slack`.
    pub name: String,
    /// The builds the entry is about.
    pub apps: Vec<AppKey>,
    /// The settings the publisher documents.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub settings: Vec<Setting>,
    /// What the publisher's pages say about categories they document no
    /// setting for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub no_setting: Vec<NoSetting>,
    /// Apps that do the same job and are widely known for collecting less.
    /// Listed only where that standing is well established, such as a build
    /// of the same source with the telemetry taken out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<Alternative>,
    /// The publisher's pages that show each setting and each statement.
    pub sources: Vec<String>,
}

/// One app a fix is about: its platform and its app id, as a record's
/// subject holds them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppKey {
    /// The platform. Only an app's platform: a browser extension is not an
    /// app, and what a person can do about one is the same for every
    /// extension of a browser.
    pub platform: Platform,
    /// The app id, such as `com.tinyspeck.slackmacgap`. Letter case is
    /// ignored when it is looked up.
    pub id: String,
}

/// A setting that turns off some of what an app sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setting {
    /// The rule-pack categories of the services it turns off, such as
    /// `analytics` or `crash_reporting`. A finding in one of them in the app
    /// is shown with this setting.
    pub covers: Vec<String>,
    /// Where the setting is and what to set it to, in the words of the
    /// app's own menus, such as `Settings > Privacy > Share usage data: off`.
    pub steps: String,
    /// What a reader should know besides, such as that the setting applies
    /// to one account only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// What a publisher's pages say about a category they document no setting
/// for: that there is none, or that the only switch is out of the person's
/// reach, such as one for administrators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoSetting {
    /// The rule-pack categories it is about.
    pub covers: Vec<String>,
    /// What the publisher's pages say, in a sentence.
    pub says: String,
}

/// An app that does the same job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alternative {
    /// Its name.
    pub name: String,
    /// Its website. A report shows it as text and links to nothing.
    pub website: String,
    /// What it is, in a phrase that follows its name, such as `the same
    /// editor built from the same source without the telemetry`.
    pub about: String,
}

/// Hosts an SDK sends to that its rule does not name. A rule names the
/// hosts that are a witness of the SDK in an app's files; the SDK may send
/// to more, and a firewall rule must name them all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdkFix {
    /// The rule id of the SDK, such as `sdk/datadog-rum`.
    pub rule: String,
    /// The hosts, in the one form records store hosts in.
    pub block: Vec<String>,
    /// The vendor's pages that list the hosts.
    pub sources: Vec<String>,
}

/// Whether `id` can be the app id of an [`AppKey`]: letters, digits, dots,
/// hyphens and underscores, as app ids are on both platforms. Letter case
/// is kept, since an id is shown as the publisher wrote it.
#[must_use]
pub fn is_app_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= text::MAX_ID_BYTES
        && id.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

/// Whether `text` can be the text of a step, a note or a statement.
#[must_use]
pub fn is_step_text(text: &str) -> bool {
    !text.is_empty() && text::is_clean(text, MAX_STEP_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_key_ids() {
        for good in ["com.tinyspeck.slackmacgap", "com.Slack", "us.zoom.xos", "notion.id", "a"] {
            assert!(is_app_key_id(good), "{good}");
        }
        for bad in ["", ".com", "com.", "com..x", "com x", "com/x", "com.é"] {
            assert!(!is_app_key_id(bad), "{bad}");
        }
        assert!(!is_app_key_id(&"a".repeat(text::MAX_ID_BYTES + 1)));
    }

    #[test]
    fn step_text() {
        assert!(is_step_text("Settings > Privacy > Usage data: off"));
        assert!(!is_step_text(""));
        assert!(!is_step_text("one\ntwo"));
        assert!(!is_step_text("\u{202e}reversed"));
        assert!(!is_step_text(&"a".repeat(MAX_STEP_BYTES + 1)));
    }

    #[test]
    fn empty_advice_writes_nothing() {
        assert!(Fixes::default().is_empty());
        assert_eq!(crate::canon::to_string(&Fixes::default()).unwrap(), "{}");
    }
}
