//! What an app may access: the vocabulary of access edges.
//!
//! A channel edge points at an SDK a rule of the pack names. An access edge
//! points at a **permission**: something on the device the app has asked to
//! reach, such as the camera, the contacts or the network. An app asks in
//! one of three places, and each is a kind of witness of its own:
//!
//! * a usage description in the `Info.plist` of a macOS bundle
//!   ([`MatcherKind::UsageDescription`]), which is the sentence macOS shows
//!   when it asks the user;
//! * an entitlement in the code signature of the bundle's main executable
//!   ([`MatcherKind::Entitlement`]);
//! * a `uses-permission` element in an Android manifest
//!   ([`MatcherKind::AndroidPermission`]).
//!
//! All three say what the app **may** access, graded
//! [`requested`](crate::record::Grade::Requested). None says that the user
//! allowed it or that the app ever did it, and a report words it that way:
//! "may access", never more.
//!
//! The vocabulary is fixed here and not in the rule pack. The keys are the
//! platforms' own, they map to nothing a company could dispute, and a record
//! is checked against this table when it enters an evidence set: an edge to
//! a permission must rest on a key that names that permission.
//!
//! A permission has a category, which groups it with its like for a summary.
//! These categories are a list of their own, apart from the categories of
//! the rule pack, which describe channels.

use crate::matcher::MatcherKind;
use crate::text;

/// One thing on a device that an app can ask to reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permission {
    /// Its id, the object id of an access edge, such as `camera`.
    pub id: &'static str,
    /// Its name as a heading or a table cell, such as `Camera`.
    pub name: &'static str,
    /// Its name inside a sentence, after "may access", such as
    /// `your camera`.
    pub phrase: &'static str,
    /// The id of its [`Category`].
    pub category: &'static str,
}

/// A group of permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Category {
    /// Its id, the category of an access claim, such as `capture`.
    pub id: &'static str,
    /// Its name as a heading.
    pub name: &'static str,
}

/// The entitlement that puts a macOS app in the App Sandbox. It is no
/// permission: it is recorded as a fact about the app, because it decides
/// what the other entitlements mean. Outside the sandbox an app needs no
/// entitlement to open a connection or to read a file the user's account
/// can read.
pub const SANDBOX_ENTITLEMENT: &str = "com.apple.security.app-sandbox";

/// The names of Android's health permissions start with this, one per kind
/// of record. All of them are the permission `health`.
const ANDROID_HEALTH_PREFIX: &str = "android.permission.health.";

/// The categories, in the order a report lists them.
pub const CATEGORIES: [Category; 10] = [
    Category { id: "capture", name: "Camera, microphone and screen" },
    Category { id: "location", name: "Location" },
    Category { id: "personal_data", name: "Personal data" },
    Category { id: "communications", name: "Calls and messages" },
    Category { id: "files", name: "Files and folders" },
    Category { id: "network", name: "Network" },
    Category { id: "nearby_devices", name: "Nearby devices" },
    Category { id: "system_control", name: "Control of other apps and the system" },
    Category { id: "tracking", name: "Tracking identifiers" },
    Category { id: "authentication", name: "Authentication" },
];

const fn permission_of(
    id: &'static str,
    name: &'static str,
    phrase: &'static str,
    category: &'static str,
) -> Permission {
    Permission { id, name, phrase, category }
}

/// Every permission, in id order.
pub const PERMISSIONS: [Permission; 52] = [
    permission_of("accounts", "Accounts", "the list of accounts on your device", "personal_data"),
    permission_of(
        "advertising-id",
        "Advertising identifier",
        "your advertising identifier, which links your activity across apps",
        "tracking",
    ),
    permission_of("all-files", "All files", "all your files", "files"),
    permission_of(
        "app-usage",
        "App usage",
        "which apps you use and for how long",
        "system_control",
    ),
    permission_of(
        "automation",
        "Automation of other apps",
        "other apps, to control them",
        "system_control",
    ),
    permission_of(
        "biometrics",
        "Face or fingerprint unlock",
        "the face or fingerprint reader, to confirm it is you",
        "authentication",
    ),
    permission_of("bluetooth", "Bluetooth", "Bluetooth devices nearby", "nearby_devices"),
    permission_of(
        "body-sensors",
        "Body sensors",
        "body sensors such as a heart-rate monitor",
        "personal_data",
    ),
    permission_of("calendars", "Calendars", "your calendars", "personal_data"),
    permission_of(
        "calendars-add",
        "Calendars (add only)",
        "your calendars, to add events",
        "personal_data",
    ),
    permission_of("call-log", "Call history", "your call history", "communications"),
    permission_of("camera", "Camera", "your camera", "capture"),
    permission_of("contacts", "Contacts", "your contacts", "personal_data"),
    permission_of("desktop-folder", "Desktop folder", "your Desktop folder", "files"),
    permission_of("documents-folder", "Documents folder", "your Documents folder", "files"),
    permission_of("downloads-folder", "Downloads folder", "your Downloads folder", "files"),
    permission_of(
        "file-provider",
        "Cloud file storage",
        "files that a cloud storage provider manages",
        "files",
    ),
    permission_of(
        "focus-status",
        "Focus status",
        "whether you have a Focus turned on",
        "personal_data",
    ),
    permission_of("health", "Health data", "your health data", "personal_data"),
    permission_of("homekit", "HomeKit", "the HomeKit accessories of your home", "nearby_devices"),
    permission_of(
        "installed-apps",
        "Installed apps",
        "the list of apps you have installed",
        "system_control",
    ),
    permission_of(
        "local-network",
        "Local network",
        "devices on your local network",
        "nearby_devices",
    ),
    permission_of("location", "Location", "your location", "location"),
    permission_of(
        "location-background",
        "Location in the background",
        "your location while the app is in the background",
        "location",
    ),
    permission_of(
        "media-library",
        "Media library",
        "your music and media library",
        "personal_data",
    ),
    permission_of("microphone", "Microphone", "your microphone", "capture"),
    permission_of(
        "motion",
        "Motion and fitness",
        "your motion and physical activity",
        "personal_data",
    ),
    permission_of("movies-folder", "Movies folder", "your Movies folder", "files"),
    permission_of("music-folder", "Music folder", "your Music folder", "files"),
    permission_of(
        "nearby-devices",
        "Nearby devices",
        "nearby devices over Wi-Fi or ultra-wideband",
        "nearby_devices",
    ),
    permission_of(
        "network-client",
        "Network (outgoing)",
        "the network, to open connections",
        "network",
    ),
    permission_of(
        "network-server",
        "Network (incoming)",
        "the network, to accept connections",
        "network",
    ),
    permission_of("network-volumes", "Network drives", "files on network drives", "files"),
    permission_of("nfc", "NFC", "NFC tags and readers", "nearby_devices"),
    permission_of("other-apps-data", "Data of other apps", "data that other apps store", "files"),
    permission_of(
        "phone-calls",
        "Phone calls",
        "phone calls, to place and manage them",
        "communications",
    ),
    permission_of(
        "phone-state",
        "Phone number and status",
        "your phone number and call status",
        "communications",
    ),
    permission_of("photos", "Photos", "your photos and videos", "personal_data"),
    permission_of(
        "photos-add",
        "Photos (add only)",
        "your photo library, to add to it",
        "personal_data",
    ),
    permission_of("pictures-folder", "Pictures folder", "your Pictures folder", "files"),
    permission_of("reminders", "Reminders", "your reminders", "personal_data"),
    permission_of("removable-volumes", "Removable drives", "files on removable drives", "files"),
    permission_of(
        "sandbox-exception-files",
        "Files outside the sandbox",
        "files and folders outside its sandbox that its signature lists",
        "files",
    ),
    permission_of("screen", "Screen capture", "your screen", "capture"),
    permission_of("shared-storage", "Shared storage", "files in shared storage", "files"),
    permission_of("siri", "Siri", "Siri, to handle requests you make", "personal_data"),
    permission_of("sms", "Text messages", "your text messages", "communications"),
    permission_of(
        "speech-recognition",
        "Speech recognition",
        "speech recognition of what you say",
        "capture",
    ),
    permission_of(
        "system-administration",
        "System administration",
        "system settings, to change them as an administrator",
        "system_control",
    ),
    permission_of("system-audio", "System audio", "the sound your device plays", "capture"),
    permission_of("usb", "USB devices", "USB devices", "nearby_devices"),
    permission_of("user-selected-files", "Files you select", "files you select", "files"),
];

/// The usage-description keys of an `Info.plist`, each with the permission
/// it asks for (Apple, "Protected resources").
const USAGE_DESCRIPTIONS: &[(&str, &str)] = &[
    ("NFCReaderUsageDescription", "nfc"),
    ("NSAppDataUsageDescription", "other-apps-data"),
    ("NSAppleEventsUsageDescription", "automation"),
    ("NSAppleMusicUsageDescription", "media-library"),
    ("NSAudioCaptureUsageDescription", "system-audio"),
    ("NSBluetoothAlwaysUsageDescription", "bluetooth"),
    ("NSBluetoothPeripheralUsageDescription", "bluetooth"),
    ("NSCalendarsFullAccessUsageDescription", "calendars"),
    ("NSCalendarsUsageDescription", "calendars"),
    ("NSCalendarsWriteOnlyAccessUsageDescription", "calendars-add"),
    ("NSCameraUsageDescription", "camera"),
    ("NSContactsUsageDescription", "contacts"),
    ("NSDesktopFolderUsageDescription", "desktop-folder"),
    ("NSDocumentsFolderUsageDescription", "documents-folder"),
    ("NSDownloadsFolderUsageDescription", "downloads-folder"),
    ("NSFaceIDUsageDescription", "biometrics"),
    ("NSFileProviderDomainUsageDescription", "file-provider"),
    ("NSFocusStatusUsageDescription", "focus-status"),
    ("NSHealthClinicalHealthRecordsShareUsageDescription", "health"),
    ("NSHealthShareUsageDescription", "health"),
    ("NSHealthUpdateUsageDescription", "health"),
    ("NSHomeKitUsageDescription", "homekit"),
    ("NSLocalNetworkUsageDescription", "local-network"),
    ("NSLocationAlwaysAndWhenInUseUsageDescription", "location"),
    ("NSLocationAlwaysUsageDescription", "location"),
    ("NSLocationUsageDescription", "location"),
    ("NSLocationWhenInUseUsageDescription", "location"),
    ("NSMicrophoneUsageDescription", "microphone"),
    ("NSMotionUsageDescription", "motion"),
    ("NSNearbyInteractionUsageDescription", "nearby-devices"),
    ("NSNetworkVolumesUsageDescription", "network-volumes"),
    ("NSPhotoLibraryAddUsageDescription", "photos-add"),
    ("NSPhotoLibraryUsageDescription", "photos"),
    ("NSRemindersFullAccessUsageDescription", "reminders"),
    ("NSRemindersUsageDescription", "reminders"),
    ("NSRemovableVolumesUsageDescription", "removable-volumes"),
    ("NSSiriUsageDescription", "siri"),
    ("NSSpeechRecognitionUsageDescription", "speech-recognition"),
    ("NSSystemAdministrationUsageDescription", "system-administration"),
    ("NSUserTrackingUsageDescription", "advertising-id"),
];

/// The entitlements of a code signature that ask for a permission. The
/// device and personal-information keys apply inside the App Sandbox and
/// under the hardened runtime alike; the network and file keys only mean
/// something inside the sandbox (see [`SANDBOX_ENTITLEMENT`]).
const ENTITLEMENTS: &[(&str, &str)] = &[
    ("com.apple.developer.healthkit", "health"),
    ("com.apple.developer.homekit", "homekit"),
    ("com.apple.developer.persistent-content-capture", "screen"),
    ("com.apple.security.assets.movies.read-only", "movies-folder"),
    ("com.apple.security.assets.movies.read-write", "movies-folder"),
    ("com.apple.security.assets.music.read-only", "music-folder"),
    ("com.apple.security.assets.music.read-write", "music-folder"),
    ("com.apple.security.assets.pictures.read-only", "pictures-folder"),
    ("com.apple.security.assets.pictures.read-write", "pictures-folder"),
    ("com.apple.security.automation.apple-events", "automation"),
    ("com.apple.security.device.audio-input", "microphone"),
    ("com.apple.security.device.bluetooth", "bluetooth"),
    ("com.apple.security.device.camera", "camera"),
    ("com.apple.security.device.microphone", "microphone"),
    ("com.apple.security.device.usb", "usb"),
    ("com.apple.security.files.all", "all-files"),
    ("com.apple.security.files.downloads.read-only", "downloads-folder"),
    ("com.apple.security.files.downloads.read-write", "downloads-folder"),
    ("com.apple.security.files.user-selected.read-only", "user-selected-files"),
    ("com.apple.security.files.user-selected.read-write", "user-selected-files"),
    ("com.apple.security.network.client", "network-client"),
    ("com.apple.security.network.server", "network-server"),
    ("com.apple.security.personal-information.addressbook", "contacts"),
    ("com.apple.security.personal-information.calendars", "calendars"),
    ("com.apple.security.personal-information.location", "location"),
    ("com.apple.security.personal-information.photos-library", "photos"),
    ("com.apple.security.temporary-exception.apple-events", "automation"),
    (
        "com.apple.security.temporary-exception.files.absolute-path.read-only",
        "sandbox-exception-files",
    ),
    (
        "com.apple.security.temporary-exception.files.absolute-path.read-write",
        "sandbox-exception-files",
    ),
    (
        "com.apple.security.temporary-exception.files.home-relative-path.read-only",
        "sandbox-exception-files",
    ),
    (
        "com.apple.security.temporary-exception.files.home-relative-path.read-write",
        "sandbox-exception-files",
    ),
];

/// The permissions of an Android manifest that reach the user's data or
/// devices: those Android calls dangerous and asks the user about, and a few
/// it grants without asking that say as much (the network, the advertising
/// identifier, the list of installed apps, screen capture, the fingerprint
/// reader). Posting
/// notifications is asked about too, and is left out: it gives the app
/// nothing of the user's.
const ANDROID_PERMISSIONS: &[(&str, &str)] = &[
    ("android.permission.ACCEPT_HANDOVER", "phone-calls"),
    ("android.permission.ACCESS_BACKGROUND_LOCATION", "location-background"),
    ("android.permission.ACCESS_COARSE_LOCATION", "location"),
    ("android.permission.ACCESS_FINE_LOCATION", "location"),
    ("android.permission.ACCESS_LOCAL_NETWORK", "local-network"),
    ("android.permission.ACCESS_MEDIA_LOCATION", "location"),
    ("android.permission.ACTIVITY_RECOGNITION", "motion"),
    ("android.permission.ADD_VOICEMAIL", "phone-calls"),
    ("android.permission.ANSWER_PHONE_CALLS", "phone-calls"),
    ("android.permission.BLUETOOTH_ADVERTISE", "bluetooth"),
    ("android.permission.BLUETOOTH_CONNECT", "bluetooth"),
    ("android.permission.BLUETOOTH_SCAN", "bluetooth"),
    ("android.permission.BODY_SENSORS", "body-sensors"),
    ("android.permission.BODY_SENSORS_BACKGROUND", "body-sensors"),
    ("android.permission.CALL_PHONE", "phone-calls"),
    ("android.permission.CAMERA", "camera"),
    ("android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION", "screen"),
    ("android.permission.GET_ACCOUNTS", "accounts"),
    ("android.permission.INTERNET", "network-client"),
    ("android.permission.MANAGE_EXTERNAL_STORAGE", "all-files"),
    ("android.permission.NEARBY_WIFI_DEVICES", "nearby-devices"),
    ("android.permission.NFC", "nfc"),
    ("android.permission.PACKAGE_USAGE_STATS", "app-usage"),
    ("android.permission.PROCESS_OUTGOING_CALLS", "call-log"),
    ("android.permission.QUERY_ALL_PACKAGES", "installed-apps"),
    ("android.permission.READ_CALENDAR", "calendars"),
    ("android.permission.READ_CALL_LOG", "call-log"),
    ("android.permission.READ_CONTACTS", "contacts"),
    ("android.permission.READ_EXTERNAL_STORAGE", "shared-storage"),
    ("android.permission.READ_MEDIA_AUDIO", "media-library"),
    ("android.permission.READ_MEDIA_IMAGES", "photos"),
    ("android.permission.READ_MEDIA_VIDEO", "photos"),
    ("android.permission.READ_MEDIA_VISUAL_USER_SELECTED", "photos"),
    ("android.permission.READ_PHONE_NUMBERS", "phone-state"),
    ("android.permission.READ_PHONE_STATE", "phone-state"),
    ("android.permission.READ_SMS", "sms"),
    ("android.permission.RECEIVE_MMS", "sms"),
    ("android.permission.RECEIVE_SMS", "sms"),
    ("android.permission.RECEIVE_WAP_PUSH", "sms"),
    ("android.permission.RECORD_AUDIO", "microphone"),
    ("android.permission.SEND_SMS", "sms"),
    ("android.permission.USE_BIOMETRIC", "biometrics"),
    ("android.permission.USE_FINGERPRINT", "biometrics"),
    ("android.permission.USE_SIP", "phone-calls"),
    ("android.permission.UWB_RANGING", "nearby-devices"),
    ("android.permission.WRITE_CALENDAR", "calendars"),
    ("android.permission.WRITE_CALL_LOG", "call-log"),
    ("android.permission.WRITE_CONTACTS", "contacts"),
    ("android.permission.WRITE_EXTERNAL_STORAGE", "shared-storage"),
    ("com.google.android.gms.permission.AD_ID", "advertising-id"),
];

/// The built-in rules behind access edges, one per place an app asks in.
/// Like the [`declared`](crate::record::declared) rules, they cannot collide
/// with a pack rule, whose id starts with `sdk/`.
pub mod rule {
    /// A usage description in an `Info.plist`.
    pub const USAGE_DESCRIPTION: &str = "access/usage-description";
    /// An entitlement in a code signature.
    pub const ENTITLEMENT: &str = "access/entitlement";
    /// A `uses-permission` element in an Android manifest.
    pub const ANDROID_PERMISSION: &str = "access/android-permission";
}

/// The keys of one kind of declaration, or `None` for a matcher kind that is
/// no declaration of access.
const fn keys(matcher: MatcherKind) -> Option<&'static [(&'static str, &'static str)]> {
    match matcher {
        MatcherKind::UsageDescription => Some(USAGE_DESCRIPTIONS),
        MatcherKind::Entitlement => Some(ENTITLEMENTS),
        MatcherKind::AndroidPermission => Some(ANDROID_PERMISSIONS),
        _ => None,
    }
}

/// The built-in rule an access edge of this matcher kind names, or `None`
/// for a kind that is no declaration of access.
#[must_use]
pub const fn rule_of(matcher: MatcherKind) -> Option<&'static str> {
    match matcher {
        MatcherKind::UsageDescription => Some(rule::USAGE_DESCRIPTION),
        MatcherKind::Entitlement => Some(rule::ENTITLEMENT),
        MatcherKind::AndroidPermission => Some(rule::ANDROID_PERMISSION),
        _ => None,
    }
}

/// The permission with this id.
#[must_use]
pub fn permission(id: &str) -> Option<&'static Permission> {
    PERMISSIONS.iter().find(|permission| permission.id == id)
}

/// The category with this id.
#[must_use]
pub fn category(id: &str) -> Option<&'static Category> {
    CATEGORIES.iter().find(|category| category.id == id)
}

/// The permission that `key` asks for when it is declared in the place
/// `matcher` reads: a usage-description key, an entitlement or an Android
/// permission name, spelled exactly as the platform spells it. `None` for a
/// key this build has no permission for.
#[must_use]
pub fn declared(matcher: MatcherKind, key: &str) -> Option<&'static Permission> {
    let keys = keys(matcher)?;
    let id = match keys.iter().find(|(known, _)| *known == key) {
        Some((_, id)) => id,
        None if matcher == MatcherKind::AndroidPermission
            && key.len() > ANDROID_HEALTH_PREFIX.len()
            && key.starts_with(ANDROID_HEALTH_PREFIX)
            && text::is_clean(key, text::MAX_TOKEN_BYTES) =>
        {
            "health"
        }
        None => return None,
    };
    permission(id)
}

/// The Android release of each API level, as Android's own table of API
/// levels names it: index `n` is API level `n + 1`.
const ANDROID_RELEASES: [&str; 36] = [
    "1.0", "1.1", "1.5", "1.6", "2.0", "2.0.1", "2.1", "2.2", "2.3", "2.3.3", "3.0", "3.1", "3.2",
    "4.0", "4.0.3", "4.1", "4.2", "4.3", "4.4", "4.4W", "5.0", "5.1", "6.0", "7.0", "7.1", "8.0",
    "8.1", "9", "10", "11", "12", "12L", "13", "14", "15", "16",
];

/// The Android release of API level `level`, such as `9` for 28. `None`
/// for a level this build does not know.
#[must_use]
pub fn android_release(level: u32) -> Option<&'static str> {
    let index = usize::try_from(level.checked_sub(1)?).ok()?;
    ANDROID_RELEASES.get(index).copied()
}

/// The note on an access claim whose every Android permission stops at API
/// level `level` (`android:maxSdkVersion`): the devices the access is
/// limited to, such as `only on Android 9 and older (API level 28)`.
#[must_use]
pub fn android_limit_note(level: u32) -> alloc::string::String {
    match android_release(level) {
        Some(release) => alloc::format!("only on Android {release} and older (API level {level})"),
        None => alloc::format!("only up to Android API level {level}"),
    }
}

/// The usage descriptions Electron writes into the `Info.plist` of every
/// app built with it, unless the app states its own purpose: the wording of
/// Electron's own `shell/browser/resources/mac/Info.plist`
/// (<https://github.com/electron/electron/blob/main/shell/browser/resources/mac/Info.plist>).
///
/// An app that keeps one of them asks for the permission because Electron
/// does, and states no purpose of its own. That says nothing about whether
/// the app uses the camera or the microphone, so the checklist ranks such a
/// finding below one an app's own words back.
pub const ELECTRON_DEFAULT_PURPOSES: [&str; 4] = [
    "This app needs access to Bluetooth",
    "This app needs access to audio capture",
    "This app needs access to the camera",
    "This app needs access to the microphone",
];

/// Whether `purpose`, a usage description as a record holds it, is one
/// Electron writes for every app ([`ELECTRON_DEFAULT_PURPOSES`]).
#[must_use]
pub fn is_electron_default(purpose: &str) -> bool {
    ELECTRON_DEFAULT_PURPOSES.contains(&purpose)
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;

    use super::*;
    use crate::pack::is_category_id;

    const DECLARATIONS: [MatcherKind; 3] =
        [MatcherKind::UsageDescription, MatcherKind::Entitlement, MatcherKind::AndroidPermission];

    #[test]
    fn electron_s_own_wording_is_told_from_an_app_s() {
        assert!(is_electron_default("This app needs access to the camera"));
        assert!(is_electron_default("This app needs access to audio capture"));
        assert!(!is_electron_default("Slack requires camera access to make video calls."));
        assert!(!is_electron_default("This app needs access to the camera to scan QR codes"));
        assert!(!is_electron_default(""));
        // Every one names a permission a usage description can ask for.
        for (key, purpose) in [
            ("NSBluetoothAlwaysUsageDescription", ELECTRON_DEFAULT_PURPOSES[0]),
            ("NSAudioCaptureUsageDescription", ELECTRON_DEFAULT_PURPOSES[1]),
            ("NSCameraUsageDescription", ELECTRON_DEFAULT_PURPOSES[2]),
            ("NSMicrophoneUsageDescription", ELECTRON_DEFAULT_PURPOSES[3]),
        ] {
            assert!(declared(MatcherKind::UsageDescription, key).is_some(), "{key}");
            assert!(is_electron_default(purpose));
        }
    }

    #[test]
    fn the_tables_are_sorted_and_hold_no_duplicate() {
        let ids: Vec<&str> = PERMISSIONS.iter().map(|permission| permission.id).collect();
        assert!(ids.is_sorted_by(|a, b| a < b), "permissions are in id order, each once");
        let categories: BTreeSet<&str> = CATEGORIES.iter().map(|category| category.id).collect();
        assert_eq!(categories.len(), CATEGORIES.len());
        for matcher in DECLARATIONS {
            let keys = keys(matcher).unwrap();
            assert!(keys.is_sorted_by(|(a, _), (b, _)| a < b), "{matcher}: in key order");
        }
    }

    #[test]
    fn every_key_names_a_permission_and_every_permission_has_a_key_and_a_category() {
        let mut reached = BTreeSet::new();
        for matcher in DECLARATIONS {
            for (key, id) in keys(matcher).unwrap() {
                let named = declared(matcher, key).unwrap_or_else(|| panic!("{key}"));
                assert_eq!(named.id, *id);
                assert!(text::is_clean(key, text::MAX_TOKEN_BYTES), "{key}");
                reached.insert(named.id);
            }
        }
        reached.insert(
            declared(MatcherKind::AndroidPermission, "android.permission.health.READ_STEPS")
                .unwrap()
                .id,
        );
        for permission in &PERMISSIONS {
            assert!(reached.contains(permission.id), "{}: no key asks for it", permission.id);
            assert!(category(permission.category).is_some(), "{}", permission.id);
            assert_eq!(super::permission(permission.id), Some(permission));
            for shown in [permission.id, permission.name, permission.phrase] {
                assert!(!shown.is_empty() && text::is_clean(shown, text::MAX_NAME_BYTES));
            }
        }
        for category in &CATEGORIES {
            assert!(is_category_id(category.id), "{}", category.id);
            assert!(
                PERMISSIONS.iter().any(|permission| permission.category == category.id),
                "{}: empty",
                category.id
            );
        }
    }

    #[test]
    fn a_key_only_counts_in_the_place_it_belongs_to() {
        let camera = permission("camera");
        assert_eq!(declared(MatcherKind::UsageDescription, "NSCameraUsageDescription"), camera);
        assert_eq!(declared(MatcherKind::Entitlement, "com.apple.security.device.camera"), camera);
        assert_eq!(declared(MatcherKind::AndroidPermission, "android.permission.CAMERA"), camera);
        // The same key read from another place asks for nothing.
        assert_eq!(declared(MatcherKind::Entitlement, "NSCameraUsageDescription"), None);
        assert_eq!(declared(MatcherKind::UsageDescription, "android.permission.CAMERA"), None);
        // A key is taken as the platform spells it.
        assert_eq!(declared(MatcherKind::UsageDescription, "nscamerausagedescription"), None);
        assert_eq!(declared(MatcherKind::AndroidPermission, "CAMERA"), None);
        // No other kind of witness declares access.
        assert_eq!(declared(MatcherKind::PrivacyManifest, "NSCameraUsageDescription"), None);
        assert_eq!(rule_of(MatcherKind::PrivacyManifest), None);
        assert_eq!(rule_of(MatcherKind::Entitlement), Some(rule::ENTITLEMENT));
    }

    #[test]
    fn android_health_permissions_are_one_permission() {
        let health = permission("health");
        let android = |key| declared(MatcherKind::AndroidPermission, key);
        assert_eq!(android("android.permission.health.READ_HEART_RATE"), health);
        assert_eq!(android("android.permission.health.WRITE_SLEEP"), health);
        assert_eq!(android("android.permission.health."), None);
        assert_eq!(android("android.permission.healthy"), None);
        let long = alloc::format!("android.permission.health.{}", "A".repeat(300));
        assert_eq!(android(&long), None);
        assert_eq!(android("android.permission.health.READ\u{1b}[31m"), None);
        assert_eq!(android("android.permission.health.READ\u{202e}SPETS"), None);
        assert_eq!(
            declared(MatcherKind::Entitlement, "android.permission.health.READ_STEPS"),
            None
        );
    }

    /// The sandbox is a fact about the app and no permission, and posting
    /// notifications reaches nothing of the user's.
    /// The oracle is Android's published table of API levels
    /// (developer.android.com, "API levels").
    #[test]
    fn api_levels_name_the_android_release() {
        assert_eq!(android_release(0), None);
        assert_eq!(android_release(1), Some("1.0"));
        assert_eq!(android_release(20), Some("4.4W"));
        assert_eq!(android_release(23), Some("6.0"));
        assert_eq!(android_release(28), Some("9"));
        assert_eq!(android_release(29), Some("10"));
        assert_eq!(android_release(32), Some("12L"));
        assert_eq!(android_release(33), Some("13"));
        assert_eq!(android_release(36), Some("16"));
        assert_eq!(android_release(37), None);
        assert_eq!(android_limit_note(28), "only on Android 9 and older (API level 28)");
        assert_eq!(android_limit_note(99), "only up to Android API level 99");
        assert!(text::is_clean(&android_limit_note(u32::MAX), text::MAX_NAME_BYTES));
    }

    #[test]
    fn what_is_no_permission_is_not_in_the_table() {
        assert_eq!(declared(MatcherKind::Entitlement, SANDBOX_ENTITLEMENT), None);
        assert_eq!(
            declared(MatcherKind::AndroidPermission, "android.permission.POST_NOTIFICATIONS"),
            None
        );
        assert_eq!(declared(MatcherKind::AndroidPermission, "android.permission.VIBRATE"), None);
    }
}
