//! The evidence record, version 1.
//!
//! Every collector emits this one format and every claim points at one or
//! more records, which keeps collectors, rules and reports independent of
//! each other. Six rules govern it (project spec, "Evidence format"):
//!
//! 1. The subject is an artifact, not an app name; its identity includes a
//!    digest of the file or bundle.
//! 2. There are two edge types: `channel` (app to SDK or domain) and `access`
//!    (app to permission or data category).
//! 3. The record id is the hash of the record's canonical JSON and is not
//!    stored inside it.
//! 4. Proof is a pointer a person can re-check by hand: a path, a name or a
//!    count. Never file contents.
//! 5. Minimal by construction: hosts only, no paths outside the artifact, no
//!    hardware ids.
//! 6. Derivation is pure.
//!
//! An edge points at an SDK, which a rule of the pack names, or at a host the
//! app's own files declare, such as its update feed. Only the host is kept
//! of a declared address, never the address itself.
//!
//! Besides edges there are two more kinds. An `artifact` record carries facts
//! about the subject itself. A `coverage` record says what was skipped or not
//! recognized, so that "nothing found" is never confused with "not looked at".

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::canon::{self, CanonError};
use crate::digest::{DigestParseError, Sha256Digest, SubjectDigest};
use crate::matcher::MatcherKind;
use crate::path::RelPath;
use crate::serde_str::impl_serde_str;
use crate::text;

/// The id of a record: the SHA-256 of its canonical JSON, written
/// `sha256:<hex>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(Sha256Digest);

impl RecordId {
    /// The underlying digest.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.0)
    }
}

impl FromStr for RecordId {
    type Err = DigestParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        const EXPECTED: &str = "\"sha256:\" followed by 64 lowercase hex characters";
        text.strip_prefix("sha256:")
            .and_then(Sha256Digest::from_hex)
            .map(Self)
            .ok_or(DigestParseError::new(EXPECTED))
    }
}

impl_serde_str!(RecordId, "a record id such as \"sha256:…\"");

/// The record format version. Serializes as the number `1` and refuses to
/// read anything else, so a record from a future format is an error rather
/// than a silently misread one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct V1;

impl Serialize for V1 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(1)
    }
}

impl<'de> Deserialize<'de> for V1 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match u64::deserialize(deserializer)? {
            1 => Ok(Self),
            other => Err(serde::de::Error::custom(format_args!(
                "unsupported format version {other}; this build reads version 1"
            ))),
        }
    }
}

/// One piece of evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    /// A link from a subject to an SDK, with the proof that supports it.
    Edge(EdgeRecord),
    /// Facts about the subject itself.
    Artifact(ArtifactRecord),
    /// Something that was skipped or not recognized.
    Coverage(CoverageRecord),
}

impl Record {
    /// The id of this record: the SHA-256 of its canonical JSON.
    ///
    /// # Errors
    ///
    /// Fails only if a count exceeds the canonical integer range.
    pub fn id(&self) -> Result<RecordId, CanonError> {
        Ok(RecordId(Sha256Digest::of(&canon::to_vec(self)?)))
    }

    /// The artifact this record is about.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        match self {
            Self::Edge(record) => &record.subject,
            Self::Artifact(record) => &record.subject,
            Self::Coverage(record) => &record.subject,
        }
    }

    /// Checks the invariants the type system does not express.
    ///
    /// Every record passes through here on its way into an
    /// [`EvidenceSet`](crate::EvidenceSet), whether a collector built it or it
    /// was read back from a report file.
    ///
    /// # Errors
    ///
    /// Returns the first violated invariant.
    pub fn validate(&self) -> Result<(), RecordError> {
        self.subject().validate()?;
        // What was not read is evidence of nothing, and was not looked at
        // and found wanting either.
        let read = self.subject().digest != SubjectDigest::Unread;
        match self {
            Self::Coverage(record) if read || record.status == CoverageStatus::Skipped => {
                record.validate()
            }
            Self::Edge(record) if read => record.validate(),
            Self::Artifact(record) if read => record.validate(),
            Self::Edge(_) | Self::Artifact(_) | Self::Coverage(_) => {
                Err(RecordError::UnreadSubject)
            }
        }
    }
}

/// Why a record is not well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// A text field is empty, over its length budget or holds a control
    /// character. The payload names the field.
    BadText(&'static str),
    /// The grade does not belong to the ladder of the edge type.
    GradeOffLadder,
    /// An edge to an SDK must be produced by the rule of that SDK, and an
    /// edge to a host by one of the built-in [`declared`] rules.
    ObjectRuleMismatch,
    /// A count of zero says nothing was seen, which is not evidence.
    ZeroCount,
    /// The record draws on the content of an artifact that was not read.
    /// About such a subject there can only be a `coverage` record that says
    /// it was skipped.
    UnreadSubject,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadText(field) => {
                write!(f, "field `{field}` is empty, too long or holds a control character")
            }
            Self::GradeOffLadder => f.write_str("grade does not belong to the edge type's ladder"),
            Self::ObjectRuleMismatch => f.write_str(
                "an edge to an SDK must name that SDK's rule as its rule, and an edge to a host \
                 one of the built-in declaration rules",
            ),
            Self::ZeroCount => f.write_str("count must be at least 1"),
            Self::UnreadSubject => f.write_str(
                "the subject was not read, so the only record about it is a coverage record \
                 that says it was skipped",
            ),
        }
    }
}

impl core::error::Error for RecordError {}

fn check_text(field: &'static str, value: &str, max_bytes: usize) -> Result<(), RecordError> {
    if value.is_empty() || !text::is_clean(value, max_bytes) {
        return Err(RecordError::BadText(field));
    }
    Ok(())
}

/// The artifact a record is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    /// What sort of thing the subject is.
    pub kind: SubjectKind,
    /// The platform the artifact is built for.
    pub platform: Platform,
    /// The app id the artifact declares, such as `com.x8bit.bitwarden`.
    pub id: String,
    /// The version the artifact declares, if it declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The digest that tells two builds of one app id apart.
    pub digest: SubjectDigest,
}

impl Subject {
    fn validate(&self) -> Result<(), RecordError> {
        check_text("subject.id", &self.id, text::MAX_ID_BYTES)?;
        if let Some(version) = &self.version {
            check_text("subject.version", version, text::MAX_VERSION_BYTES)?;
        }
        Ok(())
    }
}

/// What sort of thing a subject is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// An installable application.
    App,
}

/// The platform an artifact is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// An Android package.
    Android,
    /// A macOS application bundle.
    Macos,
}

impl Platform {
    /// The name used in records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Macos => "macos",
        }
    }
}

/// The collector that produced a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Collector {
    /// An Android package as a whole: its identity, the names of its
    /// entries, and what could not be read of it.
    #[serde(rename = "android.apk")]
    AndroidApk,
    /// Class and string tables of an Android DEX file.
    #[serde(rename = "android.dex")]
    AndroidDex,
    /// The compiled manifest of an Android package.
    #[serde(rename = "android.manifest")]
    AndroidManifest,
    /// A macOS application bundle.
    #[serde(rename = "macos.bundle")]
    MacosBundle,
    /// The code of an Electron app: its asar archives and loose scripts.
    #[serde(rename = "electron.app")]
    ElectronApp,
}

/// The two kinds of link a subject can have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    /// The app gives an SDK or a domain a channel to the user's data.
    Channel,
    /// The app can reach a permission or a data category.
    Access,
}

impl EdgeType {
    /// The name used in records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Channel => "channel",
            Self::Access => "access",
        }
    }
}

/// How strong the evidence for an edge is.
///
/// Each edge type has its own ladder, and the variants are declared in
/// ascending order within each, so `Ord` compares rungs of one ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    /// Channel: the app's own files name the endpoint.
    Declares,
    /// Channel: the app ships the SDK's code. Proves presence, not use.
    Contains,
    /// Channel: the OS or a capture recorded a connection.
    Contacts,
    /// Channel: the receiver lists the sender, or a payload was inspected.
    Confirmed,
    /// Access: the app asks for the permission.
    Requested,
    /// Access: the user allowed it.
    Granted,
    /// Access: the OS logged an access.
    Used,
}

impl Grade {
    /// The edge type whose ladder this grade is a rung of.
    #[must_use]
    pub const fn ladder(self) -> EdgeType {
        match self {
            Self::Declares | Self::Contains | Self::Contacts | Self::Confirmed => EdgeType::Channel,
            Self::Requested | Self::Granted | Self::Used => EdgeType::Access,
        }
    }
}

/// A link from a subject to an object, with its proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeRecord {
    /// Format version.
    pub v: V1,
    /// The collector that produced the record.
    pub collector: Collector,
    /// The artifact the edge starts at.
    pub subject: Subject,
    /// Which kind of link this is.
    pub edge: EdgeType,
    /// How strong the evidence is.
    pub grade: Grade,
    /// What the edge points at.
    pub object: ObjectRef,
    /// The id of the rule whose token matched.
    pub rule: String,
    /// The pointer a person can re-check by hand.
    pub proof: Proof,
}

impl EdgeRecord {
    fn validate(&self) -> Result<(), RecordError> {
        if self.grade.ladder() != self.edge {
            return Err(RecordError::GradeOffLadder);
        }
        check_text("object.id", &self.object.id, text::MAX_ID_BYTES)?;
        check_text("rule", &self.rule, text::MAX_ID_BYTES)?;
        match self.object.kind {
            ObjectKind::Sdk if self.object.id != self.rule => {
                return Err(RecordError::ObjectRuleMismatch);
            }
            ObjectKind::Sdk => {}
            ObjectKind::Host if !text::is_host(&self.object.id) => {
                return Err(RecordError::BadText("object.id"));
            }
            ObjectKind::Host if declared::category(&self.rule).is_none() => {
                return Err(RecordError::ObjectRuleMismatch);
            }
            ObjectKind::Host => {}
        }
        check_text("proof.token", &self.proof.token, text::MAX_TOKEN_BYTES)?;
        if let Some(example) = &self.proof.example {
            check_text("proof.example", example, text::MAX_EXAMPLE_BYTES)?;
        }
        if self.proof.count == 0 {
            return Err(RecordError::ZeroCount);
        }
        Ok(())
    }
}

/// What an edge points at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    /// What sort of thing the object is.
    pub kind: ObjectKind,
    /// Its id: a rule id such as `sdk/firebase-crashlytics` for an SDK, the
    /// host name such as `updates.example.com` for a host.
    pub id: String,
}

/// What sort of thing an edge points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// A software development kit named by a rule.
    Sdk,
    /// A host the app's own files declare. Records hold the host only, never
    /// the address it was taken from.
    Host,
}

impl ObjectKind {
    /// The name used in records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sdk => "sdk",
            Self::Host => "host",
        }
    }
}

/// The built-in rules behind edges to hosts.
///
/// A host the app itself declares is not named by any rule of the pack: the
/// collector reads it from a fixed key of a property list. The edge names
/// one of these ids as its rule instead, which says what kind of declaration
/// it is. They cannot collide with a pack rule, whose id starts with `sdk/`.
pub mod declared {
    /// The update feed an app's property list names.
    pub const UPDATE_FEED: &str = "declared/update-feed";
    /// A tracking domain a privacy manifest lists.
    pub const TRACKING_DOMAIN: &str = "declared/tracking-domain";

    /// The category id of the claims a built-in rule supports, or `None` if
    /// `rule` is not a built-in rule. A rule pack must define these
    /// categories for such claims to be derived.
    #[must_use]
    pub fn category(rule: &str) -> Option<&'static str> {
        match rule {
            UPDATE_FEED => Some("update_feed"),
            TRACKING_DOMAIN => Some("tracking_domain"),
            _ => None,
        }
    }
}

/// Where and how a rule token was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    /// The kind of witness.
    pub matcher: MatcherKind,
    /// The rule token that matched. For a host the app declares, the key of
    /// the property list that holds the declaration, such as `SUFeedURL`.
    pub token: String,
    /// How many times it matched in this place.
    pub count: u32,
    /// The smallest matching value in byte order, capped at 160 bytes. Never
    /// "the first one seen", which would depend on thread timing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
    /// The file or folder inside the artifact where the hit is.
    #[serde(rename = "where")]
    pub location: RelPath,
    /// The table or section inside that file.
    pub region: Region,
    /// What kind of code the file is. Confidence depends on it.
    pub scope: Scope,
}

/// The table or section a hit was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Region {
    /// The `class_defs` table of a DEX file: classes the file defines.
    ClassDefs,
    /// The names of the entries of a directory.
    DirEntries,
    /// The file table in the header of an asar archive.
    AsarHeader,
    /// The content of the files a folder or an archive holds. The count is
    /// the number of files the token was found in, and the example is the
    /// path of one of them inside that folder or archive.
    Files,
    /// The `__objc_classname` section of a Mach-O file: the names of the
    /// Objective-C classes, categories and protocols it defines.
    ObjcClassname,
    /// The load commands of a Mach-O file, which name the libraries it links.
    LoadCommands,
    /// The bytes of a Mach-O file outside its executable-code sections.
    NonCode,
    /// A section of a Mach-O file that holds script text, such as
    /// `__BUN,__bun`.
    EmbeddedScript,
    /// The values a property list holds under one key.
    PropertyList,
    /// The components and `meta-data` entries an Android manifest declares.
    Components,
    /// The `string_ids` table of a DEX file: its string constants.
    StringIds,
    /// The names of the entries of a zip archive.
    ZipEntries,
}

/// What kind of code a file holds (design report, section 5.2 control 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Code the app's own developer wrote or bundled as theirs.
    AppCode,
    /// A third-party library shipped alongside the app.
    Dependency,
    /// A language runtime or embedded browser engine.
    Runtime,
    /// Data files, documentation and other non-code resources.
    Resource,
}

/// Facts about the subject itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    /// Format version.
    pub v: V1,
    /// The collector that produced the record.
    pub collector: Collector,
    /// The artifact the facts are about.
    pub subject: Subject,
    /// The facts.
    pub facts: Facts,
}

impl ArtifactRecord {
    fn validate(&self) -> Result<(), RecordError> {
        if let Some(name) = &self.facts.name {
            check_text("facts.name", name, text::MAX_NAME_BYTES)?;
        }
        if let Some(team_id) = &self.facts.team_id {
            check_text("facts.team_id", team_id, text::MAX_TEAM_ID_BYTES)?;
        }
        Ok(())
    }
}

/// What a collector learned about an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    /// The display name the artifact declares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The Apple Team ID the code signature of the main executable names.
    /// It is what the signature claims: the scanner reads it and does not
    /// verify the signature, so it is a fact about the file and never part
    /// of the subject's identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// How many files the collector read.
    pub files_scanned: u64,
    /// How many bytes the collector read.
    pub bytes_scanned: u64,
}

/// Something that was skipped or not recognized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageRecord {
    /// Format version.
    pub v: V1,
    /// The collector that produced the record.
    pub collector: Collector,
    /// The artifact that was not fully covered.
    pub subject: Subject,
    /// Whether input was skipped or read but not understood.
    pub status: CoverageStatus,
    /// Why.
    pub reason: CoverageReason,
    /// The place inside the artifact, when there is a single one.
    #[serde(rename = "where", default, skip_serializing_if = "Option::is_none")]
    pub location: Option<RelPath>,
    /// The size in bytes of the input that was not covered, when the size is
    /// the reason: a file the collector reads, but over the per-file byte
    /// budget. A size past the largest integer canonical JSON holds
    /// (2^53 - 1) is stored as that integer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// How many items this record stands for.
    pub count: u32,
}

impl CoverageRecord {
    const fn validate(&self) -> Result<(), RecordError> {
        if self.count == 0 {
            return Err(RecordError::ZeroCount);
        }
        Ok(())
    }
}

/// Whether input was skipped or read but not understood.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    /// The collector did not read the input.
    Skipped,
    /// The collector read the input and could not interpret it.
    Unrecognized,
}

/// Why something was not covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageReason {
    /// The collector lacks the privilege the input needs.
    NoPrivilege,
    /// The binary is encrypted, so its bytes are ciphertext.
    EncryptedBinary,
    /// A deterministic budget (bytes, items or depth) was exceeded.
    OverBudget,
    /// The input is damaged or not what its name says.
    ParseError,
    /// A name differs only in letter case from one the artifact's layout
    /// fixes, such as `contents` for `Contents`. The collector takes names
    /// as they are stored, so what sits there was not looked at as that part
    /// of the layout.
    UnexpectedCase,
    /// An import format contained a record of an unknown shape.
    UnrecognizedRecord,
    /// The input could not be read as one file: the file system refused the
    /// read, or the file changed while it was being read, so that what was
    /// read of it belongs to no one version of it.
    Unreadable,
    /// The format is known but this build has no reader for it.
    UnsupportedFormat,
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use serde_json::json;

    use super::*;

    /// The Bitwarden record from the spike (design report, appendix A),
    /// migrated to format version 1 (section 4.3).
    pub(crate) const BITWARDEN_JSON: &str = r#"{
      "v": 1,
      "kind": "edge",
      "collector": "android.dex",
      "subject": {
        "kind": "app", "platform": "android",
        "id": "com.x8bit.bitwarden", "version": "2026.9.1",
        "digest": "sha256:8aa0e5bf089ace014976eb8cae42a857ceb0604a7d2f00870419a3f03c588293"
      },
      "edge": "channel",
      "grade": "contains",
      "object": {"kind": "sdk", "id": "sdk/firebase-crashlytics"},
      "rule": "sdk/firebase-crashlytics",
      "proof": {
        "matcher": "android_class_prefix",
        "token": "com.google.firebase.crashlytics.",
        "count": 2,
        "example": "com.google.firebase.crashlytics.CrashlyticsRegistrar",
        "where": "classes2.dex",
        "region": "class_defs",
        "scope": "app_code"
      }
    }"#;

    /// The canonical JSON of that record, written out by hand so that the
    /// test does not depend on the writer it is checking.
    const BITWARDEN_CANONICAL: &str = concat!(
        r#"{"collector":"android.dex","edge":"channel","grade":"contains","kind":"edge","#,
        r#""object":{"id":"sdk/firebase-crashlytics","kind":"sdk"},"#,
        r#""proof":{"count":2,"example":"com.google.firebase.crashlytics.CrashlyticsRegistrar","#,
        r#""matcher":"android_class_prefix","region":"class_defs","scope":"app_code","#,
        r#""token":"com.google.firebase.crashlytics.","where":"classes2.dex"},"#,
        r#""rule":"sdk/firebase-crashlytics","#,
        r#""subject":{"digest":"sha256:8aa0e5bf089ace014976eb8cae42a857ceb0604a7d2f00870419a3f03c588293","#,
        r#""id":"com.x8bit.bitwarden","kind":"app","platform":"android","version":"2026.9.1"},"#,
        r#""v":1}"#
    );

    /// SHA-256 of `BITWARDEN_CANONICAL`, computed outside this code base with
    /// `printf '%s' '<canonical json>' | shasum -a 256`.
    const BITWARDEN_ID: &str =
        "sha256:6aaab06fe1e8cc0d0b77e75f9b5b97f25fa3d8434ffee9ead8cd1bac63c0badb";

    pub(crate) fn bitwarden() -> Record {
        serde_json::from_str(BITWARDEN_JSON).unwrap()
    }

    #[test]
    fn the_spike_record_round_trips_to_a_fixed_id() {
        let record = bitwarden();
        record.validate().unwrap();

        let canonical = canon::to_string(&record).unwrap();
        assert_eq!(canonical, BITWARDEN_CANONICAL);
        assert_eq!(record.id().unwrap().to_string(), BITWARDEN_ID);

        let reparsed: Record = serde_json::from_str(&canonical).unwrap();
        assert_eq!(reparsed, record);
        assert_eq!(reparsed.id().unwrap(), record.id().unwrap());
    }

    #[test]
    fn the_id_is_not_stored_in_the_record() {
        let canonical = canon::to_string(&bitwarden()).unwrap();
        assert!(!canonical.contains(&BITWARDEN_ID["sha256:".len()..]));
    }

    fn edit(pointer: &str, value: serde_json::Value) -> Result<Record, serde_json::Error> {
        let mut tree: serde_json::Value = serde_json::from_str(BITWARDEN_JSON).unwrap();
        *tree.pointer_mut(pointer).unwrap() = value;
        serde_json::from_value(tree)
    }

    #[test]
    fn any_change_to_the_record_changes_the_id() {
        let base = bitwarden().id().unwrap();
        let edits = [
            ("/proof/count", json!(3)),
            ("/proof/where", json!("classes3.dex")),
            ("/subject/version", json!("2026.9.2")),
            (
                "/subject/digest",
                json!("sha256:8aa0e5bf089ace014976eb8cae42a857ceb0604a7d2f00870419a3f03c588294"),
            ),
            ("/proof/scope", json!("dependency")),
        ];
        let mut seen = Vec::from([base]);
        for (pointer, value) in edits {
            let id = edit(pointer, value).unwrap().id().unwrap();
            assert!(!seen.contains(&id), "{pointer}");
            seen.push(id);
        }
    }

    #[test]
    fn refuses_unknown_versions_fields_and_values() {
        assert!(edit("/v", json!(2)).is_err());
        assert!(edit("/kind", json!("rumour")).is_err());
        assert!(edit("/grade", json!("spying")).is_err());
        assert!(edit("/proof/where", json!("/Users/someone/classes.dex")).is_err());
        assert!(edit("/subject/digest", json!("8aa0e5bf")).is_err());

        let mut tree: serde_json::Value = serde_json::from_str(BITWARDEN_JSON).unwrap();
        tree["confidence"] = json!("high");
        assert!(serde_json::from_value::<Record>(tree).is_err(), "v1 has no confidence field");
    }

    #[test]
    fn validation_catches_what_the_types_cannot() {
        let check = |pointer, value| edit(pointer, value).unwrap().validate();
        assert_eq!(check("/grade", json!("granted")), Err(RecordError::GradeOffLadder));
        assert_eq!(check("/rule", json!("sdk/other")), Err(RecordError::ObjectRuleMismatch));
        assert_eq!(check("/proof/count", json!(0)), Err(RecordError::ZeroCount));
        assert_eq!(
            check("/proof/example", json!("x".repeat(161))),
            Err(RecordError::BadText("proof.example"))
        );
        assert_eq!(
            check("/subject/id", json!("a\u{1b}[2J")),
            Err(RecordError::BadText("subject.id"))
        );
        assert_eq!(check("/subject/id", json!("")), Err(RecordError::BadText("subject.id")));
    }

    /// An edge to a host the app declares: the object is the host alone and
    /// the rule is a built-in one.
    #[test]
    fn a_declared_host_is_an_edge_with_a_built_in_rule() {
        let feed = json!({
            "v": 1, "kind": "edge", "collector": "macos.bundle",
            "subject": {
                "kind": "app", "platform": "macos", "id": "com.example.app",
                "digest": "bd1:8aa0e5bf089ace014976eb8cae42a857ceb0604a7d2f00870419a3f03c588293"
            },
            "edge": "channel", "grade": "declares",
            "object": {"kind": "host", "id": "updates.example.com"},
            "rule": "declared/update-feed",
            "proof": {
                "matcher": "update_feed", "token": "SUFeedURL", "count": 1,
                "where": "Contents/Info.plist", "region": "property_list", "scope": "app_code"
            }
        });
        let record: Record = serde_json::from_value(feed.clone()).unwrap();
        record.validate().unwrap();
        assert_eq!(serde_json::to_value(&record).unwrap(), feed);

        let with = |pointer: &str, value: serde_json::Value| {
            let mut tree = feed.clone();
            *tree.pointer_mut(pointer).unwrap() = value;
            serde_json::from_value::<Record>(tree).unwrap().validate()
        };
        // Hosts only: no address, no port, no other spelling of the name.
        for not_a_host in [
            "https://updates.example.com/feed.xml",
            "updates.example.com:443",
            "Updates.Example.com",
            "updates.example.com.",
        ] {
            assert_eq!(
                with("/object/id", json!(not_a_host)),
                Err(RecordError::BadText("object.id"))
            );
        }
        // No pack rule names a host, and no built-in rule names an SDK.
        assert_eq!(with("/rule", json!("sdk/sparkle")), Err(RecordError::ObjectRuleMismatch));
        assert_eq!(with("/rule", json!("declared/other")), Err(RecordError::ObjectRuleMismatch));
        assert_eq!(with("/rule", json!("declared/tracking-domain")), Ok(()));
        assert_eq!(declared::category(declared::UPDATE_FEED), Some("update_feed"));
        assert_eq!(declared::category(declared::TRACKING_DOMAIN), Some("tracking_domain"));
        assert_eq!(declared::category("sdk/sparkle"), None);
    }

    #[test]
    fn grades_order_within_their_ladder() {
        assert!(Grade::Declares < Grade::Contains);
        assert!(Grade::Contains < Grade::Contacts);
        assert!(Grade::Contacts < Grade::Confirmed);
        assert!(Grade::Requested < Grade::Granted);
        assert!(Grade::Granted < Grade::Used);
        assert_eq!(Grade::Confirmed.ladder(), EdgeType::Channel);
        assert_eq!(Grade::Used.ladder(), EdgeType::Access);
    }

    #[test]
    fn artifact_and_coverage_records_round_trip() {
        let artifact = json!({
            "v": 1, "kind": "artifact", "collector": "macos.bundle",
            "subject": {
                "kind": "app", "platform": "macos", "id": "com.example.app",
                "digest": "bd1:8aa0e5bf089ace014976eb8cae42a857ceb0604a7d2f00870419a3f03c588293"
            },
            "facts": {
                "name": "Example", "team_id": "ABCDE12345",
                "files_scanned": 41, "bytes_scanned": 68_219_904
            }
        });
        let coverage = json!({
            "v": 1, "kind": "coverage", "collector": "macos.bundle",
            "subject": artifact["subject"],
            "status": "skipped", "reason": "encrypted_binary",
            "where": "Wrapper/X.app/X", "count": 1
        });
        let oversized = json!({
            "v": 1, "kind": "coverage", "collector": "macos.bundle",
            "subject": artifact["subject"],
            "status": "skipped", "reason": "over_budget",
            "where": "Contents/MacOS/Huge", "bytes": 2_147_483_649_u64, "count": 1
        });
        let miscased = json!({
            "v": 1, "kind": "coverage", "collector": "macos.bundle",
            "subject": artifact["subject"],
            "status": "skipped", "reason": "unexpected_case",
            "where": "Contents/frameworks", "count": 1
        });
        for tree in [artifact, coverage, oversized, miscased] {
            let record: Record = serde_json::from_value(tree.clone()).unwrap();
            record.validate().unwrap();
            assert_eq!(serde_json::to_value(&record).unwrap(), tree);
        }
    }

    /// An artifact that could not be read has no hash, and nothing can be
    /// said about its content: not that it holds something, not what it is,
    /// and not that it was looked at and not understood.
    #[test]
    fn an_unread_subject_carries_only_records_that_say_it_was_skipped() {
        let subject = json!({
            "kind": "app", "platform": "android", "id": "locked.apk", "digest": "unread"
        });
        let skipped = |reason: &str, count: u32| {
            json!({
                "v": 1, "kind": "coverage", "collector": "android.apk", "subject": subject,
                "status": "skipped", "reason": reason, "count": count
            })
        };
        for tree in [skipped("unreadable", 1), skipped("unreadable", 2)] {
            let record: Record = serde_json::from_value(tree.clone()).unwrap();
            record.validate().unwrap();
            assert_eq!(serde_json::to_value(&record).unwrap(), tree);
        }
        // The reasons are a fixed list, and a package that changed while it
        // was read has no reason of its own in it.
        assert!(serde_json::from_value::<Record>(skipped("changed", 1)).is_err());

        let refused =
            |tree: serde_json::Value| serde_json::from_value::<Record>(tree).unwrap().validate();
        let mut unrecognized = skipped("parse_error", 1);
        unrecognized["status"] = json!("unrecognized");
        assert_eq!(refused(unrecognized), Err(RecordError::UnreadSubject));
        let artifact = json!({
            "v": 1, "kind": "artifact", "collector": "android.apk", "subject": subject,
            "facts": {"files_scanned": 0, "bytes_scanned": 0}
        });
        assert_eq!(refused(artifact), Err(RecordError::UnreadSubject));
        let mut edge: serde_json::Value = serde_json::from_str(BITWARDEN_JSON).unwrap();
        edge["subject"]["digest"] = json!("unread");
        assert_eq!(refused(edge), Err(RecordError::UnreadSubject));
    }
}
