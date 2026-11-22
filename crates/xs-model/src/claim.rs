//! Claims: what the report states, each backed by evidence ids.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::canon::{self, CanonError};
use crate::digest::{DigestParseError, Sha256Digest};
use crate::record::{EdgeType, Grade, ObjectKind, ObjectRef, RecordId, Subject};
use crate::serde_str::impl_serde_str;

macro_rules! claim_digest {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Sha256Digest);

        impl $name {
            /// The underlying digest.
            #[must_use]
            pub const fn digest(&self) -> &Sha256Digest {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "sha256:{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = DigestParseError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                const EXPECTED: &str = "\"sha256:\" followed by 64 lowercase hex characters";
                text.strip_prefix("sha256:")
                    .and_then(Sha256Digest::from_hex)
                    .map(Self)
                    .ok_or(DigestParseError::new(EXPECTED))
            }
        }

        impl_serde_str!($name, "an id such as \"sha256:…\"");
    };
}

claim_digest!(
    /// Identifies a claim about one build of an app.
    ///
    /// It hashes the edge type, the subject digest and the object, so two
    /// builds that share an app id produce two claims. Leaving the digest out
    /// was the ordering bug the spike's determinism test caught.
    ClaimId
);

claim_digest!(
    /// Identifies a claim across builds of an app.
    ///
    /// It hashes the edge type, the platform, the app id and the object, and
    /// leaves the digest out, so a later `diff` can follow one claim through
    /// app updates.
    ClaimKey
);

impl ClaimId {
    /// The id of the claim that `subject` has an edge of type `edge` to
    /// `object`.
    ///
    /// # Errors
    ///
    /// Never in practice; the signature reflects the canonical JSON writer.
    pub fn of(edge: EdgeType, subject: &Subject, object: &ObjectRef) -> Result<Self, CanonError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            claim: &'static str,
            r#type: EdgeType,
            digest: &'a crate::SubjectDigest,
            object: &'a ObjectRef,
        }
        let preimage = Preimage { claim: "id/1", r#type: edge, digest: &subject.digest, object };
        Ok(Self(Sha256Digest::of(&canon::to_vec(&preimage)?)))
    }
}

impl ClaimKey {
    /// The key of the claim that the app `subject` is a build of has an edge
    /// of type `edge` to `object`.
    ///
    /// # Errors
    ///
    /// Never in practice; the signature reflects the canonical JSON writer.
    pub fn of(edge: EdgeType, subject: &Subject, object: &ObjectRef) -> Result<Self, CanonError> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            claim: &'static str,
            r#type: EdgeType,
            platform: crate::record::Platform,
            app: &'a str,
            object: &'a ObjectRef,
        }
        let preimage = Preimage {
            claim: "key/1",
            r#type: edge,
            platform: subject.platform,
            app: &subject.id,
            object,
        };
        Ok(Self(Sha256Digest::of(&canon::to_vec(&preimage)?)))
    }
}

/// One statement of the report: this build of this app has this kind of link
/// to this object, at this grade, on this evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// Identity of the claim for this build.
    pub id: ClaimId,
    /// Identity of the claim across builds.
    pub key: ClaimKey,
    /// Which kind of link the claim is about.
    #[serde(rename = "type")]
    pub edge: EdgeType,
    /// The build the claim is about.
    pub subject: Subject,
    /// What the link points at.
    pub object: ClaimObject,
    /// The company behind the object: the one at the top of the ownership
    /// chain of the entity that operates the SDK or the host. `None` in
    /// three cases, none of which counts anywhere. A component is a library
    /// with no network side of its own. A host the rule pack lists under no
    /// company is unmapped: it is shown as itself and nobody is named as its
    /// owner. A permission is something the app may reach, not somebody.
    pub company: Option<String>,
    /// The category of the object, from the rule pack's fixed list. For a
    /// permission of a browser extension it is the built-in
    /// [`permission::CATEGORY`](crate::permission::CATEGORY), which is not
    /// in the pack.
    pub category: String,
    /// Whether the claim counts in the report's headline: it is a channel,
    /// it names a company, and its category is one of those the rule pack
    /// counts there. Hosting is not receiving, so an update feed or a crash
    /// reporter does not.
    pub headline: bool,
    /// Whether the company is the app's own vendor.
    pub party: Party,
    /// Who publishes the app, as far as its files tell, and what `party`
    /// rests on. `None` when nothing identifies the vendor, or when what
    /// does contradicts itself.
    pub vendor: Option<Vendor>,
    /// The highest rung the evidence reaches.
    pub grade: Grade,
    /// Every rung that has evidence, in ascending order. `declares` and
    /// `contains` sit on one ladder but neither implies the other.
    pub rungs: Vec<Grade>,
    /// The highest confidence any single witness earns. There is no score.
    pub confidence: Confidence,
    /// How many distinct matcher kinds agreed.
    pub witnesses: u32,
    /// Ids of the records that support the claim, in id order. Never empty.
    pub evidence: Vec<RecordId>,
    /// Remarks carried over from the rule, such as `retired:2025-03-31`.
    /// A claim about a permission that rests on optional manifest keys
    /// alone carries [`permission::NOTE_OPTIONAL`](crate::permission::NOTE_OPTIONAL).
    /// A claim about an app that names itself after a listed company the
    /// scan could not confirm as its vendor carries [`NOTE_CLAIMED_VENDOR`]
    /// with the company's id.
    pub notes: Vec<String>,
}

/// The note, followed by a company id, of every claim about an app whose
/// app id is listed under that company while nothing the scan read confirms
/// that the app is the company's, as in `claims-vendor:google`. The app's
/// vendor is then none and the party `unknown`.
///
/// Any developer can give an app any id, so the id alone never makes a
/// company's SDK first party. Such a claim still counts as an app's
/// third-party channel in the headline: naming an app after a company must
/// not hide what it ships.
pub const NOTE_CLAIMED_VENDOR: &str = "claims-vendor";

impl Claim {
    /// The company the app names itself after without being confirmed as
    /// its vendor: the id after [`NOTE_CLAIMED_VENDOR`], if the claim carries
    /// that note.
    #[must_use]
    pub fn claimed_vendor(&self) -> Option<&str> {
        self.notes.iter().find_map(|note| {
            note.strip_prefix(NOTE_CLAIMED_VENDOR).and_then(|rest| rest.strip_prefix(':'))
        })
    }

    /// Whether the claim is a third-party channel of its app for the
    /// headline: its party is `third`, or the app only claims to be the
    /// company's own (see [`NOTE_CLAIMED_VENDOR`]).
    #[must_use]
    pub fn counts_as_third_party(&self) -> bool {
        self.party == Party::Third
            || (self.party == Party::Unknown && self.claimed_vendor().is_some())
    }
}

/// The object of a claim, with the name a reader recognizes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimObject {
    /// What sort of thing the object is.
    pub kind: ObjectKind,
    /// Its id, such as `sdk/firebase-crashlytics`.
    pub id: String,
    /// Its display name, such as `Firebase Crashlytics`.
    pub name: String,
}

/// Who publishes an app, and how that is known.
///
/// Reversing an app id proves nothing about ownership, so the signature
/// comes first (design report, section 3, M5): the Apple Team ID that the
/// code signature names, then the app id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vendor {
    /// The company the rule pack lists the app under. `None` when the pack
    /// lists neither its Team ID nor its app id: the vendor is then nobody
    /// the pack knows, and so none of the companies it names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    /// Which identifier the pack lists under `company`. Present exactly when
    /// `company` is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<VendorBasis>,
    /// The registrable domain the app id spells when read backwards, such as
    /// `ranchero.com` for `com.ranchero.NetNewsWire-Evergreen`. It is what
    /// the app says of itself, not a verified fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// The artifact records that hold the Team ID, in id order, when `by` is
    /// `team_id`. Empty otherwise: the app id is in the claim's subject.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<RecordId>,
}

/// The identifier a vendor was recognised by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VendorBasis {
    /// The Apple Team ID the code signature names. The signature is read,
    /// not verified.
    TeamId,
    /// The app id the artifact declares.
    AppId,
}

/// Whether the company behind an object is the app's own vendor.
///
/// Only a claim that names a company, or is about a host under the app's
/// own domain, can be first or third party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Party {
    /// The company is the app's vendor, or the host is under the domain the
    /// app's own id spells.
    First,
    /// The company is someone else: the app belongs to another company the
    /// rule pack lists, or to nobody it lists.
    Third,
    /// Neither is asserted. The object names no company (a component, an
    /// unmapped host), or the app's vendor could not be established.
    Unknown,
}

/// How much a witness can be trusted not to have hit by coincidence.
///
/// Confidence comes from the matcher kind and the place of the hit, not from
/// a score. The variants are declared in ascending order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// A content literal inside a dependency or resource.
    Low,
    /// A content literal in app code, or a token in a binary.
    Medium,
    /// A name read from a parsed table.
    High,
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::record::{Platform, SubjectKind};

    fn subject(digest: &str, version: &str) -> Subject {
        Subject {
            kind: SubjectKind::App,
            platform: Platform::Android,
            id: "com.x8bit.bitwarden".into(),
            version: Some(version.into()),
            digest: digest.parse().unwrap(),
        }
    }

    fn object(id: &str) -> ObjectRef {
        ObjectRef { kind: ObjectKind::Sdk, id: id.into() }
    }

    const PLAY: &str = "sha256:8aa0e5bf089ace014976eb8cae42a857ceb0604a7d2f00870419a3f03c588293";
    const FDROID: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn two_builds_of_one_app_are_two_claims_with_one_key() {
        let sdk = object("sdk/firebase-crashlytics");
        let play = subject(PLAY, "2026.9.1");
        let fdroid = subject(FDROID, "2026.9.1");

        let play_id = ClaimId::of(EdgeType::Channel, &play, &sdk).unwrap();
        let fdroid_id = ClaimId::of(EdgeType::Channel, &fdroid, &sdk).unwrap();
        assert_ne!(play_id, fdroid_id);

        let play_key = ClaimKey::of(EdgeType::Channel, &play, &sdk).unwrap();
        let fdroid_key = ClaimKey::of(EdgeType::Channel, &fdroid, &sdk).unwrap();
        assert_eq!(play_key, fdroid_key);
    }

    #[test]
    fn the_key_follows_a_claim_across_versions_but_not_across_objects() {
        let sdk = object("sdk/firebase-crashlytics");
        let old = subject(PLAY, "2026.9.1");
        let new = subject(FDROID, "2026.10.0");
        assert_eq!(
            ClaimKey::of(EdgeType::Channel, &old, &sdk).unwrap(),
            ClaimKey::of(EdgeType::Channel, &new, &sdk).unwrap()
        );
        assert_ne!(
            ClaimKey::of(EdgeType::Channel, &old, &sdk).unwrap(),
            ClaimKey::of(EdgeType::Channel, &old, &object("sdk/sentry")).unwrap()
        );
        assert_ne!(
            ClaimKey::of(EdgeType::Channel, &old, &sdk).unwrap(),
            ClaimKey::of(EdgeType::Access, &old, &sdk).unwrap()
        );
    }

    #[test]
    fn ids_and_keys_never_collide_for_the_same_inputs() {
        let sdk = object("sdk/sentry");
        let build = subject(PLAY, "1");
        let id = ClaimId::of(EdgeType::Channel, &build, &sdk).unwrap().to_string();
        let key = ClaimKey::of(EdgeType::Channel, &build, &sdk).unwrap().to_string();
        assert_ne!(id, key);
        assert_eq!(id.parse::<ClaimId>().unwrap().to_string(), id);
    }

    #[test]
    fn confidence_orders_low_to_high() {
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
    }
}
