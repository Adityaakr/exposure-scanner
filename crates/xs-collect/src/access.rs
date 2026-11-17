//! Access edges: what an app asks to reach, as its own files declare it.
//!
//! The collectors read the declaration (a usage description, an
//! entitlement, an Android permission) and this module turns it into the
//! record. Which key asks for which permission is not decided here: that is
//! the fixed list in [`xs_model::access`], which a record is checked against
//! when it enters the evidence set.

use xs_model::record::{
    Collector, EdgeRecord, EdgeType, ObjectKind, ObjectRef, Proof, Record, Region, Scope, Subject,
    V1,
};
use xs_model::{MatcherKind, RelPath, access, text};

/// Where an app asks for a permission, and how.
pub(crate) struct Asked<'a> {
    /// The collector that read the declaration.
    pub(crate) collector: Collector,
    /// The kind of declaration.
    pub(crate) matcher: MatcherKind,
    /// The platform's key, as the file spells it.
    pub(crate) key: &'a str,
    /// How many entries the declaration holds; one for a plain one.
    pub(crate) count: u32,
    /// The purpose the app states with the declaration, as written.
    pub(crate) purpose: Option<&'a str>,
    /// The file that holds the declaration.
    pub(crate) location: &'a RelPath,
    /// The part of that file.
    pub(crate) region: Region,
}

impl Asked<'_> {
    /// The edge from `subject` to the permission the key asks for, or `None`
    /// for a key that asks for no permission this build knows.
    ///
    /// The edge is graded by the kind of declaration, which is `requested`
    /// for all of them: the app may access the thing. Whether the user
    /// allowed it is not in the artifact.
    pub(crate) fn edge(&self, subject: &Subject) -> Option<Record> {
        let permission = access::declared(self.matcher, self.key)?;
        let rule = access::rule_of(self.matcher)?;
        Some(Record::Edge(EdgeRecord {
            v: V1,
            collector: self.collector,
            subject: subject.clone(),
            edge: EdgeType::Access,
            grade: self.matcher.grade(),
            object: ObjectRef { kind: ObjectKind::Permission, id: permission.id.into() },
            rule: rule.into(),
            proof: Proof {
                matcher: self.matcher,
                token: self.key.into(),
                count: self.count.max(1),
                example: self.purpose.and_then(stated_purpose),
                location: self.location.clone(),
                region: self.region,
                // The declaration is the app's own, wherever its code is from.
                scope: Scope::AppCode,
            },
        }))
    }
}

/// The purpose an app states, made safe to carry: runs of white space
/// become one space, so that a sentence broken over lines reads as one, and
/// the text is cut to the budget of a proof example. `None` for a purpose
/// that says nothing.
fn stated_purpose(purpose: &str) -> Option<String> {
    let mut joined = String::with_capacity(purpose.len().min(text::MAX_EXAMPLE_BYTES));
    for word in purpose.split_whitespace() {
        // Past the budget the rest is cut anyway.
        if joined.len() > text::MAX_EXAMPLE_BYTES {
            break;
        }
        if !joined.is_empty() {
            joined.push(' ');
        }
        joined.push_str(word);
    }
    let cleaned = text::clean(&joined, text::MAX_EXAMPLE_BYTES);
    (!cleaned.is_empty()).then_some(cleaned)
}

#[cfg(test)]
mod tests {
    use xs_model::record::{Grade, Platform, SubjectKind};
    use xs_model::{Sha256Digest, SubjectDigest};

    use super::*;

    fn subject() -> Subject {
        Subject {
            kind: SubjectKind::App,
            platform: Platform::Macos,
            id: "com.example.app".into(),
            version: None,
            digest: SubjectDigest::Bundle(Sha256Digest::of(b"bundle")),
        }
    }

    fn asked<'a>(key: &'a str, purpose: Option<&'a str>, location: &'a RelPath) -> Asked<'a> {
        Asked {
            collector: Collector::MacosBundle,
            matcher: MatcherKind::UsageDescription,
            key,
            count: 1,
            purpose,
            location,
            region: Region::PropertyList,
        }
    }

    #[test]
    fn a_known_key_becomes_a_valid_access_edge_and_an_unknown_one_nothing() {
        let location = RelPath::new("Contents/Info.plist").unwrap();
        let record = asked("NSCameraUsageDescription", Some("For video calls."), &location)
            .edge(&subject())
            .unwrap();
        record.validate().unwrap();
        let Record::Edge(edge) = record else { unreachable!() };
        assert_eq!(edge.edge, EdgeType::Access);
        assert_eq!(edge.grade, Grade::Requested);
        assert_eq!((edge.object.kind, edge.object.id.as_str()), (ObjectKind::Permission, "camera"));
        assert_eq!(edge.rule, "access/usage-description");
        assert_eq!(edge.proof.token, "NSCameraUsageDescription");
        assert_eq!(edge.proof.example.as_deref(), Some("For video calls."));

        assert!(asked("NSNoSuchUsageDescription", None, &location).edge(&subject()).is_none());
        // The key of another place asks for nothing here.
        assert!(asked("android.permission.CAMERA", None, &location).edge(&subject()).is_none());
    }

    #[test]
    fn a_purpose_is_one_line_within_the_budget_and_never_hostile() {
        assert_eq!(
            stated_purpose("  Needs\n\tthe   camera.\r\n"),
            Some("Needs the camera.".into())
        );
        assert_eq!(stated_purpose(""), None);
        assert_eq!(stated_purpose(" \n\t "), None);
        assert_eq!(stated_purpose("a\u{1b}[31mb\u{202e}c"), Some("a\u{fffd}[31mb\u{fffd}c".into()));
        let long = stated_purpose(&"word ".repeat(10_000)).unwrap();
        assert!(long.len() <= text::MAX_EXAMPLE_BYTES && long.ends_with('…'), "{long}");
        let unbroken = stated_purpose(&"x".repeat(1 << 20)).unwrap();
        assert!(text::is_clean(&unbroken, text::MAX_EXAMPLE_BYTES));
    }
}
