//! Derivation: evidence and a rule pack in, claims out.
//!
//! This is a pure function. The crate is `no_std`, so it cannot read a clock,
//! a file, the environment or the network, and it has no randomly seeded
//! collection whose order could leak into the result. The same evidence and
//! the same pack give the same claims on any machine, in any process.
//!
//! What derivation decides (design report, sections 3 and 4.4):
//!
//! * **Identity.** Edges about the same build of an app and the same object
//!   become one claim.
//! * **Grade.** The claim takes the highest rung its evidence reaches and
//!   lists every rung that has evidence. Adding evidence can therefore raise
//!   a grade and never lower it.
//! * **Confidence** and **witnesses** are two separate axes. Confidence is
//!   the highest any single witness earns, from the kind of matcher and the
//!   place of the hit. Witnesses counts how many kinds of matcher agreed.
//!   Neither is a score.
//! * **Company.** The rule names the entity that operates the SDK; the claim
//!   names the company at the top of that entity's ownership chain. A rule
//!   without an entity is a component and yields a claim with no company.
//!
//! Party (first or third) needs the app's vendor, which arrives with the
//! resolver in task 10. Until then every claim says `unknown` rather than
//! guess.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use xs_model::EvidenceSet;
use xs_model::canon::CanonError;
use xs_model::claim::{Claim, ClaimId, ClaimKey, ClaimObject, Confidence, Party};
use xs_model::matcher::MatcherKind;
use xs_model::pack::{Pack, Rule};
use xs_model::record::{
    EdgeRecord, EdgeType, Grade, ObjectKind, ObjectRef, Record, RecordId, Scope, Subject,
};

/// Why evidence could not be turned into claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveError {
    /// An edge names a rule the pack does not hold. The evidence was produced
    /// with a different pack; deriving anyway would silently drop findings.
    UnknownRule {
        /// The record that names the rule.
        record: String,
        /// The rule id.
        rule: String,
    },
    /// An id could not be computed.
    Canon(CanonError),
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRule { record, rule } => write!(
                f,
                "record {record} was produced by rule `{rule}`, which the loaded rule pack does \
                 not contain"
            ),
            Self::Canon(error) => write!(f, "cannot compute a claim id: {error}"),
        }
    }
}

impl core::error::Error for DeriveError {}

impl From<CanonError> for DeriveError {
    fn from(error: CanonError) -> Self {
        Self::Canon(error)
    }
}

/// How much a witness can be trusted not to have hit by coincidence.
///
/// This table lives here and not in the record, so retuning it never changes
/// an evidence id (design report, section 4.3).
#[must_use]
pub const fn confidence(matcher: MatcherKind, scope: Scope) -> Confidence {
    match matcher {
        // Names read from a parsed table, or the app's own declaration.
        MatcherKind::ManifestComponent
        | MatcherKind::AndroidClassPrefix
        | MatcherKind::ApkFile
        | MatcherKind::NpmPackage
        | MatcherKind::AppleFramework
        | MatcherKind::MachoDylib
        | MatcherKind::MachoObjcClass
        | MatcherKind::PrivacyManifest => Confidence::High,
        // Literals in a binary's data.
        MatcherKind::DexString | MatcherKind::MachoToken => Confidence::Medium,
        // Literals in script text: medium in the app's own code, low anywhere
        // else, because dependencies ship demo pages and documentation.
        MatcherKind::ContentLiteral => match scope {
            Scope::AppCode => Confidence::Medium,
            Scope::Dependency | Scope::Runtime | Scope::Resource => Confidence::Low,
        },
    }
}

/// Everything known about one claim while its evidence is gathered.
struct Group<'a> {
    edge: EdgeType,
    subject: &'a Subject,
    object: &'a ObjectRef,
    rule: &'a Rule,
    rungs: BTreeSet<Grade>,
    matchers: BTreeSet<MatcherKind>,
    confidence: Confidence,
    evidence: Vec<RecordId>,
}

/// Derives the claims that `evidence` supports under `pack`.
///
/// Claims come back ordered by platform, app id, version, digest and object,
/// so the order is meaningful to a reader and independent of hash values.
/// Artifact and coverage records support no claim and are skipped here; the
/// report carries them alongside.
///
/// # Errors
///
/// Fails if an edge names a rule that `pack` does not contain.
pub fn derive(evidence: &EvidenceSet, pack: &Pack) -> Result<Vec<Claim>, DeriveError> {
    let mut groups: BTreeMap<ClaimId, Group<'_>> = BTreeMap::new();

    // The set iterates in record-id order, so each group's evidence list is
    // sorted without further work.
    for (&record_id, record) in evidence {
        let Record::Edge(edge) = record else { continue };
        let rule = pack.rule(&edge.rule).ok_or_else(|| DeriveError::UnknownRule {
            record: record_id.to_string(),
            rule: edge.rule.clone(),
        })?;
        let claim_id = ClaimId::of(edge.edge, &edge.subject, &edge.object)?;
        let witness = confidence(edge.proof.matcher, edge.proof.scope);

        let group = groups.entry(claim_id).or_insert_with(|| new_group(edge, rule));
        // Records in one group share a digest. Should they disagree on the
        // rest of the subject, keep the smallest, never the first seen.
        if edge.subject < *group.subject {
            group.subject = &edge.subject;
        }
        group.rungs.insert(edge.grade);
        group.matchers.insert(edge.proof.matcher);
        group.confidence = group.confidence.max(witness);
        group.evidence.push(record_id);
    }

    let mut claims = Vec::with_capacity(groups.len());
    for (id, group) in groups {
        claims.push(finish(id, group, pack)?);
    }
    claims.sort_by(|a, b| order_key(a).cmp(&order_key(b)));
    Ok(claims)
}

fn new_group<'a>(edge: &'a EdgeRecord, rule: &'a Rule) -> Group<'a> {
    Group {
        edge: edge.edge,
        subject: &edge.subject,
        object: &edge.object,
        rule,
        rungs: BTreeSet::new(),
        matchers: BTreeSet::new(),
        confidence: Confidence::Low,
        evidence: Vec::new(),
    }
}

fn finish(id: ClaimId, group: Group<'_>, pack: &Pack) -> Result<Claim, DeriveError> {
    let company = group
        .rule
        .entity
        .as_deref()
        .and_then(|entity| pack.company_of(entity))
        .map(|company| company.id.clone());
    // Variants are declared in ladder order, so the last rung is the highest.
    // A group is only created for a record, so it always has one.
    let grade = group.rungs.last().copied().unwrap_or(Grade::Declares);
    Ok(Claim {
        id,
        key: ClaimKey::of(group.edge, group.subject, group.object)?,
        edge: group.edge,
        subject: group.subject.clone(),
        object: ClaimObject {
            kind: group.object.kind,
            id: group.object.id.clone(),
            name: match group.object.kind {
                ObjectKind::Sdk => group.rule.name.clone(),
            },
        },
        company,
        category: group.rule.category.clone(),
        party: Party::Unknown,
        grade,
        rungs: group.rungs.into_iter().collect(),
        confidence: group.confidence,
        witnesses: u32::try_from(group.matchers.len()).unwrap_or(u32::MAX),
        evidence: group.evidence,
        notes: group.rule.notes.clone(),
    })
}

/// The order claims are listed in: by app, then by object.
///
/// The key is total. Two claims that agree on it agree on the subject digest,
/// the object and the edge type, which is exactly what a claim id hashes.
fn order_key(claim: &Claim) -> (&Subject, ObjectKind, &str, EdgeType) {
    (&claim.subject, claim.object.kind, claim.object.id.as_str(), claim.edge)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use std::format;

    use proptest::prelude::*;
    use xs_model::matcher::Boundary;
    use xs_model::pack::{Category, Entity, Layer, LoadedLayer, Token};
    use xs_model::record::{Collector, Platform, Proof, Region, SubjectKind, V1};
    use xs_model::{RelPath, Sha256Digest, SubjectDigest};

    use super::*;

    fn pack() -> Pack {
        let rule =
            |id: &str, name: &str, entity: Option<&str>, category: &str, notes: Vec<String>| Rule {
                id: id.into(),
                name: name.into(),
                entity: entity.map(Into::into),
                category: category.into(),
                sources: vec![],
                notes,
                matchers: BTreeMap::from([(
                    MatcherKind::AppleFramework,
                    vec![Token { lit: format!("{name}.framework"), at: Boundary::Exact }],
                )]),
                min_distinct: BTreeMap::new(),
            };
        let layer = Layer {
            format: V1,
            layer: "core".into(),
            version: 1,
            license: "CC-BY-4.0".into(),
            categories: vec![
                Category {
                    id: "crash_reporting".into(),
                    name: "Crash reporting".into(),
                    headline: false,
                },
                Category { id: "component".into(), name: "Component".into(), headline: false },
            ],
            entities: vec![
                Entity {
                    id: "firebase".into(),
                    name: "Firebase".into(),
                    parent: Some("google".into()),
                    website: "https://firebase.google.com/".into(),
                    source: "https://firebase.google.com/".into(),
                },
                Entity {
                    id: "google".into(),
                    name: "Google LLC".into(),
                    parent: None,
                    website: "https://about.google/".into(),
                    source: "https://about.google/".into(),
                },
            ],
            rules: vec![
                rule(
                    "sdk/crashlytics",
                    "Crashlytics",
                    Some("firebase"),
                    "crash_reporting",
                    vec!["retired:2025-03-31".into()],
                ),
                rule("sdk/sparkle", "Sparkle", None, "component", vec![]),
            ],
        };
        Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
    }

    fn digest(seed: u8) -> SubjectDigest {
        SubjectDigest::Bundle(Sha256Digest::of(&[seed]))
    }

    fn subject(id: &str, seed: u8) -> Subject {
        Subject {
            kind: SubjectKind::App,
            platform: Platform::Macos,
            id: id.into(),
            version: Some("1.0".into()),
            digest: digest(seed),
        }
    }

    fn edge(
        subject: Subject,
        rule: &str,
        grade: Grade,
        matcher: MatcherKind,
        scope: Scope,
        count: u32,
    ) -> Record {
        Record::Edge(EdgeRecord {
            v: V1,
            collector: Collector::MacosBundle,
            subject,
            edge: EdgeType::Channel,
            grade,
            object: ObjectRef { kind: ObjectKind::Sdk, id: rule.into() },
            rule: rule.into(),
            proof: Proof {
                matcher,
                token: "token".into(),
                count,
                example: None,
                location: RelPath::new("Contents/Frameworks").unwrap(),
                region: Region::DirEntries,
                scope,
            },
        })
    }

    fn set(records: impl IntoIterator<Item = Record>) -> EvidenceSet {
        let mut set = EvidenceSet::new();
        for record in records {
            set.insert(record).unwrap();
        }
        set
    }

    fn framework_edge(app: &str, seed: u8, rule: &str) -> Record {
        edge(
            subject(app, seed),
            rule,
            Grade::Contains,
            MatcherKind::AppleFramework,
            Scope::Dependency,
            1,
        )
    }

    #[test]
    fn one_edge_yields_one_claim_with_the_rule_s_facts() {
        let evidence = set([framework_edge("com.example.app", 1, "sdk/crashlytics")]);
        let claims = derive(&evidence, &pack()).unwrap();
        assert_eq!(claims.len(), 1);
        let claim = &claims[0];
        assert_eq!(claim.object.name, "Crashlytics");
        assert_eq!(claim.company.as_deref(), Some("google"), "the top of the ownership chain");
        assert_eq!(claim.category, "crash_reporting");
        assert_eq!(claim.party, Party::Unknown);
        assert_eq!(claim.grade, Grade::Contains);
        assert_eq!(claim.rungs, [Grade::Contains]);
        assert_eq!(claim.confidence, Confidence::High);
        assert_eq!(claim.witnesses, 1);
        assert_eq!(claim.notes, ["retired:2025-03-31"]);
        assert_eq!(claim.evidence, evidence.iter().map(|(id, _)| *id).collect::<Vec<_>>());
    }

    #[test]
    fn a_component_has_no_company() {
        let evidence = set([framework_edge("com.example.app", 1, "sdk/sparkle")]);
        let claims = derive(&evidence, &pack()).unwrap();
        assert_eq!(claims[0].company, None);
        assert_eq!(claims[0].category, "component");
    }

    #[test]
    fn witnesses_count_matcher_kinds_and_confidence_is_the_best_of_them() {
        let app = || subject("com.example.app", 1);
        let evidence = set([
            edge(
                app(),
                "sdk/crashlytics",
                Grade::Contains,
                MatcherKind::ContentLiteral,
                Scope::Dependency,
                1,
            ),
            edge(
                app(),
                "sdk/crashlytics",
                Grade::Contains,
                MatcherKind::ContentLiteral,
                Scope::Dependency,
                2,
            ),
            edge(
                app(),
                "sdk/crashlytics",
                Grade::Contains,
                MatcherKind::MachoToken,
                Scope::AppCode,
                1,
            ),
        ]);
        let claims = derive(&evidence, &pack()).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].witnesses, 2, "two records of one kind are one witness");
        assert_eq!(claims[0].confidence, Confidence::Medium);
        assert_eq!(claims[0].evidence.len(), 3);
        assert!(claims[0].evidence.is_sorted());
    }

    #[test]
    fn the_grade_is_the_highest_rung_and_all_rungs_are_listed() {
        let app = || subject("com.example.app", 1);
        let evidence = set([
            edge(
                app(),
                "sdk/crashlytics",
                Grade::Contains,
                MatcherKind::AppleFramework,
                Scope::Dependency,
                1,
            ),
            edge(
                app(),
                "sdk/crashlytics",
                Grade::Declares,
                MatcherKind::PrivacyManifest,
                Scope::AppCode,
                1,
            ),
        ]);
        let claims = derive(&evidence, &pack()).unwrap();
        assert_eq!(claims[0].grade, Grade::Contains);
        assert_eq!(claims[0].rungs, [Grade::Declares, Grade::Contains]);
    }

    #[test]
    fn two_builds_of_one_app_stay_separate() {
        let evidence = set([
            framework_edge("com.example.app", 1, "sdk/crashlytics"),
            framework_edge("com.example.app", 2, "sdk/crashlytics"),
        ]);
        let claims = derive(&evidence, &pack()).unwrap();
        assert_eq!(claims.len(), 2);
        assert_ne!(claims[0].id, claims[1].id);
        assert_eq!(claims[0].key, claims[1].key, "diff follows the claim across builds");
    }

    #[test]
    fn artifact_and_coverage_records_make_no_claims() {
        use xs_model::record::{
            ArtifactRecord, CoverageReason, CoverageRecord, CoverageStatus, Facts,
        };
        let evidence = set([
            Record::Artifact(ArtifactRecord {
                v: V1,
                collector: Collector::MacosBundle,
                subject: subject("com.example.app", 1),
                facts: Facts { name: Some("Example".into()), files_scanned: 1, bytes_scanned: 1 },
            }),
            Record::Coverage(CoverageRecord {
                v: V1,
                collector: Collector::MacosBundle,
                subject: subject("com.example.app", 1),
                status: CoverageStatus::Skipped,
                reason: CoverageReason::Unreadable,
                location: None,
                bytes: None,
                count: 1,
            }),
        ]);
        assert_eq!(derive(&evidence, &pack()), Ok(vec![]));
    }

    #[test]
    fn evidence_from_another_pack_is_an_error_not_an_empty_report() {
        let evidence = set([framework_edge("com.example.app", 1, "sdk/unheard-of")]);
        let error = derive(&evidence, &pack()).unwrap_err();
        assert!(
            matches!(&error, DeriveError::UnknownRule { rule, .. } if rule == "sdk/unheard-of")
        );
    }

    #[test]
    fn claims_are_listed_by_app_then_object() {
        let evidence = set([
            framework_edge("com.zebra.app", 1, "sdk/crashlytics"),
            framework_edge("com.apple.app", 2, "sdk/sparkle"),
            framework_edge("com.apple.app", 2, "sdk/crashlytics"),
        ]);
        let claims = derive(&evidence, &pack()).unwrap();
        let listed: Vec<(&str, &str)> = claims
            .iter()
            .map(|claim| (claim.subject.id.as_str(), claim.object.id.as_str()))
            .collect();
        assert_eq!(
            listed,
            [
                ("com.apple.app", "sdk/crashlytics"),
                ("com.apple.app", "sdk/sparkle"),
                ("com.zebra.app", "sdk/crashlytics"),
            ]
        );
    }

    #[test]
    fn the_confidence_table_follows_the_design() {
        use Confidence::{High, Low, Medium};
        assert_eq!(confidence(MatcherKind::AppleFramework, Scope::Dependency), High);
        assert_eq!(confidence(MatcherKind::ManifestComponent, Scope::AppCode), High);
        assert_eq!(confidence(MatcherKind::DexString, Scope::AppCode), Medium);
        assert_eq!(confidence(MatcherKind::MachoToken, Scope::AppCode), Medium);
        assert_eq!(confidence(MatcherKind::ContentLiteral, Scope::AppCode), Medium);
        assert_eq!(confidence(MatcherKind::ContentLiteral, Scope::Dependency), Low);
        assert_eq!(confidence(MatcherKind::ContentLiteral, Scope::Resource), Low);
    }

    /// A small universe of edges to draw evidence from.
    fn arb_edge() -> impl Strategy<Value = Record> {
        let grades = prop_oneof![
            Just(Grade::Declares),
            Just(Grade::Contains),
            Just(Grade::Contacts),
            Just(Grade::Confirmed)
        ];
        let matchers = prop::sample::select(MatcherKind::ALL.to_vec());
        let scopes = prop_oneof![
            Just(Scope::AppCode),
            Just(Scope::Dependency),
            Just(Scope::Runtime),
            Just(Scope::Resource)
        ];
        let rules = prop_oneof![Just("sdk/crashlytics"), Just("sdk/sparkle")];
        (0u8..3, rules, grades, matchers, scopes, 1u32..4).prop_map(
            |(app, rule, grade, matcher, scope, count)| {
                edge(subject("com.example.app", app), rule, grade, matcher, scope, count)
            },
        )
    }

    proptest! {
        /// The order evidence was gathered in cannot reach the claims.
        #[test]
        fn derivation_ignores_insertion_order(
            records in prop::collection::vec(arb_edge(), 0..24).prop_flat_map(|records| {
                (Just(records.clone()), Just(records).prop_shuffle())
            })
        ) {
            let (forward, shuffled) = records;
            prop_assert_eq!(derive(&set(forward), &pack()), derive(&set(shuffled), &pack()));
        }

        /// Grades only rise: more evidence never lowers a claim's grade or
        /// confidence, never removes a rung, a witness or a claim.
        #[test]
        fn more_evidence_never_weakens_a_claim(
            base in prop::collection::vec(arb_edge(), 0..12),
            extra in prop::collection::vec(arb_edge(), 0..12),
        ) {
            let before = derive(&set(base.clone()), &pack()).unwrap();
            let after = derive(&set(base.into_iter().chain(extra)), &pack()).unwrap();
            for old in &before {
                let new = after.iter().find(|claim| claim.id == old.id);
                prop_assert!(new.is_some(), "a claim disappeared");
                let new = new.unwrap();
                prop_assert!(new.grade >= old.grade);
                prop_assert!(new.confidence >= old.confidence);
                prop_assert!(new.witnesses >= old.witnesses);
                prop_assert!(old.rungs.iter().all(|rung| new.rungs.contains(rung)));
                prop_assert!(old.evidence.iter().all(|id| new.evidence.contains(id)));
            }
        }

        /// Every claim cites evidence that exists, and nothing else.
        #[test]
        fn every_claim_cites_existing_edges(records in prop::collection::vec(arb_edge(), 0..24)) {
            let evidence = set(records);
            let claims = derive(&evidence, &pack()).unwrap();
            let mut cited = 0;
            for claim in &claims {
                prop_assert!(!claim.evidence.is_empty());
                for id in &claim.evidence {
                    prop_assert!(matches!(evidence.get(id), Some(Record::Edge(_))));
                    cited += 1;
                }
            }
            prop_assert_eq!(cited, evidence.len(), "every edge supports exactly one claim");
        }
    }
}
