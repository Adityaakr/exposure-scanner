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
//! * **Declared hosts.** An edge to a host the app's own files declare, such
//!   as its update feed, is not the work of a pack rule. Its claim takes the
//!   category of the kind of declaration. The company is the one the pack
//!   lists the host's domain under. A host under no listed domain is
//!   unmapped: it is shown as itself, names no company and is counted
//!   nowhere. No generic table of host owners is consulted.
//! * **Vendor and party.** Who publishes the app is read from its signature
//!   first and its app id second, and the claim says whether the company is
//!   that vendor: first party, third party, or unknown. The rules are
//!   written out in the `resolve` module.
//! * **Headline.** A claim counts in the report's headline when it is a
//!   channel, names a company, and its category is one the pack counts
//!   there.
//!
//! The Public Suffix List that cuts a host down to its registrable domain is
//! compiled into the build, like the rule pack, so it is data and not a
//! lookup. It is part of what a scanner version means.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod resolve;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use xs_model::canon::CanonError;
use xs_model::claim::{Claim, ClaimId, ClaimKey, ClaimObject, Confidence};
use xs_model::matcher::MatcherKind;
use xs_model::pack::{Pack, Rule};
use xs_model::record::{
    EdgeRecord, EdgeType, Grade, ObjectKind, ObjectRef, Record, RecordId, Scope, Subject, declared,
};
use xs_model::{EvidenceSet, SubjectDigest};

use crate::resolve::Signers;

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
    /// An edge to a declared host needs a category the pack does not define.
    /// As with an unknown rule, the evidence and the pack do not belong
    /// together.
    UnknownCategory {
        /// The record that needs the category.
        record: String,
        /// The category id.
        category: String,
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
            Self::UnknownCategory { record, category } => write!(
                f,
                "record {record} needs the category `{category}`, which the loaded rule pack \
                 does not define"
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
        | MatcherKind::PrivacyManifest
        | MatcherKind::UpdateFeed => Confidence::High,
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

/// What stands behind the object of a claim.
#[derive(Clone, Copy)]
enum Origin<'a> {
    /// An SDK, described by its rule.
    Rule(&'a Rule),
    /// A host the app declares, with the category id of the declaration.
    Declared(&'a str),
}

/// Everything known about one claim while its evidence is gathered.
struct Group<'a> {
    edge: EdgeType,
    subject: &'a Subject,
    object: &'a ObjectRef,
    origin: Origin<'a>,
    rungs: BTreeSet<Grade>,
    matchers: BTreeSet<MatcherKind>,
    confidence: Confidence,
    evidence: Vec<RecordId>,
}

/// Derives the claims that `evidence` supports under `pack`.
///
/// Claims come back ordered by platform, app id, version, digest and object,
/// so the order is meaningful to a reader and independent of hash values.
/// Coverage records support no claim and are skipped here; the report
/// carries them alongside. Artifact records support none either, but the
/// Team ID one holds says who publishes the app, which decides the party of
/// every claim about it.
///
/// # Errors
///
/// Fails if an edge names a rule that `pack` does not contain, or is to a
/// declared host whose category `pack` does not define.
pub fn derive(evidence: &EvidenceSet, pack: &Pack) -> Result<Vec<Claim>, DeriveError> {
    let mut groups: BTreeMap<ClaimId, Group<'_>> = BTreeMap::new();
    // Who signed each build, by the digest that identifies the build.
    let mut signers: BTreeMap<&SubjectDigest, Signers<'_>> = BTreeMap::new();

    // The set iterates in record-id order, so each group's evidence list is
    // sorted without further work.
    for (&record_id, record) in evidence {
        let edge = match record {
            Record::Edge(edge) => edge,
            Record::Artifact(artifact) => {
                if let Some(team) = &artifact.facts.team_id {
                    let build = signers.entry(&artifact.subject.digest).or_default();
                    build.entry(team.as_str()).or_default().push(record_id);
                }
                continue;
            }
            Record::Coverage(_) => continue,
        };
        let origin = origin(record_id, edge, pack)?;
        let claim_id = ClaimId::of(edge.edge, &edge.subject, &edge.object)?;
        let witness = confidence(edge.proof.matcher, edge.proof.scope);

        let group = groups.entry(claim_id).or_insert_with(|| new_group(edge, origin));
        // Records in one group share a digest. Should they disagree on the
        // rest of the subject, keep the smallest, never the first seen.
        if edge.subject < *group.subject {
            group.subject = &edge.subject;
        }
        // One host may be declared in two ways. The claim then takes the
        // least category id, never that of the first record seen.
        if let (Origin::Declared(ours), Origin::Declared(theirs)) = (group.origin, origin)
            && theirs < ours
        {
            group.origin = origin;
        }
        group.rungs.insert(edge.grade);
        group.matchers.insert(edge.proof.matcher);
        group.confidence = group.confidence.max(witness);
        group.evidence.push(record_id);
    }

    let mut claims = Vec::with_capacity(groups.len());
    for (id, group) in groups {
        let signers = signers.get(&group.subject.digest);
        claims.push(finish(id, group, signers, pack)?);
    }
    claims.sort_by(|a, b| order_key(a).cmp(&order_key(b)));
    Ok(claims)
}

/// Finds what stands behind the object of `edge`: the pack rule of an SDK,
/// or the pack category of a declared host.
fn origin<'a>(
    record_id: RecordId,
    edge: &'a EdgeRecord,
    pack: &'a Pack,
) -> Result<Origin<'a>, DeriveError> {
    let unknown_rule =
        || DeriveError::UnknownRule { record: record_id.to_string(), rule: edge.rule.clone() };
    match edge.object.kind {
        ObjectKind::Sdk => pack.rule(&edge.rule).map(Origin::Rule).ok_or_else(unknown_rule),
        ObjectKind::Host => {
            let id = declared::category(&edge.rule).ok_or_else(unknown_rule)?;
            let category = pack.category(id).ok_or_else(|| DeriveError::UnknownCategory {
                record: record_id.to_string(),
                category: id.to_string(),
            })?;
            Ok(Origin::Declared(category.id.as_str()))
        }
    }
}

fn new_group<'a>(edge: &'a EdgeRecord, origin: Origin<'a>) -> Group<'a> {
    Group {
        edge: edge.edge,
        subject: &edge.subject,
        object: &edge.object,
        origin,
        rungs: BTreeSet::new(),
        matchers: BTreeSet::new(),
        confidence: Confidence::Low,
        evidence: Vec::new(),
    }
}

fn finish(
    id: ClaimId,
    group: Group<'_>,
    signers: Option<&Signers<'_>>,
    pack: &Pack,
) -> Result<Claim, DeriveError> {
    let (name, company, category, notes) = match group.origin {
        Origin::Rule(rule) => (
            rule.name.clone(),
            rule.entity
                .as_deref()
                .and_then(|entity| pack.company_of(entity))
                .map(|company| company.id.clone()),
            rule.category.as_str(),
            rule.notes.clone(),
        ),
        // A host is shown as itself. Only a domain the pack lists names its
        // owner; any other host stays unmapped.
        Origin::Declared(category) => (
            group.object.id.clone(),
            resolve::host_company(pack, &group.object.id),
            category,
            Vec::new(),
        ),
    };
    let headline = group.edge == EdgeType::Channel
        && company.is_some()
        && pack.category(category).is_some_and(|category| category.headline);
    let vendor = resolve::vendor(group.subject, signers, pack);
    let party = resolve::party(company.as_deref(), group.object, vendor.as_ref(), pack);
    // Variants are declared in ladder order, so the last rung is the highest.
    // A group is only created for a record, so it always has one.
    let grade = group.rungs.last().copied().unwrap_or(Grade::Declares);
    Ok(Claim {
        id,
        key: ClaimKey::of(group.edge, group.subject, group.object)?,
        edge: group.edge,
        subject: group.subject.clone(),
        object: ClaimObject { kind: group.object.kind, id: group.object.id.clone(), name },
        company,
        category: category.to_string(),
        headline,
        party,
        vendor,
        grade,
        rungs: group.rungs.into_iter().collect(),
        confidence: group.confidence,
        witnesses: u32::try_from(group.matchers.len()).unwrap_or(u32::MAX),
        evidence: group.evidence,
        notes,
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
    use xs_model::claim::{Party, Vendor, VendorBasis};
    use xs_model::matcher::Boundary;
    use xs_model::pack::{Category, Entity, Layer, LoadedLayer, Token};
    use xs_model::record::{
        ArtifactRecord, Collector, Facts, Platform, Proof, Region, SubjectKind, V1,
    };
    use xs_model::{Headline, RelPath, Sha256Digest};

    use super::*;

    /// Google's Team ID in the test pack.
    const GOOGLE_TEAM: &str = "EQHXZ8M8AV";
    /// A Team ID the test pack does not list.
    const OTHER_TEAM: &str = "M8L2WTLA8W";

    /// A pack with one company that lists a Team ID (Google, which owns
    /// Firebase), one that lists none (Acme), a rule in a headline category,
    /// one outside it, and a component.
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
        let category =
            |id: &str, headline: bool| Category { id: id.into(), name: id.into(), headline };
        let entity =
            |id: &str, parent: Option<&str>, team: &[&str], apps: &[&str], domains: &[&str]| {
                let list = |items: &[&str]| items.iter().map(|&item| item.into()).collect();
                Entity {
                    id: id.into(),
                    name: id.into(),
                    parent: parent.map(Into::into),
                    website: format!("https://{id}.example/"),
                    team_ids: list(team),
                    app_ids: list(apps),
                    domains: list(domains),
                    sources: vec![format!("https://{id}.example/terms")],
                }
            };
        let layer = Layer {
            format: V1,
            layer: "core".into(),
            version: 1,
            license: "CC-BY-4.0".into(),
            categories: vec![
                category("analytics", true),
                category("crash_reporting", false),
                category("component", false),
                category("update_feed", false),
            ],
            entities: vec![
                entity("acme", None, &[], &["com.acme"], &["acme.com"]),
                entity("firebase", Some("google"), &[], &[], &["firebaseio.com"]),
                entity("google", None, &[GOOGLE_TEAM], &["com.google"], &["google.com"]),
            ],
            rules: vec![
                rule("sdk/acme-analytics", "AcmeAnalytics", Some("acme"), "analytics", vec![]),
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

    /// The artifact record of a build, with the Team ID its signature names.
    fn artifact(app: &str, seed: u8, team_id: Option<&str>) -> Record {
        Record::Artifact(ArtifactRecord {
            v: V1,
            collector: Collector::MacosBundle,
            subject: subject(app, seed),
            facts: Facts {
                name: Some("Example".into()),
                team_id: team_id.map(Into::into),
                files_scanned: 1,
                bytes_scanned: 1,
            },
        })
    }

    /// An edge to a host the app declares under `rule`.
    fn host_edge(app: &str, seed: u8, host: &str, rule: &str, matcher: MatcherKind) -> Record {
        let Record::Edge(mut edge) =
            edge(subject(app, seed), "sdk/sparkle", Grade::Declares, matcher, Scope::AppCode, 1)
        else {
            unreachable!()
        };
        edge.object = ObjectRef { kind: ObjectKind::Host, id: host.into() };
        edge.rule = rule.into();
        Record::Edge(edge)
    }

    fn feed(app: &str, seed: u8, host: &str) -> Record {
        host_edge(app, seed, host, declared::UPDATE_FEED, MatcherKind::UpdateFeed)
    }

    /// The claims of one build: the app `app`, signed by `team_id`, with an
    /// edge of each of `rules` and an update feed on each of `hosts`.
    fn claims_of(app: &str, team_id: Option<&str>, rules: &[&str], hosts: &[&str]) -> Vec<Claim> {
        let records = [artifact(app, 1, team_id)]
            .into_iter()
            .chain(rules.iter().map(|rule| framework_edge(app, 1, rule)))
            .chain(hosts.iter().map(|host| feed(app, 1, host)));
        derive(&set(records), &pack()).unwrap()
    }

    fn claim<'a>(claims: &'a [Claim], object: &str) -> &'a Claim {
        claims.iter().find(|claim| claim.object.id == object).unwrap()
    }

    /// The vendor of a build no listed company publishes.
    fn unlisted(domain: &str) -> Option<Vendor> {
        Some(Vendor { company: None, by: None, domain: Some(domain.into()), evidence: vec![] })
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
        assert_eq!(claim.party, Party::Third);
        assert_eq!(claim.vendor, unlisted("example.com"));
        assert_eq!(claim.grade, Grade::Contains);
        assert_eq!(claim.rungs, [Grade::Contains]);
        assert_eq!(claim.confidence, Confidence::High);
        assert_eq!(claim.witnesses, 1);
        assert_eq!(claim.notes, ["retired:2025-03-31"]);
        assert_eq!(claim.evidence, evidence.iter().map(|(id, _)| *id).collect::<Vec<_>>());
    }

    #[test]
    fn a_component_has_no_company_and_no_party() {
        let claims = claims_of("com.google.Chrome", Some(GOOGLE_TEAM), &["sdk/sparkle"], &[]);
        assert_eq!(claims[0].company, None);
        assert_eq!(claims[0].category, "component");
        assert_eq!(claims[0].party, Party::Unknown, "whoever publishes the app");
        assert!(!claims[0].headline);
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
        use xs_model::record::{CoverageReason, CoverageRecord, CoverageStatus};
        let evidence = set([
            artifact("com.example.app", 1, Some(GOOGLE_TEAM)),
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

    /// Design report, section 3, M5: the signature is asked first. An app
    /// signed by a listed team is that company's, whatever its app id says.
    #[test]
    fn the_vendor_is_the_company_that_lists_the_team_id() {
        let records = [
            artifact("com.unrelated.app", 1, Some(GOOGLE_TEAM)),
            framework_edge("com.unrelated.app", 1, "sdk/crashlytics"),
            framework_edge("com.unrelated.app", 1, "sdk/acme-analytics"),
        ];
        let signed_by = records[0].id().unwrap();
        let claims = derive(&set(records), &pack()).unwrap();

        let own = claim(&claims, "sdk/crashlytics");
        assert_eq!(own.party, Party::First, "Firebase is Google's, and so is the app");
        let vendor = own.vendor.as_ref().unwrap();
        assert_eq!(vendor.company.as_deref(), Some("google"));
        assert_eq!(vendor.by, Some(VendorBasis::TeamId));
        assert_eq!(vendor.domain.as_deref(), Some("unrelated.com"));
        assert_eq!(vendor.evidence, [signed_by], "the record that holds the Team ID");

        let other = claim(&claims, "sdk/acme-analytics");
        assert_eq!(other.party, Party::Third);
        assert_eq!(other.vendor, own.vendor, "one build, one vendor");
    }

    #[test]
    fn then_the_company_that_lists_the_app_id() {
        // Unsigned, as an Android package is: the app id is all there is.
        let claims =
            claims_of("com.google.Chrome", None, &["sdk/crashlytics", "sdk/acme-analytics"], &[]);
        let own = claim(&claims, "sdk/crashlytics");
        assert_eq!(own.party, Party::First);
        assert_eq!(
            own.vendor,
            Some(Vendor {
                company: Some("google".into()),
                by: Some(VendorBasis::AppId),
                domain: Some("google.com".into()),
                evidence: vec![],
            })
        );
        assert_eq!(claim(&claims, "sdk/acme-analytics").party, Party::Third);

        // Signed by a team nobody lists, under a company that lists no Team
        // ID: the signature says nothing against the app id.
        let claims =
            claims_of("com.acme.Dashboard", Some(OTHER_TEAM), &["sdk/acme-analytics"], &[]);
        assert_eq!(claims[0].party, Party::First);
        assert_eq!(claims[0].vendor.as_ref().unwrap().by, Some(VendorBasis::AppId));
    }

    /// An app cannot make a tracker first party by naming itself after the
    /// tracker's company.
    #[test]
    fn a_signature_by_another_team_overrules_the_app_id() {
        let claims = claims_of(
            "com.google.Lookalike",
            Some(OTHER_TEAM),
            &["sdk/crashlytics", "sdk/acme-analytics"],
            &[],
        );
        for claim in &claims {
            assert_eq!(claim.vendor, None, "{}", claim.object.id);
            assert_eq!(claim.party, Party::Unknown, "{}", claim.object.id);
        }
    }

    #[test]
    fn two_signatures_of_different_owners_name_no_vendor() {
        let app = "com.example.app";
        let build = |teams: &[&str]| {
            let records = teams
                .iter()
                .enumerate()
                .map(|(index, team)| {
                    // Two records of one build: they differ in what was read.
                    let Record::Artifact(mut record) = artifact(app, 1, Some(team)) else {
                        unreachable!()
                    };
                    record.facts.files_scanned = index as u64 + 1;
                    Record::Artifact(record)
                })
                .chain([framework_edge(app, 1, "sdk/crashlytics")]);
            derive(&set(records), &pack()).unwrap().remove(0)
        };
        assert_eq!(build(&[GOOGLE_TEAM, OTHER_TEAM]).vendor, None);
        assert_eq!(build(&[GOOGLE_TEAM, OTHER_TEAM]).party, Party::Unknown);

        // Two records that agree are one answer, and both are cited.
        let agreed = build(&[GOOGLE_TEAM, GOOGLE_TEAM]);
        assert_eq!(agreed.party, Party::First);
        let cited = &agreed.vendor.as_ref().unwrap().evidence;
        assert_eq!(cited.len(), 2);
        assert!(cited.is_sorted());
    }

    /// Design report, section 3, A6: only companies that own an SDK can be
    /// first party to one, so an app nobody lists is third party to all.
    #[test]
    fn an_app_nobody_lists_is_third_party_to_every_listed_company() {
        for team in [None, Some(OTHER_TEAM)] {
            let claims = claims_of(
                "com.lwouis.alt-tab-macos",
                team,
                &["sdk/crashlytics", "sdk/acme-analytics"],
                &[],
            );
            for claim in &claims {
                assert_eq!(claim.vendor, unlisted("lwouis.com"));
                assert_eq!(claim.party, Party::Third, "{}", claim.object.id);
            }
        }
    }

    /// The pack lists `firebaseio.com` as Firebase's and no app id under it.
    /// An app that names itself after that domain may be Firebase's own, and
    /// nothing confirms it: neither first nor third is said.
    #[test]
    fn unless_its_app_id_points_at_that_company() {
        let claims = claims_of(
            "com.firebaseio.Console",
            None,
            &["sdk/crashlytics", "sdk/acme-analytics"],
            &[],
        );
        assert_eq!(claim(&claims, "sdk/crashlytics").vendor, unlisted("firebaseio.com"));
        assert_eq!(claim(&claims, "sdk/crashlytics").party, Party::Unknown);
        assert_eq!(claim(&claims, "sdk/acme-analytics").party, Party::Third);
    }

    #[test]
    fn an_app_that_says_nothing_of_its_vendor_has_none() {
        let claims = claims_of("Skeleton", None, &["sdk/crashlytics"], &["updates.example.net"]);
        for claim in &claims {
            assert_eq!(claim.vendor, None);
            assert_eq!(claim.party, Party::Unknown);
        }
        // A Team ID nobody lists does not say who either.
        let claims = claims_of("Skeleton", Some(OTHER_TEAM), &["sdk/crashlytics"], &[]);
        assert_eq!(claims[0].vendor, None);
        assert_eq!(claims[0].party, Party::Unknown);
    }

    /// Build plan, task 10: NetNewsWire's feed grades first party. Its app
    /// id, its Team ID and the host of its feed are those of the real app;
    /// the pack lists none of them.
    #[test]
    fn a_feed_on_the_app_s_own_domain_is_first_party() {
        let app = "com.ranchero.NetNewsWire-Evergreen";
        let claims = claims_of(app, Some(OTHER_TEAM), &["sdk/sparkle"], &["ranchero.com"]);
        let feed = claim(&claims, "ranchero.com");
        assert_eq!(feed.object.kind, ObjectKind::Host);
        assert_eq!(feed.object.name, "ranchero.com");
        assert_eq!(feed.category, "update_feed");
        assert_eq!(feed.grade, Grade::Declares);
        assert_eq!(feed.rungs, [Grade::Declares]);
        assert_eq!(feed.confidence, Confidence::High);
        assert_eq!(feed.party, Party::First);
        assert_eq!(feed.vendor, unlisted("ranchero.com"));
        assert_eq!(feed.company, None, "the vendor is nobody the pack lists");
        assert!(!feed.headline);
        assert!(feed.notes.is_empty());

        // A host below the domain is under it too.
        let claims = claims_of(app, None, &[], &["updates.cdn.ranchero.com"]);
        assert_eq!(claims[0].party, Party::First);
        // A name that merely contains the domain is not.
        let claims = claims_of(app, None, &[], &["ranchero.com.example.net", "notranchero.com"]);
        assert!(claims.iter().all(|claim| claim.party == Party::Unknown), "{claims:#?}");
    }

    /// Build plan, task 10: an unmapped domain is shown and not counted.
    #[test]
    fn an_unmapped_host_is_shown_as_itself_and_counted_nowhere() {
        let claims = claims_of("org.p0deje.Maccy", Some(OTHER_TEAM), &[], &["cdn.example.net"]);
        assert_eq!(claims.len(), 1, "it is shown");
        let host = &claims[0];
        assert_eq!(host.object.kind, ObjectKind::Host);
        assert_eq!(host.object.id, "cdn.example.net");
        assert_eq!(host.object.name, "cdn.example.net", "as itself");
        assert_eq!(host.company, None, "nobody is named as its owner");
        assert_eq!(host.party, Party::Unknown, "so nobody is first or third party");
        assert!(!host.headline);
        assert_eq!(Headline::of(&claims), Headline::default());

        // Not even in a category the headline counts: with no company there
        // is nobody to count.
        let tracking = host_edge(
            "org.p0deje.Maccy",
            1,
            "t.example.net",
            declared::UPDATE_FEED,
            MatcherKind::UpdateFeed,
        );
        let mut counted = pack();
        let mut layers = counted.layers().to_vec();
        for category in &mut layers[0].layer.categories {
            category.headline = true;
        }
        counted = Pack::new(layers).unwrap();
        let claims = derive(&set([tracking]), &counted).unwrap();
        assert!(!claims[0].headline);
        assert_eq!(Headline::of(&claims), Headline::default());
    }

    #[test]
    fn a_host_under_a_listed_domain_names_its_company() {
        // Somebody else's app fetches its updates from a Google host.
        let claims =
            claims_of("org.p0deje.Maccy", None, &[], &["dl.google.com", "x.firebaseio.com"]);
        for claim in &claims {
            assert_eq!(claim.company.as_deref(), Some("google"), "{}", claim.object.id);
            assert_eq!(claim.object.name, claim.object.id, "still shown as itself");
            assert_eq!(claim.party, Party::Third);
            assert_eq!(claim.category, "update_feed");
            assert!(!claim.headline, "hosting is not receiving");
        }
        // Google's own app does.
        let claims = claims_of("com.google.Chrome", Some(GOOGLE_TEAM), &[], &["dl.google.com"]);
        assert_eq!(claims[0].party, Party::First);
        // A name that merely looks like the domain is unmapped.
        let claims = claims_of("org.p0deje.Maccy", None, &[], &["google.com.example.net"]);
        assert_eq!(claims[0].company, None);
    }

    /// A suffix a company runs for its users has an owner per name, and the
    /// Public Suffix List says so.
    #[test]
    fn a_shared_suffix_is_not_one_owner() {
        let app = "io.github.alice.tool";
        let claims = claims_of(app, None, &[], &["alice.github.io", "bob.github.io"]);
        assert_eq!(claim(&claims, "alice.github.io").party, Party::First);
        assert_eq!(claim(&claims, "bob.github.io").party, Party::Unknown);
    }

    #[test]
    fn a_host_under_no_known_suffix_is_nobody_s_own_domain() {
        let claims = claims_of("lan.printer", None, &[], &["printer.lan", "10.0.0.1"]);
        for claim in &claims {
            assert_eq!(claim.vendor, None);
            assert_eq!(claim.party, Party::Unknown, "{}", claim.object.id);
        }
    }

    /// Design report, section 3, A7: only the categories the pack marks
    /// count in the headline.
    #[test]
    fn only_company_channels_in_headline_categories_count() {
        let claims = claims_of(
            "com.example.app",
            None,
            &["sdk/acme-analytics", "sdk/crashlytics", "sdk/sparkle"],
            &["dl.google.com", "cdn.example.net"],
        );
        let counted: Vec<&str> = claims
            .iter()
            .filter(|claim| claim.headline)
            .map(|claim| claim.object.id.as_str())
            .collect();
        assert_eq!(counted, ["sdk/acme-analytics"]);
        assert_eq!(
            Headline::of(&claims),
            Headline { companies_contacts: 0, companies_contains: 1, apps_third_party: 1 }
        );

        // The same SDK in its vendor's own app: the company still has the
        // channel, and no app has a third-party one.
        let claims = claims_of("com.acme.Dashboard", None, &["sdk/acme-analytics"], &[]);
        assert!(claims[0].headline);
        assert_eq!(
            Headline::of(&claims),
            Headline { companies_contacts: 0, companies_contains: 1, apps_third_party: 0 }
        );
    }

    #[test]
    fn a_declared_host_needs_its_category_in_the_pack() {
        // The test pack defines `update_feed` and not `tracking_domain`.
        let evidence = set([host_edge(
            "com.example.app",
            1,
            "tracker.example.net",
            declared::TRACKING_DOMAIN,
            MatcherKind::PrivacyManifest,
        )]);
        let error = derive(&evidence, &pack()).unwrap_err();
        assert!(matches!(
            &error,
            DeriveError::UnknownCategory { category, .. } if category == "tracking_domain"
        ));
        assert!(error.to_string().contains("tracking_domain"));
    }

    #[test]
    fn the_confidence_table_follows_the_design() {
        use Confidence::{High, Low, Medium};
        assert_eq!(confidence(MatcherKind::AppleFramework, Scope::Dependency), High);
        assert_eq!(confidence(MatcherKind::ManifestComponent, Scope::AppCode), High);
        assert_eq!(confidence(MatcherKind::UpdateFeed, Scope::AppCode), High);
        assert_eq!(confidence(MatcherKind::PrivacyManifest, Scope::Dependency), High);
        assert_eq!(confidence(MatcherKind::DexString, Scope::AppCode), Medium);
        assert_eq!(confidence(MatcherKind::MachoToken, Scope::AppCode), Medium);
        assert_eq!(confidence(MatcherKind::ContentLiteral, Scope::AppCode), Medium);
        assert_eq!(confidence(MatcherKind::ContentLiteral, Scope::Dependency), Low);
        assert_eq!(confidence(MatcherKind::ContentLiteral, Scope::Resource), Low);
    }

    /// The apps evidence is drawn from: one of each way a vendor resolves.
    const APPS: [&str; 5] = [
        "com.example.app",
        "com.google.Chrome",
        "com.acme.Dashboard",
        "com.ranchero.NetNewsWire-Evergreen",
        "Skeleton",
    ];

    fn arb_app() -> impl Strategy<Value = (&'static str, u8)> {
        (prop::sample::select(APPS.to_vec()), 0u8..2)
    }

    /// A small universe of records to draw evidence from: edges to SDKs in
    /// and out of the headline, edges to hosts that are mapped, unmapped and
    /// the app's own, and artifact records that name a listed team, an
    /// unlisted one or none.
    fn arb_record() -> impl Strategy<Value = Record> {
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
        let rules =
            prop_oneof![Just("sdk/crashlytics"), Just("sdk/acme-analytics"), Just("sdk/sparkle")];
        let sdks = (arb_app(), rules, grades, matchers, scopes, 1u32..4).prop_map(
            |((app, seed), rule, grade, matcher, scope, count)| {
                edge(subject(app, seed), rule, grade, matcher, scope, count)
            },
        );
        let hosts =
            prop_oneof![Just("dl.google.com"), Just("ranchero.com"), Just("cdn.example.net")];
        let feeds = (arb_app(), hosts).prop_map(|((app, seed), host)| feed(app, seed, host));
        let teams = prop_oneof![Just(None), Just(Some(GOOGLE_TEAM)), Just(Some(OTHER_TEAM))];
        let artifacts =
            (arb_app(), teams).prop_map(|((app, seed), team)| artifact(app, seed, team));
        prop_oneof![5 => sdks, 2 => feeds, 2 => artifacts]
    }

    proptest! {
        /// The order evidence was gathered in cannot reach the claims.
        #[test]
        fn derivation_ignores_insertion_order(
            records in prop::collection::vec(arb_record(), 0..24).prop_flat_map(|records| {
                (Just(records.clone()), Just(records).prop_shuffle())
            })
        ) {
            let (forward, shuffled) = records;
            prop_assert_eq!(derive(&set(forward), &pack()), derive(&set(shuffled), &pack()));
        }

        /// Grades only rise: more evidence never lowers a claim's grade or
        /// confidence, never removes a rung, a witness or a claim. What it
        /// may change is who is known to publish the app, and with that the
        /// party; it never changes who is behind the object.
        #[test]
        fn more_evidence_never_weakens_a_claim(
            base in prop::collection::vec(arb_record(), 0..12),
            extra in prop::collection::vec(arb_record(), 0..12),
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
                prop_assert_eq!(&new.company, &old.company);
                prop_assert_eq!(&new.category, &old.category);
                prop_assert_eq!(new.headline, old.headline);
            }
        }

        /// Every claim cites evidence that exists, and nothing else.
        #[test]
        fn every_claim_cites_existing_edges(records in prop::collection::vec(arb_record(), 0..24)) {
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
            let edges = evidence.iter().filter(|(_, record)| matches!(record, Record::Edge(_)));
            prop_assert_eq!(cited, edges.count(), "every edge supports exactly one claim");
        }

        /// What a claim says about the vendor holds together, and a vendor
        /// known by its signature shows the records that hold the signature.
        #[test]
        fn the_party_rests_on_a_vendor_that_can_be_checked(
            records in prop::collection::vec(arb_record(), 0..24)
        ) {
            let evidence = set(records);
            for claim in derive(&evidence, &pack()).unwrap() {
                if claim.party != Party::Unknown {
                    prop_assert!(claim.vendor.is_some(), "a party without a vendor");
                }
                if claim.headline {
                    prop_assert!(claim.company.is_some(), "a counted claim names a company");
                }
                let Some(vendor) = &claim.vendor else { continue };
                prop_assert_eq!(vendor.company.is_some(), vendor.by.is_some());
                prop_assert!(vendor.company.is_some() || vendor.domain.is_some());
                prop_assert_eq!(
                    vendor.by == Some(VendorBasis::TeamId),
                    !vendor.evidence.is_empty()
                );
                for id in &vendor.evidence {
                    let Some(Record::Artifact(artifact)) = evidence.get(id) else {
                        return Err(TestCaseError::fail("the vendor cites no artifact record"));
                    };
                    prop_assert_eq!(&artifact.subject.digest, &claim.subject.digest);
                    prop_assert_eq!(artifact.facts.team_id.as_deref(), Some(GOOGLE_TEAM));
                }
            }
        }
    }
}
