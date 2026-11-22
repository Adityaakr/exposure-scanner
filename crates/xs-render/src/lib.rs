//! Renderers: claims and their evidence in, a report document out.
//!
//! Rendering is pure, like derivation: the crate is `no_std` and has no way
//! to read a clock, a file or the environment. A report holds no timestamp
//! and no machine-specific value, so rendering the same claims and evidence
//! twice gives the same bytes.
//!
//! Every renderer first checks the **honesty** property: each claim must cite
//! at least one record, and every cited record must be in the evidence set
//! that travels with the report. The same holds for what a claim says about
//! the app's vendor: a vendor known by its signature must cite the record
//! that holds the Team ID. A report that cannot show the record behind a
//! finding is refused rather than written.
//!
//! The headline counts are tallied here, from the very claims the document
//! carries, so the numbers a reader sees first cannot disagree with the
//! findings below them.
//!
//! There are two renderers. [`json`] writes the document a program reads
//! and a later render starts from. [`html`] writes the one a person reads:
//! the same findings, grouped by company, with the records behind them, what
//! the scan covered and what no scan can see.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod html;
mod markup;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::Serialize;
use xs_model::canon::{self, CanonError};
use xs_model::pack::PackRef;
use xs_model::record::{Record, RecordId};
use xs_model::report::{ReportSchema, ScanScope, Scanner};
use xs_model::{Claim, EvidenceSet, Headline};

pub use crate::html::{CONTENT_SECURITY_POLICY, checklist, html};

/// How much an entry of the checklist exposes. Entries are listed with
/// the highest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TodoPriority {
    /// Code of an advertising, analytics, attribution, profiling or session
    /// replay company in an app it does not publish, and a browser extension
    /// that may read the pages a person visits.
    High,
    /// What apps may reach of a person: camera, microphone, screen,
    /// location, personal data; and a domain an app declares for tracking.
    Medium,
    /// The rest a person can act on.
    Low,
}

impl TodoPriority {
    /// The word the report uses for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
        }
    }

    /// Whether an entry of this priority is one a person should look at
    /// first: high and medium are, low is not.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        !matches!(self, Self::Low)
    }
}

/// One entry of the checklist, in plain words ([`checklist`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Todo {
    pub priority: TodoPriority,
    /// What it is about: a service, an extension, a pane of the settings or
    /// an app.
    pub title: String,
    /// One sentence on what was found and where.
    pub about: String,
    /// The first thing to do. The HTML report has every step.
    pub step: String,
}

/// How many entries of the checklist a summary leads with, on the page and
/// on the terminal alike.
pub const FIRST_TODOS: usize = 5;

/// The entries of `todos`, a checklist in its own order, that a summary
/// leads with: the first [`FIRST_TODOS`] of those that need attention
/// ([`TodoPriority::needs_attention`]), or, when none does, the first of
/// the rest. The HTML report's "What needs your attention" and the summary
/// a scan prints are both these entries.
#[must_use]
pub fn first_todos(todos: &[Todo]) -> &[Todo] {
    let urgent = todos.iter().take_while(|todo| todo.priority.needs_attention()).count();
    let shown = if urgent > 0 { urgent } else { todos.len() };
    todos.get(..shown.min(FIRST_TODOS)).unwrap_or(todos)
}

/// What a report says about how it was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportMeta {
    /// The scanner that produced the evidence.
    pub scanner: Scanner,
    /// The rule-pack layers the claims were derived with.
    pub packs: Vec<PackRef>,
    /// Where the scan looked for apps and where it deliberately did not.
    ///
    /// The JSON document carries it, so a report rendered again from a
    /// saved one states the same scope as the scan did. A report saved
    /// before the document had the field has `None`, and the HTML report
    /// then says that the scope is not on record instead of leaving it out.
    pub scope: Option<ScanScope>,
}

/// Why a report was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// A claim cites no evidence at all.
    NoEvidence {
        /// The claim.
        claim: String,
    },
    /// A claim cites a record the evidence set does not hold.
    MissingEvidence {
        /// The claim.
        claim: String,
        /// The record id it cites.
        record: String,
    },
    /// A claim cites a record that is not an edge, and so proves no link.
    NotAnEdge {
        /// The claim.
        claim: String,
        /// The record id it cites.
        record: String,
    },
    /// A claim says who publishes the app and cites, for that, a record that
    /// is not an artifact record of the same build, and so holds no
    /// signature of it.
    NotTheArtifact {
        /// The claim.
        claim: String,
        /// The record id it cites.
        record: String,
    },
    /// The rule pack handed to the renderer is not the one the report names,
    /// so its names would be put on claims derived with other rules.
    PackMismatch,
    /// A claim names a company or a category the rule pack does not hold. The
    /// category of an access claim is looked up in the fixed access list of
    /// `xs_model::access` instead, or is `xs_model::permission::CATEGORY`
    /// for a browser extension.
    NotInPack {
        /// The claim.
        claim: String,
        /// What kind of thing is named: `company` or `category`.
        kind: &'static str,
        /// The id that does not resolve.
        id: String,
    },
    /// The document has no canonical form.
    Canon(CanonError),
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEvidence { claim } => write!(f, "claim {claim} cites no evidence"),
            Self::MissingEvidence { claim, record } => {
                write!(f, "claim {claim} cites record {record}, which the report does not carry")
            }
            Self::NotAnEdge { claim, record } => {
                write!(f, "claim {claim} cites record {record}, which is not an edge")
            }
            Self::NotTheArtifact { claim, record } => write!(
                f,
                "claim {claim} cites record {record} for the app's vendor, which is not an \
                 artifact record of that build"
            ),
            Self::PackMismatch => {
                f.write_str("the rule pack is not the one the report says it was derived with")
            }
            Self::NotInPack { claim, kind, id } => {
                write!(
                    f,
                    "claim {claim} names the {kind} `{id}`, which the rule pack does not hold"
                )
            }
            Self::Canon(error) => write!(f, "report has no canonical form: {error}"),
        }
    }
}

impl core::error::Error for RenderError {}

impl From<CanonError> for RenderError {
    fn from(error: CanonError) -> Self {
        Self::Canon(error)
    }
}

/// Checks that every claim can show the records behind it.
///
/// # Errors
///
/// Returns the first claim that cites nothing, cites a record missing from
/// `evidence`, cites a record that is not an edge, or cites for the app's
/// vendor a record that is not an artifact record of the same build.
pub fn check_honest(claims: &[Claim], evidence: &EvidenceSet) -> Result<(), RenderError> {
    for claim in claims {
        if claim.evidence.is_empty() {
            return Err(RenderError::NoEvidence { claim: claim.id.to_string() });
        }
        let missing = |id: &RecordId| RenderError::MissingEvidence {
            claim: claim.id.to_string(),
            record: id.to_string(),
        };
        for id in &claim.evidence {
            match evidence.get(id).ok_or_else(|| missing(id))? {
                Record::Edge(_) => {}
                _ => {
                    return Err(RenderError::NotAnEdge {
                        claim: claim.id.to_string(),
                        record: id.to_string(),
                    });
                }
            }
        }
        for id in claim.vendor.iter().flat_map(|vendor| &vendor.evidence) {
            match evidence.get(id).ok_or_else(|| missing(id))? {
                Record::Artifact(artifact) if artifact.subject.digest == claim.subject.digest => {}
                _ => {
                    return Err(RenderError::NotTheArtifact {
                        claim: claim.id.to_string(),
                        record: id.to_string(),
                    });
                }
            }
        }
    }
    Ok(())
}

/// The report document, borrowing its parts. Field for field the same as
/// [`xs_model::Report`], which is what reads it back.
#[derive(Serialize)]
struct ReportRef<'a> {
    schema: ReportSchema,
    scanner: &'a Scanner,
    packs: &'a [PackRef],
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<ScanScope>,
    headline: Headline,
    claims: &'a [Claim],
    evidence: &'a EvidenceSet,
}

/// Renders the JSON report: canonical JSON followed by one newline.
///
/// The document carries the claims and the complete evidence set, so every
/// finding can be traced to its raw record and the report can be rendered
/// again from the file alone. Its headline is [`Headline::of`] the claims.
///
/// # Errors
///
/// Fails if the claims do not pass [`check_honest`].
pub fn json(
    claims: &[Claim],
    evidence: &EvidenceSet,
    meta: &ReportMeta,
) -> Result<String, RenderError> {
    check_honest(claims, evidence)?;
    let document = ReportRef {
        schema: ReportSchema,
        scanner: &meta.scanner,
        packs: &meta.packs,
        scope: meta.scope,
        headline: Headline::of(claims),
        claims,
        evidence,
    };
    let mut text = canon::to_string(&document)?;
    text.push('\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use xs_model::claim::{ClaimId, ClaimKey, ClaimObject, Confidence, Party, Vendor, VendorBasis};
    use xs_model::record::{
        ArtifactRecord, Collector, EdgeRecord, EdgeType, Facts, Grade, ObjectKind, ObjectRef,
        Platform, Proof, Region, Scope, Subject, SubjectKind, V1,
    };
    use xs_model::{MatcherKind, RecordId, RelPath, Report, Sha256Digest, SubjectDigest};

    use super::*;

    fn subject() -> Subject {
        Subject {
            kind: SubjectKind::App,
            platform: Platform::Macos,
            id: "com.example.app".into(),
            version: Some("1.0".into()),
            digest: SubjectDigest::Bundle(Sha256Digest::of(b"bundle")),
        }
    }

    fn object() -> ObjectRef {
        ObjectRef { kind: ObjectKind::Sdk, id: "sdk/sentry".into() }
    }

    fn edge() -> Record {
        Record::Edge(EdgeRecord {
            v: V1,
            collector: Collector::MacosBundle,
            subject: subject(),
            edge: EdgeType::Channel,
            grade: Grade::Contains,
            object: object(),
            rule: "sdk/sentry".into(),
            proof: Proof {
                matcher: MatcherKind::AppleFramework,
                token: "Sentry.framework".into(),
                count: 1,
                example: Some("Sentry.framework".into()),
                location: RelPath::new("Contents/Frameworks").unwrap(),
                region: Region::DirEntries,
                scope: Scope::Dependency,
                max_sdk: None,
            },
        })
    }

    fn artifact() -> Record {
        Record::Artifact(ArtifactRecord {
            v: V1,
            collector: Collector::MacosBundle,
            subject: subject(),
            facts: Facts {
                name: Some("Example".into()),
                team_id: None,
                sandbox: None,
                files_scanned: 2,
                bytes_scanned: 64,
                ..Facts::default()
            },
        })
    }

    fn claim(evidence: Vec<RecordId>) -> Claim {
        Claim {
            id: ClaimId::of(EdgeType::Channel, &subject(), &object()).unwrap(),
            key: ClaimKey::of(EdgeType::Channel, &subject(), &object()).unwrap(),
            edge: EdgeType::Channel,
            subject: subject(),
            object: ClaimObject {
                kind: ObjectKind::Sdk,
                id: "sdk/sentry".into(),
                name: "Sentry".into(),
            },
            company: Some("sentry".into()),
            category: "crash_reporting".into(),
            headline: false,
            party: Party::Third,
            vendor: Some(Vendor {
                company: None,
                by: None,
                domain: Some("example.com".into()),
                evidence: vec![],
            }),
            grade: Grade::Contains,
            rungs: vec![Grade::Contains],
            confidence: Confidence::High,
            witnesses: 1,
            evidence,
            notes: vec![],
        }
    }

    fn meta() -> ReportMeta {
        ReportMeta {
            scanner: Scanner { name: "exposure".into(), version: "0.1.0".into() },
            packs: vec![PackRef {
                layer: "core".into(),
                version: 1,
                sha256: Sha256Digest::of(b"pack").to_hex(),
            }],
            scope: None,
        }
    }

    /// An evidence set with one edge and one artifact record, and the claim
    /// the edge supports.
    fn fixture() -> (Vec<Claim>, EvidenceSet, RecordId, RecordId) {
        let mut evidence = EvidenceSet::new();
        let edge_id = evidence.insert(edge()).unwrap();
        let artifact_id = evidence.insert(artifact()).unwrap();
        (vec![claim(vec![edge_id])], evidence, edge_id, artifact_id)
    }

    #[test]
    fn the_report_reads_back_as_the_model_s_report() {
        let (claims, evidence, _, _) = fixture();
        let text = json(&claims, &evidence, &meta()).unwrap();
        assert!(text.ends_with("}\n"));
        let report: Report = serde_json::from_str(&text).unwrap();
        assert_eq!(report.claims, claims);
        assert_eq!(report.evidence, evidence);
        assert_eq!(report.scanner, meta().scanner);
        assert_eq!(report.packs, meta().packs);
        assert_eq!(report.scope, None);
    }

    /// The document carries where the scan looked, so a later render can
    /// state it. A report without a scope has no such field at all, which
    /// is the document as it was before the field existed.
    #[test]
    fn the_report_carries_the_scope_of_the_scan() {
        let (claims, evidence, _, _) = fixture();
        for (scope, stored) in [(ScanScope::Installed, "installed"), (ScanScope::Given, "given")] {
            let meta = ReportMeta { scope: Some(scope), ..meta() };
            let text = json(&claims, &evidence, &meta).unwrap();
            let tree: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(tree["scope"], stored);
            let report: Report = serde_json::from_str(&text).unwrap();
            assert_eq!(report.scope, Some(scope));
            // The scope is beside the evidence, not in it.
            assert_eq!(report.evidence, evidence);
        }
        let text = json(&claims, &evidence, &meta()).unwrap();
        let tree: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(tree.get("scope").is_none(), "{text}");
    }

    #[test]
    fn rendering_twice_gives_the_same_bytes() {
        let (claims, evidence, _, _) = fixture();
        assert_eq!(json(&claims, &evidence, &meta()), json(&claims, &evidence, &meta()));
    }

    #[test]
    fn the_report_shows_grade_confidence_and_the_raw_record_of_every_finding() {
        let (claims, evidence, edge_id, _) = fixture();
        let text = json(&claims, &evidence, &meta()).unwrap();
        let tree: serde_json::Value = serde_json::from_str(&text).unwrap();
        let finding = &tree["claims"][0];
        assert_eq!(finding["grade"], "contains");
        assert_eq!(finding["confidence"], "high");
        let cited = finding["evidence"][0].as_str().unwrap();
        assert_eq!(cited, edge_id.to_string());
        assert_eq!(tree["evidence"][cited]["proof"]["token"], "Sentry.framework");
    }

    /// Design report, section 7 property 6: delete one record and the
    /// renderer must fail.
    #[test]
    fn deleting_a_cited_record_fails_the_render() {
        let (claims, mut evidence, edge_id, _) = fixture();
        evidence.remove(&edge_id).unwrap();
        let error = json(&claims, &evidence, &meta()).unwrap_err();
        assert_eq!(
            error,
            RenderError::MissingEvidence {
                claim: claims[0].id.to_string(),
                record: edge_id.to_string()
            }
        );
    }

    #[test]
    fn deleting_an_uncited_record_does_not() {
        let (claims, mut evidence, _, artifact_id) = fixture();
        evidence.remove(&artifact_id).unwrap();
        assert!(json(&claims, &evidence, &meta()).is_ok());
    }

    #[test]
    fn a_claim_must_cite_edges() {
        let (_, evidence, _, artifact_id) = fixture();
        assert!(matches!(
            json(&[claim(vec![])], &evidence, &meta()),
            Err(RenderError::NoEvidence { .. })
        ));
        assert!(matches!(
            json(&[claim(vec![artifact_id])], &evidence, &meta()),
            Err(RenderError::NotAnEdge { .. })
        ));
    }

    /// A claim whose vendor is known by its signature, citing `cited` for it.
    fn signed_claim(edge_id: RecordId, cited: Vec<RecordId>) -> Claim {
        let mut claim = claim(vec![edge_id]);
        claim.party = Party::First;
        claim.vendor = Some(Vendor {
            company: Some("sentry".into()),
            by: Some(VendorBasis::TeamId),
            domain: Some("example.com".into()),
            evidence: cited,
        });
        claim
    }

    /// The party of a finding rests on who signed the app, so the record
    /// that holds the signature's Team ID is part of what the report must
    /// be able to show.
    #[test]
    fn a_vendor_known_by_its_signature_must_cite_the_artifact_record() {
        let (_, mut evidence, edge_id, artifact_id) = fixture();
        let claims = [signed_claim(edge_id, vec![artifact_id])];
        assert!(json(&claims, &evidence, &meta()).is_ok());

        // An edge holds no signature.
        let not_an_artifact = [signed_claim(edge_id, vec![edge_id])];
        assert_eq!(
            json(&not_an_artifact, &evidence, &meta()).unwrap_err(),
            RenderError::NotTheArtifact {
                claim: claims[0].id.to_string(),
                record: edge_id.to_string()
            }
        );

        // Nor does the artifact record of another build.
        let Record::Artifact(mut other) = artifact() else { unreachable!() };
        other.subject.digest = SubjectDigest::Bundle(Sha256Digest::of(b"another bundle"));
        let other_id = evidence.insert(Record::Artifact(other)).unwrap();
        let another_build = [signed_claim(edge_id, vec![other_id])];
        assert!(matches!(
            json(&another_build, &evidence, &meta()),
            Err(RenderError::NotTheArtifact { .. })
        ));

        // Delete the record and the render fails, as for any cited record.
        evidence.remove(&artifact_id).unwrap();
        assert_eq!(
            json(&claims, &evidence, &meta()).unwrap_err(),
            RenderError::MissingEvidence {
                claim: claims[0].id.to_string(),
                record: artifact_id.to_string()
            }
        );
    }

    #[test]
    fn the_headline_is_a_tally_of_the_claims_in_the_document() {
        let (mut claims, evidence, _, _) = fixture();
        let headline = |claims: &[Claim]| {
            let text = json(claims, &evidence, &meta()).unwrap();
            let report: Report = serde_json::from_str(&text).unwrap();
            assert_eq!(report.headline, Headline::of(&report.claims));
            report.headline
        };
        // Crash reporting is outside the headline.
        assert_eq!(headline(&claims), Headline::default());
        claims[0].headline = true;
        assert_eq!(
            headline(&claims),
            Headline { companies_contacts: 0, companies_contains: 1, apps_third_party: 1 }
        );
    }

    fn todo(priority: TodoPriority, title: &str) -> Todo {
        Todo { priority, title: title.into(), about: String::new(), step: String::new() }
    }

    /// A summary leads with the entries that need attention, at most
    /// [`FIRST_TODOS`] of them, and with low-priority ones only when there
    /// is nothing else.
    #[test]
    fn a_summary_leads_with_what_needs_attention() {
        use TodoPriority::{High, Low, Medium};
        let titles = |todos: &[Todo]| todos.iter().map(|t| t.title.clone()).collect::<Vec<_>>();
        let mixed = [todo(High, "a"), todo(Medium, "b"), todo(Low, "c"), todo(Low, "d")];
        assert_eq!(titles(first_todos(&mixed)), ["a", "b"]);
        let many: Vec<Todo> = (0..7).map(|at| todo(Medium, &at.to_string())).collect();
        assert_eq!(titles(first_todos(&many)), ["0", "1", "2", "3", "4"]);
        let low: Vec<Todo> = (0..7).map(|at| todo(Low, &at.to_string())).collect();
        assert_eq!(titles(first_todos(&low)), ["0", "1", "2", "3", "4"]);
        assert_eq!(titles(first_todos(&low[..2])), ["0", "1"]);
        assert!(first_todos(&[]).is_empty());
        assert!(High.needs_attention() && Medium.needs_attention() && !Low.needs_attention());
    }

    #[test]
    fn an_empty_scan_is_a_valid_report() {
        let text = json(&[], &EvidenceSet::new(), &meta()).unwrap();
        let report: Report = serde_json::from_str(&text).unwrap();
        assert!(report.claims.is_empty());
        assert!(report.evidence.is_empty());
        assert_eq!(report.headline, Headline::default());
    }
}
