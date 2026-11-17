//! Renderers: claims and their evidence in, a report document out.
//!
//! Rendering is pure, like derivation: the crate is `no_std` and has no way
//! to read a clock, a file or the environment. A report holds no timestamp
//! and no machine-specific value, so rendering the same claims and evidence
//! twice gives the same bytes.
//!
//! Every renderer first checks the **honesty** property: each claim must cite
//! at least one record, and every cited record must be in the evidence set
//! that travels with the report. A report that cannot show the record behind
//! a finding is refused rather than written.
//!
//! The JSON document is the only renderer so far. The HTML report is task 11
//! of the build plan.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::Serialize;
use xs_model::canon::{self, CanonError};
use xs_model::pack::PackRef;
use xs_model::record::Record;
use xs_model::report::{ReportSchema, Scanner};
use xs_model::{Claim, EvidenceSet};

/// What a report says about how it was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportMeta {
    /// The scanner that produced the evidence.
    pub scanner: Scanner,
    /// The rule-pack layers the claims were derived with.
    pub packs: Vec<PackRef>,
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
/// `evidence`, or cites a record that is not an edge.
pub fn check_honest(claims: &[Claim], evidence: &EvidenceSet) -> Result<(), RenderError> {
    for claim in claims {
        if claim.evidence.is_empty() {
            return Err(RenderError::NoEvidence { claim: claim.id.to_string() });
        }
        for id in &claim.evidence {
            match evidence.get(id) {
                Some(Record::Edge(_)) => {}
                Some(_) => {
                    return Err(RenderError::NotAnEdge {
                        claim: claim.id.to_string(),
                        record: id.to_string(),
                    });
                }
                None => {
                    return Err(RenderError::MissingEvidence {
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
    claims: &'a [Claim],
    evidence: &'a EvidenceSet,
}

/// Renders the JSON report: canonical JSON followed by one newline.
///
/// The document carries the claims and the complete evidence set, so every
/// finding can be traced to its raw record and the report can be rendered
/// again from the file alone.
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

    use xs_model::claim::{ClaimId, ClaimKey, ClaimObject, Confidence, Party};
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
            },
        })
    }

    fn artifact() -> Record {
        Record::Artifact(ArtifactRecord {
            v: V1,
            collector: Collector::MacosBundle,
            subject: subject(),
            facts: Facts { name: Some("Example".into()), files_scanned: 2, bytes_scanned: 64 },
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
            party: Party::Unknown,
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

    #[test]
    fn an_empty_scan_is_a_valid_report() {
        let text = json(&[], &EvidenceSet::new(), &meta()).unwrap();
        let report: Report = serde_json::from_str(&text).unwrap();
        assert!(report.claims.is_empty());
        assert!(report.evidence.is_empty());
    }
}
