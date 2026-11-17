//! The report document.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::claim::{Claim, Party};
use crate::evidence::EvidenceSet;
use crate::pack::PackRef;
use crate::record::{EdgeType, Grade};

/// The schema tag of a report file. Serializes as `"exposure-report/1"` and
/// refuses to read anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReportSchema;

impl ReportSchema {
    /// The tag as it appears in a file.
    pub const TAG: &'static str = "exposure-report/1";
}

impl Serialize for ReportSchema {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(Self::TAG)
    }
}

impl<'de> Deserialize<'de> for ReportSchema {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tag = String::deserialize(deserializer)?;
        if tag == Self::TAG {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format_args!(
                "unsupported report schema `{tag}`; this build reads `{}`",
                Self::TAG
            )))
        }
    }
}

/// Everything a report says, together with everything it rests on.
///
/// The claims and the evidence travel in one document so that every finding
/// can show the raw record behind it, and so that the report can be rendered
/// again later from the evidence alone.
///
/// The document holds no timestamp, no host name and no path outside an
/// artifact: the same evidence and the same rule pack give the same bytes on
/// any machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// The schema of this document.
    pub schema: ReportSchema,
    /// The scanner that produced it.
    pub scanner: Scanner,
    /// The rule-pack layers that were in use.
    pub packs: Vec<PackRef>,
    /// The three counts a reader sees first. They are a tally of `claims`
    /// and say nothing the claims do not.
    pub headline: Headline,
    /// The claims, in a fixed order.
    pub claims: Vec<Claim>,
    /// The evidence the claims cite, keyed by record id.
    pub evidence: EvidenceSet,
}

/// The headline of a report: three counts, and no score (project spec,
/// "Grading and scoring").
///
/// Only claims marked [`headline`](Claim::headline) are tallied: channels
/// that name a company, in the categories the rule pack counts. A component,
/// an unmapped host, an update feed and a crash reporter are in the report
/// and in none of these numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Headline {
    /// Companies with a channel at `contacts` or above: a connection was
    /// observed, through at least one app.
    pub companies_contacts: u32,
    /// Companies whose strongest channel is `contains`: an app ships their
    /// code and no connection was observed. A company whose strongest
    /// channel is `declares` is in neither count.
    pub companies_contains: u32,
    /// Apps with at least one third-party channel, at any grade. Two builds
    /// of one app id are one app.
    pub apps_third_party: u32,
}

impl Headline {
    /// Tallies `claims`.
    #[must_use]
    pub fn of(claims: &[Claim]) -> Self {
        let mut strongest: BTreeMap<&str, Grade> = BTreeMap::new();
        let mut apps = BTreeSet::new();
        for claim in claims {
            // The grades of the two ladders share one ordering, so the
            // channel ladder is asked for by name.
            let (true, EdgeType::Channel, Some(company)) =
                (claim.headline, claim.edge, claim.company.as_deref())
            else {
                continue;
            };
            let grade = strongest.entry(company).or_insert(claim.grade);
            *grade = claim.grade.max(*grade);
            if claim.party == Party::Third {
                apps.insert((claim.subject.platform, claim.subject.id.as_str()));
            }
        }
        let companies = |wanted: fn(Grade) -> bool| {
            let count = strongest.values().filter(|&&grade| wanted(grade)).count();
            u32::try_from(count).unwrap_or(u32::MAX)
        };
        Self {
            companies_contacts: companies(|grade| grade >= Grade::Contacts),
            companies_contains: companies(|grade| grade == Grade::Contains),
            apps_third_party: u32::try_from(apps.len()).unwrap_or(u32::MAX),
        }
    }
}

/// The program that produced a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scanner {
    /// The program's name.
    pub name: String,
    /// The program's version.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::claim::{ClaimId, ClaimKey, ClaimObject, Confidence};
    use crate::record::{ObjectKind, ObjectRef, Platform, Subject, SubjectKind};
    use crate::{Sha256Digest, SubjectDigest};

    /// A counted claim: `app` (build `seed`) has a third-party channel to an
    /// SDK of `company` at `grade`.
    fn claim(app: &str, seed: u8, company: &str, grade: Grade) -> Claim {
        let subject = Subject {
            kind: SubjectKind::App,
            platform: Platform::Macos,
            id: app.into(),
            version: None,
            digest: SubjectDigest::Bundle(Sha256Digest::of(&[seed])),
        };
        let object = ObjectRef { kind: ObjectKind::Sdk, id: alloc::format!("sdk/{company}") };
        Claim {
            id: ClaimId::of(EdgeType::Channel, &subject, &object).unwrap(),
            key: ClaimKey::of(EdgeType::Channel, &subject, &object).unwrap(),
            edge: EdgeType::Channel,
            subject,
            object: ClaimObject { kind: object.kind, id: object.id, name: company.into() },
            company: Some(company.into()),
            category: "analytics".into(),
            headline: true,
            party: Party::Third,
            vendor: None,
            grade,
            rungs: vec![grade],
            confidence: Confidence::High,
            witnesses: 1,
            evidence: vec![],
            notes: vec![],
        }
    }

    fn counts(headline: Headline) -> (u32, u32, u32) {
        (headline.companies_contacts, headline.companies_contains, headline.apps_third_party)
    }

    #[test]
    fn nothing_found_is_three_zeros() {
        assert_eq!(counts(Headline::of(&[])), (0, 0, 0));
        assert_eq!(Headline::of(&[]), Headline::default());
    }

    #[test]
    fn a_company_is_counted_once_at_its_strongest_grade() {
        let claims = [
            claim("com.example.a", 1, "acme", Grade::Contains),
            claim("com.example.b", 2, "acme", Grade::Contains),
            claim("com.example.b", 2, "bolt", Grade::Contains),
        ];
        assert_eq!(counts(Headline::of(&claims)), (0, 2, 2));

        // One observed connection moves the company up, not into both.
        let mut claims = claims.to_vec();
        claims.push(claim("com.example.c", 3, "acme", Grade::Contacts));
        assert_eq!(counts(Headline::of(&claims)), (1, 1, 3));
        claims.push(claim("com.example.c", 3, "bolt", Grade::Confirmed));
        assert_eq!(counts(Headline::of(&claims)), (2, 0, 3));
    }

    #[test]
    fn a_declaration_alone_puts_no_company_in_a_count() {
        let claims = [claim("com.example.a", 1, "acme", Grade::Declares)];
        assert_eq!(counts(Headline::of(&claims)), (0, 0, 1), "the app still has the channel");
    }

    #[test]
    fn claims_outside_the_headline_are_not_counted() {
        let mut hosting = claim("com.example.a", 1, "acme", Grade::Contains);
        hosting.headline = false;
        assert_eq!(counts(Headline::of(&[hosting])), (0, 0, 0));

        // Marked or not, a claim that names nobody accuses nobody.
        let mut unmapped = claim("com.example.a", 1, "acme", Grade::Contains);
        unmapped.company = None;
        assert_eq!(counts(Headline::of(&[unmapped])), (0, 0, 0));
    }

    #[test]
    fn only_third_party_channels_count_an_app() {
        let mut own = claim("com.example.a", 1, "acme", Grade::Contains);
        own.party = Party::First;
        let mut unsure = claim("com.example.b", 2, "acme", Grade::Contains);
        unsure.party = Party::Unknown;
        // The company has the channel either way.
        assert_eq!(counts(Headline::of(&[own, unsure])), (0, 1, 0));
    }

    #[test]
    fn two_builds_of_one_app_id_are_one_app() {
        let claims = [
            claim("com.example.a", 1, "acme", Grade::Contains),
            claim("com.example.a", 2, "acme", Grade::Contains),
        ];
        assert_eq!(counts(Headline::of(&claims)), (0, 1, 1));

        let mut android = claim("com.example.a", 3, "acme", Grade::Contains);
        android.subject.platform = Platform::Android;
        let mut claims = claims.to_vec();
        claims.push(android);
        assert_eq!(counts(Headline::of(&claims)), (0, 1, 2), "another platform, another app");
    }

    #[test]
    fn the_access_ladder_is_not_mistaken_for_an_observed_connection() {
        // `used` sorts above `contacts`, but it is a rung of the other ladder.
        let mut access = claim("com.example.a", 1, "acme", Grade::Used);
        access.edge = EdgeType::Access;
        assert_eq!(counts(Headline::of(&[access])), (0, 0, 0));
    }

    #[test]
    fn the_schema_tag_is_checked() {
        assert_eq!(serde_json::to_string(&ReportSchema).unwrap(), "\"exposure-report/1\"");
        assert!(serde_json::from_str::<ReportSchema>("\"exposure-report/1\"").is_ok());
        assert!(serde_json::from_str::<ReportSchema>("\"exposure-report/2\"").is_err());
        assert!(serde_json::from_str::<ReportSchema>("1").is_err());
    }
}
