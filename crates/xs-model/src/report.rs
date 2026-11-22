//! The report document.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::claim::Claim;
use crate::evidence::EvidenceSet;
use crate::pack::PackRef;
use crate::record::{Browser, EdgeType, Grade, ObjectKind, Platform};

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
/// artifact: the same evidence, the same rule pack and the same scope give
/// the same bytes on any machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// The schema of this document.
    pub schema: ReportSchema,
    /// The scanner that produced it.
    pub scanner: Scanner,
    /// The rule-pack layers that were in use.
    pub packs: Vec<PackRef>,
    /// Where the scan looked for apps. It is a fact about the scan and not
    /// about any app, so it is a field of the report and no evidence record
    /// holds it. A report written before the field existed has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScanScope>,
    /// The three counts a reader sees first. They are a tally of `claims`
    /// and say nothing the claims do not.
    pub headline: Headline,
    /// The claims, in a fixed order.
    pub claims: Vec<Claim>,
    /// The evidence the claims cite, keyed by record id.
    pub evidence: EvidenceSet,
}

/// Where a scan looked for apps, and where it deliberately did not.
///
/// A report stores which of the two it was and never a sentence, so the
/// words a reader sees are always the scanner's own. They are the same on
/// every machine and for every user: the fixed folders are named, the
/// user's own as `~/Applications` whether or not it exists, and a path the
/// user gave never is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanScope {
    /// No path was given: the installed-app folders and the profile folders
    /// of the browsers were searched, and `/System/Applications` was not.
    Installed,
    /// Paths were given: what they name was scanned and nothing else. The
    /// installed-app folders were not searched.
    Given,
}

impl fmt::Display for ScanScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f, &[])
    }
}

impl ScanScope {
    /// Where the scan looked, as [`Display`](fmt::Display) words it, with
    /// the browsers in `unread` taken out of those whose extensions were
    /// searched: none of their extensions could be read, so the scan did
    /// not cover them, and the words must not say it did.
    #[must_use]
    pub fn words(self, unread: &[Browser]) -> String {
        struct Words<'a>(ScanScope, &'a [Browser]);
        impl fmt::Display for Words<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.write(f, self.1)
            }
        }
        alloc::format!("{}", Words(self, unread))
    }

    fn write(self, f: &mut fmt::Formatter<'_>, unread: &[Browser]) -> fmt::Result {
        match self {
            Self::Installed => {
                f.write_str(
                    "the apps installed in /Applications and ~/Applications; \
                     /System/Applications (Apple's own apps on the sealed system volume) was \
                     not searched: name the folder to scan it",
                )?;
                let read: Vec<Browser> =
                    Browser::ALL.into_iter().filter(|browser| !unread.contains(browser)).collect();
                if !read.is_empty() {
                    f.write_str("; the extensions installed in your profiles of ")?;
                    list(f, &read)?;
                }
                let not_read: Vec<Browser> =
                    Browser::ALL.into_iter().filter(|browser| unread.contains(browser)).collect();
                if !not_read.is_empty() {
                    f.write_str("; not the extensions of ")?;
                    list(f, &not_read)?;
                    f.write_str(", which could not be read")?;
                }
                Ok(())
            }
            Self::Given => f.write_str(
                "the paths given and nothing else; the installed-app folders were not searched",
            ),
        }
    }
}

/// `browsers` by name, as `A, B and C`.
fn list(f: &mut fmt::Formatter<'_>, browsers: &[Browser]) -> fmt::Result {
    for (index, browser) in browsers.iter().enumerate() {
        if index > 0 && index + 1 == browsers.len() {
            f.write_str(" and ")?;
        } else if index > 0 {
            f.write_str(", ")?;
        }
        f.write_str(browser.name())?;
    }
    Ok(())
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
    /// of one app id are one app. An app that only claims to be a company's
    /// own counts for that company's channels too
    /// ([`Claim::counts_as_third_party`]).
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
            if claim.counts_as_third_party() {
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

/// What an Android scan ships beside the headline: the SDKs of companies in
/// categories the headline does not count, such as crash reporting, push
/// messaging and payments.
///
/// On Android most of what ships is a large company's infrastructure, which
/// the headline leaves out on principle (hosting is not receiving). Shown
/// beside the three counts, it keeps a scan whose counts are zero from
/// reading as "nothing found". It is a tally of claims like the headline,
/// is never stored in a report, and is no score.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Uncounted<'a> {
    /// For each company, the SDKs of it that the Android apps ship, by
    /// object id.
    pub by_company: BTreeMap<&'a str, BTreeSet<&'a str>>,
}

impl<'a> Uncounted<'a> {
    /// Tallies the claims about Android apps: SDK channels at `contains`
    /// or above that name a company and do not count in the headline.
    #[must_use]
    pub fn android(claims: &'a [Claim]) -> Self {
        let mut by_company: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for claim in claims {
            let (Platform::Android, EdgeType::Channel, ObjectKind::Sdk, false, Some(company)) = (
                claim.subject.platform,
                claim.edge,
                claim.object.kind,
                claim.headline,
                claim.company.as_deref(),
            ) else {
                continue;
            };
            if claim.grade >= Grade::Contains {
                by_company.entry(company).or_default().insert(&claim.object.id);
            }
        }
        Self { by_company }
    }

    /// How many SDKs.
    #[must_use]
    pub fn sdks(&self) -> u32 {
        let count: usize = self.by_company.values().map(BTreeSet::len).sum();
        u32::try_from(count).unwrap_or(u32::MAX)
    }

    /// How many companies.
    #[must_use]
    pub fn companies(&self) -> u32 {
        u32::try_from(self.by_company.len()).unwrap_or(u32::MAX)
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
    use crate::claim::{ClaimId, ClaimKey, ClaimObject, Confidence, Party};
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
    fn beside_the_headline_android_counts_the_sdks_it_leaves_out() {
        let android = |app: &str, sdk: &str, company: &str, category: &str| {
            let mut claim = claim(app, 1, company, Grade::Contains);
            claim.subject.platform = Platform::Android;
            claim.object.id = alloc::format!("sdk/{sdk}");
            claim.category = category.into();
            claim.headline = category == "analytics";
            claim
        };
        let claims = [
            android("com.example.a", "crashlytics", "google", "crash_reporting"),
            android("com.example.b", "crashlytics", "google", "crash_reporting"),
            android("com.example.a", "fcm", "google", "push_messaging"),
            android("com.example.a", "billing", "google", "payments"),
            android("com.example.a", "sentry", "sentry", "crash_reporting"),
            // Counted in the headline, so not beside it.
            android("com.example.a", "posthog", "posthog", "analytics"),
        ];
        let uncounted = Uncounted::android(&claims);
        assert_eq!((uncounted.sdks(), uncounted.companies()), (4, 2));
        assert_eq!(
            uncounted.by_company.get("google").map(|sdks| sdks.iter().copied().collect()),
            Some(vec!["sdk/billing", "sdk/crashlytics", "sdk/fcm"])
        );

        // Only Android, only SDKs that ship, only claims that name somebody.
        let mut macos = android("com.example.c", "x", "acme", "crash_reporting");
        macos.subject.platform = Platform::Macos;
        let mut declared = android("com.example.c", "y", "acme", "crash_reporting");
        declared.grade = Grade::Declares;
        let mut component = android("com.example.c", "z", "acme", "crash_reporting");
        component.company = None;
        let mut host = android("com.example.c", "w", "acme", "crash_reporting");
        host.object.kind = ObjectKind::Host;
        assert_eq!(Uncounted::android(&[macos, declared, component, host]), Uncounted::default());
    }

    /// A report as `scope` makes it, with nothing else in it.
    fn report_text(scope: &str) -> String {
        alloc::format!(
            "{{\"schema\":\"exposure-report/1\",\"scanner\":{{\"name\":\"exposure\",\
             \"version\":\"0.1.0\"}},\"packs\":[],{scope}\"headline\":{{\
             \"companies_contacts\":0,\"companies_contains\":0,\"apps_third_party\":0}},\
             \"claims\":[],\"evidence\":{{}}}}"
        )
    }

    /// The scope is one of two fixed values in the file, so a report cannot
    /// bring words of its own, and a report from before the field existed
    /// is still read and written back without it.
    #[test]
    fn a_report_names_its_scope_and_one_without_it_is_still_read() {
        for (stored, scope) in [("installed", ScanScope::Installed), ("given", ScanScope::Given)] {
            let text = report_text(&alloc::format!("\"scope\":\"{stored}\","));
            let report: Report = serde_json::from_str(&text).unwrap();
            assert_eq!(report.scope, Some(scope));
            assert_eq!(serde_json::to_string(&report).unwrap(), text);
        }

        let older = report_text("");
        let report: Report = serde_json::from_str(&older).unwrap();
        assert_eq!(report.scope, None);
        assert_eq!(serde_json::to_string(&report).unwrap(), older);

        for refused in ["\"/Users/someone/Apps\"", "\"Installed\"", "7"] {
            let text = report_text(&alloc::format!("\"scope\":{refused},"));
            assert!(serde_json::from_str::<Report>(&text).is_err(), "{refused}");
        }
    }

    #[test]
    fn the_schema_tag_is_checked() {
        assert_eq!(serde_json::to_string(&ReportSchema).unwrap(), "\"exposure-report/1\"");
        assert!(serde_json::from_str::<ReportSchema>("\"exposure-report/1\"").is_ok());
        assert!(serde_json::from_str::<ReportSchema>("\"exposure-report/2\"").is_err());
        assert!(serde_json::from_str::<ReportSchema>("1").is_err());
    }
}
