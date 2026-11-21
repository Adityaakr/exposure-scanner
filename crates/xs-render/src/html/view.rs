//! What the HTML report shows, worked out before a single tag is written.
//!
//! The claims are grouped by company, then by app, and once more by what
//! was found; the records by app. Every order here is defined by content (a
//! name, an id, a digest) and never by the order the claims or records
//! arrived in, so the same evidence and the same rule pack give the same
//! view.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::Reverse;

use xs_model::pack::{Entity, Pack};
use xs_model::record::{
    Browser, CoverageRecord, EdgeType, Grade, ObjectKind, Record, RecordId, Subject,
};
use xs_model::{Claim, EvidenceSet, Headline, MatcherKind, SubjectDigest, Uncounted};
use xs_model::{access, permission};

use crate::RenderError;

/// What tells one build from another: its digest. A package that could not
/// be read has no hash, and is told from the others by the rest of its
/// subject, which holds the name of its file.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Build<'a> {
    Hashed(&'a SubjectDigest),
    Unread(&'a Subject),
}

impl<'a> Build<'a> {
    fn of(subject: &'a Subject) -> Self {
        match subject.digest {
            SubjectDigest::Unread => Self::Unread(subject),
            _ => Self::Hashed(&subject.digest),
        }
    }
}

/// One build of an app that the scan read, or tried to.
pub(crate) struct App<'a> {
    /// The build. When records of one digest disagree on the rest of the
    /// subject, the smallest, as derivation does.
    pub(crate) subject: &'a Subject,
    /// The display name the app declares, if it declares one.
    pub(crate) name: Option<&'a str>,
    /// How many files and bytes were read, when an artifact record says.
    pub(crate) read: Option<(u64, u64)>,
    /// For a browser extension, the browser it was found installed in.
    pub(crate) browser: Option<Browser>,
    /// How many claims are about this build.
    pub(crate) findings: u64,
    /// Every record about this build, in id order.
    pub(crate) records: Vec<(&'a RecordId, &'a Record)>,
}

impl<'a> App<'a> {
    fn new(subject: &'a Subject) -> Self {
        Self { subject, name: None, read: None, browser: None, findings: 0, records: Vec::new() }
    }

    /// Whether the scan read the app. If not, all that is known of it is
    /// the name of its file and why it was set aside.
    pub(crate) fn was_read(&self) -> bool {
        self.subject.digest != SubjectDigest::Unread
    }

    /// The name to show: the one the app declares, or else its app id.
    pub(crate) fn title(&self) -> &'a str {
        self.name.unwrap_or(&self.subject.id)
    }

    /// The coverage records about this build.
    pub(crate) fn coverage(&self) -> impl Iterator<Item = (&'a RecordId, &'a CoverageRecord)> {
        self.records.iter().filter_map(|&(id, record)| match record {
            Record::Coverage(coverage) => Some((id, coverage)),
            _ => None,
        })
    }

    fn add(&mut self, id: &'a RecordId, record: &'a Record) {
        self.subject = self.subject.min(record.subject());
        if let Record::Artifact(artifact) = record {
            // Never "the first one seen": the smallest name, the largest
            // counts.
            if let Some(name) = artifact.facts.name.as_deref() {
                self.name = Some(self.name.map_or(name, |current| current.min(name)));
            }
            if let Some(browser) = artifact.facts.browser {
                self.browser = Some(self.browser.map_or(browser, |current| current.min(browser)));
            }
            let (files, bytes) = self.read.unwrap_or((0, 0));
            self.read = Some((
                files.max(artifact.facts.files_scanned),
                bytes.max(artifact.facts.bytes_scanned),
            ));
        }
        self.records.push((id, record));
    }

    /// Where the app sorts among apps: by name as a reader sees it, then by
    /// everything that tells two builds apart.
    fn order(&self) -> (String, &'a Subject) {
        (self.title().to_lowercase(), self.subject)
    }
}

/// The category of a claim: one of the rule pack's for a channel, one of the
/// fixed list in [`access`] for an app's access claim, and
/// [`permission::CATEGORY`] for a browser extension's.
#[derive(Clone, Copy)]
pub(crate) struct Category<'a> {
    pub(crate) name: &'a str,
    /// Whether claims in it count in the headline. No access category does.
    pub(crate) headline: bool,
}

/// One claim, with the names the rule pack gives what it mentions.
pub(crate) struct Finding<'a> {
    pub(crate) claim: &'a Claim,
    pub(crate) category: Category<'a>,
    /// The company the claim names.
    pub(crate) company: Option<&'a Entity>,
    /// The entity that operates the SDK or the host, when it is not the
    /// company itself but one the company owns.
    pub(crate) operator: Option<&'a Entity>,
    /// The company that publishes the app, when the pack lists it.
    pub(crate) publisher: Option<&'a Entity>,
}

/// The findings about one app, under one heading.
pub(crate) struct AppFindings<'a> {
    /// Index into [`View::apps`].
    pub(crate) app: usize,
    pub(crate) findings: Vec<Finding<'a>>,
}

/// A company and the findings that name it.
pub(crate) struct Company<'a> {
    pub(crate) entity: &'a Entity,
    /// Whether any of its findings counts in the headline.
    pub(crate) counted: bool,
    /// The highest grade any of its findings has.
    pub(crate) strongest: Grade,
    pub(crate) apps: Vec<AppFindings<'a>>,
}

impl Company<'_> {
    pub(crate) fn finding_count(&self) -> u64 {
        self.apps.iter().map(|app| app.findings.len() as u64).sum()
    }
}

/// One app that holds a thing the scan found.
pub(crate) struct FoundIn<'a> {
    /// The finding that says so. When one build has more than one, the
    /// first in the order of the findings.
    pub(crate) claim: &'a Claim,
    /// The highest grade the app has it at.
    pub(crate) grade: Grade,
}

/// One thing the scan found: one object, under one company or under none,
/// with every app it was found in.
pub(crate) struct Found<'a> {
    /// The name of the object.
    pub(crate) name: &'a str,
    pub(crate) kind: ObjectKind,
    pub(crate) edge: EdgeType,
    pub(crate) category: Category<'a>,
    /// The company its findings name.
    pub(crate) company: Option<&'a Entity>,
    /// Whether any of its findings counts in the headline.
    pub(crate) counted: bool,
    /// The apps it was found in, by index into [`View::apps`], which is the
    /// order a reader looks them up in.
    pub(crate) apps: BTreeMap<usize, FoundIn<'a>>,
}

impl<'a> Found<'a> {
    fn add(&mut self, app: usize, claim: &'a Claim) {
        self.counted |= claim.headline;
        let found = self.apps.entry(app).or_insert(FoundIn { claim, grade: claim.grade });
        found.grade = found.grade.max(claim.grade);
    }

    /// How many apps have it at each grade, the highest grade first. An app
    /// is counted once, at the highest grade it has it at.
    pub(crate) fn by_grade(&self) -> Vec<(Grade, u64)> {
        let mut counts: BTreeMap<Grade, u64> = BTreeMap::new();
        for found in self.apps.values() {
            *counts.entry(found.grade).or_default() += 1;
        }
        counts.into_iter().rev().collect()
    }
}

/// Everything the report shows.
pub(crate) struct View<'a> {
    /// The scanned builds, in the order a reader looks them up.
    pub(crate) apps: Vec<App<'a>>,
    /// Where each build is in [`Self::apps`].
    index: BTreeMap<Build<'a>, usize>,
    /// The companies findings name: those with a counted finding first, each
    /// group by name.
    pub(crate) companies: Vec<Company<'a>>,
    /// The channels that name no company: components and unmapped hosts.
    pub(crate) unnamed: Vec<AppFindings<'a>>,
    /// The findings on the access ladder. They are not channels to a
    /// company, and are under none.
    pub(crate) access: Vec<AppFindings<'a>>,
    /// Everything that was found, once each: what is in the most apps
    /// first, then by name.
    pub(crate) found: Vec<Found<'a>>,
    pub(crate) headline: Headline,
    pub(crate) claims: u64,
    pub(crate) coverage_notes: u64,
    pub(crate) records: u64,
    /// The names of the categories the headline counts.
    pub(crate) counted_categories: Vec<&'a str>,
    /// What the Android apps ship beside the headline: each company, by
    /// name, with the names of its SDKs in categories the headline does not
    /// count.
    pub(crate) uncounted: Vec<(&'a Entity, Vec<&'a str>)>,
}

impl<'a> View<'a> {
    pub(crate) fn new(
        claims: &'a [Claim],
        evidence: &'a EvidenceSet,
        pack: &'a Pack,
    ) -> Result<Self, RenderError> {
        let mut builds: BTreeMap<Build<'a>, App<'a>> = BTreeMap::new();
        for (id, record) in evidence {
            let subject = record.subject();
            builds.entry(Build::of(subject)).or_insert_with(|| App::new(subject)).add(id, record);
        }
        for claim in claims {
            let app =
                builds.entry(Build::of(&claim.subject)).or_insert_with(|| App::new(&claim.subject));
            app.findings += 1;
        }
        let mut apps: Vec<App<'a>> = builds.into_values().collect();
        apps.sort_by(|a, b| a.order().cmp(&b.order()));
        let index: BTreeMap<Build<'a>, usize> =
            apps.iter().enumerate().map(|(at, app)| (Build::of(app.subject), at)).collect();

        // Company id, then app, then the claims in a fixed order.
        let mut named: BTreeMap<&str, BTreeMap<usize, Vec<Finding<'a>>>> = BTreeMap::new();
        let mut unnamed: BTreeMap<usize, Vec<Finding<'a>>> = BTreeMap::new();
        let mut access: BTreeMap<usize, Vec<Finding<'a>>> = BTreeMap::new();
        let mut things: BTreeMap<_, Found<'a>> = BTreeMap::new();
        let mut ordered: Vec<&Claim> = claims.iter().collect();
        ordered.sort_by_key(|&claim| (claim.object.kind, &claim.object.id, claim.edge, claim.id));
        for claim in ordered {
            let finding = finding(claim, pack)?;
            let Some(&app) = index.get(&Build::of(&claim.subject)) else { continue };
            let company = claim.company.as_deref();
            things
                .entry((claim.object.kind, claim.object.id.as_str(), claim.edge, company))
                .or_insert_with(|| Found {
                    name: &claim.object.name,
                    kind: claim.object.kind,
                    edge: claim.edge,
                    category: finding.category,
                    company: finding.company,
                    counted: false,
                    apps: BTreeMap::new(),
                })
                .add(app, claim);
            let group = match (claim.edge, company) {
                (EdgeType::Access, _) => &mut access,
                (EdgeType::Channel, Some(company)) => named.entry(company).or_default(),
                (EdgeType::Channel, None) => &mut unnamed,
            };
            group.entry(app).or_default().push(finding);
        }

        let mut companies = Vec::with_capacity(named.len());
        for by_app in named.into_values() {
            let apps: Vec<AppFindings<'a>> = group(by_app);
            let all = || apps.iter().flat_map(|app| &app.findings);
            // A group is only made for a claim, which names the company.
            let Some(entity) = all().find_map(|finding| finding.company) else { continue };
            companies.push(Company {
                entity,
                counted: all().any(|finding| finding.claim.headline),
                strongest: all().map(|f| f.claim.grade).max().unwrap_or(Grade::Declares),
                apps,
            });
        }
        companies.sort_by_key(|company| {
            (!company.counted, company.entity.name.to_lowercase(), company.entity.id.as_str())
        });

        // What is in the most apps first. The sort keeps the order of the
        // keys for the rest.
        let mut found: Vec<Found<'a>> = things.into_values().collect();
        found.sort_by_key(|thing| (Reverse(thing.apps.len()), thing.name.to_lowercase()));

        let coverage_notes =
            evidence.iter().filter(|(_, record)| matches!(record, Record::Coverage(_))).count();
        let mut uncounted: Vec<(&'a Entity, Vec<&'a str>)> = Vec::new();
        for (company, sdks) in Uncounted::android(claims).by_company {
            let Some(entity) = pack.entity(company) else { continue };
            let mut names: Vec<&'a str> = sdks
                .into_iter()
                .map(|id| pack.rule(id).map_or(id, |rule| rule.name.as_str()))
                .collect();
            names.sort_by_key(|name| name.to_lowercase());
            uncounted.push((entity, names));
        }
        uncounted.sort_by_key(|(entity, _)| (entity.name.to_lowercase(), entity.id.as_str()));
        Ok(Self {
            apps,
            index,
            companies,
            unnamed: group(unnamed),
            access: group(access),
            found,
            headline: Headline::of(claims),
            claims: claims.len() as u64,
            coverage_notes: coverage_notes as u64,
            records: evidence.len() as u64,
            counted_categories: pack
                .layers()
                .iter()
                .flat_map(|loaded| &loaded.layer.categories)
                .filter(|category| category.headline)
                .map(|category| category.name.as_str())
                .collect(),
            uncounted,
        })
    }

    /// The build a claim or a record is about.
    pub(crate) fn app_of(&self, subject: &Subject) -> Option<&App<'a>> {
        self.apps.get(*self.index.get(&Build::of(subject))?)
    }

    /// Whether `claim` rests on nothing but usage descriptions in
    /// Electron's own wording ([`access::is_electron_default`]): the app
    /// asks because Electron does, and states no purpose of its own.
    pub(crate) fn states_only_electron_s_purpose(&self, claim: &Claim) -> bool {
        let Some(app) = self.app_of(&claim.subject) else { return false };
        !claim.evidence.is_empty() && claim.evidence.iter().all(|id| {
            let record = app
                .records
                .binary_search_by(|(other, _)| (*other).cmp(id))
                .ok()
                .and_then(|at| app.records.get(at));
            matches!(
                record,
                Some((_, Record::Edge(edge)))
                    if edge.proof.matcher == MatcherKind::UsageDescription
                        && edge.proof.example.as_deref().is_some_and(access::is_electron_default)
            )
        })
    }

    /// The apps the scan read, in the order a reader looks them up.
    pub(crate) fn read_apps(&self) -> impl Iterator<Item = &App<'a>> {
        self.apps.iter().filter(|app| app.was_read())
    }

    /// How many companies the findings name.
    pub(crate) fn company_count(&self) -> u64 {
        self.companies.len() as u64
    }
}

fn group<'a>(by_app: BTreeMap<usize, Vec<Finding<'a>>>) -> Vec<AppFindings<'a>> {
    by_app.into_iter().map(|(app, findings)| AppFindings { app, findings }).collect()
}

/// Looks up the names of everything `claim` mentions.
///
/// The claims a report shows were derived with the pack it names, so each id
/// resolves. One that does not means the claims and the pack do not belong
/// together, and the report is refused rather than written with a gap.
fn finding<'a>(claim: &'a Claim, pack: &'a Pack) -> Result<Finding<'a>, RenderError> {
    let unknown = |kind: &'static str, id: &str| RenderError::NotInPack {
        claim: claim.id.to_string(),
        kind,
        id: id.to_string(),
    };
    let entity = |id: &'a str| pack.entity(id).ok_or_else(|| unknown("company", id));

    let category = match claim.edge {
        EdgeType::Channel => pack
            .category(&claim.category)
            .map(|category| Category { name: &category.name, headline: category.headline }),
        EdgeType::Access if claim.category == permission::CATEGORY => {
            Some(Category { name: permission::CATEGORY_NAME, headline: false })
        }
        EdgeType::Access => access::category(&claim.category)
            .map(|category| Category { name: category.name, headline: false }),
    }
    .ok_or_else(|| unknown("category", &claim.category))?;
    let company = claim.company.as_deref().map(entity).transpose()?;
    let publisher = claim
        .vendor
        .as_ref()
        .and_then(|vendor| vendor.company.as_deref())
        .map(entity)
        .transpose()?;
    let operator = match claim.object.kind {
        ObjectKind::Sdk => pack
            .rule(&claim.object.id)
            .and_then(|rule| rule.entity.as_deref())
            .and_then(|id| pack.entity(id)),
        ObjectKind::Host => pack.entity_by_host(&claim.object.id),
        ObjectKind::Permission => None,
    }
    .filter(|operator| company.is_some_and(|company| company.id != operator.id));
    Ok(Finding { claim, category, company, operator, publisher })
}
