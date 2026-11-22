//! `exposure diff`: what changed from one report to another.
//!
//! A claim's [`ClaimKey`] hashes its type, the app's platform and id, and
//! its object, and leaves the build digest out, so it follows one finding
//! from a build of an app to the next. Two reports are compared key by key:
//! a key only the new report has is a finding it adds, one only the old
//! report has is a finding it no longer has, and a key both have at
//! different grades changed grade.
//!
//! The comparison is of what the two reports say, each derived with the
//! rule pack it names. When the packs differ, a difference may come from
//! the rules rather than from the apps, and the summary says so.
//!
//! Like a report, the comparison is ordered by content only, so the same
//! two reports give the same bytes.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use xs_model::claim::{ClaimKey, ClaimObject, Party};
use xs_model::pack::PackRef;
use xs_model::record::{EdgeType, Grade, Platform, Record};
use xs_model::report::Scanner;
use xs_model::{Claim, Pack, Report, access, permission};

/// The schema tag of a diff document.
pub(crate) const SCHEMA: &str = "exposure-diff/1";

/// An app across builds: its platform and its app id.
type AppKey<'a> = (Platform, &'a str);

/// What one report says about one app.
#[derive(Default)]
struct Side<'a> {
    /// Each finding once, at the highest grade any build of the app has
    /// it at. Of two claims at that grade, the one with the smaller id.
    claims: BTreeMap<&'a ClaimKey, &'a Claim>,
    /// The versions of the builds the report holds.
    versions: BTreeSet<&'a str>,
    /// The smallest display name the builds declare.
    name: Option<&'a str>,
}

/// Every app of a report, by platform and app id.
fn sides(report: &Report) -> BTreeMap<AppKey<'_>, Side<'_>> {
    let mut apps: BTreeMap<AppKey<'_>, Side<'_>> = BTreeMap::new();
    for (_, record) in &report.evidence {
        let Record::Artifact(artifact) = record else { continue };
        let subject = &artifact.subject;
        let side = apps.entry((subject.platform, subject.id.as_str())).or_default();
        if let Some(version) = subject.version.as_deref() {
            side.versions.insert(version);
        }
        if let Some(name) = artifact.facts.name.as_deref() {
            side.name = Some(side.name.map_or(name, |current| current.min(name)));
        }
    }
    for claim in &report.claims {
        let subject = &claim.subject;
        let side = apps.entry((subject.platform, subject.id.as_str())).or_default();
        if let Some(version) = subject.version.as_deref() {
            side.versions.insert(version);
        }
        side.claims
            .entry(&claim.key)
            .and_modify(|kept| {
                if (claim.grade, std::cmp::Reverse(claim.id))
                    > (kept.grade, std::cmp::Reverse(kept.id))
                {
                    *kept = claim;
                }
            })
            .or_insert(claim);
    }
    apps
}

/// Whether an app is in both reports or in one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Presence {
    Both,
    OnlyOld,
    OnlyNew,
}

/// One finding as the comparison shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Change<'a> {
    pub(crate) key: &'a ClaimKey,
    #[serde(rename = "type")]
    pub(crate) edge: EdgeType,
    pub(crate) object: &'a ClaimObject,
    pub(crate) company: Option<&'a str>,
    pub(crate) category: &'a str,
    pub(crate) headline: bool,
    /// The grade in the old report, for a finding that changed grade.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) old_grade: Option<Grade>,
    /// The grade in the report that has the finding: the new one, except
    /// for a finding the new report no longer has.
    pub(crate) grade: Grade,
}

impl<'a> Change<'a> {
    fn of(claim: &'a Claim, old_grade: Option<Grade>) -> Self {
        Self {
            key: &claim.key,
            edge: claim.edge,
            object: &claim.object,
            company: claim.company.as_deref(),
            category: &claim.category,
            headline: claim.headline,
            old_grade,
            grade: claim.grade,
        }
    }

    /// Channels before access, then by name as a reader sees it.
    fn order(&self) -> (EdgeType, String, &'a str, &'a ClaimKey) {
        (self.edge, self.object.name.to_lowercase(), &self.object.id, self.key)
    }
}

/// What changed for one app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AppDiff<'a> {
    pub(crate) platform: Platform,
    pub(crate) id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<&'a str>,
    pub(crate) presence: Presence,
    pub(crate) old_versions: Vec<&'a str>,
    pub(crate) new_versions: Vec<&'a str>,
    pub(crate) added: Vec<Change<'a>>,
    pub(crate) removed: Vec<Change<'a>>,
    pub(crate) changed: Vec<Change<'a>>,
}

impl AppDiff<'_> {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// How many of each.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Totals {
    /// Apps in either report.
    pub(crate) apps: usize,
    /// Apps with a finding added, removed or changed.
    pub(crate) apps_changed: usize,
    pub(crate) added: usize,
    pub(crate) removed: usize,
    pub(crate) changed: usize,
}

/// One side of the comparison: who made the report, with which rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Made<'a> {
    pub(crate) scanner: &'a Scanner,
    pub(crate) packs: &'a [PackRef],
}

/// The comparison of two reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Diff<'a> {
    pub(crate) schema: &'static str,
    pub(crate) old: Made<'a>,
    pub(crate) new: Made<'a>,
    /// Whether the two reports were derived with the same rule packs.
    pub(crate) same_rules: bool,
    pub(crate) totals: Totals,
    /// The apps with a change, ordered by name as a reader sees it.
    pub(crate) apps: Vec<AppDiff<'a>>,
    /// Each finding of the new report with the same finding in the old
    /// one, if it has it, for `--fail-on`.
    #[serde(skip)]
    pairs: Vec<(&'a Claim, Option<&'a Claim>)>,
    /// The name of each app that declares one, for `--fail-on`.
    #[serde(skip)]
    names: BTreeMap<AppKey<'a>, &'a str>,
}

/// Compares `old` with `new`.
pub(crate) fn compare<'a>(old: &'a Report, new: &'a Report) -> Diff<'a> {
    let mut before = sides(old);
    let mut after = sides(new);
    let keys: BTreeSet<AppKey<'a>> = before.keys().chain(after.keys()).copied().collect();
    let mut totals = Totals { apps: keys.len(), ..Totals::default() };
    let mut apps = Vec::new();
    let mut pairs = Vec::new();
    let mut names = BTreeMap::new();
    for key in keys {
        let (old_side, new_side) = (before.remove(&key), after.remove(&key));
        let presence = match (&old_side, &new_side) {
            (Some(_), None) => Presence::OnlyOld,
            (None, Some(_)) => Presence::OnlyNew,
            _ => Presence::Both,
        };
        let old_side = old_side.unwrap_or_default();
        let new_side = new_side.unwrap_or_default();
        if let Some(name) = new_side.name.or(old_side.name) {
            names.insert(key, name);
        }
        let mut app = AppDiff {
            platform: key.0,
            id: key.1,
            name: new_side.name.or(old_side.name),
            presence,
            old_versions: old_side.versions.iter().copied().collect(),
            new_versions: new_side.versions.iter().copied().collect(),
            added: Vec::new(),
            removed: Vec::new(),
            changed: Vec::new(),
        };
        for (claim_key, &claim) in &new_side.claims {
            let was = old_side.claims.get(claim_key).copied();
            pairs.push((claim, was));
            match was {
                None => app.added.push(Change::of(claim, None)),
                Some(was) if was.grade != claim.grade => {
                    app.changed.push(Change::of(claim, Some(was.grade)));
                }
                Some(_) => {}
            }
        }
        for (claim_key, &claim) in &old_side.claims {
            if !new_side.claims.contains_key(claim_key) {
                app.removed.push(Change::of(claim, None));
            }
        }
        if app.is_empty() {
            continue;
        }
        for list in [&mut app.added, &mut app.removed, &mut app.changed] {
            list.sort_by(|a, b| a.order().cmp(&b.order()));
        }
        totals.apps_changed += 1;
        totals.added += app.added.len();
        totals.removed += app.removed.len();
        totals.changed += app.changed.len();
        apps.push(app);
    }
    apps.sort_by(|a, b| {
        let order =
            |app: &AppDiff<'a>| (app.name.unwrap_or(app.id).to_lowercase(), app.platform, app.id);
        order(a).cmp(&order(b))
    });
    Diff {
        schema: SCHEMA,
        old: Made { scanner: &old.scanner, packs: &old.packs },
        new: Made { scanner: &new.scanner, packs: &new.packs },
        same_rules: old.packs == new.packs,
        totals,
        apps,
        pairs,
        names,
    }
}

impl<'a> Diff<'a> {
    /// Each finding of the new report with the same finding in the old
    /// one, if it has it, for `--fail-on`.
    pub(crate) fn pairs(&self) -> impl Iterator<Item = (&'a Claim, Option<&'a Claim>)> + Clone {
        self.pairs.iter().copied()
    }

    /// A finding of the new report that newly meets a `--fail-on`
    /// condition, with what makes it new: it was added, or what changed
    /// from `was`, the same finding in the old report.
    pub(crate) fn describe(&self, pack: &Pack, claim: &Claim, was: Option<&Claim>) -> String {
        let subject = &claim.subject;
        let name = self.names.get(&(subject.platform, subject.id.as_str())).copied();
        let app = title(subject.platform, &subject.id, name);
        let about = about(pack, &claim.category, claim.company.as_deref());
        let why = match was {
            None => String::from("added"),
            Some(was) => {
                let mut why = Vec::new();
                if was.grade != claim.grade {
                    why.push(format!("grade {} → {}", grade_id(was.grade), grade_id(claim.grade)));
                }
                if was.category != claim.category {
                    let old = category_name(pack, &was.category);
                    why.push(format!("new category, was {old}"));
                }
                if was.company != claim.company {
                    why.push(String::from("names another company"));
                }
                if was.party != Party::Third && claim.party == Party::Third {
                    why.push(String::from("now third-party"));
                }
                if !was.headline && claim.headline {
                    why.push(String::from("now counted in the headline"));
                }
                why.join(", ")
            }
        };
        format!("{} ({about}) in {app}: {why}", claim.object.name)
    }
}

/// An app as a line of the comparison names it.
fn title(platform: Platform, id: &str, name: Option<&str>) -> String {
    let platform = platform_name(platform);
    match name {
        Some(name) => format!("{name} ({platform}, {id})"),
        None => format!("{id} ({platform})"),
    }
}

/// A finding's category and the company it names, if it names one.
fn about(pack: &Pack, category: &str, company: Option<&str>) -> String {
    let category = category_name(pack, category);
    match company.map(|id| pack.entity(id).map_or(id, |entity| entity.name.as_str())) {
        Some(company) => format!("{category}, {company}"),
        None => format!("{category}, no company"),
    }
}

/// The name of a platform in a sentence.
const fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::Macos => "macOS",
        Platform::Android => "Android",
        Platform::Chromium => "Chromium extension",
        Platform::Firefox => "Firefox extension",
    }
}

/// What a line of the comparison calls a category: the rule pack's name for
/// it, or the fixed name of an access category. A category this build does
/// not know, from a report made with other rules, is shown by its id.
fn category_name<'p>(pack: &'p Pack, id: &'p str) -> &'p str {
    if id == permission::CATEGORY {
        return permission::CATEGORY_NAME;
    }
    pack.category(id)
        .map(|category| category.name.as_str())
        .or_else(|| access::category(id).map(|category| category.name))
        .unwrap_or(id)
}

fn versions(list: &[&str]) -> String {
    if list.is_empty() { String::from("no version stated") } else { list.join(", ") }
}

/// The comparison in words, for a terminal.
pub(crate) fn text(diff: &Diff<'_>, pack: &Pack) -> String {
    let mut out = String::new();
    for app in &diff.apps {
        let title = title(app.platform, app.id, app.name);
        let heading = match app.presence {
            Presence::Both if app.old_versions == app.new_versions => {
                format!("{title}, {}", versions(&app.new_versions))
            }
            Presence::Both => format!(
                "{title}, {} → {}",
                versions(&app.old_versions),
                versions(&app.new_versions)
            ),
            Presence::OnlyNew => {
                format!("{title}, {}: only in the new report", versions(&app.new_versions))
            }
            Presence::OnlyOld => {
                format!("{title}, {}: only in the old report", versions(&app.old_versions))
            }
        };
        out.push_str(&heading);
        out.push('\n');
        for (sign, list) in [('+', &app.added), ('-', &app.removed), ('~', &app.changed)] {
            for change in list {
                let category = category_name(pack, change.category);
                let company = change
                    .company
                    .map(|id| pack.entity(id).map_or(id, |entity| entity.name.as_str()));
                let about = match company {
                    Some(company) => format!("{category}, {company}"),
                    None => String::from(category),
                };
                let grade = match change.old_grade {
                    Some(old) => format!("{} → {}", grade_id(old), grade_id(change.grade)),
                    None => String::from(grade_id(change.grade)),
                };
                let counted = if change.headline { ", counted in the headline" } else { "" };
                out.push_str(&format!(
                    "  {sign} {} ({about}{counted}): {grade}\n",
                    change.object.name
                ));
            }
        }
        out.push('\n');
    }
    let totals = diff.totals;
    if diff.apps.is_empty() {
        out.push_str(&format!(
            "No finding was added, removed or changed grade, in {}.\n",
            apps(totals.apps)
        ));
    } else {
        out.push_str(&format!(
            "{} added, {} removed, {} changed grade, in {} of {}.\n",
            findings(totals.added),
            findings(totals.removed),
            findings(totals.changed),
            totals.apps_changed,
            apps(totals.apps),
        ));
    }
    out
}

fn findings(count: usize) -> String {
    if count == 1 { String::from("1 finding") } else { format!("{count} findings") }
}

fn apps(count: usize) -> String {
    if count == 1 { String::from("1 app") } else { format!("{count} apps") }
}

/// A grade as the JSON report spells it.
const fn grade_id(grade: Grade) -> &'static str {
    match grade {
        Grade::Declares => "declares",
        Grade::Contains => "contains",
        Grade::Contacts => "contacts",
        Grade::Confirmed => "confirmed",
        Grade::Requested => "requested",
        Grade::Granted => "granted",
        Grade::Used => "used",
    }
}
