//! The HTML report: one file a person can open, read and print.
//!
//! It leads with what needs a person's attention: how much was found, then
//! the first entries of the checklist, each in one sentence with its first
//! step. The headline counts and everything that was found, each thing once
//! with the apps it is in, are under it, opened on demand. Then comes the
//! whole checklist of what a person can do, with what exposes the most first
//! ([`advice`]). Then the findings grouped by company, each with its grade,
//! and, opened on demand, its confidence, what can be done about it and the
//! records it rests on; what the scan covered and what it set aside; what no
//! scan of a device can see; and every evidence record, exactly as stored.
//!
//! What is opened on demand is in a `details` element: the browser shows and
//! hides it, with no script, and it is in the document whether it is open
//! or not. Printing opens it in browsers that support the `::details-content`
//! pseudo-element (current Chrome, Edge, Safari and Firefox); an older browser
//! prints it closed. A link never leads into one: a browser that
//! does not open it for the link would show nothing, so what a link names is
//! outside every `details`.
//!
//! The page is made from one list, [`SECTIONS`]. The navigation at its top is
//! written from the same list, so it names the sections that are on the page
//! and no other.
//!
//! The values it shows come out of scanned apps, so the document is built to
//! stay inert whatever they hold (design report, section 3, M3):
//!
//! * **Every value is escaped.** The [`markup`](crate::markup) writer lets a
//!   value in as character data only, and never as an attribute.
//! * **No script.** The document holds none, and its policy allows none.
//! * **Nothing is loaded.** The content security policy is
//!   `default-src 'none'`. The one stylesheet is in the document, and the
//!   policy admits it by its hash, so a second one could not apply. There
//!   is no image, no font, and no link that leaves the document.
//!
//! It is also a pure function of its input, like the JSON report: no date,
//! no path outside an app, and no order that depends on anything but the
//! content.

mod advice;
mod view;
mod words;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use xs_model::claim::{Party, VendorBasis};
use xs_model::pack::Pack;
use xs_model::record::{
    CoverageRecord, EdgeRecord, EdgeType, Grade, ObjectKind, Record, RecordId, Subject,
};
use xs_model::{Claim, EvidenceSet, Headline};
use xs_model::{canon, permission};

use self::view::{App, AppFindings, Company, Finding, Found, View};
use self::words::{list_words, plural, short};
use crate::markup::{Markup, Value};
use crate::{RenderError, ReportMeta, check_honest};

/// The hash source that admits the stylesheet of the report, `report.css`,
/// and no other style, under the content security policy. A test recomputes
/// it from the stylesheet.
macro_rules! style_source {
    () => {
        "'sha256-jh6LY3j9ajrAIb6lcb57XCIFPyyelrBK1+K1RRIWOO8='"
    };
}

macro_rules! policy {
    () => {
        concat!(
            "default-src 'none'; style-src ",
            style_source!(),
            "; base-uri 'none'; form-action 'none'"
        )
    };
}

/// The content security policy of the report.
///
/// `default-src 'none'` forbids every load and every script. The stylesheet
/// in the document is admitted by its hash alone, so an inline `style`
/// attribute or a second stylesheet would not apply. `base-uri` and
/// `form-action` do not fall back to `default-src` and are closed by name.
pub const CONTENT_SECURITY_POLICY: &str = policy!();

/// Everything before the navigation: the head, and the top of the page.
const HEAD: &str = concat!(
    "<!doctype html>\n",
    "<html lang=\"en\">\n",
    "<head>\n",
    "<meta charset=\"utf-8\">\n",
    "<meta http-equiv=\"Content-Security-Policy\" content=\"",
    policy!(),
    "\">\n",
    "<meta name=\"referrer\" content=\"no-referrer\">\n",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n",
    "<meta name=\"color-scheme\" content=\"light dark\">\n",
    "<title>Exposure report</title>\n",
    "<style>",
    include_str!("report.css"),
    "</style>\n",
    "</head>\n",
    "<body>\n",
    "<header class=\"top\">\n",
    "<p class=\"kicker\">Device exposure scan</p>\n",
    "<h1>Exposure report</h1>\n",
    "<p class=\"lede\">What the scanned apps ship and may access, what needs your attention, and \
     what you can do about it. The evidence behind each finding is further down, for when you \
     want it.</p>\n",
    "<p class=\"private\">This file was made on your device and lists apps you use, so treat \
     it as private. It loads nothing from the network and runs no script.</p>\n",
    "</header>\n",
);

/// What a section is written from.
struct Input<'a> {
    view: &'a View<'a>,
    evidence: &'a EvidenceSet,
    meta: &'a ReportMeta,
    /// The rule pack, for the advice it carries.
    pack: &'a Pack,
}

/// One section of the page.
struct Section {
    /// Its anchor.
    id: &'static str,
    /// The link to that anchor.
    href: &'static str,
    /// What the navigation calls it.
    nav: &'static str,
    heading: &'static str,
    /// Writes what is below the heading. A section whose body writes
    /// nothing is not on the page, and not in the navigation.
    body: fn(&mut Markup, &Input<'_>) -> Result<(), RenderError>,
}

macro_rules! section {
    ($id:literal, $nav:literal, $heading:literal, $body:expr) => {
        Section { id: $id, href: concat!("#", $id), nav: $nav, heading: $heading, body: $body }
    };
}

/// The sections of the report, in the order they are on the page.
const SECTIONS: [Section; 8] = [
    section!("summary", "Summary", "What needs your attention", summary),
    section!("actions", "What you can do", "What you can do", actions),
    section!("reading", "How to read it", "How to read this report", reading),
    section!("findings", "Findings", "Findings by company", findings),
    section!("coverage", "Coverage", "What was scanned, and what was not", coverage),
    section!("limits", "Limits", "What this report cannot tell you", limits),
    section!("records", "Records", "Evidence records", records),
    section!("about", "About", "About this report", about),
];

/// What the summary and the findings say when there is no finding.
const NOTHING_FOUND: &str = "<p class=\"none\">No scanned app matched a rule. That does not \
show the apps hold no third-party code: the scanner recognises only what its rule pack \
describes. See <a href=\"#limits\">the limits</a>.</p>\n";

/// The limits statement. It is the same in every report, because it is true
/// of every scan of a device (project spec, "What can be observed, and what
/// cannot").
const LIMITS: &str = "<p>This report rests on files that are on the device. It shows what an app ships and what \
it declares. Three things are out of reach of this scan and of every scan of a device:</p>\n\
<ul class=\"limits\">\n\
<li><strong>What is sent.</strong> Apps encrypt their traffic, so the content of a request \
cannot be read from the device. No finding here says which data was sent, or that any \
was.</li>\n\
<li><strong>What companies pass on between their own servers.</strong> Sharing from one \
server to another never touches the device and leaves nothing on it to find.</li>\n\
<li><strong>What is sent through the app's own domain.</strong> An app can send data to its \
publisher's servers, which forward it to another company. On the device this looks like the \
app talking to its publisher.</li>\n\
</ul>\n\
<p>Four more limits apply to what is reported:</p>\n\
<ul class=\"limits\">\n\
<li><strong>Presence is not use.</strong> <code>contains</code> means the code is in the \
app. The code may never run, and the service behind it may be retired. Only a recorded \
connection, at grade <code>contacts</code>, shows a live flow, and a scan of app files \
records none.</li>\n\
<li><strong>Only what has a rule is recognised.</strong> The scanner knows the SDKs its \
rule pack describes and no others. An app with no finding is not shown to be free of \
third-party code.</li>\n\
<li><strong>Some code hides its markers.</strong> Heavily obfuscated code, an encrypted \
binary, short text inside Swift code and JavaScript compiled to bytecode can each keep an \
SDK from being recognised. What the scan set aside is listed under \
<a href=\"#coverage\">coverage</a>.</li>\n\
<li><strong>Names are as the files give them.</strong> An app's name, its id and the Team \
ID in its signature are read from the app and are not verified.</li>\n\
</ul>\n";

/// Renders the HTML report.
///
/// `pack` is the rule pack the claims were derived with: it supplies the
/// names of companies and categories, and must be the pack `meta` names.
///
/// The document carries every record of `evidence`, so each finding links
/// to the raw records behind it. For the same claims, evidence, `meta` and
/// pack it is the same bytes, whatever order the claims are given in.
///
/// # Errors
///
/// Fails if the claims do not pass [`check_honest`], if `pack` is not the
/// pack `meta` names, or if a claim names a company or a category that
/// `pack` does not hold.
pub fn html(
    claims: &[Claim],
    evidence: &EvidenceSet,
    meta: &ReportMeta,
    pack: &Pack,
) -> Result<String, RenderError> {
    check_honest(claims, evidence)?;
    if meta.packs != pack.refs() {
        return Err(RenderError::PackMismatch);
    }
    let view = View::new(claims, evidence, pack)?;
    document(&SECTIONS, &Input { view: &view, evidence, meta, pack })
}

/// The checklist of the report, "What you can do", in plain words: one
/// entry per thing to do, with what exposes the most first.
///
/// It is the checklist [`html`] writes for the same input, in the same
/// order, and each entry gives the first of the steps the report gives for
/// it. Every value from a scanned app is made safe to print on a terminal.
///
/// # Errors
///
/// Fails where [`html`] fails.
pub fn checklist(
    claims: &[Claim],
    evidence: &EvidenceSet,
    meta: &ReportMeta,
    pack: &Pack,
) -> Result<Vec<crate::Todo>, RenderError> {
    check_honest(claims, evidence)?;
    if meta.packs != pack.refs() {
        return Err(RenderError::PackMismatch);
    }
    let view = View::new(claims, evidence, pack)?;
    Ok(advice::text::todos(pack, &view))
}

/// Writes the page: the head, a link to each section that is on the page,
/// and those sections.
fn document(sections: &[Section], input: &Input<'_>) -> Result<String, RenderError> {
    let mut written = Vec::with_capacity(sections.len());
    for section in sections {
        let mut body = Markup::new();
        (section.body)(&mut body, input)?;
        // Sections to come, such as app permissions, can have nothing to say on a machine.
        if !body.is_empty() {
            written.push((section, body));
        }
    }

    let mut page = Markup::new();
    page.raw(HEAD);
    page.raw("<nav class=\"toc\">\n");
    for (section, _) in &written {
        page.element("a", &[("href", Value::Fixed(section.href))], section.nav);
        page.raw("\n");
    }
    page.raw("</nav>\n<main>\n");
    for (section, body) in written {
        page.open("section", &[("id", Value::Fixed(section.id))]);
        page.raw("\n");
        page.element("h2", &[], section.heading);
        page.raw("\n");
        page.append(body);
        page.close();
        page.raw("\n");
    }
    page.raw("</main>\n</body>\n</html>\n");
    Ok(page.finish())
}

/// How much was found, then what needs attention first, then the three
/// counts of the headline and the totals, and everything that was found.
fn summary(page: &mut Markup, input: &Input<'_>) -> Result<(), RenderError> {
    let view = input.view;
    lead(page, view);
    if view.claims > 0 {
        attention(page, input);
    }
    headline(page, view);
    found(page, view);
    Ok(())
}

/// One sentence with how much was found, or that nothing was.
fn lead(page: &mut Markup, view: &View<'_>) {
    if view.claims == 0 {
        page.raw(NOTHING_FOUND);
        return;
    }
    let scanned = view.read_apps().count() as u64;
    let with_findings = view.read_apps().filter(|app| app.findings > 0).count() as u64;
    page.open_class("p", "lead");
    page.text(&plural(view.claims, "finding", "findings"));
    page.raw(" in ");
    page.number(with_findings);
    page.raw(" of ");
    page.text(&plural(scanned, "app scanned", "apps scanned"));
    page.raw(".");
    page.close();
    page.raw("\n");
}

/// The first entries of the checklist, each in one sentence with its first
/// step and a link to every step: [`crate::first_todos`] of the checklist,
/// which a scan prints on the terminal too.
fn attention(page: &mut Markup, input: &Input<'_>) {
    let items = advice::text::items(input.pack, input.view);
    let todos: Vec<crate::Todo> = items.iter().map(|item| item.todo.clone()).collect();
    let first = crate::first_todos(&todos);
    let Some(top) = first.first() else {
        page.raw(advice::NOTHING_TO_DO);
        return;
    };
    page.open_class("p", "status");
    let entries = plural(todos.len() as u64, "entry", "entries");
    if top.priority.needs_attention() {
        if first.len() == 1 {
            page.raw("Start with this one. ");
        } else {
            page.raw("Start with these ");
            page.number(first.len() as u64);
            page.raw(". ");
        }
        page.raw("<a href=\"#actions\">What you can do</a> has every step, for ");
        page.raw(if todos.len() > 1 { "all " } else { "its " });
        page.text(&entries);
        let mut by_priority: Vec<String> = Vec::new();
        for priority in
            [crate::TodoPriority::High, crate::TodoPriority::Medium, crate::TodoPriority::Low]
        {
            let count = todos.iter().filter(|todo| todo.priority == priority).count();
            if count > 0 {
                by_priority.push(format!("{count} {}", priority.name().to_lowercase()));
            }
        }
        if by_priority.len() > 1 {
            page.raw(": ");
            let by_priority: Vec<&str> = by_priority.iter().map(String::as_str).collect();
            page.text(&list_words(&by_priority));
            page.raw(" priority");
        }
        page.raw(".");
    } else {
        page.raw("Nothing here needs your attention first: ");
        page.raw(if todos.len() > 1 { "all " } else { "the " });
        page.text(&entries);
        page.raw(" of <a href=\"#actions\">What you can do</a> ");
        page.raw(if todos.len() > 1 { "are" } else { "is" });
        page.raw(" of low priority. ");
        page.raw(if first.len() < todos.len() { "The first of them:" } else { "Here they are:" });
    }
    page.close();
    page.raw("\n<ol class=\"first\">\n");
    for (todo, item) in first.iter().zip(&items) {
        page.open_class(
            "li",
            match todo.priority {
                crate::TodoPriority::High => "first-high",
                crate::TodoPriority::Medium => "first-medium",
                crate::TodoPriority::Low => "first-low",
            },
        );
        page.raw("\n");
        page.open_class("p", "todo-head");
        page.classed("span", priority_class(todo.priority), todo.priority.name());
        page.raw(" ");
        page.element("strong", &[], &todo.title);
        page.close();
        page.raw("\n");
        page.element("p", &[], &todo.about);
        page.raw("\n");
        page.open_class("p", "do");
        page.classed("span", "do-label", "First step:");
        page.raw(" ");
        page.text(&todo.step);
        page.raw(" ");
        page.element("a", &[("href", Value::Link("t-", item.anchor.id.digest()))], "Every step");
        page.close();
        page.raw("\n");
        page.close();
        page.raw("\n");
    }
    page.raw("</ol>\n");
}

/// The class of the badge of a priority, as the checklist writes it.
const fn priority_class(priority: crate::TodoPriority) -> &'static str {
    match priority {
        crate::TodoPriority::High => "prio p-high",
        crate::TodoPriority::Medium => "prio p-medium",
        crate::TodoPriority::Low => "prio p-low",
    }
}

/// Everything the scan found, once each, whether or not it counts in the
/// headline: what it is, whose it is, in how many apps, and in which. It is
/// opened on demand.
fn found(page: &mut Markup, view: &View<'_>) {
    if view.claims == 0 {
        return;
    }
    let scanned = view.read_apps().count() as u64;
    page.raw("<details class=\"more\">\n<summary>");
    page.raw("Everything the scan found: ");
    page.text(&plural(view.found.len() as u64, "thing", "things"));
    page.raw(", each with the apps it is in");
    page.raw("</summary>\n<h3>What was found</h3>\n");
    page.raw(
        "<p class=\"note\">Each entry is one thing the scan found and the apps it is in, \
         with what is in the most apps first. An app's name links to its finding further \
         down, which shows the evidence.</p>\n<ul class=\"found\">\n",
    );
    for thing in &view.found {
        found_item(page, view, thing, scanned);
    }
    page.raw("</ul>\n</details>\n");
}

/// One thing that was found.
fn found_item(page: &mut Markup, view: &View<'_>, thing: &Found<'_>, scanned: u64) {
    page.open("li", &[]);
    page.raw("\n");
    page.open_class("p", "thing");
    page.element("strong", &[], thing.name);
    page.raw(" ");
    page.classed("span", "tag", thing.category.name);
    page.close();
    page.raw("\n");

    page.open_class("p", "owner");
    match (thing.company, thing.edge, thing.kind) {
        (Some(company), _, _) => page.text(&company.name),
        (None, EdgeType::Channel, ObjectKind::Sdk) => {
            page.raw("No company named: a component, with no network side of its own.");
        }
        (None, EdgeType::Channel, ObjectKind::Host) => {
            page.raw("No company named: a host the rule pack lists under no company.");
        }
        (None, EdgeType::Access, _) | (None, _, ObjectKind::Permission) => {
            page.raw("No company named: this is about what the apps may access.");
        }
    }
    page.close();
    page.raw("\n");

    page.open_class("p", "fact");
    for (at, (grade, apps)) in thing.by_grade().into_iter().enumerate() {
        if at == 0 {
            grade_badge(page, grade);
            page.raw(" ");
        } else {
            page.raw(", ");
        }
        page.text(&words::found_words(grade, apps, scanned));
    }
    page.close();
    page.raw("\n");

    page.open_class("p", "where");
    page.raw("In ");
    for (at, (&app, found)) in thing.apps.iter().enumerate() {
        let Some(app) = view.apps.get(app) else { continue };
        if at > 0 {
            page.raw(", ");
        }
        let name = name_in_entry(view, thing, app);
        page.element("a", &[("href", Value::Link("f-", found.claim.id.digest()))], &name);
    }
    page.close();
    page.raw("\n");

    page.open("p", &[]);
    if thing.counted {
        page.classed("span", "tag counted", "counted");
    } else {
        page.classed("span", "tag uncounted", "not counted");
    }
    page.close();
    page.raw("\n");
    page.close();
    page.raw("\n");
}

/// What a summary entry calls one of its apps: its name, and when another
/// app of the entry has the same name, what tells the two apart. That is
/// the platform; for two on one platform the version as well; and for two
/// of one version the start of the build digest as well.
fn name_in_entry(view: &View<'_>, thing: &Found<'_>, app: &App<'_>) -> String {
    let subject = app.subject;
    let mut alike: Vec<&Subject> = thing
        .apps
        .keys()
        .filter_map(|&other| view.apps.get(other))
        .filter(|other| other.title() == app.title() && other.subject != subject)
        .map(|other| other.subject)
        .collect();
    if alike.is_empty() {
        return String::from(app.title());
    }
    let mut told_by = String::from(words::platform_name(subject.platform));
    alike.retain(|other| other.platform == subject.platform);
    if !alike.is_empty() {
        told_by.push_str(", ");
        match &subject.version {
            Some(version) => {
                told_by.push_str("version ");
                told_by.push_str(version);
            }
            None => told_by.push_str("no version stated"),
        }
        alike.retain(|other| other.version == subject.version);
        if let (false, Some(build)) = (alike.is_empty(), build_words(subject)) {
            told_by.push_str(", build ");
            told_by.push_str(&build);
        }
    }
    format!("{} ({told_by})", app.title())
}

/// The three counts of the headline, what they count, and the totals. The
/// line that opens them on demand states the three numbers.
fn headline(page: &mut Markup, view: &View<'_>) {
    let headline = view.headline;
    let zeros = view.claims > 0 && headline == Headline::default();
    page.raw("<details class=\"more\">\n<summary>The three headline counts: ");
    page.text(&format!(
        "{}, {} and {}",
        plural(
            headline.companies_contacts.into(),
            "company with a recorded connection",
            "companies with a recorded connection"
        ),
        plural(
            headline.companies_contains.into(),
            "company whose code the apps ship",
            "companies whose code the apps ship"
        ),
        plural(
            headline.apps_third_party.into(),
            "app with a third-party channel",
            "apps with a third-party channel"
        ),
    ));
    page.raw(if zeros { ". None of the findings adds to them." } else { "." });
    page.raw("</summary>\n<h3>The three headline counts</h3>\n");
    page.open_class("p", "note");
    page.raw(
        "These three numbers do not count every finding. They count the findings that name a \
         company",
    );
    if !view.counted_categories.is_empty() {
        page.raw(" in the categories ");
        page.text(&list_words(&view.counted_categories));
    }
    page.raw(
        ". Every other finding, such as crash reporting or an update feed, is in the list \
         of what was found and in the findings below, and in none of these numbers. There is \
         no score.",
    );
    page.close();
    page.raw("\n");
    if zeros {
        page.raw(
            "<p class=\"zero\">None of the findings adds to these three counts, which is why \
             they are zero. A count takes a finding that names a company in a counted \
             category: a company is counted from grade <code>contains</code> up, and an app \
             only for a third-party finding.</p>\n",
        );
    }
    page.raw("<div class=\"counts\">\n");
    count(
        page,
        headline.companies_contacts,
        ("company with a recorded connection", "companies with a recorded connection"),
        "Grade <code>contacts</code> or above: a connection to the company was recorded.",
    );
    count(
        page,
        headline.companies_contains,
        ("company whose code the scanned apps ship", "companies whose code the scanned apps ship"),
        "Strongest grade <code>contains</code>: the code is present. Presence is not use.",
    );
    count(
        page,
        headline.apps_third_party,
        ("app with a third-party channel", "apps with a third-party channel"),
        "A counted finding names a company that is not the app's own publisher.",
    );
    page.raw("</div>\n");
    beside_the_headline(page, view);
    page.raw("<ul class=\"totals\">\n");
    for total in [
        plural(view.read_apps().count() as u64, "app scanned", "apps scanned"),
        plural(view.claims, "finding", "findings"),
        plural(view.company_count(), "company named", "companies named"),
        plural(view.coverage_notes, "coverage note", "coverage notes"),
        plural(view.records, "evidence record", "evidence records"),
    ] {
        page.element("li", &[], &total);
        page.raw("\n");
    }
    page.raw("</ul>\n</details>\n");
}

/// What the Android apps ship in categories the headline leaves out, so a
/// scan of them does not read as "nothing found" when the counts are zero.
fn beside_the_headline(page: &mut Markup, view: &View<'_>) {
    if view.uncounted.is_empty() {
        return;
    }
    let sdks = view.uncounted.iter().map(|(_, names)| names.len() as u64).sum();
    page.open_class("p", "beside");
    page.raw("Beside these counts, the Android apps ship ");
    page.text(&plural(sdks, "SDK", "SDKs"));
    page.raw(" of ");
    page.text(&plural(view.uncounted.len() as u64, "company", "companies"));
    page.raw(" in categories the counts leave out: ");
    for (at, (company, names)) in view.uncounted.iter().enumerate() {
        if at > 0 {
            page.raw("; ");
        }
        page.element("strong", &[], &company.name);
        page.raw(" (");
        page.text(&list_words(names));
        page.raw(")");
    }
    page.raw(". They are in the list of what was found and in the findings below.");
    page.close();
    page.raw("\n");
}

fn count(page: &mut Markup, number: u32, label: (&str, &str), sub: &'static str) {
    page.open_class("div", "count");
    page.open_class("p", "n");
    page.number(number.into());
    page.close();
    page.classed("p", "label", if number == 1 { label.0 } else { label.1 });
    page.open_class("p", "sub");
    page.raw(sub);
    page.close();
    page.close();
    page.raw("\n");
}

/// The checklist of what a person can do, with what exposes the most first.
fn actions(page: &mut Markup, input: &Input<'_>) -> Result<(), RenderError> {
    advice::actions(page, input.pack, input.view);
    Ok(())
}

/// What a grade, a confidence and a party mean.
fn reading(page: &mut Markup, input: &Input<'_>) -> Result<(), RenderError> {
    page.raw(
        "<p>Each finding is a graded fact about what an app's files hold. The grade says what \
         kind of evidence there is, and a finding takes the highest grade its evidence \
         reaches. No finding says what an app or a company intends.</p>\n\
         <details class=\"more\">\n<summary>What each grade shows, and the other terms of a \
         finding</summary>\n\
         <div class=\"scroll\">\n<table class=\"ladder\">\n\
         <thead><tr><th scope=\"col\">Grade</th><th scope=\"col\">In a word</th>\
         <th scope=\"col\">What it shows</th></tr></thead>\n<tbody>\n",
    );
    let access = if input.view.access.is_empty() { &[] } else { &words::ACCESS_LADDER[..] };
    for &grade in words::CHANNEL_LADDER.iter().chain(access) {
        page.open("tr", &[]);
        page.open("td", &[]);
        grade_badge(page, grade);
        page.close();
        page.element("td", &[], words::grade_verb(grade));
        page.element("td", &[], words::grade_meaning(grade));
        page.close();
        page.raw("\n");
    }
    page.raw(
        "</tbody>\n</table>\n</div>\n<dl class=\"terms\">\n\
         <dt>Confidence</dt>\n<dd>How unlikely it is that a marker matched by coincidence. High \
         for a name read from a structured table, medium for text in the app's own code or in \
         a binary's data, low for text inside a bundled library. It is not a score.</dd>\n\
         <dt>Kinds of evidence</dt>\n<dd>How many independent kinds of marker agree, such as a \
         class name and an entry in the app's manifest.</dd>\n\
         <dt>First party, third party</dt>\n<dd>First party: the company is the app's own \
         publisher. Third party: it is someone else.</dd>\n\
         <dt>Component</dt>\n<dd>A library with no network side of its own, such as an \
         updater. It names no company.</dd>\n\
         <dt>Unmapped host</dt>\n<dd>A host the app declares that the rule pack lists under no \
         company. It is shown as itself and nobody is named as its owner.</dd>\n\
         </dl>\n</details>\n",
    );
    Ok(())
}

fn grade_badge(page: &mut Markup, grade: Grade) {
    page.classed("span", words::grade_class(grade), words::grade_name(grade));
}

/// The findings: by company, then the channels that name no company, then
/// what the apps may access.
fn findings(page: &mut Markup, input: &Input<'_>) -> Result<(), RenderError> {
    let view = input.view;
    if view.claims == 0 {
        page.raw(NOTHING_FOUND);
    } else {
        page.raw(
            "<p>Companies with a finding that counts in the summary come first, then the \
             others, each in alphabetical order. Open a finding to see what you can do about \
             it and the evidence it rests on.</p>\n",
        );
    }
    for company in &view.companies {
        company_block(page, input, company);
    }
    if !view.unnamed.is_empty() {
        page.raw(
            "<section class=\"company\">\n<h3>No company named</h3>\n\
             <p class=\"meta\">Components, and hosts the rule pack lists under no company. \
             They are findings like the others, and the three headline counts hold none of \
             them.</p>\n",
        );
        for group in &view.unnamed {
            app_block(page, input, group);
        }
        page.raw("</section>\n");
    }
    if !view.access.is_empty() {
        page.raw(
            "<section class=\"company access\">\n<h3>What the apps may access</h3>\n\
             <p class=\"meta\">What an app asks for, what was allowed on this device, and \
             what the operating system logged as used. These are not channels to a company, \
             so they are under none, and the three headline counts hold none of them.</p>\n",
        );
        for group in &view.access {
            app_block(page, input, group);
        }
        page.raw("</section>\n");
    }
    Ok(())
}

fn company_block(page: &mut Markup, input: &Input<'_>, company: &Company<'_>) {
    page.raw("<section class=\"company\">\n");
    page.open("h3", &[]);
    page.text(&company.entity.name);
    page.raw(" ");
    if company.counted {
        page.classed("span", "tag counted", "counted in the summary");
    } else {
        page.classed("span", "tag uncounted", "not in the counted categories");
    }
    page.close();
    page.raw("\n");
    page.open_class("p", "meta");
    page.text(&plural(company.apps.len() as u64, "app", "apps"));
    page.raw(" · ");
    page.text(&plural(company.finding_count(), "finding", "findings"));
    page.raw(" · strongest grade ");
    grade_badge(page, company.strongest);
    page.close();
    page.raw("\n");
    for group in &company.apps {
        app_block(page, input, group);
    }
    page.raw("</section>\n");
}

/// One app under a company: who it is, who publishes it, and its findings.
fn app_block(page: &mut Markup, input: &Input<'_>, group: &AppFindings<'_>) {
    let Some(app) = input.view.apps.get(group.app) else { return };
    page.open_class("div", "app");
    page.raw("\n");
    page.element("h4", &[], app.title());
    page.raw("\n");
    app_line(page, app.subject);
    if let Some(first) = group.findings.first() {
        publisher(page, first);
    }
    for finding in &group.findings {
        finding_block(page, input, finding);
    }
    page.close();
    page.raw("\n");
}

/// The line under an app's name that tells one build from another.
fn app_line(page: &mut Markup, subject: &Subject) {
    page.open_class("p", "meta");
    page.element("code", &[], &subject.id);
    if let Some(version) = &subject.version {
        page.raw(" · version ");
        page.text(version);
    }
    page.raw(" · ");
    page.raw(words::platform_name(subject.platform));
    page.raw(" · build ");
    build(page, subject);
    page.close();
    page.raw("\n");
}

/// The start of the digest that tells two builds of one app apart. The
/// whole digest is in the app's records. A package that could not be read
/// has no digest.
fn build(page: &mut Markup, subject: &Subject) {
    match build_words(subject) {
        Some(build) => page.element("code", &[], &build),
        None => page.raw("none, the file was not read"),
    }
}

fn build_words(subject: &Subject) -> Option<String> {
    let digest = subject.digest.to_string();
    let (scheme, hex) = digest.split_once(':')?;
    Some(format!("{scheme}:{}…", short(hex)))
}

/// Who publishes the app, and how that is known. The party of every finding
/// about the app rests on it.
fn publisher(page: &mut Markup, finding: &Finding<'_>) {
    page.open_class("p", "publisher");
    page.raw("Publisher: ");
    match (&finding.claim.vendor, finding.publisher) {
        (None, _) => page.raw("not established from the app's files."),
        (Some(vendor), Some(company)) => {
            page.text(&company.name);
            match vendor.by {
                Some(VendorBasis::TeamId) => page.raw(
                    ", by the Apple Team ID its code signature names. The signature is read, \
                     not verified.",
                ),
                Some(VendorBasis::AppId) | None => page.raw(", by its app id."),
            }
            for id in &vendor.evidence {
                page.raw(" ");
                record_link(page, id);
            }
        }
        (Some(vendor), None) => {
            page.raw("not a company the rule pack lists.");
            if let Some(domain) = &vendor.domain {
                page.raw(" Its app id spells the domain ");
                page.element("code", &[], domain);
                page.raw(", which is what the app says of itself.");
            }
        }
    }
    page.close();
    page.raw("\n");
}

/// A link to a record in the last section of the document.
fn record_link(page: &mut Markup, id: &RecordId) {
    let text = format!("sha256:{}…", short(&id.digest().to_string()));
    page.element("a", &[("href", Value::Link("r-", id.digest()))], &text);
}

/// One finding: what it is about, its grade, what can be done about it, and
/// the evidence behind it.
fn finding_block(page: &mut Markup, input: &Input<'_>, finding: &Finding<'_>) {
    let claim = finding.claim;
    page.open(
        "div",
        &[("class", Value::Fixed("finding")), ("id", Value::Anchor("f-", claim.id.digest()))],
    );
    page.raw("\n");
    page.open("h5", &[]);
    page.text(&claim.object.name);
    page.raw(" ");
    page.classed("span", "tag", finding.category.name);
    page.close();
    page.raw("\n");

    page.open_class("p", "graded");
    grade_badge(page, claim.grade);
    page.raw(" ");
    page.raw(words::grade_meaning(claim.grade));
    page.close();
    page.raw("\n<details class=\"more\">\n<summary>What you can do, and the evidence: ");
    page.text(&plural(claim.evidence.len() as u64, "record", "records"));
    page.raw("</summary>\n<dl class=\"facts\">\n");

    match (claim.edge, claim.object.kind, finding.company) {
        (EdgeType::Access, _, _) | (_, ObjectKind::Permission, _) => {}
        (EdgeType::Channel, ObjectKind::Sdk, Some(_)) => {
            fact(page, "Rule", |page| code(page, &claim.object.id));
        }
        (EdgeType::Channel, ObjectKind::Sdk, None) => fact(page, "Kind", |page| {
            page.raw("Component: a library with no network side of its own. Rule ");
            code(page, &claim.object.id);
        }),
        (EdgeType::Channel, ObjectKind::Host, Some(_)) => {
            fact(page, "Kind", |page| page.raw("A host the app's own files declare."));
        }
        (EdgeType::Channel, ObjectKind::Host, None) => fact(page, "Kind", |page| {
            page.raw("Unmapped host: the rule pack lists it under no company.");
        }),
    }
    if let (Some(operator), Some(company)) = (finding.operator, finding.company) {
        fact(page, "Operated by", |page| {
            page.text(&operator.name);
            page.raw(", which ");
            page.text(&company.name);
            page.raw(" owns.");
        });
    }
    fact(page, "Confidence", |page| {
        page.raw(words::confidence_name(claim.confidence));
        page.raw(": ");
        page.raw(words::confidence_meaning(claim.confidence));
        page.raw(".");
    });
    fact(page, "Kinds of evidence", |page| {
        page.text(&plural(claim.witnesses.into(), "kind", "independent kinds agree"));
        page.raw(".");
    });
    fact(page, "Party", |page| party(page, finding));
    fact(page, "In the summary", |page| counted(page, finding));
    if claim.rungs.len() > 1 {
        fact(page, "Grades with evidence", |page| {
            for (at, &rung) in claim.rungs.iter().enumerate() {
                if at > 0 {
                    page.raw(" ");
                }
                grade_badge(page, rung);
            }
        });
    }
    for note in &claim.notes {
        fact(page, "Note", |page| match note.strip_prefix("retired:") {
            Some(date) => {
                page.raw("The service behind this code was retired on ");
                page.text(date);
                page.raw(". An app that still ships the code does not show a live flow.");
            }
            None if note == permission::NOTE_OPTIONAL => page.raw(
                "Optional: the extension does not hold this until it asks while it runs and \
                 the person agrees.",
            ),
            None => page.text(note),
        });
    }
    page.raw("</dl>\n<p class=\"todo-head\">What you can do</p>\n<ul class=\"steps\">\n");
    advice::finding_steps(page, input.pack, input.view, finding);
    page.raw("</ul>\n");

    page.open_class("p", "evidence-head");
    page.raw("Evidence: ");
    page.text(&plural(claim.evidence.len() as u64, "record", "records"));
    page.close();
    page.raw("\n<ul class=\"evidence\">\n");
    for id in &claim.evidence {
        if let Some(Record::Edge(edge)) = input.evidence.get(id) {
            evidence_item(page, id, edge);
        }
    }
    page.raw("</ul>\n</details>\n");
    page.close();
    page.raw("\n");
}

/// One row of a list of facts.
fn fact(page: &mut Markup, name: &'static str, value: impl FnOnce(&mut Markup)) {
    page.element("dt", &[], name);
    page.open("dd", &[]);
    value(page);
    page.close();
    page.raw("\n");
}

fn code(page: &mut Markup, value: &str) {
    page.element("code", &[], value);
}

fn party(page: &mut Markup, finding: &Finding<'_>) {
    match (finding.claim.party, finding.company) {
        (Party::First, Some(company)) => {
            page.raw("First party: ");
            page.text(&company.name);
            page.raw(" publishes this app.");
        }
        (Party::First, None) => {
            page.raw("First party: the host is under the domain the app's own id spells.");
        }
        (Party::Third, Some(company)) => {
            page.raw("Third party: ");
            page.text(&company.name);
            page.raw(" is not this app's publisher.");
        }
        (Party::Third, None) => page.raw("Third party."),
        (Party::Unknown, Some(_)) => page.raw(
            "Not established: nothing in the app's files identifies its publisher, or what \
             does contradicts itself.",
        ),
        (Party::Unknown, None) => page.raw("Not stated: the finding names no company."),
    }
}

/// Whether the finding is one of those the summary counts, and if not, why.
fn counted(page: &mut Markup, finding: &Finding<'_>) {
    let claim = finding.claim;
    if claim.headline {
        page.raw("Counted.");
    } else if claim.edge != EdgeType::Channel {
        page.raw("Not counted: the summary counts channels.");
    } else if finding.company.is_none() {
        page.raw("Not counted: the finding names no company.");
    } else if !finding.category.headline {
        page.raw("Not counted: ");
        page.text(finding.category.name);
        page.raw(" is not one of the counted categories.");
    } else {
        page.raw("Not counted.");
    }
}

/// One record behind a finding, in words, with a link to the record itself.
fn evidence_item(page: &mut Markup, id: &RecordId, edge: &EdgeRecord) {
    let proof = &edge.proof;
    page.open("li", &[]);
    page.classed("p", "what", words::matcher_words(proof.matcher));
    page.raw("\n<dl class=\"facts\">\n");
    fact(page, "Marker", |page| code(page, &proof.token));
    fact(page, "Found in", |page| {
        code(page, proof.location.as_str());
        page.raw(", in ");
        page.raw(words::region_words(proof.region));
    });
    if let Some(example) = &proof.example {
        fact(page, "Example", |page| code(page, example));
    }
    fact(page, "Count", |page| page.text(&words::count_words(proof.region, proof.count)));
    fact(page, "Kind of file", |page| page.raw(words::scope_words(proof.scope)));
    fact(page, "Grade", |page| grade_badge(page, edge.grade));
    fact(page, "Record", |page| record_link(page, id));
    page.raw("</dl>\n");
    page.close();
    page.raw("\n");
}

/// What the scan read, and what it set aside and why.
fn coverage(page: &mut Markup, input: &Input<'_>) -> Result<(), RenderError> {
    page.raw(
        "<p>Nothing found is not the same as not looked at. This section says where the scan \
         looked, lists every app it read, and lists everything it set aside or could not \
         interpret.</p>\n",
    );
    scope(page, input.meta);
    apps_scanned(page, input.view);
    set_aside(page, input.view);
    Ok(())
}

/// What no scan of a device can see.
fn limits(page: &mut Markup, _: &Input<'_>) -> Result<(), RenderError> {
    page.raw(LIMITS);
    Ok(())
}

/// Where the scan looked for apps, and where it deliberately did not.
///
/// The scan states this when it runs and the JSON report carries it. A
/// report saved before it did has no scope, and its page says so.
fn scope(page: &mut Markup, meta: &ReportMeta) {
    page.raw("<h3>Where the scan looked</h3>\n");
    page.open_class("p", "scope");
    match &meta.scope {
        Some(scope) => {
            page.raw("This scan covered ");
            page.text(&scope.to_string());
            page.raw(".");
        }
        None => page.raw(
            "This page was rendered from saved evidence, which does not record where the scan \
             looked. The scan stated it in the summary it printed when it ran.",
        ),
    }
    page.close();
    page.raw("\n");
}

/// Every app the scan read, also those with no finding. An app that could
/// not be read is not one of them: it is listed with what was set aside.
fn apps_scanned(page: &mut Markup, view: &View<'_>) {
    page.raw("<h3>Apps scanned</h3>\n");
    if view.read_apps().next().is_none() {
        page.raw("<p class=\"none\">The scan found no app to read.</p>\n");
    } else {
        page.raw("<details class=\"more\">\n<summary>");
        page.text(&plural(view.read_apps().count() as u64, "app", "apps"));
        page.raw(", with what was read of each and how many findings it has</summary>\n");
        page.raw(
            "<div class=\"scroll\">\n<table>\n<thead><tr><th scope=\"col\">App</th>\
             <th scope=\"col\">App id</th><th scope=\"col\">Version</th>\
             <th scope=\"col\">Build</th><th scope=\"col\">Platform</th>\
             <th scope=\"col\">Read</th>\
             <th scope=\"col\">Findings</th><th scope=\"col\">Not covered</th></tr></thead>\n\
             <tbody>\n",
        );
        for app in view.read_apps() {
            page.open("tr", &[]);
            page.element("td", &[], app.title());
            page.open("td", &[]);
            code(page, &app.subject.id);
            page.close();
            page.element("td", &[], app.subject.version.as_deref().unwrap_or("not stated"));
            page.open("td", &[]);
            build(page, app.subject);
            page.close();
            page.element("td", &[], words::platform_name(app.subject.platform));
            let read = app.read.map_or_else(
                || String::from("not recorded"),
                |(files, bytes)| {
                    format!("{}, {}", plural(files, "file", "files"), words::size_words(bytes))
                },
            );
            page.element("td", &[], &read);
            page.open("td", &[]);
            page.number(app.findings);
            page.close();
            let gaps = app.coverage().count() as u64;
            let gaps =
                if gaps == 0 { String::from("nothing") } else { plural(gaps, "note", "notes") };
            page.element("td", &[], &gaps);
            page.close();
            page.raw("\n");
        }
        page.raw("</tbody>\n</table>\n</div>\n</details>\n");
    }
}

/// What the scan skipped or could not interpret, and why.
fn set_aside(page: &mut Markup, view: &View<'_>) {
    page.raw("<h3>Set aside, and why</h3>\n");
    if view.coverage_notes == 0 {
        page.raw(
            "<p class=\"none\">The scan recorded nothing it skipped and nothing it could not \
             interpret in these apps.</p>\n",
        );
    } else {
        page.raw("<details class=\"more\">\n<summary>");
        page.text(&plural(
            view.coverage_notes,
            "thing the scan set aside or could not interpret",
            "things the scan set aside or could not interpret",
        ));
        page.raw("</summary>\n");
        page.raw(
            "<div class=\"scroll\">\n<table>\n<thead><tr><th scope=\"col\">App</th>\
             <th scope=\"col\">Where</th><th scope=\"col\">What happened</th>\
             <th scope=\"col\">Why</th><th scope=\"col\">Record</th></tr></thead>\n<tbody>\n",
        );
        for app in &view.apps {
            for (id, note) in app.coverage() {
                coverage_row(page, app, id, note);
            }
        }
        page.raw("</tbody>\n</table>\n</div>\n</details>\n");
    }
}

fn coverage_row(page: &mut Markup, app: &App<'_>, id: &RecordId, note: &CoverageRecord) {
    page.open("tr", &[]);
    page.element("td", &[], app.title());
    page.open("td", &[]);
    match &note.location {
        Some(location) => code(page, location.as_str()),
        None => page.raw("the app as a whole"),
    }
    page.close();
    page.element("td", &[], words::status_words(note.status));
    page.open("td", &[]);
    page.raw(words::reason_words(note.reason));
    if let Some(bytes) = note.bytes {
        page.raw(" Size: ");
        page.text(&words::size_words(bytes));
        page.raw(".");
    }
    if note.count > 1 {
        page.raw(" ");
        page.text(&plural(note.count.into(), "item", "items"));
        page.raw(".");
    }
    page.close();
    page.open("td", &[]);
    record_link(page, id);
    page.close();
    page.close();
    page.raw("\n");
}

/// Every record of the evidence set, as stored, grouped by app.
fn records(page: &mut Markup, input: &Input<'_>) -> Result<(), RenderError> {
    let view = input.view;
    page.raw(
        "<p>Every record the scan produced, exactly as it is stored. The findings above link \
         to the records they rest on. The id of a record is the SHA-256 of its text as shown \
         here, so a record that was changed no longer matches its id.</p>\n",
    );
    if view.records == 0 {
        page.raw("<p class=\"none\">The scan produced no record.</p>\n");
    }
    for app in view.apps.iter().filter(|app| !app.records.is_empty()) {
        page.element("h3", &[], app.title());
        page.raw("\n");
        app_line(page, app.subject);
        for &(id, record) in &app.records {
            page.open(
                "div",
                &[("class", Value::Fixed("record")), ("id", Value::Anchor("r-", id.digest()))],
            );
            page.raw("\n");
            page.open_class("p", "record-head");
            page.classed(
                "span",
                "tag",
                match record {
                    Record::Edge(_) => "evidence of a finding",
                    Record::Artifact(_) => "facts about the app",
                    Record::Coverage(_) => "coverage note",
                },
            );
            page.raw(" ");
            code(page, &id.to_string());
            page.close();
            page.raw("\n");
            page.element("pre", &[], &canon::to_string(record)?);
            page.raw("\n");
            page.close();
            page.raw("\n");
        }
    }
    Ok(())
}

/// What made the report: the scanner and the rule pack.
fn about(page: &mut Markup, input: &Input<'_>) -> Result<(), RenderError> {
    let meta = input.meta;
    page.raw("<dl class=\"facts\">\n");
    fact(page, "Scanner", |page| {
        page.text(&meta.scanner.name);
        page.raw(" ");
        page.text(&meta.scanner.version);
    });
    for layer in &meta.packs {
        fact(page, "Rule pack", |page| {
            page.text(&layer.layer);
            page.raw(" version ");
            page.number(layer.version.into());
            page.raw(", SHA-256 ");
            code(page, &layer.sha256);
        });
    }
    page.raw(
        "</dl>\n<p>The same evidence, the same rule pack and the same scan scope always give \
         this same file, byte for byte. It holds no date, no device name and no path outside \
         an app.</p>\n",
    );
    Ok(())
}

#[cfg(test)]
mod tests;
