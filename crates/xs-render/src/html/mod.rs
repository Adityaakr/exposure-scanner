//! The HTML report: one file a person can open, read and print.
//!
//! It shows the findings grouped by company, each with its grade, its
//! confidence and the records it rests on; what the scan covered and what it
//! set aside; what no scan of a device can see; and every evidence record,
//! exactly as stored.
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

mod view;
mod words;

use alloc::format;
use alloc::string::{String, ToString};

use xs_model::canon;
use xs_model::claim::{Party, VendorBasis};
use xs_model::pack::Pack;
use xs_model::record::{
    CoverageRecord, EdgeRecord, EdgeType, Grade, ObjectKind, Record, RecordId, Subject,
};
use xs_model::{Claim, EvidenceSet};

use self::view::{App, AppFindings, Company, Finding, View};
use self::words::{list_words, plural, short};
use crate::markup::{Markup, Value};
use crate::{RenderError, ReportMeta, check_honest};

/// The hash source that admits the stylesheet of the report, `report.css`,
/// and no other style, under the content security policy. A test recomputes
/// it from the stylesheet.
macro_rules! style_source {
    () => {
        "'sha256-rNa04b7I1iqCjn2UDk60hfrfNT0kV8XgvNEXLXEU8Gw='"
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

/// Everything before the first value: the head, and the top of the page.
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
    "<p class=\"lede\">Which companies have a channel to your data through the apps that were \
     scanned, and the evidence for each one. Every finding states how strong its evidence is \
     and links to the raw record behind it.</p>\n",
    "<p class=\"private\">This file was made on your device and lists apps you use, so treat \
     it as private. It loads nothing from the network and runs no script.</p>\n",
    "</header>\n",
    "<nav class=\"toc\">\n",
    "<a href=\"#summary\">Summary</a>\n",
    "<a href=\"#reading\">How to read it</a>\n",
    "<a href=\"#findings\">Findings</a>\n",
    "<a href=\"#coverage\">Coverage</a>\n",
    "<a href=\"#limits\">Limits</a>\n",
    "<a href=\"#records\">Records</a>\n",
    "<a href=\"#about\">About</a>\n",
    "</nav>\n",
    "<main>\n",
);

/// The limits statement. It is the same in every report, because it is true
/// of every scan of a device (project spec, "What can be observed, and what
/// cannot").
const LIMITS: &str = "<section id=\"limits\">\n\
<h2>What this report cannot tell you</h2>\n\
<p>This report rests on files that are on the device. It shows what an app ships and what \
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
</ul>\n\
</section>\n";

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

    let mut page = Markup::new();
    page.raw(HEAD);
    summary(&mut page, &view);
    reading(&mut page, &view);
    findings(&mut page, &view, evidence);
    coverage(&mut page, &view, meta);
    page.raw(LIMITS);
    records(&mut page, &view)?;
    about(&mut page, meta);
    page.raw("</main>\n</body>\n</html>\n");
    Ok(page.finish())
}

/// The three counts of the headline, and what was scanned.
fn summary(page: &mut Markup, view: &View<'_>) {
    page.raw("<section id=\"summary\">\n<h2>Summary</h2>\n<div class=\"counts\">\n");
    let headline = view.headline;
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

    page.open_class("p", "note");
    page.raw("These three numbers count the findings that name a company");
    if !view.counted_categories.is_empty() {
        page.raw(" in the categories ");
        page.text(&list_words(&view.counted_categories));
    }
    page.raw(
        ". Every other finding, such as crash reporting or an update feed, is listed below \
         and counted in none of them. There is no score.",
    );
    page.close();
    page.raw("\n<ul class=\"totals\">\n");
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
    page.raw("</ul>\n</section>\n");
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

/// What a grade, a confidence and a party mean.
fn reading(page: &mut Markup, view: &View<'_>) {
    page.raw(
        "<section id=\"reading\">\n<h2>How to read this report</h2>\n\
         <p>Each finding is a graded fact about what an app's files hold. The grade says what \
         kind of evidence there is, and a finding takes the highest grade its evidence \
         reaches. No finding says what an app or a company intends.</p>\n\
         <div class=\"scroll\">\n<table class=\"ladder\">\n\
         <thead><tr><th scope=\"col\">Grade</th><th scope=\"col\">In a word</th>\
         <th scope=\"col\">What it shows</th></tr></thead>\n<tbody>\n",
    );
    let access = if view.has_access { &words::ACCESS_LADDER[..] } else { &[] };
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
         </dl>\n</section>\n",
    );
}

fn grade_badge(page: &mut Markup, grade: Grade) {
    page.classed("span", words::grade_class(grade), words::grade_name(grade));
}

/// The findings: by company, then the ones that name no company.
fn findings(page: &mut Markup, view: &View<'_>, evidence: &EvidenceSet) {
    page.raw("<section id=\"findings\">\n<h2>Findings by company</h2>\n");
    if view.claims == 0 {
        page.raw(
            "<p class=\"none\">No scanned app matched a rule. That does not show the apps hold \
             no third-party code: the scanner recognises only what its rule pack describes. \
             See <a href=\"#limits\">the limits</a>.</p>\n",
        );
    } else {
        page.raw(
            "<p>Companies with a finding that counts in the summary come first, then the \
             others, each in alphabetical order.</p>\n",
        );
    }
    for company in &view.companies {
        company_block(page, view, company, evidence);
    }
    if !view.unnamed.is_empty() {
        page.raw(
            "<section class=\"company\">\n<h3>No company named</h3>\n\
             <p class=\"meta\">Components, and hosts the rule pack lists under no company. \
             They are shown for completeness and counted nowhere.</p>\n",
        );
        for group in &view.unnamed {
            app_block(page, view, group, evidence);
        }
        page.raw("</section>\n");
    }
    page.raw("</section>\n");
}

fn company_block(
    page: &mut Markup,
    view: &View<'_>,
    company: &Company<'_>,
    evidence: &EvidenceSet,
) {
    page.raw("<section class=\"company\">\n");
    page.open("h3", &[]);
    page.text(&company.entity.name);
    page.raw(" ");
    if company.counted {
        page.classed("span", "tag counted", "counted in the summary");
    } else {
        page.classed("span", "tag", "not counted");
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
        app_block(page, view, group, evidence);
    }
    page.raw("</section>\n");
}

/// One app under a company: who it is, who publishes it, and its findings.
fn app_block(page: &mut Markup, view: &View<'_>, group: &AppFindings<'_>, evidence: &EvidenceSet) {
    let Some(app) = view.apps.get(group.app) else { return };
    page.open_class("div", "app");
    page.raw("\n");
    page.element("h4", &[], app.title());
    page.raw("\n");
    app_line(page, app.subject);
    if let Some(first) = group.findings.first() {
        publisher(page, first);
    }
    for finding in &group.findings {
        finding_block(page, finding, evidence);
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
    let digest = subject.digest.to_string();
    match digest.split_once(':') {
        Some((scheme, hex)) => page.element("code", &[], &format!("{scheme}:{}…", short(hex))),
        None => page.raw("none, the file was not read"),
    }
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

/// One finding: what it is about, its grade, and the evidence behind it.
fn finding_block(page: &mut Markup, finding: &Finding<'_>, evidence: &EvidenceSet) {
    let claim = finding.claim;
    page.open(
        "div",
        &[("class", Value::Fixed("finding")), ("id", Value::Anchor("f-", claim.id.digest()))],
    );
    page.raw("\n");
    page.open("h5", &[]);
    page.text(&claim.object.name);
    page.raw(" ");
    page.classed("span", "tag", &finding.category.name);
    page.close();
    page.raw("\n");

    page.open_class("p", "graded");
    grade_badge(page, claim.grade);
    page.raw(" ");
    page.raw(words::grade_meaning(claim.grade));
    page.close();
    page.raw("\n<dl class=\"facts\">\n");

    match (claim.object.kind, finding.company) {
        (ObjectKind::Sdk, Some(_)) => fact(page, "Rule", |page| code(page, &claim.object.id)),
        (ObjectKind::Sdk, None) => fact(page, "Kind", |page| {
            page.raw("Component: a library with no network side of its own. Rule ");
            code(page, &claim.object.id);
        }),
        (ObjectKind::Host, Some(_)) => {
            fact(page, "Kind", |page| page.raw("A host the app's own files declare."));
        }
        (ObjectKind::Host, None) => fact(page, "Kind", |page| {
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
            None => page.text(note),
        });
    }
    page.raw("</dl>\n");

    page.open_class("p", "evidence-head");
    page.raw("Evidence: ");
    page.text(&plural(claim.evidence.len() as u64, "record", "records"));
    page.close();
    page.raw("\n<ul class=\"evidence\">\n");
    for id in &claim.evidence {
        if let Some(Record::Edge(edge)) = evidence.get(id) {
            evidence_item(page, id, edge);
        }
    }
    page.raw("</ul>\n");
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
        page.text(&finding.category.name);
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
fn coverage(page: &mut Markup, view: &View<'_>, meta: &ReportMeta) {
    page.raw(
        "<section id=\"coverage\">\n<h2>What was scanned, and what was not</h2>\n\
         <p>Nothing found is not the same as not looked at. This section says where the scan \
         looked, lists every app it read, and lists everything it set aside or could not \
         interpret.</p>\n",
    );
    scope(page, meta);
    apps_scanned(page, view);
    set_aside(page, view);
    page.raw("</section>\n");
}

/// Where the scan looked for apps, and where it deliberately did not.
///
/// The scan states this when it runs. It is not evidence about any app, so
/// the saved evidence does not hold it, and a page rendered from saved
/// evidence says so.
fn scope(page: &mut Markup, meta: &ReportMeta) {
    page.raw("<h3>Where the scan looked</h3>\n");
    page.open_class("p", "scope");
    match &meta.scope {
        Some(scope) => {
            page.raw("This scan covered ");
            page.text(scope);
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
        page.raw("</tbody>\n</table>\n</div>\n");
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
        page.raw("</tbody>\n</table>\n</div>\n");
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
fn records(page: &mut Markup, view: &View<'_>) -> Result<(), RenderError> {
    page.raw(
        "<section id=\"records\">\n<h2>Evidence records</h2>\n\
         <p>Every record the scan produced, exactly as it is stored. The findings above link \
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
    page.raw("</section>\n");
    Ok(())
}

/// What made the report: the scanner and the rule pack.
fn about(page: &mut Markup, meta: &ReportMeta) {
    page.raw("<section id=\"about\">\n<h2>About this report</h2>\n<dl class=\"facts\">\n");
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
        "</dl>\n<p>The same evidence and the same rule pack always give this same file, byte \
         for byte. It holds no date, no device name and no path outside an app.</p>\n\
         </section>\n",
    );
}

#[cfg(test)]
mod tests;
