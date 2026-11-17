//! The properties of the HTML report: honest, inert, deterministic, and
//! plain about what it cannot see.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use std::format;

use xs_model::matcher::{Boundary, MatcherKind};
use xs_model::pack::{Category, Entity, Layer, LoadedLayer, Rule, Token};
use xs_model::record::{
    ArtifactRecord, Collector, CoverageReason, CoverageRecord, CoverageStatus, Facts, ObjectRef,
    Platform, Proof, Region, Scope, SubjectKind, V1, declared,
};
use xs_model::report::{ScanScope, Scanner};
use xs_model::{RelPath, Sha256Digest, SubjectDigest};

use super::*;
use crate::testkit::{self, Element};

/// Google's Team ID in the test pack.
const GOOGLE_TEAM: &str = "EQHXZ8M8AV";

/// A pack with a company in a counted category whose name needs escaping,
/// a company that owns another, and a component.
fn pack() -> Pack {
    Pack::new(vec![LoadedLayer { layer: layer(), sha256: Sha256Digest::of(b"pack") }]).unwrap()
}

/// The layer of [`pack`].
fn layer() -> Layer {
    let rule = |id: &str, name: &str, entity: Option<&str>, category: &str, notes: &[&str]| Rule {
        id: id.into(),
        name: name.into(),
        entity: entity.map(Into::into),
        category: category.into(),
        sources: vec![format!("https://docs.example/{name}")],
        notes: notes.iter().map(|&note| note.into()).collect(),
        matchers: BTreeMap::from([(
            MatcherKind::AppleFramework,
            vec![Token { lit: format!("{name}.framework"), at: Boundary::Exact }],
        )]),
        min_distinct: BTreeMap::new(),
    };
    let category = |id: &str, name: &str, headline: bool| Category {
        id: id.into(),
        name: name.into(),
        headline,
    };
    let entity =
        |id: &str, name: &str, parent: Option<&str>, team: &[&str], domains: &[&str]| Entity {
            id: id.into(),
            name: name.into(),
            parent: parent.map(Into::into),
            website: format!("https://{id}.example/"),
            team_ids: team.iter().map(|&team| team.into()).collect(),
            app_ids: vec![],
            domains: domains.iter().map(|&domain| domain.into()).collect(),
            sources: vec![format!("https://{id}.example/terms")],
        };
    Layer {
        format: V1,
        fixes: xs_model::fix::Fixes::default(),
        layer: "core".into(),
        version: 7,
        license: "CC-BY-4.0".into(),
        categories: vec![
            category("analytics", "Analytics", true),
            category("session_replay", "Session replay", true),
            category("crash_reporting", "Crash reporting", false),
            category("component", "Component", false),
            category("update_feed", "Update feed", false),
        ],
        entities: vec![
            entity("acme", "Acme <Analytics> & \"Sons\"", None, &[], &["acme.com"]),
            entity("firebase", "Firebase", Some("google"), &[], &["firebaseio.com"]),
            entity("google", "Google LLC", None, &[GOOGLE_TEAM], &["google.com"]),
        ],
        rules: vec![
            rule("sdk/acme-analytics", "AcmeAnalytics", Some("acme"), "analytics", &[]),
            rule(
                "sdk/crashlytics",
                "Crashlytics",
                Some("firebase"),
                "crash_reporting",
                &["retired:2025-03-31"],
            ),
            rule("sdk/sparkle", "Sparkle", None, "component", &[]),
        ],
    }
}

fn meta(pack: &Pack) -> ReportMeta {
    ReportMeta {
        scanner: Scanner { name: "exposure".into(), version: "0.1.0".into() },
        packs: pack.refs(),
        scope: Some(ScanScope::Given),
    }
}

fn subject(platform: Platform, id: &str, seed: u8) -> Subject {
    let digest = Sha256Digest::of(&[seed]);
    Subject {
        kind: SubjectKind::App,
        platform,
        id: id.into(),
        version: Some("1.0".into()),
        digest: match platform {
            Platform::Macos | Platform::Chromium => SubjectDigest::Bundle(digest),
            Platform::Android | Platform::Firefox => SubjectDigest::Sha256(digest),
        },
    }
}

fn artifact(subject: &Subject, name: &str, team_id: Option<&str>) -> Record {
    Record::Artifact(ArtifactRecord {
        v: V1,
        collector: Collector::MacosBundle,
        subject: subject.clone(),
        facts: Facts {
            name: Some(name.into()),
            team_id: team_id.map(Into::into),
            files_scanned: 41,
            bytes_scanned: 68_219_904,
            sandbox: None,
            publisher: None,
            homepage: None,
            browser: None,
        },
    })
}

/// An edge from `subject` to the SDK of `rule`.
fn sdk(subject: &Subject, rule: &str, matcher: MatcherKind, example: Option<&str>) -> Record {
    Record::Edge(EdgeRecord {
        v: V1,
        collector: Collector::MacosBundle,
        subject: subject.clone(),
        edge: EdgeType::Channel,
        grade: matcher.grade(),
        object: ObjectRef { kind: ObjectKind::Sdk, id: rule.into() },
        rule: rule.into(),
        proof: Proof {
            matcher,
            token: "Token.framework".into(),
            count: 2,
            example: example.map(Into::into),
            location: RelPath::new("Contents/Frameworks").unwrap(),
            region: Region::DirEntries,
            scope: Scope::Dependency,
            max_sdk: None,
        },
    })
}

/// An edge from `subject` to the host its update feed is on.
fn feed(subject: &Subject, host: &str) -> Record {
    let Record::Edge(mut edge) = sdk(subject, "sdk/sparkle", MatcherKind::UpdateFeed, None) else {
        unreachable!()
    };
    edge.object = ObjectRef { kind: ObjectKind::Host, id: host.into() };
    edge.rule = declared::UPDATE_FEED.into();
    edge.proof.token = "SUFeedURL".into();
    edge.proof.location = RelPath::new("Contents/Info.plist").unwrap();
    edge.proof.region = Region::PropertyList;
    edge.proof.scope = Scope::AppCode;
    Record::Edge(edge)
}

fn gap(subject: &Subject, reason: CoverageReason, location: &str, bytes: Option<u64>) -> Record {
    Record::Coverage(CoverageRecord {
        v: V1,
        collector: Collector::MacosBundle,
        subject: subject.clone(),
        status: CoverageStatus::Skipped,
        reason,
        location: Some(RelPath::new(location).unwrap()),
        bytes,
        count: 1,
    })
}

fn set(records: impl IntoIterator<Item = Record>) -> EvidenceSet {
    let mut set = EvidenceSet::new();
    for record in records {
        set.insert(record).unwrap();
    }
    set
}

/// A scan of four apps:
///
/// * *Notes*, by nobody the pack lists: Acme's analytics SDK by two kinds of
///   witness on two rungs, the Sparkle component, an update feed on its own
///   domain and one on Google's, and two files that were set aside.
/// * *Mail*, signed by Google: Crashlytics, which Firebase operates.
/// * *Droid*, an Android package: Acme's analytics SDK.
/// * *Clean*: nothing.
fn evidence() -> EvidenceSet {
    let notes = subject(Platform::Macos, "org.example.notes", 1);
    let mail = subject(Platform::Macos, "com.google.mail", 2);
    let droid = subject(Platform::Android, "org.example.droid", 3);
    let clean = subject(Platform::Macos, "org.example.clean", 4);
    set([
        artifact(&notes, "Notes", None),
        sdk(&notes, "sdk/acme-analytics", MatcherKind::AppleFramework, Some("Acme.framework")),
        sdk(&notes, "sdk/acme-analytics", MatcherKind::PrivacyManifest, None),
        sdk(&notes, "sdk/sparkle", MatcherKind::AppleFramework, Some("Sparkle.framework")),
        feed(&notes, "updates.example.org"),
        feed(&notes, "dl.google.com"),
        gap(&notes, CoverageReason::EncryptedBinary, "Wrapper/X.app/X", None),
        gap(&notes, CoverageReason::OverBudget, "Contents/MacOS/Huge", Some(2_147_483_649)),
        artifact(&mail, "Mail", Some(GOOGLE_TEAM)),
        sdk(&mail, "sdk/crashlytics", MatcherKind::MachoObjcClass, Some("FIRCrashlytics")),
        artifact(&droid, "Droid", None),
        sdk(&droid, "sdk/acme-analytics", MatcherKind::AndroidClassPrefix, Some("com.acme.A")),
        artifact(&clean, "Clean", None),
    ])
}

fn claims(evidence: &EvidenceSet, pack: &Pack) -> Vec<Claim> {
    xs_derive::derive(evidence, pack).unwrap()
}

/// Renders and reads the report back. It must read as a strict reader
/// demands, and be inert.
fn render(claims: &[Claim], evidence: &EvidenceSet, meta: &ReportMeta, pack: &Pack) -> Element {
    let document = html(claims, evidence, meta, pack).unwrap();
    let root = testkit::parse(&document).unwrap();
    testkit::check_inert(&root, CONTENT_SECURITY_POLICY).unwrap();
    root
}

fn report() -> Element {
    let (pack, evidence) = (pack(), evidence());
    render(&claims(&evidence, &pack), &evidence, &meta(&pack), &pack)
}

fn anchor(prefix: &str, digest: &Sha256Digest) -> String {
    format!("{prefix}{digest}")
}

fn section<'a>(root: &'a Element, id: &str) -> &'a Element {
    root.by_id(id).unwrap_or_else(|| panic!("no section `{id}`"))
}

/// The finding about `object` in the app `app`.
fn finding<'a>(root: &'a Element, claims: &[Claim], app: &str, object: &str) -> &'a Element {
    let claim = claims
        .iter()
        .find(|claim| claim.subject.id == app && claim.object.id == object)
        .unwrap_or_else(|| panic!("no claim that {app} has {object}"));
    root.by_id(&anchor("f-", claim.id.digest())).unwrap()
}

/// Property 6, "honest": every finding shows its grade, its confidence and
/// the raw record behind it.
#[test]
fn every_finding_shows_its_grade_its_confidence_and_its_raw_records() {
    let (pack, evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    assert_eq!(claims.len(), 6);

    for claim in &claims {
        let shown = root.by_id(&anchor("f-", claim.id.digest())).expect("the finding is shown");
        assert!(shown.has_class("finding"));

        // Its grade, as the badge that leads the finding, and every rung.
        let graded = shown.descendants().into_iter().find(|e| e.has_class("graded")).unwrap();
        let badge = graded.named("span")[0];
        assert!(badge.has_class("grade"));
        assert_eq!(badge.text(), words::grade_name(claim.grade));
        assert!(graded.text().contains(words::grade_meaning(claim.grade)));
        let text = shown.text();
        for &rung in &claim.rungs {
            assert!(text.contains(words::grade_name(rung)));
        }
        // Its confidence, and how many kinds of witness agree.
        assert!(text.contains(&format!("{}: ", words::confidence_name(claim.confidence))));
        assert!(text.contains(&format!("{} ", claim.witnesses)));

        // Every record it cites: a link, and behind the link the record.
        let links: Vec<&str> =
            shown.named("a").into_iter().filter_map(|link| link.attr("href")).collect();
        assert_eq!(links.len(), claim.evidence.len());
        for id in &claim.evidence {
            let target = anchor("r-", id.digest());
            assert!(links.contains(&format!("#{target}").as_str()));
            let record = root.by_id(&target).expect("the cited record is in the document");
            assert!(record.has_class("record"));
            assert!(record.text().contains(&id.to_string()));
            // The raw record: the stored text, which hashes to the id.
            let raw = record.named("pre")[0].text();
            assert_eq!(raw, canon::to_string(evidence.get(id).unwrap()).unwrap());
            let parsed: Record = serde_json::from_str(&raw).unwrap();
            assert_eq!(parsed.id().unwrap(), *id);
        }
    }

    // Nothing is shown that is not a claim, and no finding twice.
    let shown = root.descendants().into_iter().filter(|e| e.has_class("finding")).count();
    assert_eq!(shown, claims.len());
}

/// The document carries the whole evidence set, not only what is cited, and
/// each record under its own id.
#[test]
fn every_record_of_the_evidence_is_in_the_document_as_stored() {
    let (pack, evidence) = (pack(), evidence());
    let root = render(&claims(&evidence, &pack), &evidence, &meta(&pack), &pack);
    let records: Vec<&Element> = section(&root, "records")
        .descendants()
        .into_iter()
        .filter(|e| e.has_class("record"))
        .collect();
    assert_eq!(records.len(), evidence.len());

    let mut read_back = EvidenceSet::new();
    for shown in records {
        let record: Record = serde_json::from_str(&shown.named("pre")[0].text()).unwrap();
        let id = read_back.insert(record).unwrap();
        assert_eq!(shown.attr("id"), Some(anchor("r-", id.digest()).as_str()));
    }
    assert_eq!(read_back, evidence);
}

/// Design report, section 7 property 6: delete one record and the renderer
/// must fail.
#[test]
fn deleting_a_cited_record_fails_the_render() {
    let (pack, mut evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let cited = claims[0].evidence[0];
    evidence.remove(&cited).unwrap();
    assert_eq!(
        html(&claims, &evidence, &meta(&pack), &pack),
        Err(RenderError::MissingEvidence {
            claim: claims[0].id.to_string(),
            record: cited.to_string()
        })
    );
}

/// The record that says who signed an app is evidence too: the party of a
/// finding rests on it, so the publisher line links to it.
#[test]
fn a_publisher_known_by_its_signature_links_to_the_record_that_names_it() {
    let (pack, evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    let crashlytics = claims.iter().find(|claim| claim.object.id == "sdk/crashlytics").unwrap();
    let cited = crashlytics.vendor.as_ref().unwrap().evidence[0];

    let publisher = section(&root, "findings")
        .descendants()
        .into_iter()
        .find(|e| e.has_class("publisher") && e.text().contains("Google LLC"))
        .unwrap();
    assert!(publisher.text().contains("by the Apple Team ID its code signature names"));
    assert!(publisher.text().contains("read, not verified"));
    let link = publisher.named("a")[0].attr("href").unwrap();
    assert_eq!(link, format!("#{}", anchor("r-", cited.digest())));
    assert!(root.by_id(&link[1..]).unwrap().text().contains(GOOGLE_TEAM));
}

/// The strings a hostile app controls, and those the report file controls.
struct Strings {
    name: &'static str,
    app_id: &'static str,
    version: &'static str,
    team_id: &'static str,
    example: &'static str,
    location: &'static str,
    scanner: &'static str,
    scanner_version: &'static str,
    sdk_name: &'static str,
    note: &'static str,
}

const BENIGN: Strings = Strings {
    name: "Notes",
    // Like the hostile one, an app id that spells no domain.
    app_id: "Notes",
    version: "1.0",
    team_id: "ABCDE12345",
    example: "com.acme.Analytics",
    location: "Contents/MacOS/Notes",
    scanner: "exposure",
    scanner_version: "0.1.0",
    sdk_name: "AcmeAnalytics",
    note: "a remark",
};

/// Markup in every place a value is shown: element and attribute breakouts,
/// a closing tag for each element a value sits in, references, and an
/// attempt at each kind of address.
const HOSTILE: Strings = Strings {
    name: "<script>alert('name')</script>",
    app_id: "\"><img src=x onerror=alert(1)>.<svg/onload=alert(2)>",
    version: "</p></div><iframe src=//evil.example>",
    team_id: "<b onclick=alert(3)>&lt;",
    example: "io.sentry.</code></dd><script src=https://evil.example/x.js></script>&amp;",
    location: "Contents/</pre><style>*{display:none}</style>/<a href=javascript:alert(4)>x",
    scanner: "</title><meta http-equiv=refresh content=0;url=https://evil.example>",
    scanner_version: "' onmouseover='alert(5)' x=\"",
    sdk_name: "</h5><form action=https://evil.example><input name=q>",
    note: "<link rel=stylesheet href=https://evil.example/x.css><!-- --> &#60;script&#62;",
};

/// One app that ships Acme's SDK, with `strings` wherever a value can go.
fn render_with(strings: &Strings) -> (Element, String) {
    let pack = pack();
    let mut app = subject(Platform::Macos, strings.app_id, 9);
    app.version = Some(strings.version.into());
    let Record::Edge(mut edge) =
        sdk(&app, "sdk/acme-analytics", MatcherKind::MachoObjcClass, Some(strings.example))
    else {
        unreachable!()
    };
    edge.proof.location = RelPath::new(strings.location).unwrap();
    let evidence = set([
        artifact(&app, strings.name, Some(strings.team_id)),
        Record::Edge(edge),
        gap(&app, CoverageReason::ParseError, strings.location, None),
    ]);
    let mut claims = claims(&evidence, &pack);
    // What a claim says comes from the signed pack. The renderer does not
    // lean on that either.
    claims[0].object.name = strings.sdk_name.into();
    claims[0].notes = vec![strings.note.into()];
    let meta = ReportMeta {
        scanner: Scanner { name: strings.scanner.into(), version: strings.scanner_version.into() },
        packs: pack.refs(),
        scope: Some(ScanScope::Given),
    };
    let document = html(&claims, &evidence, &meta, &pack).unwrap();
    (render(&claims, &evidence, &meta, &pack), document)
}

/// Build plan, task 11: the markup-injection fixture renders inert.
#[test]
fn hostile_names_render_as_text_and_add_nothing_to_the_document() {
    let (hostile, document) = render_with(&HOSTILE);
    let (benign, _) = render_with(&BENIGN);

    // Each value is on the page, character for character, as text.
    let text = hostile.text();
    for value in [
        HOSTILE.name,
        HOSTILE.app_id,
        HOSTILE.version,
        HOSTILE.team_id,
        HOSTILE.example,
        HOSTILE.location,
        HOSTILE.scanner,
        HOSTILE.scanner_version,
        HOSTILE.sdk_name,
        HOSTILE.note,
    ] {
        assert!(text.contains(value), "not shown as text: {value}");
    }

    // And as nothing else: the hostile report is made of exactly the
    // elements of the benign one, in the same order, with the same
    // attributes. The only values that differ are the anchors, which are
    // hashes of the records.
    let shape = |root: &Element| -> Vec<(String, Vec<String>)> {
        root.descendants()
            .into_iter()
            .map(|element| {
                let attrs = element
                    .attrs
                    .iter()
                    .map(|(name, value)| match name.as_str() {
                        "id" | "href" if value.len() > 64 => name.clone(),
                        _ => format!("{name}={value}"),
                    })
                    .collect();
                (element.name.clone(), attrs)
            })
            .collect()
    };
    assert_eq!(shape(&hostile), shape(&benign));

    // No value reached an attribute: every one is fixed text, or an anchor
    // of lowercase hex.
    for element in hostile.descendants() {
        for (name, value) in &element.attrs {
            let plain = value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b" -#=;'/,.+".contains(&byte));
            assert!(plain, "{name}=\"{value}\" on <{}>", element.name);
        }
    }
    // The source holds no tag a value brought in.
    for tag in ["<script", "<img", "<iframe", "<svg", "<form", "<input", "<link", "<b ", "<!--"] {
        assert!(!document.contains(tag), "{tag}");
    }
    assert_eq!(document.matches("<style>").count(), 1);
    assert_eq!(document.matches("<meta ").count(), 5);
}

/// A report file names the scanner that made it, and nothing checks that
/// name. Characters that would reorder the page are replaced.
#[test]
fn characters_a_record_may_not_hold_are_replaced_wherever_they_come_from() {
    let (pack, evidence) = (pack(), evidence());
    let meta = ReportMeta {
        scanner: Scanner { name: "exposure\u{202e}erusopxe".into(), version: "1\u{0}\n2".into() },
        packs: pack.refs(),
        scope: None,
    };
    let root = render(&claims(&evidence, &pack), &evidence, &meta, &pack);
    let about = section(&root, "about").text();
    assert!(about.contains("exposure\u{fffd}erusopxe 1\u{fffd}\u{fffd}2"), "{about}");
}

/// Base64, as a content security policy writes a hash.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().fold(0u32, |word, &byte| (word << 8) | u32::from(byte))
            << (8 * (3 - chunk.len()));
        for position in 0..4 {
            if position <= chunk.len() {
                let index = (word >> (18 - 6 * position)) & 63;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The policy admits the stylesheet by its hash, so the hash in the policy
/// must be that of the stylesheet in the document.
#[test]
fn the_policy_admits_the_stylesheet_in_the_document_and_nothing_else() {
    // RFC 4648, section 10.
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    assert_eq!(base64(b"fooba"), "Zm9vYmE=");
    assert_eq!(base64(b"foob"), "Zm9vYg==");

    let root = report();
    let style = root.named("style")[0].text();
    assert_eq!(style, include_str!("report.css"));
    let source = format!("'sha256-{}'", base64(Sha256Digest::of(style.as_bytes()).as_bytes()));
    assert_eq!(
        CONTENT_SECURITY_POLICY,
        format!("default-src 'none'; style-src {source}; base-uri 'none'; form-action 'none'"),
        "the stylesheet changed: put {source} in `style_source!`"
    );
    // No keyword that would let anything else in.
    for loose in ["unsafe", "*", "data:", "http", "self"] {
        assert!(!CONTENT_SECURITY_POLICY.contains(loose), "{loose}");
    }
}

/// Design report, section 7, "report safety": the HTML references no remote
/// resource. The pack's sources and websites are addresses; none is shown.
#[test]
fn the_document_names_no_address_and_holds_no_script() {
    let (pack, evidence) = (pack(), evidence());
    let document = html(&claims(&evidence, &pack), &evidence, &meta(&pack), &pack).unwrap();
    for address in [
        "://",
        "//",
        "http:",
        "https:",
        "javascript:",
        "data:",
        "<script",
        " src=",
        "@import",
        "url(",
    ] {
        assert!(!document.contains(address), "{address}");
    }
    let root = testkit::parse(&document).unwrap();
    for link in root.named("a") {
        let target = link.attr("href").unwrap().strip_prefix('#').unwrap();
        assert!(root.by_id(target).is_some(), "the link to #{target} leads nowhere");
    }
}

/// Property 3, "deterministic": the same evidence, rule pack and scan scope
/// give the same bytes, and the order the claims come in does not reach the
/// document.
#[test]
fn the_same_evidence_and_pack_give_the_same_bytes() {
    let (pack, evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let meta = meta(&pack);
    let first = html(&claims, &evidence, &meta, &pack).unwrap();
    assert_eq!(html(&claims, &evidence, &meta, &pack).unwrap(), first);

    let mut reversed = claims.clone();
    reversed.reverse();
    assert_eq!(html(&reversed, &evidence, &meta, &pack).unwrap(), first);
    let mut rotated = claims;
    rotated.rotate_left(2);
    assert_eq!(html(&rotated, &evidence, &meta, &pack).unwrap(), first);

    // Nothing in it could disturb a terminal or reorder the page.
    assert!(first.chars().all(|c| c == '\n' || xs_model::text::is_storable(c)));
}

#[test]
fn findings_are_grouped_by_company_with_the_counted_ones_first() {
    let root = report();
    let findings = section(&root, "findings");
    let headings: Vec<String> = findings.named("h3").into_iter().map(Element::text).collect();
    assert_eq!(
        headings,
        [
            // Counted: analytics. Its name is the pack's, escaped.
            "Acme <Analytics> & \"Sons\" counted in the summary",
            // Not counted: crash reporting and an update feed.
            "Google LLC not in the counted categories",
            "No company named",
        ]
    );

    let companies: Vec<&Element> =
        findings.descendants().into_iter().filter(|e| e.has_class("company")).collect();
    // Acme: two apps, by name. Each app is named, with what tells it apart.
    let apps: Vec<String> = companies[0].named("h4").into_iter().map(Element::text).collect();
    assert_eq!(apps, ["Droid", "Notes"]);
    let line = companies[0].descendants().into_iter().find(|e| e.has_class("meta")).unwrap().text();
    assert_eq!(line, "2 apps · 2 findings · strongest grade contains");
    assert!(
        companies[0].text().contains("org.example.droid · version 1.0 · Android · build sha256:")
    );
    assert!(companies[0].text().contains("org.example.notes · version 1.0 · macOS · build bd1:"));
    // Google: its own app, and the update feed of someone else's.
    let apps: Vec<String> = companies[1].named("h4").into_iter().map(Element::text).collect();
    assert_eq!(apps, ["Mail", "Notes"]);
}

#[test]
fn a_finding_says_who_operates_it_whose_party_it_is_and_whether_it_counts() {
    let (pack, evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    let text = |app: &str, object: &str| finding(&root, &claims, app, object).text();

    let acme = text("org.example.notes", "sdk/acme-analytics");
    assert!(acme.starts_with("\nAcmeAnalytics Analytics\n"), "{acme}");
    assert!(acme.contains("Third party: Acme <Analytics> & \"Sons\" is not this app's publisher."));
    assert!(acme.contains("In the summaryCounted."));
    assert!(acme.contains("2 independent kinds agree."));
    // Both rungs that have evidence are shown, and the finding takes the higher.
    assert!(acme.contains("Grades with evidencedeclares contains"));
    assert!(acme.contains("Evidence: 2 records"));
    assert!(acme.contains("A framework folder"));
    assert!(acme.contains("MarkerToken.framework"));
    assert!(
        acme.contains("Found inContents/Frameworks, in the names of the entries of the folder")
    );
    assert!(acme.contains("ExampleAcme.framework"));
    assert!(acme.contains("Count2 matches"));
    assert!(acme.contains("Kind of filea library shipped with the app"));

    let crashlytics = text("com.google.mail", "sdk/crashlytics");
    assert!(crashlytics.contains("Operated byFirebase, which Google LLC owns."));
    assert!(crashlytics.contains("First party: Google LLC publishes this app."));
    assert!(
        crashlytics.contains("Not counted: Crash reporting is not one of the counted categories.")
    );
    assert!(crashlytics.contains("1 kind."));
    assert!(crashlytics.contains(
        "The service behind this code was retired on 2025-03-31. An app that still ships the \
         code does not show a live flow."
    ));

    let google_feed = text("org.example.notes", "dl.google.com");
    assert!(google_feed.contains("A host the app's own files declare."));
    assert!(google_feed.contains("Third party: Google LLC is not this app's publisher."));
    assert!(google_feed.contains(words::grade_meaning(Grade::Declares)));

    // The two that name nobody: a component and a host under no listed
    // domain. Neither is counted, and neither is put under a company.
    let sparkle = text("org.example.notes", "sdk/sparkle");
    assert!(sparkle.contains("Component: a library with no network side of its own."));
    assert!(sparkle.contains("Not stated: the finding names no company."));
    assert!(sparkle.contains("Not counted: the finding names no company."));
    let own_feed = text("org.example.notes", "updates.example.org");
    assert!(own_feed.contains("Unmapped host: the rule pack lists it under no company."));
    assert!(
        own_feed.contains("First party: the host is under the domain the app's own id spells.")
    );
    let unnamed = section(&root, "findings")
        .descendants()
        .into_iter()
        .rfind(|e| e.has_class("company"))
        .unwrap();
    assert_eq!(unnamed.descendants().into_iter().filter(|e| e.has_class("finding")).count(), 2);

    // Who publishes Notes: nobody the pack lists.
    assert!(root.text().contains(
        "Publisher: not a company the rule pack lists. Its app id spells the domain \
         example.org, which is what the app says of itself."
    ));
}

/// The entries of the summary's list of what was found: the text of each
/// paragraph of each entry.
fn found(root: &Element) -> Vec<Vec<String>> {
    let list = section(root, "summary")
        .named("ul")
        .into_iter()
        .find(|list| list.has_class("found"))
        .expect("the summary lists what was found");
    list.named("li")
        .into_iter()
        .map(|entry| entry.named("p").into_iter().map(Element::text).collect())
        .collect()
}

/// The three headline counts as the summary shows them.
fn counts(root: &Element) -> Vec<String> {
    section(root, "summary")
        .descendants()
        .into_iter()
        .filter(|e| e.has_class("count"))
        .map(|count| format!("{} {}", count.named("p")[0].text(), count.named("p")[1].text()))
        .collect()
}

/// The summary leads with what was found, whether or not it counts: the
/// fixture has six findings in three of its four apps, about five things.
/// Each is stated once, as a graded fact with the number of apps, what is
/// in the most apps first and then by name.
#[test]
fn the_summary_leads_with_everything_that_was_found() {
    let root = report();
    let summary = section(&root, "summary");
    let parts: Vec<String> = summary.named("h3").into_iter().map(Element::text).collect();
    assert_eq!(parts, ["What was found", "The three headline counts"]);
    let lead = summary.named("p")[0];
    assert!(lead.has_class("lead"));
    assert_eq!(lead.text(), "6 findings in 3 of 4 apps scanned.");

    assert_eq!(
        found(&root),
        [
            [
                "AcmeAnalytics Analytics",
                "Acme <Analytics> & \"Sons\"",
                "contains ships in 2 of 4 apps",
                "In Droid, Notes",
                "counted",
            ],
            // Outside the counted categories, and as plain as the one above.
            [
                "Crashlytics Crash reporting",
                "Google LLC",
                "contains ships in 1 of 4 apps",
                "In Mail",
                "not counted",
            ],
            [
                "dl.google.com Update feed",
                "Google LLC",
                "declares declared by 1 of 4 apps",
                "In Notes",
                "not counted",
            ],
            [
                "Sparkle Component",
                "No company named: a component, with no network side of its own.",
                "contains ships in 1 of 4 apps",
                "In Notes",
                "not counted",
            ],
            [
                "updates.example.org Update feed",
                "No company named: a host the rule pack lists under no company.",
                "declares declared by 1 of 4 apps",
                "In Notes",
                "not counted",
            ],
        ]
    );
    // The tag that says a thing is not counted is a tag of its own kind,
    // not the grey of a category.
    let tags =
        |class: &str| summary.descendants().into_iter().filter(|e| e.has_class(class)).count();
    assert_eq!((tags("counted"), tags("uncounted")), (1, 4));
}

/// Two apps of one entry that share a name are told apart in the entry: by
/// platform, then by version, then by the start of the build digest, as
/// the line under a finding shows it. A name that is alone in its entry
/// stays as it is, and every link still leads to that app's finding.
#[test]
fn apps_that_share_a_name_are_told_apart_in_a_summary_entry() {
    let pack = pack();
    let mac = |id: &str, seed: u8, version: &str| {
        let mut subject = subject(Platform::Macos, id, seed);
        subject.version = Some(version.into());
        subject
    };
    let first = mac("org.example.one", 1, "1.0");
    let android = subject(Platform::Android, "org.example.two", 2);
    let (third, fourth) = (mac("org.example.three", 3, "2.0"), mac("org.example.four", 4, "2.0"));
    let other = mac("org.example.other", 5, "1.0");
    let acme = |subject: &Subject, matcher| sdk(subject, "sdk/acme-analytics", matcher, None);
    let evidence = set([
        artifact(&first, "Skeleton", None),
        acme(&first, MatcherKind::AppleFramework),
        sdk(&first, "sdk/sparkle", MatcherKind::AppleFramework, None),
        artifact(&android, "Skeleton", None),
        acme(&android, MatcherKind::AndroidClassPrefix),
        artifact(&third, "Skeleton", None),
        acme(&third, MatcherKind::AppleFramework),
        artifact(&fourth, "Skeleton", None),
        acme(&fourth, MatcherKind::AppleFramework),
        artifact(&other, "Other", None),
        acme(&other, MatcherKind::AppleFramework),
    ]);
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);

    let entries = section(&root, "summary").named("ul")[0].named("li");
    let named = |entry: &Element| -> BTreeMap<String, String> {
        entry
            .named("a")
            .into_iter()
            .map(|link| (link.attr("href").unwrap().to_string(), link.text()))
            .collect()
    };
    let to = |subject: &Subject, object: &str| {
        let claim = claims.iter().find(|c| c.subject == *subject && c.object.id == object).unwrap();
        format!("#{}", anchor("f-", claim.id.digest()))
    };
    let build = |seed: u8| format!("bd1:{}…", &Sha256Digest::of(&[seed]).to_hex()[..12]);

    assert_eq!(entries[0].named("strong")[0].text(), "AcmeAnalytics");
    let expected: BTreeMap<String, String> = [
        (&other, String::from("Other")),
        (&android, String::from("Skeleton (Android)")),
        (&first, String::from("Skeleton (macOS, version 1.0)")),
        (&third, format!("Skeleton (macOS, version 2.0, build {})", build(3))),
        (&fourth, format!("Skeleton (macOS, version 2.0, build {})", build(4))),
    ]
    .into_iter()
    .map(|(subject, name)| (to(subject, "sdk/acme-analytics"), name))
    .collect();
    assert_eq!(named(entries[0]), expected);

    // Alone in its entry, the same app needs nothing added.
    assert_eq!(entries[1].named("strong")[0].text(), "Sparkle");
    assert_eq!(
        named(entries[1]),
        BTreeMap::from([(to(&first, "sdk/sparkle"), String::from("Skeleton"))])
    );
}

/// Each app named in the summary links to the finding about that thing in
/// that app, further down the page.
#[test]
fn each_app_in_the_summary_links_to_its_finding() {
    let (pack, evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    let list = section(&root, "summary").named("ul")[0];
    let links: Vec<(String, &str)> =
        list.named("a").into_iter().map(|link| (link.text(), link.attr("href").unwrap())).collect();
    let to = |app: &str, object: &str| {
        let claim = claims.iter().find(|c| c.subject.id == app && c.object.id == object).unwrap();
        format!("#{}", anchor("f-", claim.id.digest()))
    };
    let expected = [
        ("Droid", to("org.example.droid", "sdk/acme-analytics")),
        ("Notes", to("org.example.notes", "sdk/acme-analytics")),
        ("Mail", to("com.google.mail", "sdk/crashlytics")),
        ("Notes", to("org.example.notes", "dl.google.com")),
        ("Notes", to("org.example.notes", "sdk/sparkle")),
        ("Notes", to("org.example.notes", "updates.example.org")),
    ];
    assert_eq!(links.len(), expected.len());
    for ((name, href), (app, target)) in links.iter().zip(&expected) {
        assert_eq!((name.as_str(), *href), (*app, target.as_str()));
        let shown = root.by_id(href.strip_prefix('#').unwrap()).unwrap();
        assert!(shown.has_class("finding"));
    }
}

/// A thing two apps have at different grades is not stated at the higher
/// grade for both: each grade has its own count.
#[test]
fn a_thing_found_at_two_grades_is_counted_at_each() {
    let (pack, evidence) = (pack(), evidence());
    let mut claims = claims(&evidence, &pack);
    let droid = claims
        .iter_mut()
        .find(|c| c.subject.id == "org.example.droid" && c.object.id == "sdk/acme-analytics")
        .unwrap();
    droid.grade = Grade::Contacts;
    droid.rungs = vec![Grade::Contains, Grade::Contacts];
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    assert_eq!(found(&root)[0][2], "contacts contacted by 1 of 4 apps, ships in 1 of 4 apps");
}

/// Under what was found come the three headline counts, said to be counts
/// of the counted categories, and then the totals.
#[test]
fn the_summary_is_the_headline_of_the_claims_and_says_what_it_counts() {
    let (pack, evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    let summary = section(&root, "summary");
    let headline = xs_model::Headline::of(&claims);
    assert_eq!((headline.companies_contacts, headline.companies_contains), (0, 1));
    assert_eq!(headline.apps_third_party, 2);
    assert_eq!(
        counts(&root),
        [
            "0 companies with a recorded connection",
            "1 company whose code the scanned apps ship",
            "2 apps with a third-party channel",
        ]
    );
    let text = summary.text();
    assert!(text.contains("These three numbers do not count every finding."));
    assert!(text.contains("in the categories Analytics and Session replay."));
    assert!(text.contains("There is no score."));
    assert!(summary.descendants().into_iter().all(|e| !e.has_class("zero")));
    // What was found, then the counts, then the totals.
    let at = |part: &str| text.find(part).unwrap_or_else(|| panic!("no `{part}`"));
    let order = [
        at("What was found"),
        at("In Droid, Notes"),
        at("The three headline counts"),
        at("companies with a recorded connection"),
        at("13 evidence records"),
    ];
    assert!(order.is_sorted(), "{order:?}");
    let totals: Vec<String> = summary
        .named("ul")
        .into_iter()
        .find(|list| list.has_class("totals"))
        .unwrap()
        .named("li")
        .into_iter()
        .map(Element::text)
        .collect();
    assert_eq!(
        totals,
        [
            "4 apps scanned",
            "6 findings",
            "2 companies named",
            "2 coverage notes",
            "13 evidence records"
        ]
    );
}

/// What the summary says of three zero counts beside findings. It holds
/// whichever way the findings missed the counts.
const ZEROS: &str = "None of the findings above adds to these three counts, which is why they \
                     are zero. A count takes a finding that names a company in a counted \
                     category: a company is counted from grade contains up, and an app only for \
                     a third-party finding.";

/// The case the owner reported: findings, none of them in a counted
/// category. Three zeros must not read as "nothing found": the findings
/// lead, and the page says why the counts are zero.
#[test]
fn three_zeros_beside_findings_are_explained() {
    let pack = pack();
    let notes = subject(Platform::Macos, "org.example.notes", 1);
    let mail = subject(Platform::Macos, "com.google.mail", 2);
    let evidence = set([
        artifact(&notes, "Notes", None),
        sdk(&notes, "sdk/sparkle", MatcherKind::AppleFramework, None),
        artifact(&mail, "Mail", Some(GOOGLE_TEAM)),
        sdk(&mail, "sdk/crashlytics", MatcherKind::MachoObjcClass, None),
    ]);
    let claims = claims(&evidence, &pack);
    assert_eq!(xs_model::Headline::of(&claims), xs_model::Headline::default());
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    let summary = section(&root, "summary");
    assert_eq!(summary.named("p")[0].text(), "2 findings in 2 of 2 apps scanned.");
    let names: Vec<String> = found(&root).into_iter().map(|entry| entry[0].clone()).collect();
    assert_eq!(names, ["Crashlytics Crash reporting", "Sparkle Component"]);
    assert_eq!(counts(&root).len(), 3);
    let explained: Vec<String> = summary
        .descendants()
        .into_iter()
        .filter(|e| e.has_class("zero"))
        .map(Element::text)
        .collect();
    assert_eq!(explained, [ZEROS]);

    // A finding in a counted category that adds to no count: an app whose
    // publisher nothing identifies declares Acme's analytics. It is tagged
    // counted, the company is below `contains` and the finding is not
    // third party, so the counts stay zero, and the same sentence says
    // what they would have needed.
    let own = subject(Platform::Macos, "Notes", 3);
    let evidence = set([
        artifact(&own, "Acme Notes", None),
        sdk(&own, "sdk/acme-analytics", MatcherKind::PrivacyManifest, None),
    ]);
    let claims = xs_derive::derive(&evidence, &pack).unwrap();
    let [declared] = claims.as_slice() else { panic!("one claim: {claims:#?}") };
    assert!(declared.headline);
    assert_eq!((declared.grade, declared.party), (Grade::Declares, Party::Unknown));
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    assert_eq!(found(&root)[0][4], "counted");
    assert_eq!(
        counts(&root),
        [
            "0 companies with a recorded connection",
            "0 companies whose code the scanned apps ship",
            "0 apps with a third-party channel",
        ]
    );
    let zero = section(&root, "summary")
        .descendants()
        .into_iter()
        .find(|e| e.has_class("zero"))
        .expect("three zeros beside a counted finding are explained");
    assert_eq!(zero.text(), ZEROS);

    // With no finding there is nothing to explain, and no list: the plain
    // statement that nothing matched stands where the findings would lead.
    let nothing = render(&[], &set([artifact(&notes, "Notes", None)]), &meta(&pack), &pack);
    let summary = section(&nothing, "summary");
    assert!(summary.descendants().into_iter().all(|e| !e.has_class("zero")));
    assert!(summary.named("ul").into_iter().all(|list| !list.has_class("found")));
    assert!(summary.named("p")[0].text().starts_with("No scanned app matched a rule."));
}

/// The navigation is written from the sections that are on the page: one
/// link per section, in the order of the page.
#[test]
fn the_navigation_names_the_sections_of_the_page_in_order() {
    let root = report();
    let links: Vec<(String, String)> = root.named("nav")[0]
        .named("a")
        .into_iter()
        .map(|link| (link.text(), link.attr("href").unwrap().to_string()))
        .collect();
    let labels: Vec<&str> = links.iter().map(|(label, _)| label.as_str()).collect();
    assert_eq!(
        labels,
        [
            "Summary",
            "What you can do",
            "How to read it",
            "Findings",
            "Coverage",
            "Limits",
            "Records",
            "About"
        ]
    );
    let sections: Vec<String> = root
        .named("section")
        .into_iter()
        .filter_map(|section| section.attr("id"))
        .map(|id| format!("#{id}"))
        .collect();
    let targets: Vec<String> = links.into_iter().map(|(_, href)| href).collect();
    assert_eq!(targets, sections);
}

/// A section with nothing to say is not on the page, under no heading, and
/// the navigation does not link to it.
#[test]
fn a_section_with_nothing_under_it_is_left_out_of_the_page_and_the_navigation() {
    fn said(page: &mut Markup, _: &Input<'_>) -> Result<(), RenderError> {
        page.raw("<p>Something true.</p>\n");
        Ok(())
    }
    fn silent(_: &mut Markup, _: &Input<'_>) -> Result<(), RenderError> {
        Ok(())
    }
    let (pack, evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let view = View::new(&claims, &evidence, &pack).unwrap();
    let meta = meta(&pack);
    let sections = [
        section!("first", "First", "The first", said),
        section!("absent", "Absent", "Nothing to say", silent),
        section!("last", "Last", "The last", said),
    ];
    let input = Input { view: &view, evidence: &evidence, meta: &meta, pack: &pack };
    let page = document(&sections, &input).unwrap();
    let root = testkit::parse(&page).unwrap();
    testkit::check_inert(&root, CONTENT_SECURITY_POLICY).unwrap();

    let links: Vec<(String, &str)> = root.named("nav")[0]
        .named("a")
        .into_iter()
        .map(|link| (link.text(), link.attr("href").unwrap()))
        .collect();
    assert_eq!(links, [("First".to_string(), "#first"), ("Last".to_string(), "#last")]);
    let headings: Vec<String> = root.named("h2").into_iter().map(Element::text).collect();
    assert_eq!(headings, ["The first", "The last"]);
    assert!(root.by_id("absent").is_none());
    assert_eq!(section(&root, "last").text(), "\nThe last\nSomething true.\n");
}

/// The coverage section: what was read, and what was skipped and why.
#[test]
fn coverage_lists_every_app_and_everything_that_was_set_aside() {
    let root = report();
    let coverage = section(&root, "coverage");
    let tables = coverage.named("table");
    let rows = |table: &Element| -> Vec<Vec<String>> {
        table.named("tbody")[0]
            .named("tr")
            .into_iter()
            .map(|row| row.named("td").into_iter().map(Element::text).collect())
            .collect()
    };

    // Two builds of one app id differ in nothing but the build column.
    let mut scanned = rows(tables[0]);
    for row in &mut scanned {
        let build = row.remove(3);
        assert!(build.starts_with("bd1:") || build.starts_with("sha256:"), "{build}");
        assert!(build.ends_with('…') && build.chars().count() < 24, "{build}");
    }

    // Every app, also the one with no finding: not found is not the same
    // as not looked at.
    assert_eq!(
        scanned,
        [
            ["Clean", "org.example.clean", "1.0", "macOS", "41 files, 68.2 MB", "0", "nothing"],
            ["Droid", "org.example.droid", "1.0", "Android", "41 files, 68.2 MB", "1", "nothing"],
            ["Mail", "com.google.mail", "1.0", "macOS", "41 files, 68.2 MB", "1", "nothing"],
            ["Notes", "org.example.notes", "1.0", "macOS", "41 files, 68.2 MB", "4", "2 notes"],
        ]
    );

    let skipped = rows(tables[1]);
    assert_eq!(skipped.len(), 2);
    for row in &skipped {
        assert_eq!(row[0], "Notes");
        assert_eq!(row[2], "Not read");
        assert!(row[4].starts_with("sha256:"));
    }
    let row = |location: &str| skipped.iter().find(|row| row[1] == location).unwrap();
    assert_eq!(
        row("Wrapper/X.app/X")[3],
        "The binary is encrypted. Its bytes are ciphertext, so they were not searched."
    );
    assert_eq!(
        row("Contents/MacOS/Huge")[3],
        "It is over one of the scanner's limits of size or count. Size: 2.1 GB."
    );
    // Each row links to its record.
    for link in tables[1].named("a") {
        let record = root.by_id(&link.attr("href").unwrap()[1..]).unwrap();
        assert!(record.text().contains("coverage note"));
    }
}

/// A package that could not be read has no hash and no content to report
/// on. It is not an app that was scanned: it is listed with what was set
/// aside, under the name of its file, and two of them stay two.
#[test]
fn a_package_that_could_not_be_read_is_set_aside_and_not_counted_as_scanned() {
    let pack = pack();
    let unread = |file: &str, count: u32| {
        let mut subject = subject(Platform::Android, file, 0);
        subject.version = None;
        subject.digest = SubjectDigest::Unread;
        Record::Coverage(CoverageRecord {
            v: V1,
            collector: Collector::AndroidApk,
            subject,
            status: CoverageStatus::Skipped,
            reason: CoverageReason::Unreadable,
            location: None,
            bytes: None,
            count,
        })
    };
    let clean = subject(Platform::Macos, "org.example.clean", 4);
    let evidence =
        set([artifact(&clean, "Clean", None), unread("locked.apk", 1), unread("other.apk", 2)]);
    let root = render(&[], &evidence, &meta(&pack), &pack);

    let summary = section(&root, "summary").text();
    assert!(summary.contains("1 app scanned") && summary.contains("2 coverage notes"), "{summary}");
    let coverage = section(&root, "coverage");
    let rows = |table: &Element| -> Vec<Vec<String>> {
        table.named("tbody")[0]
            .named("tr")
            .into_iter()
            .map(|row| row.named("td").into_iter().map(Element::text).collect())
            .collect()
    };
    let tables = coverage.named("table");
    let scanned = rows(tables[0]);
    assert_eq!(scanned.len(), 1);
    assert_eq!(scanned[0][0], "Clean");
    let aside: Vec<Vec<String>> =
        rows(tables[1]).into_iter().map(|row| row[..4].to_vec()).collect();
    assert_eq!(
        aside,
        [
            ["locked.apk", "the app as a whole", "Not read", "The file system refused the read."],
            [
                "other.apk",
                "the app as a whole",
                "Not read",
                "The file system refused the read. 2 items."
            ],
        ]
    );
    // Each has its record, under its own heading, and no build digest.
    let records = section(&root, "records");
    let headings: Vec<String> = records.named("h3").into_iter().map(Element::text).collect();
    assert_eq!(headings, ["Clean", "locked.apk", "other.apk"]);
    assert!(records.text().contains("locked.apk · Android · build none, the file was not read"));
}

/// The coverage section starts with where the scan looked, and where it
/// deliberately did not, in the words the README gives for each kind of
/// scan. A page rendered from a report saved without a scope has none to
/// state, and says so instead of saying nothing.
#[test]
fn coverage_says_where_the_scan_looked_or_that_it_is_not_on_record() {
    let (pack, evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let stated = |scope: Option<ScanScope>| {
        let mut meta = meta(&pack);
        meta.scope = scope;
        let root = render(&claims, &evidence, &meta, &pack);
        let coverage = section(&root, "coverage");
        let parts: Vec<String> = coverage.named("h3").into_iter().map(Element::text).collect();
        assert_eq!(parts, ["Where the scan looked", "Apps scanned", "Set aside, and why"]);
        coverage.descendants().into_iter().find(|e| e.has_class("scope")).unwrap().text()
    };

    assert_eq!(
        stated(Some(ScanScope::Given)),
        "This scan covered the paths given and nothing else; the installed-app folders were \
         not searched."
    );
    // What was left out on purpose is part of the statement.
    assert_eq!(
        stated(Some(ScanScope::Installed)),
        "This scan covered the apps installed in /Applications and ~/Applications; \
         /System/Applications (Apple's own apps on the sealed system volume) was not searched: \
         name the folder to scan it; the extensions installed in your profiles of Arc, Brave, \
         Google Chrome, Chromium, Dia, Microsoft Edge, Firefox and Vivaldi."
    );
    assert_eq!(
        stated(None),
        "This page was rendered from saved evidence, which does not record where the scan \
         looked. The scan stated it in the summary it printed when it ran."
    );
}

#[test]
fn every_coverage_reason_and_matcher_has_words() {
    use CoverageReason::{
        EncryptedBinary, NoPrivilege, OverBudget, ParseError, UnexpectedCase, Unreadable,
        UnrecognizedRecord, UnsupportedFormat,
    };
    let reasons = [
        NoPrivilege,
        EncryptedBinary,
        OverBudget,
        ParseError,
        UnexpectedCase,
        UnrecognizedRecord,
        Unreadable,
        UnsupportedFormat,
    ];
    let mut seen: Vec<&str> = reasons.into_iter().map(words::reason_words).collect();
    seen.extend(MatcherKind::ALL.into_iter().map(words::matcher_words));
    let distinct: alloc::collections::BTreeSet<&str> = seen.iter().copied().collect();
    assert_eq!(distinct.len(), seen.len(), "two things share one wording");
    assert!(seen.iter().all(|words| words.len() > 10));
}

/// The limits statement is in every report, also in one with no finding:
/// what a scan of a device cannot see.
#[test]
fn every_report_states_what_a_device_side_scan_cannot_see() {
    let pack = pack();
    let empty = render(&[], &EvidenceSet::new(), &meta(&pack), &pack);
    for root in [report(), empty] {
        let limits = section(&root, "limits");
        let points: Vec<String> = limits.named("strong").into_iter().map(Element::text).collect();
        assert_eq!(
            points,
            [
                // Encrypted payloads, server-side sharing, first-party proxying.
                "What is sent.",
                "What companies pass on between their own servers.",
                "What is sent through the app's own domain.",
                "Presence is not use.",
                "Only what has a rule is recognised.",
                "Some code hides its markers.",
                "Names are as the files give them.",
            ]
        );
        let text = limits.text();
        assert!(text.contains("Apps encrypt their traffic"));
        assert!(text.contains("never touches the device"));
        assert!(text.contains("which forward it to another company"));
        assert!(
            text.contains("An app with no finding is not shown to be free of third-party code.")
        );
    }
}

/// Project spec: the tool never says "spying". It states graded facts.
#[test]
fn the_report_states_graded_facts_and_accuses_nobody() {
    let root = report();
    let text = root.text().to_lowercase();
    for banned in ["spy", "spie", "steal", "leak", "surveil", "snoop", "track you", "malicious"] {
        assert!(!text.contains(banned), "the report says `{banned}`");
    }
    // The ladder is explained in the spec's words.
    let ladder: Vec<Vec<String>> = section(&root, "reading").named("tbody")[0]
        .named("tr")
        .into_iter()
        .map(|row| row.named("td").into_iter().take(2).map(Element::text).collect())
        .collect();
    assert_eq!(
        ladder,
        [
            ["declares", "declares"],
            ["contains", "ships"],
            ["contacts", "contacted"],
            ["confirmed", "confirmed"]
        ]
    );
    assert!(root.text().contains("No finding says what an app or a company intends."));
}

/// The access ladder is explained when a finding is on it, and only then.
/// Such a finding is not a channel to a company: it is in a part of its
/// own, by app, and neither under a company nor with the components.
#[test]
fn findings_about_access_have_their_own_part_and_their_own_words() {
    let (pack, evidence) = (pack(), evidence());
    let mut claims = claims(&evidence, &pack);
    let rows = |root: &Element| section(root, "reading").named("tbody")[0].named("tr").len();
    let parts = |root: &Element| -> Vec<String> {
        section(root, "findings").named("h3").into_iter().map(Element::text).collect()
    };
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    assert_eq!(rows(&root), 4);
    // No heading with nothing under it.
    assert!(!parts(&root).iter().any(|part| part == "What the apps may access"));

    // Two of the findings become access claims: one that named a company,
    // and one that named none. An access claim points at a permission of
    // the fixed list in `xs_model::access`, in a category of that list, and
    // names no company.
    let on_access =
        |claims: &mut [Claim], app: &str, object: &str, permission: &str, grade: Grade| {
            let claim =
                claims.iter_mut().find(|c| c.subject.id == app && c.object.id == object).unwrap();
            let permission = xs_model::access::permission(permission).unwrap();
            claim.edge = EdgeType::Access;
            claim.object.kind = ObjectKind::Permission;
            claim.object.id = permission.id.into();
            claim.object.name = permission.name.into();
            claim.category = permission.category.into();
            claim.company = None;
            claim.headline = false;
            claim.grade = grade;
            claim.rungs = vec![grade];
            *claim.id.digest()
        };
    let asked = on_access(
        &mut claims,
        "org.example.droid",
        "sdk/acme-analytics",
        "camera",
        Grade::Requested,
    );
    let allowed =
        on_access(&mut claims, "org.example.notes", "sdk/sparkle", "contacts", Grade::Granted);
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    assert_eq!(rows(&root), 7);
    assert_eq!(
        parts(&root),
        [
            "Acme <Analytics> & \"Sons\" counted in the summary",
            "Google LLC not in the counted categories",
            "No company named",
            "What the apps may access",
        ]
    );

    let groups: Vec<&Element> = section(&root, "findings")
        .descendants()
        .into_iter()
        .filter(|e| e.has_class("company"))
        .collect();
    let shown = |group: &Element| -> Vec<String> {
        group
            .descendants()
            .into_iter()
            .filter(|e| e.has_class("finding"))
            .map(|finding| finding.attr("id").unwrap().to_string())
            .collect()
    };
    // Both are in the last part, by app, and nowhere else.
    let access = groups[3];
    assert!(access.has_class("access"));
    let apps: Vec<String> = access.named("h4").into_iter().map(Element::text).collect();
    assert_eq!(apps, ["Droid", "Notes"]);
    assert_eq!(shown(access), [anchor("f-", &asked), anchor("f-", &allowed)]);
    let apps: Vec<String> = groups[0].named("h4").into_iter().map(Element::text).collect();
    assert_eq!(apps, ["Notes"], "Acme keeps the channel and not the access");
    assert_eq!(shown(groups[2]).len(), 1, "the unmapped host, without the former component");

    let asked = root.by_id(&anchor("f-", &asked)).unwrap().text();
    assert!(asked.contains("requested The app asks for this permission."));
    assert!(asked.contains("Not counted: the summary counts channels."));
    let allowed = root.by_id(&anchor("f-", &allowed)).unwrap().text();
    assert!(allowed.contains("granted The permission was allowed on this device."));
    assert!(!allowed.contains("Component:"), "{allowed}");

    // The summary states them in the words of the access ladder.
    let entries = found(&root);
    let entry = |name: &str| entries.iter().find(|entry| entry[0] == name).unwrap()[1..].to_vec();
    assert_eq!(
        entry("Contacts Personal data"),
        [
            "No company named: this is about what the apps may access.",
            "granted 1 of 4 apps may access it, and it was allowed on this device",
            "In Notes",
            "not counted",
        ]
    );
    assert_eq!(
        entry("Camera Camera, microphone and screen"),
        [
            "No company named: this is about what the apps may access.",
            "requested 1 of 4 apps may access it",
            "In Droid",
            "not counted",
        ]
    );
    // What Notes ships stays a channel of its own.
    let acme: Vec<&Vec<String>> =
        entries.iter().filter(|entry| entry[0] == "AcmeAnalytics Analytics").collect();
    assert_eq!(acme.len(), 1);
    assert_eq!(acme[0][2..4], ["contains ships in 1 of 4 apps", "In Notes"]);
}

#[test]
fn an_empty_scan_is_a_valid_report_that_claims_nothing() {
    let pack = pack();
    let root = render(&[], &EvidenceSet::new(), &meta(&pack), &pack);
    let text = root.text();
    assert!(text.contains("No scanned app matched a rule."));
    assert!(text.contains("The scan found no app to read."));
    assert!(text.contains("The scan produced no record."));
    assert!(text.contains("0 apps scanned"));
    assert!(root.descendants().into_iter().all(|e| !e.has_class("finding")));
}

/// Scanned apps with nothing found: still a report, and it does not say
/// the apps are clean.
#[test]
fn apps_with_no_finding_are_listed_and_not_called_clean() {
    let pack = pack();
    let evidence =
        set([artifact(&subject(Platform::Macos, "org.example.clean", 4), "Clean", None)]);
    let root = render(&[], &evidence, &meta(&pack), &pack);
    let text = section(&root, "findings").text();
    assert!(text.contains("That does not show the apps hold no third-party code"));
    assert!(section(&root, "coverage").text().contains("org.example.clean"));
    assert!(!root.text().to_lowercase().contains("clean app"));
}

#[test]
fn the_report_names_the_scanner_and_the_exact_rules() {
    let (pack, root) = (pack(), report());
    let about = section(&root, "about").text();
    assert!(about.contains("Scannerexposure 0.1.0"));
    assert!(about.contains(&format!(
        "Rule packcore version 7, SHA-256 {}",
        Sha256Digest::of(b"pack").to_hex()
    )));
    assert_eq!(pack.refs().len(), 1);
    // No date: nothing in the input holds one.
    assert!(about.contains("It holds no date"));
}

/// The names in the report come from the pack, so it must be the pack the
/// claims were derived with.
#[test]
fn a_pack_the_report_does_not_name_is_refused() {
    let (pack, evidence) = (pack(), evidence());
    let claims = claims(&evidence, &pack);
    let mut other = meta(&pack);
    other.packs[0].version += 1;
    assert_eq!(html(&claims, &evidence, &other, &pack), Err(RenderError::PackMismatch));

    let mut stray = claims.clone();
    stray[0].company = Some("nobody".into());
    assert_eq!(
        html(&stray, &evidence, &meta(&pack), &pack),
        Err(RenderError::NotInPack {
            claim: stray[0].id.to_string(),
            kind: "company",
            id: "nobody".into()
        })
    );
    let mut stray = claims;
    stray[0].category = "weather".into();
    assert!(matches!(
        html(&stray, &evidence, &meta(&pack), &pack),
        Err(RenderError::NotInPack { kind: "category", .. })
    ));
}

/// Two records that disagree about one build: the report takes the smallest
/// name and the largest counts, never whichever came first.
#[test]
fn what_is_shown_of_an_app_does_not_depend_on_record_order() {
    let pack = pack();
    let app = subject(Platform::Macos, "org.example.notes", 1);
    let Record::Artifact(mut second) = artifact(&app, "Notes", None) else { unreachable!() };
    second.collector = Collector::ElectronApp;
    second.facts.name = Some("Alpha".into());
    second.facts.files_scanned = 50;
    second.facts.bytes_scanned = 10;
    let evidence = set([artifact(&app, "Notes", None), Record::Artifact(second)]);
    let root = render(&[], &evidence, &meta(&pack), &pack);
    let row: Vec<String> = section(&root, "coverage").named("tbody")[0]
        .named("td")
        .into_iter()
        .map(Element::text)
        .collect();
    assert_eq!(row[0], "Alpha");
    assert_eq!(row[5], "50 files, 68.2 MB");
}

/// The pack of [`pack`] with advice: a setting of Notes for analytics whose
/// steps need escaping, the statement that Droid has none, and a host Acme's
/// SDK sends to beyond what its rule names.
fn advised_pack() -> Pack {
    use xs_model::fix::{AppFix, AppKey, Fixes, NoSetting, SdkFix, Setting};
    let mut layer = layer();
    layer.fixes = Fixes {
        apps: vec![
            AppFix {
                id: "droid".into(),
                name: "Droid".into(),
                apps: vec![AppKey { platform: Platform::Android, id: "org.example.droid".into() }],
                settings: vec![],
                no_setting: vec![NoSetting {
                    covers: vec!["analytics".into()],
                    says: "Droid documents no setting that turns off its analytics.".into(),
                }],
                alternatives: vec![],
                sources: vec!["https://droid.example/privacy".into()],
            },
            AppFix {
                id: "notes".into(),
                name: "Notes".into(),
                apps: vec![AppKey { platform: Platform::Macos, id: "org.example.notes".into() }],
                settings: vec![Setting {
                    covers: vec!["analytics".into()],
                    steps: "Notes > Settings > Privacy > <b>Share usage data</b>: off".into(),
                    note: Some("It applies to this Mac only.".into()),
                }],
                no_setting: vec![],
                alternatives: vec![],
                sources: vec!["https://notes.example/privacy".into()],
            },
        ],
        sdks: vec![SdkFix {
            rule: "sdk/acme-analytics".into(),
            block: vec!["collect.acme.com".into()],
            sources: vec!["https://acme.example/hosts".into()],
        }],
    };
    Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"pack") }]).unwrap()
}

/// An edge that says `subject` asks for a permission by the usage
/// description `key`.
fn asks(subject: &Subject, key: &str) -> Record {
    Record::Edge(EdgeRecord {
        v: V1,
        collector: Collector::MacosBundle,
        subject: subject.clone(),
        edge: EdgeType::Access,
        grade: Grade::Requested,
        object: ObjectRef {
            kind: ObjectKind::Permission,
            id: xs_model::access::declared(MatcherKind::UsageDescription, key).unwrap().id.into(),
        },
        rule: xs_model::access::rule::USAGE_DESCRIPTION.into(),
        proof: Proof {
            matcher: MatcherKind::UsageDescription,
            token: key.into(),
            count: 1,
            example: None,
            location: RelPath::new("Contents/Info.plist").unwrap(),
            region: Region::PropertyList,
            scope: Scope::AppCode,
            max_sdk: None,
        },
    })
}

/// A browser extension installed in `browser` that asks for `permissions`
/// under the manifest key `key`.
fn extension(
    browser: xs_model::record::Browser,
    seed: u8,
    key: &str,
    permissions: &[xs_model::Permission],
) -> Vec<Record> {
    let mut subject = subject(browser.platform(), "abcdefghijklmnopabcdefghijklmnop", seed);
    subject.kind = SubjectKind::Extension;
    let Record::Artifact(mut facts) = artifact(&subject, "Wallet", None) else { unreachable!() };
    facts.collector = Collector::BrowserExtension;
    facts.facts.browser = Some(browser);
    let mut records = vec![Record::Artifact(facts)];
    for permission in permissions {
        records.push(Record::Edge(EdgeRecord {
            v: V1,
            collector: Collector::BrowserExtension,
            subject: subject.clone(),
            edge: EdgeType::Access,
            grade: MatcherKind::ExtensionManifest.grade(),
            object: ObjectRef { kind: ObjectKind::Permission, id: permission.id().into() },
            rule: xs_model::permission::RULE.into(),
            proof: Proof {
                matcher: MatcherKind::ExtensionManifest,
                token: key.into(),
                count: 1,
                example: None,
                location: RelPath::new("manifest.json").unwrap(),
                region: Region::ManifestKey,
                scope: Scope::AppCode,
                max_sdk: None,
            },
        }));
    }
    records
}

/// The evidence of [`evidence`], and Notes asking for the camera, the
/// network and Bluetooth, Droid for the camera, and an extension in Chrome
/// that may read every site.
fn evidence_with_access() -> EvidenceSet {
    use xs_model::Permission;
    use xs_model::record::Browser;
    let notes = subject(Platform::Macos, "org.example.notes", 1);
    let droid = subject(Platform::Android, "org.example.droid", 3);
    let mut set = evidence();
    let mut add = |record| {
        set.insert(record).unwrap();
    };
    add(asks(&notes, "NSCameraUsageDescription"));
    add(asks(&notes, "NSBluetoothAlwaysUsageDescription"));
    let Record::Edge(mut camera) = asks(&droid, "NSCameraUsageDescription") else { unreachable!() };
    camera.proof.matcher = MatcherKind::AndroidPermission;
    camera.proof.token = "android.permission.CAMERA".into();
    camera.rule = xs_model::access::rule::ANDROID_PERMISSION.into();
    camera.proof.location = RelPath::new("AndroidManifest.xml").unwrap();
    camera.proof.region = Region::ManifestKey;
    add(Record::Edge(camera));
    for record in extension(Browser::Chrome, 9, "host_permissions", &[Permission::AllSites]) {
        add(record);
    }
    for record in extension(Browser::Firefox, 10, "permissions", &[Permission::History]) {
        add(record);
    }
    set
}

/// The checklist, as its entries' heads, in order.
fn checklist(root: &Element) -> Vec<String> {
    section(root, "actions")
        .descendants()
        .into_iter()
        .filter(|e| e.has_class("todo"))
        .map(|entry| {
            entry.descendants().into_iter().find(|e| e.has_class("todo-head")).unwrap().text()
        })
        .collect()
}

/// The checklist is at the top of the page, under the summary, and lists
/// what exposes the most first: another company's analytics and an
/// extension that reads every site, then the camera, then Bluetooth. A
/// service of the app's own publisher, a component and an update feed are
/// not on it.
#[test]
fn the_checklist_comes_first_and_puts_what_exposes_the_most_first() {
    let (pack, evidence) = (advised_pack(), evidence_with_access());
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    let sections: Vec<&str> =
        root.named("section").into_iter().filter_map(|s| s.attr("id")).take(2).collect();
    assert_eq!(sections, ["summary", "actions"]);
    assert_eq!(
        checklist(&root),
        [
            "High AcmeAnalytics Analytics",
            "High Wallet Browser extension",
            "High Wallet Browser extension",
            "Medium Camera",
            "Medium Droid Android app",
            "Low Bluetooth",
        ]
    );
    let text = section(&root, "actions").text();
    assert!(!text.contains("Crashlytics"), "Google publishes Mail: {text}");
    assert!(!text.contains("Sparkle") && !text.contains("updates.example.org"), "{text}");
    // The Android camera is under the app, not under a pane of macOS.
    assert!(text.contains("Open Settings > Apps > Droid > Permissions"), "{text}");

    // Every link of the checklist leads to a finding on the page.
    for link in section(&root, "actions").named("a") {
        let target = link.attr("href").unwrap().trim_start_matches('#');
        let finding = root.by_id(target).unwrap_or_else(|| panic!("no element `{target}`"));
        assert!(finding.has_class("finding"), "{target}");
    }
}

/// An app's own setting is shown where the pack documents one, as the
/// publisher documents it and with what the scan cannot show; a statement
/// that there is none, where the pack has one; and a plain "not on record"
/// otherwise. The steps are text from the pack and render as text.
#[test]
fn an_app_s_own_setting_is_shown_as_its_publisher_documents_it() {
    let (pack, evidence) = (advised_pack(), evidence_with_access());
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);

    let notes = finding(&root, &claims, "org.example.notes", "sdk/acme-analytics").text();
    assert!(
        notes.contains(
            "Turn it off in Notes: Notes > Settings > Privacy > <b>Share usage data</b>: off. \
             Its publisher documents this setting for analytics; a scan of the app's files \
             cannot show that it stops this SDK. It applies to this Mac only."
        ),
        "{notes}"
    );
    assert!(root.named("b").is_empty(), "the steps are text, never markup");
    let droid = finding(&root, &claims, "org.example.droid", "sdk/acme-analytics").text();
    assert!(droid.contains("Droid documents no setting that turns off its analytics."), "{droid}");

    // Without advice, the report says it has none rather than guessing.
    let plain = super::tests::pack();
    let root = render(&claims, &evidence, &meta(&plain), &plain);
    let notes = finding(&root, &claims, "org.example.notes", "sdk/acme-analytics").text();
    assert!(notes.contains("No setting of this app that turns it off is on record."), "{notes}");
    assert!(notes.contains("The rule pack names no host for AcmeAnalytics"), "{notes}");
    let entry = section(&root, "actions").text();
    assert!(
        entry.contains("No setting that turns it off is on record for Droid, Notes."),
        "{entry}"
    );
    assert!(entry.contains("The rule pack names no host for AcmeAnalytics"), "{entry}");
}

/// A block list is given for a third-party service in a counted category,
/// with a firewall that runs on the app's platform, and never for a
/// service of the app's own publisher or for a crash reporter.
#[test]
fn a_block_list_names_the_hosts_and_a_firewall_of_the_platform() {
    let (pack, evidence) = (advised_pack(), evidence_with_access());
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    let notes = finding(&root, &claims, "org.example.notes", "sdk/acme-analytics").text();
    assert!(
        notes.contains(
            "Block this host for Notes with an outbound firewall such as LuLu (free) or Little \
             Snitch: collect.acme.com."
        ),
        "{notes}"
    );
    assert!(notes.contains("Or remove Notes if you can do without it."), "{notes}");
    let droid = finding(&root, &claims, "org.example.droid", "sdk/acme-analytics").text();
    assert!(droid.contains("such as NetGuard: collect.acme.com"), "{droid}");

    let mail = finding(&root, &claims, "com.google.mail", "sdk/crashlytics").text();
    assert!(mail.contains("Google LLC publishes this app"), "{mail}");
    assert!(!mail.contains("Block"), "{mail}");
    let feed = finding(&root, &claims, "org.example.notes", "updates.example.org").text();
    assert!(feed.contains("Nothing to do: this is where the app fetches its own updates."));
    let sparkle = finding(&root, &claims, "org.example.notes", "sdk/sparkle").text();
    assert!(
        sparkle.contains(
            "Nothing to do: a component is a library with no service of its own behind it."
        )
    );
}

/// A permission is turned off where the platform keeps the switch: a pane
/// of System Settings on macOS, the app's page of permissions on Android,
/// and the extension's page in its own browser.
#[test]
fn a_permission_names_where_the_platform_keeps_its_switch() {
    let (pack, evidence) = (advised_pack(), evidence_with_access());
    let claims = claims(&evidence, &pack);
    let root = render(&claims, &evidence, &meta(&pack), &pack);
    let mac = finding(&root, &claims, "org.example.notes", "camera").text();
    assert!(
        mac.contains("Open System Settings > Privacy & Security > Camera and turn off Notes"),
        "{mac}"
    );
    let android = finding(&root, &claims, "org.example.droid", "camera").text();
    assert!(android.contains("Open Settings > Apps > Droid > Permissions and set Camera"));
    let actions = section(&root, "actions").text();
    assert!(actions.contains("Open System Settings > Privacy & Security > Camera and turn off"));
    assert!(actions.contains("chrome://extensions in Google Chrome"), "{actions}");
    assert!(actions.contains("Site access choose On click or On specific sites"), "{actions}");
    assert!(actions.contains("about:addons in Firefox"), "{actions}");
    assert!(
        actions.contains("The browser has no switch") || actions.contains("stay as long as"),
        "{actions}"
    );
}

#[test]
fn a_scan_with_nothing_to_act_on_says_so() {
    let pack = pack();
    let root = render(&[], &EvidenceSet::new(), &meta(&pack), &pack);
    assert!(section(&root, "actions").text().contains("Nothing here calls for action"));
}
