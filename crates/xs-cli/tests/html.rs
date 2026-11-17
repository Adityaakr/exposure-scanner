//! The HTML report through the `exposure` binary (build plan, task 11): the
//! honesty test, the markup-injection fixture, and the same bytes for the
//! same evidence and rule pack.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]
#![allow(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "tests run the binary and may read the environment"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use xs_formats::testkit::{self as formats, Attr, AxmlBuilder, DexBuilder, ZipBuilder};
use xs_model::record::Record;
use xs_model::{Report, canon};
use xs_render::CONTENT_SECURITY_POLICY;
use xs_render::testkit::{self, Element};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");
/// The page a scan of the three committed fixtures must reproduce.
const GOLDEN: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/report/Fixtures.report.html");

/// The committed fixtures: a macOS bundle, an Electron app and an Android
/// package.
fn fixtures() -> [PathBuf; 3] {
    ["macos/Skeleton.app", "macos/ElectronSkeleton.app", "android/Skeleton.apk"]
        .map(|fixture| Path::new(FIXTURES).join(fixture))
}

fn exposure(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_exposure")).args(args).output().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Both reports of one scan.
struct Scanned {
    html: String,
    json: String,
}

/// Scans `paths` and returns the page and the JSON report of that scan.
fn scan(paths: &[&Path], threads: usize) -> Scanned {
    let dir = tempfile::tempdir().unwrap();
    let (html, json) = (dir.path().join("report.html"), dir.path().join("report.json"));
    let threads = threads.to_string();
    let mut args =
        vec!["scan", "--threads", &threads, "--html", text(&html), "--json", text(&json)];
    args.extend(paths.iter().map(|path| text(path)));
    let output = exposure(&args);
    assert!(output.status.success(), "exit {:?}: {}", output.status.code(), stderr(&output));
    assert!(output.stdout.is_empty(), "both reports go to their files");
    Scanned { html: fs::read_to_string(html).unwrap(), json: fs::read_to_string(json).unwrap() }
}

fn scan_fixtures(threads: usize) -> Scanned {
    let paths = fixtures();
    scan(&paths.each_ref().map(PathBuf::as_path), threads)
}

/// Reads a page as a strict reader does, and checks it is inert.
fn read(page: &str) -> Element {
    let root = testkit::parse(page).unwrap();
    testkit::check_inert(&root, CONTENT_SECURITY_POLICY).unwrap();
    root
}

/// Property 6 and the "done when" of task 11: every finding shows its
/// evidence grade and the raw record behind it.
#[test]
fn every_finding_shows_its_grade_and_the_raw_record_behind_it() {
    let scanned = scan_fixtures(2);
    let report: Report = serde_json::from_str(&scanned.json).unwrap();
    let page = read(&scanned.html);
    assert_eq!(report.claims.len(), 5);

    for claim in &report.claims {
        let finding = page.by_id(&format!("f-{}", claim.id.digest())).unwrap_or_else(|| {
            panic!("the page does not show {} in {}", claim.object.id, claim.subject.id)
        });
        let said = finding.text();
        assert!(said.contains(&claim.object.name), "{said}");

        // The grade, as the claim has it in the JSON report.
        let grade = serde_json::to_value(claim.grade).unwrap();
        let badge = finding.descendants().into_iter().find(|e| e.has_class("grade")).unwrap();
        assert_eq!(badge.text(), grade.as_str().unwrap());
        // The confidence.
        let confidence = serde_json::to_value(claim.confidence).unwrap();
        assert!(said.contains(&format!("Confidence{}: ", confidence.as_str().unwrap())), "{said}");

        // The raw record behind it: one link per cited record, and at the
        // end of the link the record as it is stored.
        let links: Vec<&str> =
            finding.named("a").into_iter().map(|link| link.attr("href").unwrap()).collect();
        assert_eq!(links.len(), claim.evidence.len());
        for id in &claim.evidence {
            let anchor = format!("r-{}", id.digest());
            assert!(links.contains(&format!("#{anchor}").as_str()), "no link to {id}");
            let shown = page.by_id(&anchor).expect("the cited record is on the page");
            let raw = shown.named("pre")[0].text();
            assert_eq!(raw, canon::to_string(report.evidence.get(id).unwrap()).unwrap());
            // It hashes to the id it is shown under.
            let record: Record = serde_json::from_str(&raw).unwrap();
            assert_eq!(record.id().unwrap(), *id);
            assert!(shown.text().contains(&id.to_string()));
        }
    }

    // The page holds every record of the scan, cited or not, and nothing
    // that is not a claim of the JSON report.
    let count = |class: &str| page.descendants().into_iter().filter(|e| e.has_class(class)).count();
    assert_eq!(count("record"), report.evidence.len());
    assert_eq!(count("finding"), report.claims.len());
    // The summary is the headline of the JSON report.
    let numbers: Vec<String> =
        page.descendants().into_iter().filter(|e| e.has_class("n")).map(Element::text).collect();
    let headline = report.headline;
    assert_eq!(
        numbers,
        [headline.companies_contacts, headline.companies_contains, headline.apps_third_party]
            .map(|count| count.to_string())
    );
}

/// The same bytes on every machine: the page for the committed fixtures is
/// compared with a committed file, so Linux and macOS CI must both produce
/// it. It is also a sample of the report that can be opened from the
/// repository. Regenerate it after a deliberate change with
/// `EXPOSURE_BLESS=1 cargo test -p exposure`.
#[test]
fn the_page_for_the_fixtures_matches_the_committed_bytes() {
    let page = scan_fixtures(3).html;
    if std::env::var_os("EXPOSURE_BLESS").is_some() {
        fs::write(GOLDEN, &page).unwrap();
    }
    let golden = fs::read_to_string(GOLDEN).unwrap();
    assert!(
        page == golden,
        "the page for the fixtures changed. If the change is intended, run: \
         EXPOSURE_BLESS=1 cargo test -p exposure"
    );
    read(&golden);
}

/// Property 3: one page across input order and thread count, from a scan
/// and from its saved evidence.
#[test]
fn one_page_whatever_the_input_order_the_thread_count_and_the_way_it_was_made() {
    let paths = fixtures();
    let [bundle, electron, package] = paths.each_ref().map(PathBuf::as_path);
    let reference = scan(&[bundle, electron, package], 1);
    for (name, order) in [
        ("reversed", &[package, electron, bundle][..]),
        ("shuffled", &[electron, package, bundle][..]),
        ("repeats", &[bundle, bundle, package, electron, package][..]),
    ] {
        for threads in [1, 2, 8] {
            assert!(scan(order, threads).html == reference.html, "{name} order, {threads} threads");
        }
    }

    // `report` renders the page again from the saved evidence alone.
    let dir = tempfile::tempdir().unwrap();
    let saved = dir.path().join("scan.json");
    fs::write(&saved, &reference.json).unwrap();
    let again = dir.path().join("again.html");
    let output = exposure(&["report", text(&saved), "--html", text(&again)]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stdout.is_empty(), "the page was asked for, so the JSON report is not printed");
    let rendered_again = fs::read_to_string(&again).unwrap();

    // The one thing a scan knows that its saved evidence does not is where
    // it looked. The page of the scan states it; the page rendered again
    // says it is not on record. Nothing else differs, to the byte.
    let (scanned, saved_scope) = (scope(&reference.html), scope(&rendered_again));
    assert_eq!(scanned.1, format!("This scan covered {}.", xs_collect::ScanScope::Given));
    assert!(
        saved_scope.1.starts_with("This page was rendered from saved evidence"),
        "{saved_scope:?}"
    );
    assert!(scanned.0 == saved_scope.0, "the pages differ outside the scope");

    // And both at once, the JSON report unchanged, the page the same as
    // any other rendered from that evidence.
    let json = dir.path().join("again.json");
    let second = dir.path().join("second.html");
    let output =
        exposure(&["report", text(&saved), "--html", text(&second), "--json", text(&json)]);
    assert!(output.status.success() && output.stdout.is_empty());
    assert!(fs::read_to_string(&json).unwrap() == reference.json);
    assert!(fs::read_to_string(&second).unwrap() == rendered_again);
    let output = exposure(&["report", text(&json), "--html", text(&second)]);
    assert!(output.status.success());
    assert!(fs::read_to_string(&second).unwrap() == rendered_again);
}

/// Splits a page into everything but its scope statement, and the
/// statement: the text of the one paragraph that says where the scan looked.
fn scope(page: &str) -> (String, String) {
    const OPEN: &str = "<p class=\"scope\">";
    assert_eq!(page.matches(OPEN).count(), 1, "one scope statement");
    let (before, rest) = page.split_once(OPEN).unwrap();
    let (statement, after) = rest.split_once("</p>").unwrap();
    let stated = read(page)
        .descendants()
        .into_iter()
        .find(|element| element.has_class("scope"))
        .unwrap()
        .text();
    assert!(!statement.contains('<'), "the statement is text: {statement}");
    (format!("{before}{OPEN}</p>{after}"), stated)
}

#[test]
fn where_the_apps_are_and_when_they_were_scanned_do_not_reach_the_page() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("a/b c/Renamed.apk");
    fs::create_dir_all(nested.parent().unwrap()).unwrap();
    let [_, _, package] = fixtures();
    fs::copy(&package, &nested).unwrap();

    let page = scan(&[&nested], 2).html;
    assert!(page == scan(&[&package], 1).html);
    assert!(!page.contains(text(dir.path())) && !page.contains("Renamed"));
    for outside in ["/Users/", "/home/", "/tmp", "/var/", "/private/"] {
        assert!(!page.contains(outside), "{outside}");
    }
}

/// A macOS bundle and an Android package whose names are markup. The
/// values a hostile app controls, as the scan stores them.
struct Hostile {
    bundle: PathBuf,
    package: PathBuf,
}

const HOSTILE_NAME: &str = "<script>alert('name')</script>";
const HOSTILE_BUNDLE_ID: &str = "\"><img src=x onerror=alert(1)>";
const HOSTILE_VERSION: &str = "</p></div><iframe src=//evil.example>";
const HOSTILE_LABEL: &str = "</h4><svg onload=alert(2)><!--";
const HOSTILE_PACKAGE: &str = "org.example.\"><form action=https://evil.example>";
/// A class name is stored with dots for the slashes of its descriptor, so
/// these hold no slash: what is stored is what is written here.
const HOSTILE_CLASSES: [&str; 2] = [
    "io.sentry.<img src=x onerror=alert(3)>",
    "io.sentry.\"><script>alert(4)<script><svg onload=alert(5)>",
];

fn hostile(dir: &Path) -> Hostile {
    // The fixture bundle, with a property list that names it in markup. A
    // property list is XML, so the markup is escaped there, as a real one
    // would have it; the scan reads it back as the characters themselves.
    let bundle = dir.join("Hostile.app");
    copy_tree(&Path::new(FIXTURES).join("macos/Skeleton.app"), &bundle);
    let xml = |value: &str| value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let plist = fs::read_to_string(bundle.join("Contents/Info.plist"))
        .unwrap()
        .replace(
            "<string>org.example.exposure.skeleton</string>",
            &format!("<string>{}</string>", xml(HOSTILE_BUNDLE_ID)),
        )
        .replace(
            "<key>CFBundleName</key>\n\t<string>Skeleton</string>",
            &format!("<key>CFBundleName</key>\n\t<string>{}</string>", xml(HOSTILE_NAME)),
        )
        .replace("<string>1.0.0</string>", &format!("<string>{}</string>", xml(HOSTILE_VERSION)));
    assert_eq!(plist.matches("&lt;").count(), 6, "the three values are in the property list");
    fs::write(bundle.join("Contents/Info.plist"), plist).unwrap();

    // An Android package whose label, app id and class names are markup.
    // Its classes are under a prefix a rule names, so they are evidence.
    let manifest = AxmlBuilder::new()
        .start(
            "manifest",
            &[
                Attr::android(formats::ANDROID_VERSION_NAME, "versionName", HOSTILE_VERSION),
                Attr::plain("package", HOSTILE_PACKAGE),
            ],
        )
        .start("application", &[Attr::android(formats::ANDROID_LABEL, "label", HOSTILE_LABEL)])
        .end()
        .end()
        .finish();
    let classes =
        HOSTILE_CLASSES.iter().fold(DexBuilder::new(), |dex, class| dex.class(class)).finish();
    let package = dir.join("hostile.apk");
    let apk = ZipBuilder::new()
        .deflated("AndroidManifest.xml", &manifest)
        .deflated("classes.dex", &classes)
        .finish();
    fs::write(&package, apk).unwrap();
    Hostile { bundle, package }
}

/// Copies a folder, keeping symbolic links as links.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        if kind.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(entry.path()).unwrap(), target).unwrap();
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// The "done when" of task 11: the markup-injection fixture, with hostile
/// class names and app names, renders inert.
#[test]
fn an_app_whose_names_are_markup_renders_inert() {
    let dir = tempfile::tempdir().unwrap();
    let apps = hostile(dir.path());
    let scanned = scan(&[&apps.bundle, &apps.package], 2);
    let report: Report = serde_json::from_str(&scanned.json).unwrap();

    // The fixture does what it is for: the markup is in the evidence, in an
    // app name, an app id, a version and a class name.
    let stored = scanned.json.as_str();
    let json = |value: &str| serde_json::to_string(value).unwrap();
    for value in [HOSTILE_NAME, HOSTILE_BUNDLE_ID, HOSTILE_VERSION, HOSTILE_LABEL, HOSTILE_PACKAGE]
    {
        assert!(stored.contains(&json(value)), "the scan did not keep {value}");
    }
    let smallest = HOSTILE_CLASSES.iter().min().unwrap();
    assert!(stored.contains(&json(smallest)), "no class name is in the evidence");
    assert_eq!(report.claims.len(), 2, "Sentry in the bundle and in the package");

    // The page reads as a strict reader demands and holds only the
    // elements and attributes of a report.
    let page = read(&scanned.html);
    // Every value is there, as text.
    let said = page.text();
    for value in
        [HOSTILE_NAME, HOSTILE_BUNDLE_ID, HOSTILE_VERSION, HOSTILE_LABEL, HOSTILE_PACKAGE, smallest]
    {
        assert!(said.contains(value), "the page does not show {value}");
    }
    // And none of it is markup: the page has the elements of the page of
    // two harmless apps with the same findings, and no others.
    let [bundle, _, _] = fixtures();
    let harmless = dir.path().join("harmless.apk");
    let apk = ZipBuilder::new()
        .deflated("AndroidManifest.xml", &formats::manifest("org.example.app", "1.0", &[]))
        .deflated("classes.dex", &DexBuilder::new().class("io.sentry.Sentry").finish())
        .finish();
    fs::write(&harmless, apk).unwrap();
    let plain = read(&scan(&[&bundle, &harmless], 2).html);
    let names = |root: &Element| -> Vec<String> {
        root.descendants().into_iter().map(|element| element.name.clone()).collect()
    };
    let (hostile_names, plain_names) = (names(&page), names(&plain));
    // The harmless package spells a domain, which the page shows in one
    // more `code` element; nothing else differs.
    let extra = plain_names.len() - hostile_names.len();
    assert!(extra <= 2, "{extra}");
    let without_code = |names: &[String]| -> Vec<String> {
        names.iter().filter(|name| *name != "code").cloned().collect()
    };
    assert_eq!(without_code(&hostile_names), without_code(&plain_names));

    for tag in ["<script", "<img", "<iframe", "<svg", "<form", "<!--", "onerror=\"", "onload=\""] {
        assert!(!scanned.html.contains(tag), "{tag}");
    }
    // Every attribute is fixed text or an anchor made of a hash.
    for element in page.descendants() {
        for (name, value) in &element.attrs {
            let fixed = value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b" -#=;'/,.+".contains(&byte));
            assert!(fixed, "{name}=\"{value}\" on <{}>", element.name);
        }
    }
}

#[test]
fn the_page_is_written_owner_only_and_alone_when_only_it_is_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let page = dir.path().join("report.html");
    // An existing, world-readable file is tightened as well as replaced.
    fs::write(&page, "an old report").unwrap();
    fs::set_permissions(&page, fs::Permissions::from_mode(0o644)).unwrap();

    let [bundle, _, _] = fixtures();
    let output = exposure(&["scan", text(&bundle), "--html", text(&page)]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(output.stdout.is_empty(), "the JSON report is not printed beside the page");
    assert!(stderr(&output).contains("scanned 1 app"));
    assert_eq!(fs::metadata(&page).unwrap().permissions().mode() & 0o777, 0o600);
    let written = fs::read_to_string(&page).unwrap();
    assert!(written.starts_with("<!doctype html>\n") && written.ends_with("</html>\n"));
    read(&written);
}

/// Evidence that was edited is refused before anything is rendered, so no
/// page is written from it.
#[test]
fn no_page_is_written_from_refused_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let saved = dir.path().join("edited.json");
    fs::write(&saved, scan_fixtures(1).json.replacen("\"count\":1", "\"count\":40", 1)).unwrap();
    let page = dir.path().join("report.html");
    let output = exposure(&["report", text(&saved), "--html", text(&page)]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("hashes to"), "{}", stderr(&output));
    assert!(!page.exists());
}

#[test]
fn the_usage_text_names_the_page() {
    let output = exposure(&["--help"]);
    let usage = String::from_utf8(output.stdout).unwrap();
    assert!(usage.contains("exposure scan [PATH...] [--html FILE] [--json FILE]"), "{usage}");
    assert!(usage.contains("exposure report FILE [--html FILE] [--json FILE]"), "{usage}");
    // A value is needed.
    let output = exposure(&["scan", "x.app", "--html"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--html needs a value"));
}
