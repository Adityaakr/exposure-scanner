//! The rule-pack source compiler and its lints.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]

use xs_model::matcher::{Boundary, MatcherKind};
use xs_rules::compile::{Compiled, Problem, SourceFile, compile};

const PACK: &str = r#"
layer = "core"
version = 3
license = "CC-BY-4.0"

[[category]]
id = "crash_reporting"
name = "Crash reporting"
headline = false

[[category]]
id = "analytics"
name = "Analytics"
headline = true

[[category]]
id = "component"
name = "Component"
headline = false
"#;

const ENTITIES: &str = r#"
[[entity]]
id = "sentry"
name = "Functional Software, Inc. (Sentry)"
website = "https://sentry.io/"
source = "https://sentry.io/terms/"

[[entity]]
id = "posthog"
name = "PostHog Inc."
website = "https://posthog.com/"
source = "https://posthog.com/terms"
"#;

const SENTRY: &str = r#"
id = "sdk/sentry"
name = "Sentry"
entity = "sentry"
category = "crash_reporting"
sources = ["https://example.com/b", "https://example.com/a"]
notes = ["note:two", "note:one"]

[match]
npm_package = ["@sentry/electron", "@sentry/browser"]
apple_framework = ["Sentry.framework"]
content_literal = [{ lit = "sentry.javascript.", at = "word" }]
macho_token = [{ lit = "SentryCrashMonitor", at = "word" }, { lit = "SentryAppStartTracker", at = "word" }]
min_distinct = { macho_token = 2 }
"#;

const SPARKLE: &str = r#"
id = "sdk/sparkle"
name = "Sparkle"
component = true
category = "component"
sources = ["https://example.com/sparkle"]

[match]
apple_framework = ["Sparkle.framework"]
"#;

fn files<'a>(rules: &[(&'a str, &'a str)]) -> Vec<SourceFile<'a>> {
    let mut files = vec![
        SourceFile { path: "pack.toml", text: PACK },
        SourceFile { path: "entities.toml", text: ENTITIES },
    ];
    files.extend(rules.iter().map(|&(path, text)| SourceFile { path, text }));
    files
}

fn good() -> Vec<SourceFile<'static>> {
    files(&[("sdk/sentry.toml", SENTRY), ("sdk/sparkle.toml", SPARKLE)])
}

fn compiled(files: &[SourceFile<'_>]) -> Compiled {
    compile(files).unwrap_or_else(|problems| panic!("{problems:#?}"))
}

/// The problems for one rule file that replaces the Sentry rule.
fn problems_for(rule: &str) -> Vec<String> {
    let files = files(&[("sdk/sentry.toml", rule), ("sdk/sparkle.toml", SPARKLE)]);
    problems(&files)
}

fn problems(files: &[SourceFile<'_>]) -> Vec<String> {
    compile(files)
        .expect_err("expected the sources to be refused")
        .iter()
        .map(Problem::to_string)
        .collect()
}

/// The Sentry rule with its `[match]` table replaced.
fn with_match(table: &str) -> String {
    let head = SENTRY.split("[match]").next().unwrap();
    format!("{head}[match]\n{table}\n")
}

fn assert_one(problems: &[String], needle: &str) {
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert!(problems[0].contains(needle), "{problems:#?}\n  does not mention: {needle}");
}

#[test]
fn good_sources_compile_to_a_sorted_layer() {
    let Compiled { layer, bytes } = compiled(&good());
    assert_eq!(
        (layer.layer.as_str(), layer.version, layer.license.as_str()),
        ("core", 3, "CC-BY-4.0")
    );
    let ids = |list: Vec<&str>| list.join(",");
    assert_eq!(
        ids(layer.categories.iter().map(|c| c.id.as_str()).collect()),
        "analytics,component,crash_reporting"
    );
    assert_eq!(ids(layer.entities.iter().map(|e| e.id.as_str()).collect()), "posthog,sentry");
    assert_eq!(ids(layer.rules.iter().map(|r| r.id.as_str()).collect()), "sdk/sentry,sdk/sparkle");

    let sentry = &layer.rules[0];
    assert_eq!(sentry.entity.as_deref(), Some("sentry"));
    assert_eq!(sentry.sources, ["https://example.com/a", "https://example.com/b"]);
    assert_eq!(sentry.notes, ["note:one", "note:two"]);
    let npm = &sentry.matchers[&MatcherKind::NpmPackage];
    assert_eq!(
        npm.iter().map(|t| t.lit.as_str()).collect::<Vec<_>>(),
        ["@sentry/browser", "@sentry/electron"]
    );
    assert!(
        npm.iter().all(|token| token.at == Boundary::Exact),
        "bare strings get the kind's default"
    );
    assert_eq!(sentry.matchers[&MatcherKind::ContentLiteral][0].at, Boundary::Word);
    assert_eq!(sentry.min_distinct[&MatcherKind::MachoToken], 2);

    let sparkle = &layer.rules[1];
    assert_eq!(sparkle.entity, None, "a component has no entity");

    // The bytes are the canonical JSON of the layer and nothing else.
    assert_eq!(bytes, xs_model::canon::to_vec(&layer).unwrap());
    assert_eq!(serde_json::from_slice::<xs_model::pack::Layer>(&bytes).unwrap(), layer);
}

/// Build plan, task 3: compiling twice gives identical bytes.
#[test]
fn compiling_twice_gives_identical_bytes() {
    assert_eq!(compiled(&good()).bytes, compiled(&good()).bytes);
}

#[test]
fn file_order_and_table_order_do_not_reach_the_bytes() {
    let reference = compiled(&good()).bytes;

    let mut reversed = good();
    reversed.reverse();
    assert_eq!(compiled(&reversed).bytes, reference);

    // The same rule with its keys, tokens and lists written in another order.
    let reordered = r#"
category = "crash_reporting"
notes = ["note:one", "note:two"]
sources = ["https://example.com/a", "https://example.com/b", "https://example.com/a"]
name = "Sentry"
entity = "sentry"
id = "sdk/sentry"

[match]
min_distinct = { macho_token = 2 }
macho_token = [{ at = "word", lit = "SentryAppStartTracker" }, { lit = "SentryCrashMonitor", at = "word" }]
content_literal = [{ lit = "sentry.javascript.", at = "word" }]
apple_framework = ["Sentry.framework"]
npm_package = ["@sentry/browser", "@sentry/electron"]
"#;
    let files = files(&[("sdk/sparkle.toml", SPARKLE), ("sdk/sentry.toml", reordered)]);
    assert_eq!(compiled(&files).bytes, reference);
}

/// Build plan, task 3: a 5-byte unanchored token is rejected.
#[test]
fn a_five_byte_unanchored_token_is_rejected() {
    let problems =
        problems_for(&with_match(r#"content_literal = [{ lit = "abcde", at = "none" }]"#));
    assert_one(&problems, "content_literal token `abcde` is 5 bytes");
    assert!(problems[0].starts_with("sdk/sentry.toml: "));
}

#[test]
fn short_content_tokens_are_refused_with_advice_the_matcher_allows() {
    // `content_literal` and `macho_token` have no `exact` boundary
    // (`MatcherKind::boundaries`), so the only way out is a longer token.
    for (table, kind) in [
        (r#"content_literal = [{ lit = "abcdefg", at = "word" }]"#, "content_literal"),
        (r#"content_literal = [{ lit = "x.a.co", at = "host" }]"#, "content_literal"),
        (r#"macho_token = [{ lit = "abcdefg", at = "none" }]"#, "macho_token"),
    ] {
        let problems = problems_for(&with_match(table));
        assert_one(&problems, &format!("{kind} token"));
        assert!(problems[0].contains("must be at least 8 bytes"), "{problems:#?}");
        assert!(!problems[0].contains("exact"), "{problems:#?}");
    }
    // Which is why `exact` must not be offered: taking it is refused.
    let exact =
        problems_for(&with_match(r#"content_literal = [{ lit = "abcdefg", at = "exact" }]"#));
    assert_one(&exact, "cannot use the `exact` boundary");
    // `dex_string` does allow `exact`, so there the advice stands.
    let dex = problems_for(&with_match(r#"dex_string = [{ lit = "abcdefg", at = "word" }]"#));
    assert_one(&dex, "dex_string token");
    assert!(dex[0].contains("needs the `exact` boundary"), "{dex:#?}");
    // Eight bytes is long enough, and a short token may be exact.
    compiled(&files(&[(
        "sdk/sentry.toml",
        &with_match(r#"content_literal = [{ lit = "abcdefgh", at = "none" }]"#),
    )]));
    compiled(&files(&[(
        "sdk/sentry.toml",
        &with_match(r#"dex_string = [{ lit = "abc", at = "exact" }]"#),
    )]));
    // Table matchers are not content matchers; their tokens may be short.
    compiled(&files(&[("sdk/sentry.toml", &with_match(r#"npm_package = ["ws"]"#))]));
}

#[test]
fn bare_brand_domains_are_rejected_as_content_tokens() {
    for domain in [
        "doubleclick.net",
        ".google.com",
        "google-analytics.com",
        "example.co.uk",
        "googleapis.com",
        "DoubleClick.NET",
    ] {
        let table = format!(r#"content_literal = [{{ lit = "{domain}", at = "host" }}]"#);
        let problems = problems_for(&with_match(&table));
        assert_one(&problems, "bare registrable domain");
    }
    // Specific endpoints, and dotted identifiers that are not domains.
    for fine in [
        "us.i.posthog.com",
        "firebase-settings.crashlytics.com",
        "firebaseinstallations.googleapis.com",
        "api.example.co.uk",
        "sentry.javascript.",
        "posthog.capture",
        "com.google.firebase.crashlytics",
    ] {
        let table = format!(r#"content_literal = [{{ lit = "{fine}", at = "word" }}]"#);
        compiled(&files(&[("sdk/sentry.toml", &with_match(&table))]));
    }
    // A privacy manifest declares tracking domains; a bare one is expected there.
    compiled(&files(&[(
        "sdk/sentry.toml",
        &with_match(r#"privacy_manifest = ["doubleclick.net"]"#),
    )]));
}

#[test]
fn content_tokens_must_state_their_boundary() {
    let problems = problems_for(&with_match(r#"content_literal = ["sentry.javascript."]"#));
    assert_one(&problems, "must state its boundary");
}

#[test]
fn a_boundary_must_suit_its_matcher() {
    let problems = problems_for(&with_match(
        r#"apple_framework = [{ lit = "Sentry.framework", at = "none" }]"#,
    ));
    assert_one(
        &problems,
        "apple_framework token `Sentry.framework` cannot use the `none` boundary",
    );
    let problems = problems_for(&with_match(
        r#"content_literal = [{ lit = "sentry.javascript.", at = "prefix" }]"#,
    ));
    assert_one(&problems, "cannot use the `prefix` boundary");
    let problems = problems_for(&with_match(
        r#"content_literal = [{ lit = "sentry.javascript.", at = "regex" }]"#,
    ));
    assert_one(&problems, "unknown boundary `regex`");
}

#[test]
fn malformed_tokens_and_tables_are_rejected() {
    assert_one(&problems_for(&with_match(r#"npm_package = ["has space"]"#)), "printable ASCII");
    assert_one(&problems_for(&with_match(r#"npm_package = [""]"#)), "printable ASCII");
    assert_one(&problems_for(&with_match(r#"npm_package = ["café"]"#)), "printable ASCII");
    assert_one(
        &problems_for(&with_match(r#"npm_package = [7]"#)),
        "must be a string or a { lit, at } table",
    );
    assert_one(&problems_for(&with_match(r#"npm_package = "left-pad""#)), "must be an array");
    assert_one(&problems_for(&with_match(r#"npm_package = []"#)), "has no tokens");
    assert_one(&problems_for(&with_match(r#"npm_package = ["a", "a"]"#)), "lists token `a` twice");
    assert_one(
        &problems_for(&with_match(
            r#"content_literal = [{ lit = "sentry.javascript.", at = "word", extra = 1 }]"#,
        )),
        "must be exactly { lit",
    );
    assert_one(&problems_for(&with_match(r#"regex = ["sentry.*"]"#)), "unknown matcher `regex`");
    assert_one(&problems_for(&with_match("")), "has no tokens");
}

#[test]
fn min_distinct_is_checked() {
    let rule = |minimum: &str| {
        with_match(&format!(
            "macho_token = [{{ lit = \"SentryCrashMonitor\", at = \"word\" }}, {{ lit = \"SentryAppStartTracker\", at = \"word\" }}]\n\
             min_distinct = {minimum}"
        ))
    };
    assert_one(&problems_for(&rule("{ macho_token = 3 }")), "min_distinct for macho_token");
    assert_one(&problems_for(&rule("{ macho_token = 1 }")), "min_distinct for macho_token");
    assert_one(&problems_for(&rule("{ dex_string = 2 }")), "min_distinct for dex_string");
    assert_one(&problems_for(&rule("{ nonsense = 2 }")), "unknown matcher `nonsense`");
    assert_one(&problems_for(&rule("{ macho_token = \"two\" }")), "must be a whole number");
    assert_one(&problems_for(&rule("2")), "must be a table");
}

#[test]
fn a_rule_names_an_entity_or_is_a_component() {
    let neither = SENTRY.replace("entity = \"sentry\"\n", "");
    assert_one(&problems_for(&neither), "name the `entity`");
    let both = SENTRY.replace("entity = \"sentry\"\n", "entity = \"sentry\"\ncomponent = true\n");
    assert_one(&problems_for(&both), "not both");
}

#[test]
fn ids_sources_and_notes_are_checked() {
    assert_one(
        &problems_for(&SENTRY.replace("sdk/sentry", "sdk/sentri")),
        "must be `sdk/sentry` to match the file name",
    );
    assert_one(
        &problems_for(
            &SENTRY.replace(r#"["https://example.com/b", "https://example.com/a"]"#, "[]"),
        ),
        "cite at least one source",
    );
    assert_one(
        &problems_for(&SENTRY.replace("https://example.com/b", "http://example.com/b")),
        "must be an https:// URL",
    );
    assert_one(&problems_for(&SENTRY.replace("note:two", "Has Spaces")), "note `Has Spaces`");
    assert_one(&problems_for(&SENTRY.replace("name = \"Sentry\"", "nmae = \"Sentry\"")), "nmae");
}

#[test]
fn references_must_resolve() {
    assert_one(
        &problems_for(&SENTRY.replace("entity = \"sentry\"", "entity = \"nobody\"")),
        "unknown entity `nobody`",
    );
    assert_one(
        &problems_for(&SENTRY.replace("crash_reporting", "astrology")),
        "unknown category `astrology`",
    );
}

#[test]
fn two_rules_cannot_claim_one_token() {
    let thief = SPARKLE.replace("Sparkle.framework", "Sentry.framework");
    let files = files(&[("sdk/sentry.toml", SENTRY), ("sdk/sparkle.toml", &thief)]);
    let problems = problems(&files);
    assert_one(
        &problems,
        "apple_framework token `Sentry.framework` is already claimed by `sdk/sentry`",
    );
}

#[test]
fn entities_need_https_sources() {
    let entities = ENTITIES.replace("https://sentry.io/terms/", "see wikipedia");
    let files = [
        SourceFile { path: "pack.toml", text: PACK },
        SourceFile { path: "entities.toml", text: &entities },
        SourceFile { path: "sdk/sparkle.toml", text: SPARKLE },
    ];
    assert_one(&problems(&files), "source `see wikipedia` must be an https:// URL");

    let sourceless = ENTITIES.replace("source = \"https://sentry.io/terms/\"\n", "");
    let files = [
        SourceFile { path: "pack.toml", text: PACK },
        SourceFile { path: "entities.toml", text: &sourceless },
        SourceFile { path: "sdk/sparkle.toml", text: SPARKLE },
    ];
    assert_one(&problems(&files), "source");
}

#[test]
fn the_layer_files_themselves_are_checked() {
    let no_pack = [SourceFile { path: "entities.toml", text: ENTITIES }];
    assert_one(&problems(&no_pack), "pack.toml: missing");

    let mut stray = good();
    stray.push(SourceFile { path: "sdk/nested/x.toml", text: SPARKLE });
    assert_one(&problems(&stray), "unexpected file");

    let mut twice = good();
    twice.push(SourceFile { path: "sdk/sparkle.toml", text: SPARKLE });
    assert_one(&problems(&twice), "listed more than once");

    let zero = PACK.replace("version = 3", "version = 0");
    let files = [
        SourceFile { path: "pack.toml", text: &zero },
        SourceFile { path: "sdk/sparkle.toml", text: SPARKLE },
    ];
    assert_one(&problems(&files), "version must be at least 1");

    let broken = [SourceFile { path: "pack.toml", text: "layer = " }];
    assert_eq!(problems(&broken).len(), 1);
}

#[test]
fn fixtures_are_checked_and_stay_out_of_the_compiled_layer() {
    let fixture = |sha: &str, expect: &str| {
        format!(
            "{SENTRY}\n[[fixture]]\nsha256 = \"{sha}\"\nurl = \"https://example.com/app.zip\"\nexpect = [{expect}]\n"
        )
    };
    let sha = "8aa0e5bf089ace014976eb8cae42a857ceb0604a7d2f00870419a3f03c588293";
    compiled(&files(&[("sdk/sentry.toml", &fixture(sha, "\"content_literal\""))]));

    assert_one(&problems_for(&fixture("8AA0", "\"content_literal\"")), "64 lowercase hex");
    assert_one(&problems_for(&fixture(sha, "\"dex_string\"")), "which the rule has no tokens for");
    assert_one(&problems_for(&fixture(sha, "\"guesswork\"")), "unknown matcher `guesswork`");
    assert_one(&problems_for(&fixture(sha, "")), "at least one matcher");

    // Fixtures stay out of the compiled layer; they are for CI.
    let with = compiled(&files(&[("sdk/sentry.toml", &fixture(sha, "\"content_literal\""))]));
    let without = compiled(&files(&[("sdk/sentry.toml", SENTRY)]));
    assert_eq!(with.bytes, without.bytes);
}

#[test]
fn every_problem_is_reported_at_once_in_a_fixed_order() {
    let bad_sentry = with_match(
        r#"content_literal = [{ lit = "abcde", at = "none" }, { lit = "doubleclick.net", at = "host" }]"#,
    );
    let bad_sparkle = SPARKLE.replace("component = true\n", "");
    let forward = files(&[("sdk/sentry.toml", &bad_sentry), ("sdk/sparkle.toml", &bad_sparkle)]);
    let mut backward = forward.clone();
    backward.reverse();

    let found = problems(&forward);
    assert_eq!(found.len(), 3, "{found:#?}");
    assert_eq!(found, problems(&backward));
    assert!(found.is_sorted());
}
