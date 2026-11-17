//! The match engine against the signed seed pack.
//!
//! The collectors that feed file contents to the engine arrive in later
//! tasks. These tests hand it the kind of bytes and names those collectors
//! will read, so that the seed rules and the engine are known to agree
//! before a collector is written against them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]

use xs_match::{ContentMatcher as _, HitAcc, Matchers, Verdict};
use xs_model::record::Scope;
use xs_model::{MatcherKind, Pack};
use xs_rules::{SignedLayer, TRUSTED_KEYS};

const PACK: &[u8] = include_bytes!("../../../rules/dist/core.pack.json");
const SIGNATURE: &str = include_str!("../../../rules/dist/core.pack.json.minisig");

fn seed_pack() -> Pack {
    xs_rules::load_pack(&[SignedLayer { bytes: PACK, signature: SIGNATURE }], TRUSTED_KEYS).unwrap()
}

/// Searches `script` as the text of a file of `scope`, cut into windows of
/// `window` fresh bytes the way the file reader cuts a file.
fn script_verdict<'p>(
    matchers: &Matchers<'p>,
    scope: Scope,
    script: &[u8],
    window: usize,
) -> Verdict<'p> {
    let engine = matchers.content(MatcherKind::ContentLiteral, scope);
    let mut hits = HitAcc::new();
    let mut read = 0;
    loop {
        let fresh = (script.len() - read).min(window);
        let carry = engine.overlap().min(read);
        let last = fresh < window;
        engine.scan(&script[read - carry..read + fresh], carry, last, &mut hits);
        read += fresh;
        if last {
            break;
        }
    }
    matchers.judge(&hits, scope)
}

/// `rule token count` for every edge of a verdict.
fn edges(verdict: &Verdict<'_>) -> Vec<String> {
    verdict
        .edges
        .iter()
        .map(|edge| format!("{} {} {}", edge.rule.id, edge.token.lit, edge.count))
        .collect()
}

/// What a bundler leaves of the Sentry and PostHog browser SDKs: the SDK
/// name template and the default ingestion hosts survive as string literals.
const BUNDLE: &str = concat!(
    r#"var e={api_host:"https://us.i.posthog.com",ui_host:null};"#,
    r#"function t(n){return{name:`sentry.javascript.${n}`,version:"8.0.0"}}"#,
    r#"fetch("https://eu.i.posthog.com/batch/")"#,
);

#[test]
fn the_seed_pack_compiles_into_matchers() {
    let pack = seed_pack();
    let matchers = Matchers::build(&pack).unwrap();
    let tokens: usize =
        pack.rules().map(|rule| rule.matchers.values().map(Vec::len).sum::<usize>()).sum();
    assert_eq!(matchers.pattern_count(), tokens);
    assert!(!matchers.content(MatcherKind::ContentLiteral, Scope::AppCode).is_empty());
    assert!(!matchers.content(MatcherKind::DexString, Scope::AppCode).is_empty());
}

#[test]
fn a_bundled_script_gives_sentry_and_posthog_whatever_the_window() {
    let pack = seed_pack();
    let matchers = Matchers::build(&pack).unwrap();
    let whole = script_verdict(&matchers, Scope::AppCode, BUNDLE.as_bytes(), BUNDLE.len() + 1);
    assert_eq!(
        edges(&whole),
        [
            "sdk/posthog i.posthog.com 2",
            "sdk/posthog us.i.posthog.com 1",
            "sdk/sentry sentry.javascript. 1",
        ]
    );
    assert!(whole.mentions.is_empty());
    for window in 1..=BUNDLE.len() {
        let chunked = script_verdict(&matchers, Scope::AppCode, BUNDLE.as_bytes(), window);
        assert_eq!(chunked, whole, "window {window}");
    }
}

#[test]
fn the_same_script_inside_a_runtime_gives_nothing() {
    let pack = seed_pack();
    let matchers = Matchers::build(&pack).unwrap();
    for scope in [Scope::Dependency, Scope::Resource] {
        assert_eq!(script_verdict(&matchers, scope, BUNDLE.as_bytes(), 64).edges.len(), 3);
    }
    let verdict = script_verdict(&matchers, Scope::Runtime, BUNDLE.as_bytes(), 64);
    assert_eq!(verdict, Verdict::default());
}

#[test]
fn look_alike_text_gives_nothing() {
    let pack = seed_pack();
    let matchers = Matchers::build(&pack).unwrap();
    let decoys = concat!(
        r#"a="https://us.i.posthog.community";b="xi.posthog.com";"#,
        r#"c="https://us.i.posthog.com.evil.example";d="cdn-i.posthog.com";"#,
        r#"e="sentry.javascript.browser";f="nosentry.javascript.";g="SENTRY.JAVASCRIPT.";"#,
    );
    let verdict = script_verdict(&matchers, Scope::AppCode, decoys.as_bytes(), 16);
    assert_eq!(verdict, Verdict::default());
}

#[test]
fn android_tables_give_the_sdks_their_names_and_strings_belong_to() {
    let pack = seed_pack();
    let matchers = Matchers::build(&pack).unwrap();
    let scope = Scope::AppCode;
    let mut hits = HitAcc::new();
    for class in [
        "io.sentry.Sentry",
        "io.sentry.android.core.SentryAndroid",
        "com.posthog.android.PostHogAndroid",
        // A server-side SDK of the same vendor, and names that only resemble.
        "com.posthog.server.PostHog",
        "com.example.io.sentry.Fake",
        "io.sentryx.Sentry",
    ] {
        matchers.match_value(MatcherKind::AndroidClassPrefix, scope, class.as_bytes(), &mut hits);
    }
    for component in ["io.sentry.android.core.SentryInitProvider", "com.example.MainActivity"] {
        matchers.match_value(
            MatcherKind::ManifestComponent,
            scope,
            component.as_bytes(),
            &mut hits,
        );
    }
    for string in ["https://us.i.posthog.com", "us.i.posthog.com.evil.example", "posthog"] {
        matchers.match_value(MatcherKind::DexString, scope, string.as_bytes(), &mut hits);
    }

    let verdict = matchers.judge(&hits, scope);
    assert!(verdict.mentions.is_empty());
    let found: Vec<String> = verdict
        .edges
        .iter()
        .map(|edge| {
            let example = edge.example.as_deref().unwrap();
            format!("{} {} {} {example}", edge.matcher, edge.token.lit, edge.count)
        })
        .collect();
    assert_eq!(
        found,
        [
            "android_class_prefix com.posthog.android. 1 com.posthog.android.PostHogAndroid",
            "dex_string us.i.posthog.com 1 https://us.i.posthog.com",
            "manifest_component io.sentry.android.core.SentryInitProvider 1 \
             io.sentry.android.core.SentryInitProvider",
            "android_class_prefix io.sentry. 2 io.sentry.Sentry",
        ]
    );
}
