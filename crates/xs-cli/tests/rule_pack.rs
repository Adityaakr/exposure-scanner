//! The rules of the built-in pack against the match engine.
//!
//! Two kinds of test. The first is table-driven: every token of every rule
//! is handed to the engine in the shape its matcher reads, and must find that
//! rule and no other. The second holds the shapes seen in real apps: what an
//! SDK leaves in an app that ships it, and look-alikes in apps that do not.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, reason = "test code")]

use xs_match::{ContentMatcher as _, Held, HitAcc, Matchers, Verdict};
use xs_model::matcher::Boundary;
use xs_model::pack::{Rule, Token};
use xs_model::record::Scope;
use xs_model::{MatcherKind, Pack};
use xs_rules::{SignedLayer, TRUSTED_KEYS};

const PACK: &[u8] = include_bytes!("../../../rules/dist/core.pack.json");
const SIGNATURE: &str = include_str!("../../../rules/dist/core.pack.json.minisig");

fn pack() -> Pack {
    xs_rules::load_pack(&[SignedLayer { bytes: PACK, signature: SIGNATURE }], TRUSTED_KEYS).unwrap()
}

/// A value of the kind `matcher` reads that `token` must hit.
fn value_for(matcher: MatcherKind, token: &Token) -> String {
    let lit = &token.lit;
    match (matcher, token.at) {
        (_, Boundary::Exact) => lit.clone(),
        (_, Boundary::Prefix) => format!("{lit}Example"),
        (MatcherKind::PrivacyManifest, Boundary::Host) => lit.clone(),
        (_, Boundary::Host) => format!("https://{lit}/v1/batch"),
        (_, Boundary::Word) => format!("var k=\"{lit}\";"),
        (_, Boundary::None) => format!("x{lit}x"),
    }
}

/// Feeds `values` to the engine the way a collector would: as entries of a
/// table, or as the bytes of one script or binary.
fn hits(matchers: &Matchers<'_>, matcher: MatcherKind, values: &[String]) -> HitAcc {
    let mut hits = HitAcc::new();
    match matcher {
        MatcherKind::ContentLiteral | MatcherKind::MachoToken => {
            let file: String = values.join("\n");
            matchers.content(matcher, Scope::AppCode).scan(file.as_bytes(), 0, true, &mut hits);
        }
        _ => {
            for value in values {
                matchers.match_value(matcher, Scope::AppCode, value.as_bytes(), &mut hits);
            }
        }
    }
    hits
}

fn verdict<'p>(matchers: &Matchers<'p>, matcher: MatcherKind, values: &[&str]) -> Verdict<'p> {
    let values: Vec<String> = values.iter().map(ToString::to_string).collect();
    matchers.judge(&hits(matchers, matcher, &values))
}

/// The rule ids of a verdict's edges, sorted and without repeats.
fn found(verdict: &Verdict<'_>) -> Vec<String> {
    let mut ids: Vec<String> = verdict.edges.iter().map(|edge| edge.rule.id.clone()).collect();
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn every_token_finds_its_own_rule_and_no_other() {
    let pack = pack();
    let matchers = Matchers::build(&pack).unwrap();
    let mut checked = 0;
    for rule in pack.rules() {
        for (&matcher, tokens) in &rule.matchers {
            let minimum = rule.min_distinct.get(&matcher).copied().unwrap_or(1);
            for token in tokens {
                // A kind with a minimum is only evidence with that many
                // different tokens, so the others come along.
                let mut values = vec![value_for(matcher, token)];
                if minimum > 1 {
                    values.extend(
                        tokens
                            .iter()
                            .filter(|other| *other != token)
                            .map(|t| value_for(matcher, t)),
                    );
                }
                let verdict = matchers.judge(&hits(&matchers, matcher, &values));
                let what = format!("{} {matcher} `{}`", rule.id, token.lit);
                assert!(
                    verdict.edges.iter().any(|edge| edge.rule.id == rule.id && edge.token == token),
                    "{what} found nothing: {verdict:?}"
                );
                assert_eq!(
                    found(&verdict),
                    std::slice::from_ref(&rule.id),
                    "{what} also found another rule"
                );
                checked += 1;
            }
        }
    }
    let tokens: usize =
        pack.rules().map(|rule| rule.matchers.values().map(Vec::len).sum::<usize>()).sum();
    assert_eq!(checked, tokens);
}

#[test]
fn a_rule_with_a_minimum_needs_that_many_different_tokens() {
    let pack = pack();
    let matchers = Matchers::build(&pack).unwrap();
    let limited: Vec<(&Rule, MatcherKind, u32)> = pack
        .rules()
        .flat_map(|rule| rule.min_distinct.iter().map(move |(&kind, &min)| (rule, kind, min)))
        .filter(|&(_, _, min)| min > 1)
        .collect();
    assert!(!limited.is_empty());
    for (rule, matcher, minimum) in limited {
        let tokens = &rule.matchers[&matcher];
        assert!(tokens.len() >= usize::try_from(minimum).unwrap(), "{}: unreachable", rule.id);
        let one = [value_for(matcher, &tokens[0])];
        let verdict = matchers.judge(&hits(&matchers, matcher, &one));
        assert!(verdict.edges.is_empty(), "{} {matcher}: one token is evidence", rule.id);
        assert!(verdict.mentions.iter().all(|mention| mention.held == Held::BelowMinimum));
    }
}

/// Every company a rule names exists, and these ownership chains end where
/// the companies' own pages say they do.
#[test]
fn rules_name_the_company_at_the_top_of_the_chain() {
    let pack = pack();
    for rule in pack.rules() {
        if let Some(entity) = &rule.entity {
            assert!(pack.company_of(entity).is_some(), "{}: no entity `{entity}`", rule.id);
        }
        assert!(pack.category(&rule.category).is_some(), "{}", rule.id);
    }
    let company = |rule: &str| {
        let entity = pack.rule(rule).unwrap().entity.as_deref().unwrap();
        pack.company_of(entity).unwrap().id.as_str()
    };
    for (rule, owner) in [
        ("sdk/segment", "twilio"),
        ("sdk/heap", "contentsquare"),
        ("sdk/hotjar", "contentsquare"),
        ("sdk/statsig", "openai"),
        ("sdk/bugsnag", "smartbear"),
        ("sdk/smartlook", "cisco"),
        ("sdk/ironsource", "unity"),
        ("sdk/unity-ads", "unity"),
        ("sdk/facebook-sdk", "meta"),
        ("sdk/google-analytics", "google"),
        ("sdk/google-mobile-ads", "google"),
        ("sdk/adjust", "adjust"),
    ] {
        assert_eq!(company(rule), owner, "{rule}");
    }
    for updater in ["sdk/electron-updater", "sdk/sparkle", "sdk/squirrel"] {
        let rule = pack.rule(updater).unwrap();
        assert_eq!((rule.entity.as_deref(), rule.category.as_str()), (None, "component"));
    }
}

/// What the SDKs leave in apps installed on the machine the rules were
/// tested on: cmux links PostHog's Swift SDK statically, Claude bundles
/// Datadog's browser SDK, Cursor bundles Statsig's, and Trezor Suite bundles
/// electron-updater.
#[test]
fn what_real_apps_ship_is_found() {
    let pack = pack();
    let matchers = Matchers::build(&pack).unwrap();
    let cases: [(MatcherKind, &[&str], &str); 5] = [
        (
            MatcherKind::MachoObjcClass,
            &[
                "_TtC7PostHogP33_DC4B16F10C10C26A57103DC459BDBEE712BundleFinder",
                "PostHogPropertiesSanitizer",
                // The app's own wrapper, in its own module: not a token.
                "_TtC4cmux16PostHogAnalytics",
            ],
            "sdk/posthog",
        ),
        (
            MatcherKind::MachoToken,
            &["\0https://us.i.posthog.com\0https://eu.i.posthog.com\0"],
            "sdk/posthog",
        ),
        (
            MatcherKind::ContentLiteral,
            &[r#"t.sdkName="browser-rum-sdk",t.cookieTest="dd_cookie_test_""#],
            "sdk/datadog-rum",
        ),
        (
            MatcherKind::ContentLiteral,
            &[concat!(
                r#"const a="https://api.statsigcdn.com/v1",b="featureassets.org/v1","#,
                r#"c="prodregistryv2.org/v1",d="https://statsigapi.net/v1/rgstr""#,
            )],
            "sdk/statsig",
        ),
        (
            MatcherKind::ContentLiteral,
            &[r#"path.join(process.resourcesPath,"app-update.yml")"#],
            "sdk/electron-updater",
        ),
    ];
    for (matcher, values, rule) in cases {
        assert_eq!(found(&verdict(&matchers, matcher, values)), [rule], "{values:?}");
    }
}

/// Look-alikes from apps that do not ship the SDK. Each one was a finding
/// while the rules were written, and is not one now.
#[test]
fn what_only_resembles_an_sdk_is_not_found() {
    let pack = pack();
    let matchers = Matchers::build(&pack).unwrap();
    let cases: [(MatcherKind, &[&str]); 10] = [
        // Dia names a module of its own TelemetryClient, the name of
        // TelemetryDeck's older module, and Segment is a common word.
        (
            MatcherKind::MachoObjcClass,
            &[
                "_TtC15TelemetryClient14DataDogUtility",
                "_TtC15TelemetryClient21DataDogTracingBackend",
                "_TtC7Segment12SegmentedBar",
            ],
        ),
        // A plain word or bare brand word can be an app's own class name.
        (MatcherKind::MachoObjcClass, &["Intercom", "OSNotification", "UnityAds", "UXCam"]),
        (MatcherKind::AppleFramework, &["TelemetryClient.framework", "Segment.framework"]),
        // NewPipe, which shows no ads, has an ad host among its strings.
        (
            MatcherKind::DexString,
            &["https://googleads.g.doubleclick.net/pagead/id", "pagead2.googlesyndication.com"],
        ),
        // One endpoint string of an ad network is not enough.
        (MatcherKind::DexString, &["https://ms.applovin.com/"]),
        (MatcherKind::MachoToken, &["https://ms.applovin.com/"]),
        (MatcherKind::ContentLiteral, &["https://api2.branch.io/v1/open"]),
        // Grok labels its own pages for Datadog's SDK without shipping it.
        (
            MatcherKind::ContentLiteral,
            &[r#"e["data-dd-action-name"]=n;e["data-dd-privacy"]="mask""#],
        ),
        // Claude keeps a table of vendors' bare domains to label traffic.
        (
            MatcherKind::ContentLiteral,
            &[concat!(
                r#"[["intercom.io","intercom"],["intercomcdn.com","intercom"],"#,
                r#"["segment.com","segment"],["mixpanel.com","mixpanel"],"#,
                r#"["statsig.com","statsig"],["amplitude.com","amplitude"]]"#,
            )],
        ),
        // A single storage key of Countly's web SDK.
        (MatcherKind::ContentLiteral, &[r#"localStorage.getItem("cly_queue")"#]),
    ];
    for (matcher, values) in cases {
        let verdict = verdict(&matchers, matcher, values);
        assert!(verdict.edges.is_empty(), "{matcher} {values:?}: {:?}", found(&verdict));
    }
}

/// A host token sits on hostname boundaries, so a host that only continues
/// its literal, or one the literal only ends, is not that endpoint.
#[test]
fn host_tokens_hold_their_boundary() {
    let pack = pack();
    let matchers = Matchers::build(&pack).unwrap();
    for rule in pack.rules() {
        for matcher in
            [MatcherKind::ContentLiteral, MatcherKind::MachoToken, MatcherKind::DexString]
        {
            for token in rule.matchers.get(&matcher).into_iter().flatten() {
                if token.at != Boundary::Host {
                    continue;
                }
                let lit = &token.lit;
                let decoys = [
                    format!("https://{lit}.evil.example/"),
                    format!("https://x{lit}/"),
                    format!("{lit}x"),
                ];
                // Another token may name a parent of the decoy, as
                // `i.posthog.com` does of `xus.i.posthog.com`; that one is
                // right to hit. This token must not.
                let verdict = matchers.judge(&hits(&matchers, matcher, &decoys));
                assert!(
                    !verdict.edges.iter().any(|edge| edge.token == token),
                    "{} {matcher} `{lit}` hit a host it does not name",
                    rule.id
                );
            }
        }
    }
}
