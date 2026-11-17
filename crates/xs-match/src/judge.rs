//! From hits to evidence: the controls that need the whole haystack.
//!
//! A hit says that a token was found. Whether that is evidence of an SDK
//! depends on what else the same haystack holds (design report, section
//! 5.2). Two of the false-positive controls can only be applied once a
//! haystack has been searched to the end, and they are applied here, in one
//! place, for every collector:
//!
//! * **Breadth guard** (control 4). A file that names eight or more companies
//!   in its free-form bytes is a list, such as the filter list of an ad
//!   blocker, and not code that talks to all of them. In the lab run one 129
//!   KB script named 25 ad and analytics domains.
//! * **Distinct-token minimum** (control 5). A rule may demand that several
//!   different tokens of one matcher kind hit before that kind counts, so a
//!   single coincidental string proves nothing.
//!
//! The scope control (control 1) is applied before the search, by
//! [`Matchers::content`](crate::Matchers::content), and checked again here.
//!
//! A hit that a control holds back is a **mention**: it is reported to the
//! collector with the reason, and it must never become an edge.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use xs_model::matcher::MatcherKind;
use xs_model::pack::{Rule, Token};
use xs_model::record::Scope;
use xs_model::text;

use crate::hits::HitAcc;
use crate::matchers::{Matchers, TokenRef, applies};

/// A haystack whose content hits name this many companies or more is
/// list-like.
pub const BREADTH_LIMIT: usize = 8;

/// One token that was found in a haystack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding<'p> {
    /// The rule the token belongs to.
    pub rule: &'p Rule,
    /// The kind of witness.
    pub matcher: MatcherKind,
    /// The token.
    pub token: &'p Token,
    /// How often it was found: occurrences in free-form bytes, or matching
    /// entries of a table.
    pub count: u32,
    /// For a table, the smallest entry that matched, cleaned and cut to what
    /// a record may carry. Free-form bytes are never copied.
    pub example: Option<String>,
}

/// Why a hit is not evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Held {
    /// A content matcher hit in a runtime file, where content matchers do
    /// not apply.
    Runtime,
    /// The haystack names [`BREADTH_LIMIT`] companies or more, so it is a
    /// list and not code that uses them.
    ListLike,
    /// Fewer different tokens of the rule hit than its `min_distinct` asks
    /// of this matcher kind.
    BelowMinimum,
}

/// A hit that was held back, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mention<'p> {
    /// What was found.
    pub finding: Finding<'p>,
    /// The control that held it back.
    pub held: Held,
}

/// What the hits of one haystack are evidence of.
///
/// Both lists are in pattern order: by rule id, then matcher kind, then the
/// order of the tokens in the rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict<'p> {
    /// Hits that are evidence. Each one supports an edge record.
    pub edges: Vec<Finding<'p>>,
    /// Hits that are not evidence. None of them may become an edge.
    pub mentions: Vec<Mention<'p>>,
}

impl Verdict<'_> {
    /// Whether the breadth guard found the haystack to be a list.
    #[must_use]
    pub fn is_list_like(&self) -> bool {
        self.mentions.iter().any(|mention| mention.held == Held::ListLike)
    }
}

pub(crate) fn judge<'p>(matchers: &Matchers<'p>, hits: &HitAcc, scope: Scope) -> Verdict<'p> {
    // An id from another pack's matchers has no token here and is dropped.
    let found: Vec<(TokenRef<'p>, Finding<'p>)> = hits
        .iter()
        .filter_map(|(pattern, count)| {
            let token = matchers.pattern(pattern)?;
            let example = hits
                .example(pattern)
                .map(|bytes| text::clean(&String::from_utf8_lossy(bytes), text::MAX_EXAMPLE_BYTES));
            let finding = Finding {
                rule: token.rule,
                matcher: token.matcher,
                token: token.token,
                count,
                example,
            };
            Some((token, finding))
        })
        .collect();
    let searched = |token: &TokenRef<'_>| applies(token.matcher, scope);

    // Breadth is a property of the haystack, so it is measured on every
    // content hit, also on those a minimum would hold back. A company is the
    // top of an ownership chain: Firebase and Google are one. A component
    // has no company and adds no breadth.
    let companies: BTreeSet<&str> = found
        .iter()
        .filter(|(token, _)| token.matcher.is_content() && searched(token))
        .filter_map(|(token, _)| matchers.pack().company_of(token.rule.entity.as_deref()?))
        .map(|company| company.id.as_str())
        .collect();
    let list_like = companies.len() >= BREADTH_LIMIT;

    // Tokens are unique within a rule and matcher kind, and the accumulator
    // holds each pattern once, so this counts different tokens.
    let mut distinct: BTreeMap<(&str, MatcherKind), u32> = BTreeMap::new();
    for (token, _) in found.iter().filter(|(token, _)| searched(token)) {
        let count = distinct.entry((token.rule.id.as_str(), token.matcher)).or_insert(0);
        *count = count.saturating_add(1);
    }

    let mut verdict = Verdict::default();
    for (token, finding) in found {
        let minimum = token.rule.min_distinct.get(&token.matcher).copied().unwrap_or(1);
        let hit = distinct.get(&(token.rule.id.as_str(), token.matcher)).copied().unwrap_or(0);
        let held = if !searched(&token) {
            Some(Held::Runtime)
        } else if list_like && token.matcher.is_content() {
            Some(Held::ListLike)
        } else if hit < minimum {
            Some(Held::BelowMinimum)
        } else {
            None
        };
        match held {
            Some(held) => verdict.mentions.push(Mention { finding, held }),
            None => verdict.edges.push(finding),
        }
    }
    verdict
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;

    use xs_model::Pack;
    use xs_model::matcher::Boundary;
    use xs_model::pack::Entity;

    use super::*;
    use crate::content::ContentMatcher as _;
    use crate::testkit::{entity, pack_of, rule};

    const SCRIPT: Scope = Scope::AppCode;

    /// Ten rules `sdk/vendor-0` to `sdk/vendor-9`, each with its own company
    /// and one script literal `collect.vendor-N.example`.
    fn vendors() -> Pack {
        let entities: Vec<Entity> = (0..10).map(|n| entity(&format!("vendor-{n}"), None)).collect();
        let literals: Vec<String> =
            (0..10).map(|n| format!("collect.vendor-{n}.example")).collect();
        let rules = (0..10)
            .map(|n| {
                rule(
                    &format!("sdk/vendor-{n}"),
                    Some(&format!("vendor-{n}")),
                    &[(MatcherKind::ContentLiteral, literals[n].as_str(), Boundary::Host)],
                )
            })
            .collect();
        pack_of(entities, rules)
    }

    /// A script that names the first `count` vendors.
    fn script_naming(count: usize) -> String {
        (0..count).map(|n| format!("fetch('https://collect.vendor-{n}.example/e');\n")).collect()
    }

    fn scan(matchers: &Matchers<'_>, matcher: MatcherKind, scope: Scope, data: &[u8]) -> HitAcc {
        let mut hits = HitAcc::new();
        matchers.content(matcher, scope).scan(data, 0, true, &mut hits);
        hits
    }

    fn rule_ids<'p>(findings: impl IntoIterator<Item = &'p Finding<'p>>) -> Vec<&'p str> {
        findings.into_iter().map(|finding| finding.rule.id.as_str()).collect()
    }

    #[test]
    fn a_plain_hit_is_an_edge_with_its_count_and_no_copied_bytes() {
        let pack = vendors();
        let matchers = Matchers::build(&pack).unwrap();
        let script = "x('collect.vendor-3.example'); y('collect.vendor-3.example')";
        let hits = scan(&matchers, MatcherKind::ContentLiteral, SCRIPT, script.as_bytes());
        let verdict = matchers.judge(&hits, SCRIPT);
        assert!(verdict.mentions.is_empty());
        assert!(!verdict.is_list_like());
        assert_eq!(verdict.edges.len(), 1);
        let edge = &verdict.edges[0];
        assert_eq!(edge.rule.id, "sdk/vendor-3");
        assert_eq!(edge.matcher, MatcherKind::ContentLiteral);
        assert_eq!(edge.token.lit, "collect.vendor-3.example");
        assert_eq!(edge.count, 2);
        assert_eq!(edge.example, None);
    }

    #[test]
    fn nothing_found_is_an_empty_verdict() {
        let pack = vendors();
        let matchers = Matchers::build(&pack).unwrap();
        assert_eq!(matchers.judge(&HitAcc::new(), SCRIPT), Verdict::default());
    }

    /// Design report, section 5.2 control 4.
    #[test]
    fn a_file_naming_eight_companies_is_a_list_and_yields_no_edge() {
        let pack = vendors();
        let matchers = Matchers::build(&pack).unwrap();
        for count in 0..=10 {
            let script = script_naming(count);
            let hits = scan(&matchers, MatcherKind::ContentLiteral, SCRIPT, script.as_bytes());
            let verdict = matchers.judge(&hits, SCRIPT);
            if count >= BREADTH_LIMIT {
                assert!(verdict.is_list_like(), "{count} companies");
                assert!(verdict.edges.is_empty(), "{count} companies");
                assert_eq!(verdict.mentions.len(), count);
                assert!(verdict.mentions.iter().all(|mention| mention.held == Held::ListLike));
            } else {
                assert!(!verdict.is_list_like(), "{count} companies");
                assert!(verdict.mentions.is_empty(), "{count} companies");
                assert_eq!(verdict.edges.len(), count);
            }
        }
    }

    #[test]
    fn breadth_counts_companies_not_rules_tokens_or_components() {
        // Nine rules, but seven companies: two brands share a parent, and
        // one rule is a component. Each rule has two literals.
        let mut entities: Vec<Entity> =
            (0..6).map(|n| entity(&format!("vendor-{n}"), None)).collect();
        entities.push(entity("brand-a", Some("holding")));
        entities.push(entity("brand-b", Some("holding")));
        entities.push(entity("holding", None));
        let owners: [Option<&str>; 9] = [
            Some("vendor-0"),
            Some("vendor-1"),
            Some("vendor-2"),
            Some("vendor-3"),
            Some("vendor-4"),
            Some("vendor-5"),
            Some("brand-a"),
            Some("brand-b"),
            None,
        ];
        let literals: Vec<(String, String)> = (0..9)
            .map(|n| (format!("collect.sdk-{n}.example"), format!("ingest.sdk-{n}.example")))
            .collect();
        let rules = owners
            .iter()
            .enumerate()
            .map(|(n, owner)| {
                rule(
                    &format!("sdk/sdk-{n}"),
                    *owner,
                    &[
                        (MatcherKind::ContentLiteral, literals[n].0.as_str(), Boundary::Host),
                        (MatcherKind::ContentLiteral, literals[n].1.as_str(), Boundary::Host),
                    ],
                )
            })
            .collect();
        let pack = pack_of(entities, rules);
        let matchers = Matchers::build(&pack).unwrap();

        let script: String = literals.iter().map(|(a, b)| format!("'{a}' '{b}'\n")).collect();
        let hits = scan(&matchers, MatcherKind::ContentLiteral, SCRIPT, script.as_bytes());
        let verdict = matchers.judge(&hits, SCRIPT);
        // 18 tokens of 9 rules hit, from 7 companies: not a list.
        assert_eq!(verdict.edges.len(), 18);
        assert!(verdict.mentions.is_empty());
    }

    #[test]
    fn the_breadth_guard_holds_back_content_hits_only() {
        // Eight companies, each recognised by a script literal and by a
        // framework folder. An app that ships eight SDKs is not a list.
        let entities: Vec<Entity> = (0..8).map(|n| entity(&format!("vendor-{n}"), None)).collect();
        let names: Vec<(String, String)> = (0..8)
            .map(|n| (format!("collect.vendor-{n}.example"), format!("Vendor{n}.framework")))
            .collect();
        let rules = (0..8)
            .map(|n| {
                rule(
                    &format!("sdk/vendor-{n}"),
                    Some(&format!("vendor-{n}")),
                    &[
                        (MatcherKind::ContentLiteral, names[n].0.as_str(), Boundary::Host),
                        (MatcherKind::AppleFramework, names[n].1.as_str(), Boundary::Exact),
                    ],
                )
            })
            .collect();
        let pack = pack_of(entities, rules);
        let matchers = Matchers::build(&pack).unwrap();

        // Only the folders: eight edges.
        let mut folders = HitAcc::new();
        for (_, folder) in &names {
            matchers.match_value(
                MatcherKind::AppleFramework,
                Scope::Dependency,
                folder.as_bytes(),
                &mut folders,
            );
        }
        let verdict = matchers.judge(&folders, Scope::Dependency);
        assert_eq!(verdict.edges.len(), 8);
        assert!(!verdict.is_list_like());

        // Folders and a list in one accumulator: the list is held back, the
        // folders still count.
        let script: String = names.iter().map(|(host, _)| format!("||{host}^\n")).collect();
        let mut both = scan(&matchers, MatcherKind::ContentLiteral, SCRIPT, script.as_bytes());
        both.merge(&folders);
        let verdict = matchers.judge(&both, SCRIPT);
        assert!(verdict.is_list_like());
        assert_eq!(verdict.edges.len(), 8);
        assert!(verdict.edges.iter().all(|edge| edge.matcher == MatcherKind::AppleFramework));
        assert_eq!(verdict.mentions.len(), 8);
        assert!(verdict.mentions.iter().all(|mention| {
            mention.held == Held::ListLike && mention.finding.matcher == MatcherKind::ContentLiteral
        }));
    }

    /// A rule with a two-token minimum on its binary tokens and none on its
    /// class names.
    fn crashlytics() -> Pack {
        let mut crashlytics = rule(
            "sdk/firebase-crashlytics",
            None,
            &[
                (MatcherKind::MachoToken, "FIRCLSReportManager", Boundary::Word),
                (MatcherKind::MachoToken, "FIRCLSSettings", Boundary::Word),
                (MatcherKind::MachoToken, "FIRCLSExistingReportManager", Boundary::Word),
                (MatcherKind::MachoObjcClass, "FIRCrashlytics", Boundary::Exact),
            ],
        );
        crashlytics.min_distinct.insert(MatcherKind::MachoToken, 2);
        let other =
            rule("sdk/other", None, &[(MatcherKind::MachoToken, "OTHRReporter", Boundary::Word)]);
        pack_of(vec![], vec![crashlytics, other])
    }

    /// Design report, section 5.2 control 5.
    #[test]
    fn a_rule_with_a_minimum_needs_that_many_different_tokens() {
        let pack = crashlytics();
        let matchers = Matchers::build(&pack).unwrap();
        let judge = |binary: &[u8]| {
            let hits = scan(&matchers, MatcherKind::MachoToken, SCRIPT, binary);
            matchers.judge(&hits, SCRIPT)
        };

        // One token, however often, is a coincidence.
        let verdict = judge(b"FIRCLSSettings\0FIRCLSSettings\0FIRCLSSettings\0");
        assert!(verdict.edges.is_empty());
        assert_eq!(verdict.mentions.len(), 1);
        assert_eq!(verdict.mentions[0].held, Held::BelowMinimum);
        assert_eq!(verdict.mentions[0].finding.count, 3);
        assert!(!verdict.is_list_like());

        // Two different tokens fire, and both are evidence.
        let verdict = judge(b"FIRCLSSettings\0FIRCLSReportManager\0");
        assert!(verdict.mentions.is_empty());
        assert_eq!(verdict.edges.len(), 2);
        assert_eq!(
            judge(b"FIRCLSSettings\0FIRCLSReportManager\0FIRCLSExistingReportManager\0")
                .edges
                .len(),
            3
        );

        // The minimum counts tokens of the same rule. Another rule's token
        // in the same file does not help, and needs no help itself.
        let verdict = judge(b"FIRCLSSettings\0OTHRReporter\0");
        assert_eq!(rule_ids(&verdict.edges), ["sdk/other"]);
        assert_eq!(verdict.mentions.len(), 1);
        assert_eq!(verdict.mentions[0].finding.rule.id, "sdk/firebase-crashlytics");
    }

    #[test]
    fn a_minimum_is_per_matcher_kind() {
        let pack = crashlytics();
        let matchers = Matchers::build(&pack).unwrap();
        let mut hits = scan(&matchers, MatcherKind::MachoToken, SCRIPT, b"FIRCLSSettings\0");
        matchers.match_value(MatcherKind::MachoObjcClass, SCRIPT, b"FIRCrashlytics", &mut hits);
        let verdict = matchers.judge(&hits, SCRIPT);
        // The class name has no minimum and counts. It does not make up for
        // the missing second binary token.
        assert_eq!(verdict.edges.len(), 1);
        assert_eq!(verdict.edges[0].matcher, MatcherKind::MachoObjcClass);
        assert_eq!(verdict.edges[0].example.as_deref(), Some("FIRCrashlytics"));
        assert_eq!(verdict.mentions.len(), 1);
        assert_eq!(verdict.mentions[0].finding.matcher, MatcherKind::MachoToken);
        assert_eq!(verdict.mentions[0].held, Held::BelowMinimum);
    }

    #[test]
    fn a_minimum_applies_to_table_matchers_too() {
        let mut sdk = rule(
            "sdk/two-classes",
            None,
            &[
                (MatcherKind::MachoObjcClass, "TWOAlpha", Boundary::Exact),
                (MatcherKind::MachoObjcClass, "TWOBeta", Boundary::Prefix),
            ],
        );
        sdk.min_distinct.insert(MatcherKind::MachoObjcClass, 2);
        let pack = pack_of(vec![], vec![sdk]);
        let matchers = Matchers::build(&pack).unwrap();

        let mut hits = HitAcc::new();
        // Two entries, one token.
        for class in [&b"TWOBetaOne"[..], b"TWOBetaTwo"] {
            matchers.match_value(MatcherKind::MachoObjcClass, SCRIPT, class, &mut hits);
        }
        assert!(matchers.judge(&hits, SCRIPT).edges.is_empty());
        matchers.match_value(MatcherKind::MachoObjcClass, SCRIPT, b"TWOAlpha", &mut hits);
        let verdict = matchers.judge(&hits, SCRIPT);
        assert!(verdict.mentions.is_empty());
        let counts: Vec<u32> = verdict.edges.iter().map(|edge| edge.count).collect();
        assert_eq!(counts, [1, 2]);
        assert_eq!(verdict.edges[1].example.as_deref(), Some("TWOBetaOne"));
    }

    /// Design report, section 5.2 control 1, from the judging side: hits a
    /// collector gathered with the wrong scope still cannot become edges.
    #[test]
    fn content_hits_judged_as_a_runtime_file_are_held_back() {
        let pack = crashlytics();
        let matchers = Matchers::build(&pack).unwrap();
        let mut hits = scan(
            &matchers,
            MatcherKind::MachoToken,
            Scope::AppCode,
            b"FIRCLSSettings\0FIRCLSReportManager\0",
        );
        matchers.match_value(
            MatcherKind::MachoObjcClass,
            Scope::Runtime,
            b"FIRCrashlytics",
            &mut hits,
        );

        for scope in [Scope::AppCode, Scope::Dependency, Scope::Resource] {
            let verdict = matchers.judge(&hits, scope);
            assert_eq!(verdict.edges.len(), 3, "{scope:?}");
            assert!(verdict.mentions.is_empty(), "{scope:?}");
        }
        let verdict = matchers.judge(&hits, Scope::Runtime);
        assert_eq!(verdict.edges.len(), 1);
        assert_eq!(verdict.edges[0].matcher, MatcherKind::MachoObjcClass);
        assert_eq!(verdict.mentions.len(), 2);
        assert!(verdict.mentions.iter().all(|mention| mention.held == Held::Runtime));
    }

    #[test]
    fn hits_held_as_runtime_add_no_breadth_and_meet_no_minimum() {
        let pack = vendors();
        let matchers = Matchers::build(&pack).unwrap();
        let script = script_naming(10);
        let hits = scan(&matchers, MatcherKind::ContentLiteral, SCRIPT, script.as_bytes());
        let verdict = matchers.judge(&hits, Scope::Runtime);
        assert!(verdict.edges.is_empty());
        assert!(!verdict.is_list_like());
        assert!(verdict.mentions.iter().all(|mention| mention.held == Held::Runtime));
    }

    #[test]
    fn an_example_is_cleaned_and_cut_for_a_record() {
        let sdk = rule(
            "sdk/long",
            None,
            &[(MatcherKind::AndroidClassPrefix, "com.long.", Boundary::Prefix)],
        );
        let pack = pack_of(vec![], vec![sdk]);
        let matchers = Matchers::build(&pack).unwrap();
        let example = |value: &[u8]| {
            let mut hits = HitAcc::new();
            matchers.match_value(MatcherKind::AndroidClassPrefix, SCRIPT, value, &mut hits);
            matchers.judge(&hits, SCRIPT).edges.remove(0).example.unwrap()
        };

        let long = format!("com.long.{}", "x".repeat(4000));
        let cut = example(long.as_bytes());
        assert_eq!(cut, text::clean(&long, text::MAX_EXAMPLE_BYTES));
        assert!(cut.len() <= text::MAX_EXAMPLE_BYTES && cut.ends_with('…'));

        // A value of exactly the budget is kept whole, with no cut mark.
        let fits = format!("com.long.{}", "x".repeat(text::MAX_EXAMPLE_BYTES - 9));
        assert_eq!(example(fits.as_bytes()), fits);

        // Bytes that are not text, and text that would disturb a terminal.
        let hostile = example(b"com.long.\x1b[31m\xff\xfe");
        assert!(text::is_clean(&hostile, text::MAX_EXAMPLE_BYTES), "{hostile:?}");
        assert!(hostile.starts_with("com.long."));
    }

    #[test]
    fn ids_from_other_matchers_are_dropped() {
        let pack = crashlytics();
        let matchers = Matchers::build(&pack).unwrap();
        let mut hits = HitAcc::new();
        hits.hit(crate::PatternId(4000));
        assert_eq!(matchers.judge(&hits, SCRIPT), Verdict::default());
    }
}
