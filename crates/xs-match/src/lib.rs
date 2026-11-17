//! Matchers compiled from a rule pack, and the hits they collect.
//!
//! Two shapes of matcher exist (design report, section 5.1):
//!
//! * **Table matchers** look a parsed name up in a table: a framework folder
//!   name, a class name, a zip entry name. A parsed table is a small haystack,
//!   gives exact rather than substring matches, and yields a proof a reader
//!   can verify with standard tools. [`ExactTable`] is the first of these.
//! * **Content matchers** search free-form bytes for literals. They implement
//!   [`ContentMatcher`], the seam between the file reader and the search
//!   engine, so the engine can change without touching a collector.
//!
//! The content engine itself (Aho-Corasick over a contiguous NFA, with
//! boundary rules and distinct-token minimums) is task 5 of the build plan.
//! Until then [`NoContent`] stands in for it, and the reader's windowing is
//! already exercised against the trait.
//!
//! The crate is `no_std`: matching is a pure function of bytes and the pack.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use xs_model::matcher::{Boundary, MatcherKind};
use xs_model::pack::{Pack, Rule, Token};

/// A rule token found in a pack: the token and the rule it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRef<'p> {
    /// The rule the token belongs to.
    pub rule: &'p Rule,
    /// The token.
    pub token: &'p Token,
}

/// Tokens that match a value only when the value equals the literal.
#[derive(Debug, Clone, Default)]
pub struct ExactTable<'p> {
    entries: BTreeMap<&'p str, Vec<TokenRef<'p>>>,
}

impl<'p> ExactTable<'p> {
    /// The tokens equal to `value`, in rule-id order. Usually none or one.
    #[must_use]
    pub fn lookup(&self, value: &str) -> &[TokenRef<'p>] {
        self.entries.get(value).map_or(&[], Vec::as_slice)
    }

    /// Number of distinct literals in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds no literals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Every matcher a pack compiles to.
#[derive(Debug, Clone)]
pub struct Matchers<'p> {
    exact: BTreeMap<MatcherKind, ExactTable<'p>>,
    empty: ExactTable<'p>,
}

impl<'p> Matchers<'p> {
    /// Compiles the tables for `pack`.
    ///
    /// Rules are visited in id order, so a table's content does not depend on
    /// the order of rules inside a layer file.
    #[must_use]
    pub fn build(pack: &'p Pack) -> Self {
        let mut exact: BTreeMap<MatcherKind, ExactTable<'p>> = BTreeMap::new();
        for rule in pack.rules() {
            for (&kind, tokens) in &rule.matchers {
                for token in tokens.iter().filter(|token| token.at == Boundary::Exact) {
                    exact
                        .entry(kind)
                        .or_default()
                        .entries
                        .entry(token.lit.as_str())
                        .or_default()
                        .push(TokenRef { rule, token });
                }
            }
        }
        Self { exact, empty: ExactTable::default() }
    }

    /// The exact-match table for one matcher kind.
    #[must_use]
    pub fn exact(&self, kind: MatcherKind) -> &ExactTable<'p> {
        self.exact.get(&kind).unwrap_or(&self.empty)
    }
}

/// Index of a pattern inside a content matcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatternId(pub u32);

/// Hits collected while one file is read.
///
/// It only counts. Which hit came first is deliberately not recorded, because
/// that would depend on how the file was cut into windows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HitAcc {
    counts: BTreeMap<PatternId, u32>,
}

impl HitAcc {
    /// An empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one hit of `pattern`.
    pub fn hit(&mut self, pattern: PatternId) {
        let count = self.counts.entry(pattern).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// How often `pattern` hit.
    #[must_use]
    pub fn count(&self, pattern: PatternId) -> u32 {
        self.counts.get(&pattern).copied().unwrap_or(0)
    }

    /// Patterns that hit, with their counts, in pattern order.
    pub fn iter(&self) -> impl Iterator<Item = (PatternId, u32)> + '_ {
        self.counts.iter().map(|(&pattern, &count)| (pattern, count))
    }

    /// Whether nothing hit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

/// A search over free-form bytes, fed one window at a time.
///
/// A file is read in bounded windows rather than mapped or loaded whole
/// (design report, section 6.2 decision 2). To find literals that straddle two
/// windows, the reader repeats the last `max_token_len() - 1` bytes of each
/// window at the start of the next. Those repeated bytes are the `carry`.
///
/// # Contract
///
/// An implementation must report exactly the matches that **end after** the
/// first `carry` bytes of `window`. Matches that end inside the carry were
/// reported with the previous window. Under that contract the hits for a file
/// do not depend on where the window boundaries fall.
pub trait ContentMatcher: Sync {
    /// Length in bytes of the longest literal, or 0 if there are none.
    fn max_token_len(&self) -> usize;

    /// Searches `window`, whose first `carry` bytes repeat the end of the
    /// previous window, and records hits in `out`.
    fn scan(&self, window: &[u8], carry: usize, out: &mut HitAcc);
}

/// The content matcher with no patterns. It never hits and asks for no carry.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoContent;

impl ContentMatcher for NoContent {
    fn max_token_len(&self) -> usize {
        0
    }

    fn scan(&self, _window: &[u8], _carry: usize, _out: &mut HitAcc) {}
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use xs_model::Sha256Digest;
    use xs_model::pack::{Category, Layer, LoadedLayer};
    use xs_model::record::V1;

    use super::*;

    fn rule(id: &str, tokens: &[(MatcherKind, &str, Boundary)]) -> Rule {
        let mut matchers: BTreeMap<MatcherKind, Vec<Token>> = BTreeMap::new();
        for &(kind, lit, at) in tokens {
            matchers.entry(kind).or_default().push(Token { lit: lit.into(), at });
        }
        Rule {
            id: id.into(),
            name: id.into(),
            entity: None,
            category: "component".into(),
            sources: vec![],
            notes: vec![],
            matchers,
            min_distinct: BTreeMap::new(),
        }
    }

    fn pack(rules: Vec<Rule>) -> Pack {
        let layer = Layer {
            format: V1,
            layer: "core".into(),
            version: 1,
            license: "CC-BY-4.0".into(),
            categories: vec![Category {
                id: "component".into(),
                name: "Component".into(),
                headline: false,
            }],
            entities: vec![],
            rules,
        };
        Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
    }

    #[test]
    fn exact_tables_match_whole_values_only() {
        let pack = pack(vec![
            rule(
                "sdk/sparkle",
                &[(MatcherKind::AppleFramework, "Sparkle.framework", Boundary::Exact)],
            ),
            rule(
                "sdk/sentry",
                &[
                    (MatcherKind::AppleFramework, "Sentry.framework", Boundary::Exact),
                    (MatcherKind::NpmPackage, "@sentry/electron", Boundary::Exact),
                    (MatcherKind::MachoObjcClass, "Sentry", Boundary::Prefix),
                ],
            ),
        ]);
        let matchers = Matchers::build(&pack);
        let frameworks = matchers.exact(MatcherKind::AppleFramework);

        let hits = frameworks.lookup("Sentry.framework");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule.id, "sdk/sentry");
        assert_eq!(hits[0].token.lit, "Sentry.framework");

        for miss in ["sentry.framework", "Sentry.framework ", "XSentry.framework", "Sentry", ""] {
            assert!(frameworks.lookup(miss).is_empty(), "{miss:?}");
        }
        assert_eq!(frameworks.len(), 2);
    }

    #[test]
    fn tables_are_per_matcher_kind_and_skip_other_boundaries() {
        let pack = pack(vec![rule(
            "sdk/sentry",
            &[
                (MatcherKind::NpmPackage, "@sentry/electron", Boundary::Exact),
                (MatcherKind::MachoObjcClass, "SentrySDK", Boundary::Prefix),
            ],
        )]);
        let matchers = Matchers::build(&pack);
        assert_eq!(matchers.exact(MatcherKind::NpmPackage).lookup("@sentry/electron").len(), 1);
        assert!(matchers.exact(MatcherKind::AppleFramework).lookup("@sentry/electron").is_empty());
        // A prefix token is not an exact token.
        assert!(matchers.exact(MatcherKind::MachoObjcClass).is_empty());
    }

    #[test]
    fn a_literal_shared_by_two_rules_reports_both_in_rule_order() {
        let pack = pack(vec![
            rule("sdk/zeta", &[(MatcherKind::AppleFramework, "Shared.framework", Boundary::Exact)]),
            rule(
                "sdk/alpha",
                &[(MatcherKind::AppleFramework, "Shared.framework", Boundary::Exact)],
            ),
        ]);
        let matchers = Matchers::build(&pack);
        let ids: Vec<&str> = matchers
            .exact(MatcherKind::AppleFramework)
            .lookup("Shared.framework")
            .iter()
            .map(|hit| hit.rule.id.as_str())
            .collect();
        assert_eq!(ids, ["sdk/alpha", "sdk/zeta"]);
    }

    #[test]
    fn the_accumulator_counts() {
        let mut hits = HitAcc::new();
        assert!(hits.is_empty());
        hits.hit(PatternId(7));
        hits.hit(PatternId(2));
        hits.hit(PatternId(7));
        assert_eq!(hits.count(PatternId(7)), 2);
        assert_eq!(hits.count(PatternId(3)), 0);
        assert_eq!(hits.iter().collect::<Vec<_>>(), [(PatternId(2), 1), (PatternId(7), 2)]);
    }

    #[test]
    fn no_content_never_hits() {
        let mut hits = HitAcc::new();
        NoContent.scan(b"doubleclick.net google-analytics.com", 0, &mut hits);
        assert!(hits.is_empty());
        assert_eq!(NoContent.max_token_len(), 0);
    }
}
