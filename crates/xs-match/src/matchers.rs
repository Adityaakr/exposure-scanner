//! Every matcher a rule pack compiles to.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use xs_model::matcher::{Boundary, MatcherKind};
use xs_model::pack::{Pack, Rule, Token};
use xs_model::record::Scope;

use crate::content::{ContentEngine, Literal};
use crate::hits::{HitAcc, PatternId};
use crate::judge::{self, Verdict};
use crate::table::{ExactTable, PrefixTable};

/// One token of a pack: the rule it belongs to, the matcher kind it is
/// listed under, and the token itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRef<'p> {
    /// The rule the token belongs to.
    pub rule: &'p Rule,
    /// The matcher kind the rule lists the token under.
    pub matcher: MatcherKind,
    /// The token.
    pub token: &'p Token,
}

/// Why a pack could not be compiled into matchers.
#[derive(Debug, Clone)]
pub enum BuildError {
    /// The pack holds more tokens than a pattern id can number.
    TooManyTokens,
    /// The search automaton for one matcher kind could not be built.
    Automaton(MatcherKind, aho_corasick::BuildError),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyTokens => f.write_str("the rule pack holds too many tokens"),
            Self::Automaton(matcher, error) => {
                write!(f, "cannot compile the {matcher} tokens of the rule pack: {error}")
            }
        }
    }
}

impl core::error::Error for BuildError {}

/// Whether matchers of kind `matcher` are applied to a file of `scope`
/// (design report, section 5.2 control 1).
///
/// Content matchers do not run on runtime files. A browser engine or a
/// language runtime holds the names of ad and analytics hosts as data, so
/// searching it would tie every app that embeds one to those companies: 65
/// of the 71 `doubleclick.net` hits on 16 real bundles sat in a browser
/// engine. Table matchers run everywhere, because a table says what a file
/// is made of, not what text it happens to contain.
///
/// The control is enforced by [`Matchers::content`] and
/// [`Matchers::match_value`], which find nothing where a kind is not
/// applied.
#[must_use]
pub const fn applies(matcher: MatcherKind, scope: Scope) -> bool {
    !(matcher.is_content() && matches!(scope, Scope::Runtime))
}

/// The three ways the tokens of one matcher kind are looked for.
#[derive(Debug, Clone, Default)]
struct KindMatchers<'p> {
    /// Tokens with the `exact` boundary.
    exact: ExactTable<'p>,
    /// Tokens with the `prefix` boundary.
    prefix: PrefixTable<'p>,
    /// Tokens with the `none`, `word` and `host` boundaries.
    content: ContentEngine,
}

/// Every matcher a pack compiles to.
///
/// A collector uses it in three steps, once per haystack (a file, or one
/// table of a file):
///
/// 1. Search. Free-form bytes are read through [`content`](Self::content);
///    each entry of a parsed table goes to [`match_value`](Self::match_value).
///    Both record into a [`HitAcc`].
/// 2. [`judge`](Self::judge) the hits. This is where the false-positive
///    controls that need the whole haystack are applied. The scope control
///    is not one of them: step 1 enforces it.
/// 3. Turn each edge of the [`Verdict`] into a record.
#[derive(Debug, Clone)]
pub struct Matchers<'p> {
    pack: &'p Pack,
    /// Indexed by pattern id.
    patterns: Vec<TokenRef<'p>>,
    kinds: BTreeMap<MatcherKind, KindMatchers<'p>>,
    /// What [`content`](Self::content) hands out when there is nothing to
    /// search for.
    idle: ContentEngine,
}

impl<'p> Matchers<'p> {
    /// Compiles the matchers for `pack`.
    ///
    /// Rules are visited in id order and patterns are numbered in that
    /// order, so the result does not depend on the order of rules inside a
    /// layer file.
    ///
    /// # Errors
    ///
    /// Fails if the pack is too large for the search automaton.
    pub fn build(pack: &'p Pack) -> Result<Self, BuildError> {
        #[derive(Default)]
        struct Draft<'p> {
            exact: ExactTable<'p>,
            prefix: BTreeMap<&'p [u8], Vec<PatternId>>,
            literals: Vec<Literal<'p>>,
        }

        let mut patterns: Vec<TokenRef<'p>> = Vec::new();
        let mut drafts: BTreeMap<MatcherKind, Draft<'p>> = BTreeMap::new();
        for rule in pack.rules() {
            for (&matcher, tokens) in &rule.matchers {
                let draft = drafts.entry(matcher).or_default();
                for token in tokens {
                    let pattern = u32::try_from(patterns.len())
                        .map(PatternId)
                        .map_err(|_| BuildError::TooManyTokens)?;
                    patterns.push(TokenRef { rule, matcher, token });
                    let bytes = token.lit.as_bytes();
                    match token.at {
                        Boundary::Exact => draft.exact.insert(bytes, pattern),
                        Boundary::Prefix => draft.prefix.entry(bytes).or_default().push(pattern),
                        Boundary::None | Boundary::Word | Boundary::Host => {
                            draft.literals.push(Literal { pattern, bytes, boundary: token.at });
                        }
                    }
                }
            }
        }

        let mut kinds = BTreeMap::new();
        for (matcher, draft) in drafts {
            let content = ContentEngine::new(&draft.literals)
                .map_err(|error| BuildError::Automaton(matcher, error))?;
            let prefix = PrefixTable::new(draft.prefix);
            kinds.insert(matcher, KindMatchers { exact: draft.exact, prefix, content });
        }
        Ok(Self { pack, patterns, kinds, idle: ContentEngine::default() })
    }

    /// The pack the matchers were compiled from.
    #[must_use]
    pub const fn pack(&self) -> &'p Pack {
        self.pack
    }

    /// The token a pattern id stands for.
    #[must_use]
    pub fn pattern(&self, pattern: PatternId) -> Option<TokenRef<'p>> {
        self.patterns.get(usize::try_from(pattern.0).ok()?).copied()
    }

    /// Number of tokens in the pack, over all rules and matcher kinds.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// The memory the search automatons of every matcher kind hold, in
    /// bytes. Each is built at start-up and shared by every thread.
    #[must_use]
    pub fn content_heap_bytes(&self) -> usize {
        self.kinds.values().map(|kind| kind.content.heap_bytes()).sum()
    }

    /// The engine that searches the free-form bytes of a file of `scope` for
    /// the tokens of `matcher`.
    ///
    /// It searches for nothing if the kind is not applied to that scope (see
    /// [`applies`]) or the pack has no such tokens. Reading a file with it
    /// then only hashes the file.
    ///
    /// Tokens with the `exact` or `prefix` boundary are about a whole value
    /// and a stream of bytes is not one, so they are only matched by
    /// [`match_value`](Self::match_value).
    #[must_use]
    pub fn content(&self, matcher: MatcherKind, scope: Scope) -> &ContentEngine {
        if !applies(matcher, scope) {
            return &self.idle;
        }
        self.kinds.get(&matcher).map_or(&self.idle, |kind| &kind.content)
    }

    /// Matches `value`, one entry of a parsed table, against every token of
    /// `matcher`, and records the tokens that hit in `out`.
    ///
    /// Nothing is recorded if the kind is not applied to a file of `scope`
    /// (see [`applies`]).
    ///
    /// A token hits a value at most once, however often its literal occurs
    /// in it, so a count is the number of table entries that matched. The
    /// smallest matching value becomes the token's example.
    pub fn match_value(&self, matcher: MatcherKind, scope: Scope, value: &[u8], out: &mut HitAcc) {
        if !applies(matcher, scope) {
            return;
        }
        let Some(kind) = self.kinds.get(&matcher) else { return };
        for &pattern in kind.exact.lookup(value) {
            out.hit_value(pattern, value);
        }
        kind.prefix.lookup(value, |pattern| out.hit_value(pattern, value));
        if !kind.content.is_empty() {
            for pattern in kind.content.patterns_in(value) {
                out.hit_value(pattern, value);
            }
        }
    }

    /// Decides what the hits collected from one haystack are evidence of.
    /// See [`Verdict`].
    #[must_use]
    pub fn judge(&self, hits: &HitAcc) -> Verdict<'p> {
        judge::judge(self, hits)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;

    use proptest::prelude::*;

    use super::*;
    use crate::boundary;
    use crate::content::ContentMatcher as _;
    use crate::content::tests::whole;
    use crate::testkit::{pack, rule};

    const SCOPES: [Scope; 4] = [Scope::AppCode, Scope::Dependency, Scope::Runtime, Scope::Resource];

    fn sentry_pack() -> Pack {
        pack(vec![
            rule(
                "sdk/sentry",
                None,
                &[
                    (MatcherKind::AppleFramework, "Sentry.framework", Boundary::Exact),
                    (MatcherKind::NpmPackage, "@sentry/electron", Boundary::Exact),
                    (MatcherKind::MachoObjcClass, "SentrySDK", Boundary::Exact),
                    (MatcherKind::MachoObjcClass, "SentryHub", Boundary::Prefix),
                    (MatcherKind::AndroidClassPrefix, "io.sentry.", Boundary::Prefix),
                    (MatcherKind::ContentLiteral, "sentry.javascript.", Boundary::Word),
                ],
            ),
            rule(
                "sdk/posthog",
                None,
                &[
                    (MatcherKind::DexString, "us.i.posthog.com", Boundary::Host),
                    (MatcherKind::DexString, "PostHog", Boundary::Exact),
                    (MatcherKind::DexString, "posthog-android/", Boundary::None),
                    (MatcherKind::PrivacyManifest, "i.posthog.com", Boundary::Host),
                    (MatcherKind::ContentLiteral, "i.posthog.com", Boundary::Host),
                ],
            ),
            rule(
                "sdk/sparkle",
                None,
                &[(MatcherKind::AppleFramework, "Sparkle.framework", Boundary::Exact)],
            ),
        ])
    }

    /// The rule ids and literals that `value` hits under `matcher`.
    fn value_hits(matchers: &Matchers<'_>, matcher: MatcherKind, value: &str) -> Vec<String> {
        let mut hits = HitAcc::new();
        matchers.match_value(matcher, Scope::AppCode, value.as_bytes(), &mut hits);
        hits.iter()
            .map(|(pattern, count)| {
                assert_eq!(count, 1);
                assert_eq!(hits.example(pattern), Some(value.as_bytes()));
                let token = matchers.pattern(pattern).unwrap();
                assert_eq!(token.matcher, matcher);
                alloc::format!("{} {}", token.rule.id, token.token.lit)
            })
            .collect()
    }

    #[test]
    fn patterns_are_numbered_in_rule_then_matcher_then_token_order() {
        let pack = sentry_pack();
        let matchers = Matchers::build(&pack).unwrap();
        assert_eq!(matchers.pattern_count(), 12);
        assert!(core::ptr::eq(matchers.pack(), &pack));
        let listed: Vec<(&str, MatcherKind, &str)> = (0..12)
            .map(|index| {
                let token = matchers.pattern(PatternId(index)).unwrap();
                (token.rule.id.as_str(), token.matcher, token.token.lit.as_str())
            })
            .collect();
        let mut sorted = listed.clone();
        sorted.sort_by_key(|&(rule, matcher, _)| (rule, matcher));
        assert_eq!(listed, sorted);
        assert_eq!(listed[0].0, "sdk/posthog");
        assert_eq!(listed[11], ("sdk/sparkle", MatcherKind::AppleFramework, "Sparkle.framework"));
        assert_eq!(matchers.pattern(PatternId(12)), None);
    }

    #[test]
    fn exact_tokens_match_whole_values_only() {
        let pack = sentry_pack();
        let matchers = Matchers::build(&pack).unwrap();
        let frameworks = MatcherKind::AppleFramework;
        assert_eq!(
            value_hits(&matchers, frameworks, "Sentry.framework"),
            ["sdk/sentry Sentry.framework"]
        );
        for miss in ["sentry.framework", "Sentry.framework ", "XSentry.framework", "Sentry", ""] {
            assert!(value_hits(&matchers, frameworks, miss).is_empty(), "{miss:?}");
        }
        // Tables are per matcher kind.
        assert!(value_hits(&matchers, MatcherKind::NpmPackage, "Sentry.framework").is_empty());
        assert!(value_hits(&matchers, MatcherKind::ApkFile, "Sentry.framework").is_empty());
    }

    #[test]
    fn prefix_tokens_match_values_that_start_with_them() {
        let pack = sentry_pack();
        let matchers = Matchers::build(&pack).unwrap();
        let classes = MatcherKind::AndroidClassPrefix;
        assert_eq!(
            value_hits(&matchers, classes, "io.sentry.android.core.SentryInitProvider"),
            ["sdk/sentry io.sentry."]
        );
        for miss in ["io.sentry", "xio.sentry.Sentry", "com.io.sentry.Sentry"] {
            assert!(value_hits(&matchers, classes, miss).is_empty(), "{miss:?}");
        }
        // A kind may mix exact and prefix tokens.
        let objc = MatcherKind::MachoObjcClass;
        assert_eq!(value_hits(&matchers, objc, "SentrySDK"), ["sdk/sentry SentrySDK"]);
        assert_eq!(value_hits(&matchers, objc, "SentryHubInternal"), ["sdk/sentry SentryHub"]);
        assert!(value_hits(&matchers, objc, "SentrySDKInternal").is_empty());
    }

    #[test]
    fn host_word_and_unanchored_tokens_match_inside_values() {
        let pack = sentry_pack();
        let matchers = Matchers::build(&pack).unwrap();
        let strings = MatcherKind::DexString;
        assert_eq!(
            value_hits(&matchers, strings, "https://us.i.posthog.com/batch"),
            ["sdk/posthog us.i.posthog.com"]
        );
        assert_eq!(value_hits(&matchers, strings, "PostHog"), ["sdk/posthog PostHog"]);
        assert_eq!(
            value_hits(&matchers, strings, "posthog-android/3.1.0 us.i.posthog.com"),
            ["sdk/posthog us.i.posthog.com", "sdk/posthog posthog-android/"]
        );
        for miss in ["us.i.posthog.community", "PostHog ", "aus.i.posthog.com"] {
            assert!(value_hits(&matchers, strings, miss).is_empty(), "{miss:?}");
        }
        // A declared tracking domain is a value too.
        assert_eq!(
            value_hits(&matchers, MatcherKind::PrivacyManifest, "eu.i.posthog.com"),
            ["sdk/posthog i.posthog.com"]
        );
    }

    #[test]
    fn a_value_counts_once_per_token_and_the_smallest_value_is_the_example() {
        let pack = sentry_pack();
        let matchers = Matchers::build(&pack).unwrap();
        let mut hits = HitAcc::new();
        for value in [
            "io.sentry.Sentry",
            "io.sentry.Hub",
            "com.example.Main",
            "io.sentry.android.core.SentryInitProvider",
        ] {
            matchers.match_value(
                MatcherKind::AndroidClassPrefix,
                Scope::AppCode,
                value.as_bytes(),
                &mut hits,
            );
        }
        // The literal occurs twice in this value, which is one entry.
        let twice = b"https://us.i.posthog.com https://us.i.posthog.com";
        matchers.match_value(MatcherKind::DexString, Scope::AppCode, twice, &mut hits);

        let tallies: Vec<(String, u32, &[u8])> = hits
            .iter()
            .map(|(pattern, count)| {
                let lit = matchers.pattern(pattern).unwrap().token.lit.clone();
                (lit, count, hits.example(pattern).unwrap())
            })
            .collect();
        assert_eq!(
            tallies,
            [
                (String::from("us.i.posthog.com"), 1, &twice[..]),
                (String::from("io.sentry."), 3, &b"io.sentry.Hub"[..]),
            ]
        );
    }

    #[test]
    fn a_literal_shared_by_two_rules_hits_for_both() {
        let pack = pack(vec![
            rule(
                "sdk/zeta",
                None,
                &[
                    (MatcherKind::AppleFramework, "Shared.framework", Boundary::Exact),
                    (MatcherKind::ContentLiteral, "shared.literal", Boundary::Word),
                ],
            ),
            rule(
                "sdk/alpha",
                None,
                &[
                    (MatcherKind::AppleFramework, "Shared.framework", Boundary::Exact),
                    (MatcherKind::ContentLiteral, "shared.literal", Boundary::None),
                ],
            ),
        ]);
        let matchers = Matchers::build(&pack).unwrap();
        assert_eq!(
            value_hits(&matchers, MatcherKind::AppleFramework, "Shared.framework"),
            ["sdk/alpha Shared.framework", "sdk/zeta Shared.framework"]
        );
        let engine = matchers.content(MatcherKind::ContentLiteral, Scope::AppCode);
        let rules = |data: &[u8]| -> Vec<&str> {
            whole(engine, data)
                .iter()
                .map(|(pattern, _)| matchers.pattern(pattern).unwrap().rule.id.as_str())
                .collect()
        };
        assert_eq!(rules(b"a shared.literal b"), ["sdk/alpha", "sdk/zeta"]);
        // Each keeps its own boundary.
        assert_eq!(rules(b"a shared.literals b"), ["sdk/alpha"]);
    }

    /// Design report, section 5.2 control 1.
    #[test]
    fn content_matchers_do_not_run_on_runtime_files() {
        for matcher in MatcherKind::ALL {
            for scope in SCOPES {
                let expected = !(matcher.is_content() && scope == Scope::Runtime);
                assert_eq!(applies(matcher, scope), expected, "{matcher} {scope:?}");
            }
        }

        let pack = sentry_pack();
        let matchers = Matchers::build(&pack).unwrap();
        let script = b"fetch('https://us.i.posthog.com/e'); name = 'sentry.javascript.' + n;";
        for scope in SCOPES {
            let engine = matchers.content(MatcherKind::ContentLiteral, scope);
            let hits = whole(engine, script);
            let mut values = HitAcc::new();
            matchers.match_value(MatcherKind::DexString, scope, b"us.i.posthog.com", &mut values);
            if scope == Scope::Runtime {
                // A file read with this engine is hashed and nothing else.
                assert!(engine.is_empty());
                assert_eq!(engine.overlap(), 0);
                assert!(hits.is_empty());
                assert!(values.is_empty());
            } else {
                assert_eq!(hits.iter().count(), 2, "{scope:?}");
                assert_eq!(values.iter().count(), 1, "{scope:?}");
            }

            // Table matchers say what a file is made of. They run everywhere.
            let mut frameworks = HitAcc::new();
            matchers.match_value(
                MatcherKind::AppleFramework,
                scope,
                b"Sentry.framework",
                &mut frameworks,
            );
            assert_eq!(frameworks.iter().count(), 1, "{scope:?}");
        }
    }

    #[test]
    fn a_kind_without_content_tokens_has_an_idle_engine() {
        let pack = sentry_pack();
        let matchers = Matchers::build(&pack).unwrap();
        for matcher in [MatcherKind::AppleFramework, MatcherKind::MachoToken, MatcherKind::ApkFile]
        {
            assert!(matchers.content(matcher, Scope::AppCode).is_empty(), "{matcher}");
        }
        // Exact tokens are not searched for in a stream.
        let strings = matchers.content(MatcherKind::DexString, Scope::AppCode);
        assert_eq!(strings.len(), 2);
        assert!(whole(strings, b"PostHog").is_empty());
    }

    fn boundary_of(index: u8) -> Boundary {
        match index % 5 {
            0 => Boundary::None,
            1 => Boundary::Prefix,
            2 => Boundary::Exact,
            3 => Boundary::Word,
            _ => Boundary::Host,
        }
    }

    proptest! {
        /// However a token is looked for (exact table, prefix table or
        /// automaton), a value hits it exactly when its literal occurs
        /// somewhere in the value on its boundary.
        #[test]
        fn a_value_hits_a_token_iff_the_literal_sits_on_its_boundary_somewhere(
            tokens in prop::collection::btree_map("[ab.]{1,4}", any::<u8>(), 1..12),
            values in prop::collection::vec("[ab. -]{0,10}", 1..30),
        ) {
            // Each matcher kind allows some boundaries, so the tokens are
            // spread over two kinds that between them allow all five.
            let listed: Vec<(MatcherKind, &str, Boundary)> = tokens
                .iter()
                .map(|(literal, &pick)| {
                    let at = boundary_of(pick);
                    let matcher = if at == Boundary::Prefix {
                        MatcherKind::ManifestComponent
                    } else {
                        MatcherKind::DexString
                    };
                    (matcher, literal.as_str(), at)
                })
                .collect();
            let pack = pack(vec![rule("sdk/random", None, &listed)]);
            let matchers = Matchers::build(&pack).unwrap();

            for value in &values {
                let bytes = value.as_bytes();
                for matcher in [MatcherKind::ManifestComponent, MatcherKind::DexString] {
                    let mut hits = HitAcc::new();
                    matchers.match_value(matcher, Scope::AppCode, bytes, &mut hits);
                    let found: Vec<&str> = hits
                        .iter()
                        .map(|(pattern, count)| {
                            assert_eq!(count, 1);
                            matchers.pattern(pattern).unwrap().token.lit.as_str()
                        })
                        .collect();
                    let expected: Vec<&str> = listed
                        .iter()
                        .filter(|&&(kind, literal, at)| {
                            kind == matcher
                                && (0..=bytes.len().saturating_sub(literal.len())).any(|start| {
                                    let end = start + literal.len();
                                    bytes.get(start..end) == Some(literal.as_bytes())
                                        && boundary::holds(at, bytes, start, end)
                                })
                        })
                        .map(|&(_, literal, _)| literal)
                        .collect();
                    prop_assert_eq!(found, expected, "value {:?} under {}", value, matcher);
                }
            }
        }
    }
}
