//! Table matchers: a parsed name looked up among literals.
//!
//! A framework folder name, a class name or a zip entry name is a small,
//! complete value. Looking it up gives exact rather than substring matches
//! and costs a few comparisons, however many rules a pack holds (design
//! report, section 5.1).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::hits::PatternId;

/// Literals that match a value only when the value equals one of them.
#[derive(Debug, Clone, Default)]
pub(crate) struct ExactTable<'p> {
    entries: BTreeMap<&'p [u8], Vec<PatternId>>,
}

impl<'p> ExactTable<'p> {
    pub(crate) fn insert(&mut self, literal: &'p [u8], pattern: PatternId) {
        self.entries.entry(literal).or_default().push(pattern);
    }

    /// The patterns whose literal equals `value`. Usually none or one.
    pub(crate) fn lookup(&self, value: &[u8]) -> &[PatternId] {
        self.entries.get(value).map_or(&[], Vec::as_slice)
    }
}

/// One literal of a [`PrefixTable`].
#[derive(Debug, Clone)]
struct Node<'p> {
    literal: &'p [u8],
    patterns: Vec<PatternId>,
    /// The longest other literal that this one starts with.
    parent: Option<usize>,
}

/// Literals that match a value when the value starts with one of them.
///
/// The literals are kept sorted, and each one knows the longest other
/// literal it starts with. A lookup is then one binary search plus a walk up
/// that chain:
///
/// Take the greatest literal `t` that is not greater than the value `v`. Any
/// literal `u` that `v` starts with is not greater than `v`, so `u <= t <=
/// v`. Every string between `u` and a string that starts with `u` starts
/// with `u` itself, so `t` starts with `u`. Hence every literal `v` starts
/// with is `t` or one of the literals `t` starts with, which is exactly the
/// chain.
#[derive(Debug, Clone, Default)]
pub(crate) struct PrefixTable<'p> {
    nodes: Vec<Node<'p>>,
}

impl<'p> PrefixTable<'p> {
    /// Builds the table. The map's order is the sorted order of the nodes.
    pub(crate) fn new(literals: BTreeMap<&'p [u8], Vec<PatternId>>) -> Self {
        let mut nodes: Vec<Node<'p>> = Vec::with_capacity(literals.len());
        // The literals the previous one starts with, shortest first, then
        // the previous one itself.
        let mut chain: Vec<usize> = Vec::new();
        for (literal, patterns) in literals {
            while let Some(&last) = chain.last() {
                let starts_with_it =
                    nodes.get(last).is_some_and(|node| literal.starts_with(node.literal));
                if starts_with_it {
                    break;
                }
                chain.pop();
            }
            let parent = chain.last().copied();
            chain.push(nodes.len());
            nodes.push(Node { literal, patterns, parent });
        }
        Self { nodes }
    }

    /// Calls `found` for every pattern whose literal `value` starts with.
    pub(crate) fn lookup(&self, value: &[u8], mut found: impl FnMut(PatternId)) {
        let after = self.nodes.partition_point(|node| node.literal <= value);
        let mut next = after.checked_sub(1);
        while let Some(node) = next.and_then(|index| self.nodes.get(index)) {
            if value.starts_with(node.literal) {
                node.patterns.iter().copied().for_each(&mut found);
            }
            next = node.parent;
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;

    use proptest::prelude::*;

    use super::*;

    fn prefix_table<'p>(literals: &[&'p str]) -> PrefixTable<'p> {
        let mut map: BTreeMap<&[u8], Vec<PatternId>> = BTreeMap::new();
        for (index, literal) in literals.iter().enumerate() {
            map.entry(literal.as_bytes()).or_default().push(PatternId(index as u32));
        }
        PrefixTable::new(map)
    }

    fn prefixes(table: &PrefixTable<'_>, value: &str) -> Vec<u32> {
        let mut found = Vec::new();
        table.lookup(value.as_bytes(), |pattern| found.push(pattern.0));
        found.sort_unstable();
        found
    }

    #[test]
    fn exact_lookups_match_whole_values_only() {
        let mut table = ExactTable::default();
        table.insert(b"Sentry.framework", PatternId(0));
        table.insert(b"Sparkle.framework", PatternId(1));
        table.insert(b"Sentry.framework", PatternId(2));
        assert_eq!(table.lookup(b"Sentry.framework"), [PatternId(0), PatternId(2)]);
        for miss in ["sentry.framework", "Sentry.framework ", "XSentry.framework", "Sentry", ""] {
            assert!(table.lookup(miss.as_bytes()).is_empty(), "{miss:?}");
        }
    }

    #[test]
    fn a_value_matches_every_literal_it_starts_with() {
        let table = prefix_table(&[
            "io.sentry.",
            "io.sentry.android.",
            "com.google.firebase.",
            "com.google.firebase.crashlytics.",
            "com.google.firebase.messaging.",
            "com.posthog.android.",
            "io.sentry.",
        ]);
        assert_eq!(prefixes(&table, "io.sentry.android.core.SentryInitProvider"), [0, 1, 6]);
        assert_eq!(prefixes(&table, "io.sentry.Sentry"), [0, 6]);
        assert_eq!(prefixes(&table, "io.sentry."), [0, 6]);
        assert_eq!(prefixes(&table, "com.google.firebase.crashlytics.Registrar"), [2, 3]);
        // The greatest literal below this value is the messaging one, which
        // the value does not start with. Its chain still leads to the hit.
        assert_eq!(prefixes(&table, "com.google.firebase.perf.Trace"), [2]);
        for miss in ["io.sentry", "io.sentryx.Sentry", "com.google.Firebase", "", "zzz", "a"] {
            assert!(prefixes(&table, miss).is_empty(), "{miss:?}");
        }
        assert!(prefixes(&PrefixTable::default(), "io.sentry.Sentry").is_empty());
    }

    proptest! {
        /// The chain walk finds exactly what a scan of every literal finds.
        /// A two-letter alphabet makes shared prefixes the common case.
        #[test]
        fn lookup_agrees_with_checking_every_literal(
            literals in prop::collection::vec("[ab]{1,6}", 0..40),
            values in prop::collection::vec("[ab]{0,9}", 1..40),
        ) {
            let borrowed: Vec<&str> = literals.iter().map(String::as_str).collect();
            let table = prefix_table(&borrowed);
            for value in &values {
                let expected: Vec<u32> = (0..literals.len())
                    .filter(|&index| value.starts_with(literals[index].as_str()))
                    .map(|index| index as u32)
                    .collect();
                prop_assert_eq!(prefixes(&table, value), expected, "value {}", value);
            }
        }
    }

    #[test]
    fn literals_sharing_one_text_are_all_reported() {
        let table = prefix_table(&["ab", "ab", "a"]);
        assert_eq!(prefixes(&table, "abc"), vec![0, 1, 2]);
    }
}
