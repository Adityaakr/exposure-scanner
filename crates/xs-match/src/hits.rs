//! What a search found, before any decision about what it means.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use xs_model::text;

/// Index of one token of one rule for one matcher kind, inside the
/// [`Matchers`](crate::Matchers) that issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PatternId(pub u32);

/// How many leading bytes of a matching value are kept as its example: one
/// more than a record may carry, so that cleaning the example for a record
/// can tell that the value was cut.
const EXAMPLE_BYTES: usize = text::MAX_EXAMPLE_BYTES + 1;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Tally {
    count: u32,
    example: Option<Vec<u8>>,
}

impl Tally {
    /// Keeps the smaller of the stored example and `value`.
    fn offer(&mut self, value: &[u8]) {
        let value = value.get(..EXAMPLE_BYTES).unwrap_or(value);
        if self.example.as_deref().is_none_or(|current| value < current) {
            self.example = Some(value.to_vec());
        }
    }
}

/// Hits collected while one haystack is searched: a file, or one table of a
/// file.
///
/// It counts, and for values it keeps the smallest one that matched. Which
/// hit came first is deliberately not recorded, because that would depend on
/// how a file was cut into windows or on the order a table was walked in
/// (design report, section 6.4 rule 3). Two accumulators that saw the same
/// hits in any order are equal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HitAcc {
    tallies: BTreeMap<PatternId, Tally>,
}

impl HitAcc {
    /// An empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn tally(&mut self, pattern: PatternId) -> &mut Tally {
        let tally = self.tallies.entry(pattern).or_default();
        tally.count = tally.count.saturating_add(1);
        tally
    }

    /// Records one occurrence of `pattern` in free-form bytes.
    pub fn hit(&mut self, pattern: PatternId) {
        self.tally(pattern);
    }

    /// Records that `value`, an entry of a parsed table, matched `pattern`.
    ///
    /// The smallest such value in byte order becomes the pattern's example.
    /// Only its first 161 bytes are kept, so a hostile table cannot make the
    /// accumulator large; cutting every value at the same length does not
    /// change which one is smallest.
    pub fn hit_value(&mut self, pattern: PatternId, value: &[u8]) {
        self.tally(pattern).offer(value);
    }

    /// Adds everything `other` saw, as if both had been one accumulator.
    ///
    /// The scan scheduler (build plan, task 9) merges the accumulators of
    /// the files it reads with this.
    pub fn merge(&mut self, other: &Self) {
        for (&pattern, theirs) in &other.tallies {
            let ours = self.tallies.entry(pattern).or_default();
            ours.count = ours.count.saturating_add(theirs.count);
            if let Some(example) = &theirs.example {
                ours.offer(example);
            }
        }
    }

    /// How often `pattern` hit.
    #[must_use]
    pub fn count(&self, pattern: PatternId) -> u32 {
        self.tallies.get(&pattern).map_or(0, |tally| tally.count)
    }

    /// The first bytes of the smallest value that matched `pattern`, if the
    /// pattern matched values rather than free-form bytes.
    #[must_use]
    pub fn example(&self, pattern: PatternId) -> Option<&[u8]> {
        self.tallies.get(&pattern)?.example.as_deref()
    }

    /// Patterns that hit, with their counts, in pattern order.
    pub fn iter(&self) -> impl Iterator<Item = (PatternId, u32)> + '_ {
        self.tallies.iter().map(|(&pattern, tally)| (pattern, tally.count))
    }

    /// Whether nothing hit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tallies.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn it_counts_per_pattern() {
        let mut hits = HitAcc::new();
        assert!(hits.is_empty());
        hits.hit(PatternId(7));
        hits.hit(PatternId(2));
        hits.hit(PatternId(7));
        assert_eq!(hits.count(PatternId(7)), 2);
        assert_eq!(hits.count(PatternId(3)), 0);
        assert_eq!(hits.iter().collect::<Vec<_>>(), [(PatternId(2), 1), (PatternId(7), 2)]);
        assert_eq!(hits.example(PatternId(7)), None);
    }

    #[test]
    fn the_example_is_the_smallest_value_whatever_the_order() {
        let values: [&[u8]; 4] = [b"io.sentry.Sentry", b"io.sentry.Hub", b"io.sentry.Zed", b"io."];
        let mut forward = HitAcc::new();
        let mut backward = HitAcc::new();
        for value in values {
            forward.hit_value(PatternId(1), value);
        }
        for value in values.iter().rev() {
            backward.hit_value(PatternId(1), value);
        }
        assert_eq!(forward, backward);
        assert_eq!(forward.count(PatternId(1)), 4);
        assert_eq!(forward.example(PatternId(1)), Some(&b"io."[..]));
    }

    #[test]
    fn a_long_value_is_cut_without_changing_which_is_smallest() {
        let long_a = vec![b'a'; 4000];
        let mut long_b = vec![b'a'; 4000];
        long_b[100] = b'b';
        let mut hits = HitAcc::new();
        hits.hit_value(PatternId(0), &long_b);
        hits.hit_value(PatternId(0), &long_a);
        assert_eq!(hits.example(PatternId(0)), Some(&long_a[..EXAMPLE_BYTES]));
    }

    #[test]
    fn merging_equals_one_accumulator() {
        let mut whole = HitAcc::new();
        let mut left = HitAcc::new();
        let mut right = HitAcc::new();
        for (index, value) in [&b"m"[..], b"c", b"x", b"a", b"q"].into_iter().enumerate() {
            let pattern = PatternId(u32::try_from(index % 2).unwrap());
            whole.hit_value(pattern, value);
            if index < 2 { &mut left } else { &mut right }.hit_value(pattern, value);
        }
        whole.hit(PatternId(9));
        right.hit(PatternId(9));
        left.merge(&right);
        assert_eq!(left, whole);
        assert_eq!(left.example(PatternId(1)), Some(&b"a"[..]));
    }

    #[test]
    fn counts_saturate() {
        let mut hits = HitAcc::new();
        hits.hit(PatternId(0));
        hits.tallies.entry(PatternId(0)).or_default().count = u32::MAX - 1;
        hits.hit(PatternId(0));
        hits.hit(PatternId(0));
        assert_eq!(hits.count(PatternId(0)), u32::MAX);
        let copy = hits.clone();
        hits.merge(&copy);
        assert_eq!(hits.count(PatternId(0)), u32::MAX);
    }
}
