//! The content engine: literals searched for in free-form bytes.
//!
//! Script text, the string data of a binary and the non-code sections of a
//! Mach-O file have no table to look a name up in, so they are searched. The
//! engine is the `aho-corasick` crate's contiguous NFA (design report,
//! section 6.2 decision 1): one pass over the bytes finds every literal of a
//! pack, its speed barely depends on how many literals there are, and it is
//! small enough to build at start-up, so a pack ships no compiled automaton.
//!
//! Every occurrence is reported, also when two literals overlap or one
//! contains the other. Each occurrence then has to pass its token's boundary
//! rule (see [`crate::boundary`]).
//!
//! # Windows
//!
//! A file is read in bounded windows rather than mapped or loaded whole
//! (section 6.2 decision 2). The reader repeats the last
//! [`overlap`](ContentMatcher::overlap) bytes of each window at the start of
//! the next, and says which window is the last one. For this engine the
//! overlap is the longest literal minus one, so that a literal cut by a
//! window edge is whole in the next window, plus the three bytes of context a
//! boundary rule may look at.
//!
//! An occurrence is judged in exactly one window: the first one that holds
//! the two bytes after it, or the last window if the stream ends sooner. So
//! the hits for a stream do not depend on where the windows fall (section 6.4
//! rule 4), which a property test checks against random input.

use alloc::vec::Vec;

use aho_corasick::{AhoCorasick, AhoCorasickKind, Input, MatchKind};
use xs_model::matcher::Boundary;

use crate::boundary::{self, LOOKAHEAD, LOOKBEHIND};
use crate::hits::{HitAcc, PatternId};

/// A search over free-form bytes, fed one window at a time.
///
/// # Contract
///
/// The caller cuts a stream into windows and calls [`scan`](Self::scan) once
/// per window, in order:
///
/// * Each window after the first starts with a copy of the last
///   [`overlap`](Self::overlap) bytes read so far, or of all of them if the
///   stream has been shorter than that. Those repeated bytes are the `carry`.
/// * Exactly one call has `last` set: the final one. Its window may hold
///   nothing but the carry, when the stream ended on a window edge.
///
/// In return the hits recorded for a stream must not depend on where the
/// windows fall.
pub trait ContentMatcher: Sync {
    /// How many bytes of each window the caller repeats at the start of the
    /// next. Zero if there is nothing to search for.
    fn overlap(&self) -> usize;

    /// Searches `window`, whose first `carry` bytes repeat the end of what
    /// was read before, and records hits in `out`.
    fn scan(&self, window: &[u8], carry: usize, last: bool, out: &mut HitAcc);
}

/// The content matcher with no patterns. It never hits and asks for no
/// overlap, so a file read with it is only hashed.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoContent;

impl ContentMatcher for NoContent {
    fn overlap(&self) -> usize {
        0
    }

    fn scan(&self, _window: &[u8], _carry: usize, _last: bool, _out: &mut HitAcc) {}
}

/// One literal handed to [`ContentEngine::new`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Literal<'p> {
    pub(crate) pattern: PatternId,
    pub(crate) bytes: &'p [u8],
    pub(crate) boundary: Boundary,
}

/// The literals of one matcher kind that may sit anywhere in their
/// surroundings, on a word boundary or on a hostname boundary, compiled into
/// one automaton.
#[derive(Debug, Clone, Default)]
pub struct ContentEngine {
    /// `None` when there are no literals.
    automaton: Option<AhoCorasick>,
    /// Indexed by the automaton's pattern index.
    patterns: Vec<(PatternId, Boundary)>,
    overlap: usize,
}

impl ContentEngine {
    /// Compiles `literals`. Two literals may share their bytes; each is
    /// reported.
    pub(crate) fn new(literals: &[Literal<'_>]) -> Result<Self, aho_corasick::BuildError> {
        if literals.is_empty() {
            return Ok(Self::default());
        }
        let automaton = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            // The only match kind that reports overlapping occurrences.
            .match_kind(MatchKind::Standard)
            .build(literals.iter().map(|literal| literal.bytes))?;
        let overlap = automaton
            .max_pattern_len()
            .saturating_sub(1)
            .saturating_add(LOOKBEHIND)
            .saturating_add(LOOKAHEAD);
        Ok(Self {
            automaton: Some(automaton),
            patterns: literals.iter().map(|literal| (literal.pattern, literal.boundary)).collect(),
            overlap,
        })
    }

    /// Number of literals the engine searches for.
    #[must_use]
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Whether the engine has nothing to search for.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Calls `found` for every occurrence in `window` that is this window's
    /// to judge and that sits on its token's boundary.
    fn each_hit(&self, window: &[u8], carry: usize, last: bool, mut found: impl FnMut(PatternId)) {
        let Some(automaton) = &self.automaton else { return };
        // An unanchored overlapping search is what a contiguous NFA with
        // standard match semantics supports, so this cannot fail.
        let Ok(occurrences) = automaton.try_find_overlapping_iter(Input::new(window)) else {
            return;
        };
        for occurrence in occurrences {
            let judged_from = occurrence.end().saturating_add(LOOKAHEAD);
            // An earlier window already held the bytes after it.
            if judged_from <= carry {
                continue;
            }
            // A later window will hold them.
            if !last && judged_from > window.len() {
                continue;
            }
            let Some(&(pattern, boundary)) = self.patterns.get(occurrence.pattern().as_usize())
            else {
                continue;
            };
            if boundary::holds(boundary, window, occurrence.start(), occurrence.end()) {
                found(pattern);
            }
        }
    }

    /// The patterns that occur in `value`, a complete value, each once and in
    /// pattern order.
    pub(crate) fn patterns_in(&self, value: &[u8]) -> Vec<PatternId> {
        let mut patterns = Vec::new();
        self.each_hit(value, 0, true, |pattern| patterns.push(pattern));
        patterns.sort_unstable();
        patterns.dedup();
        patterns
    }
}

impl ContentMatcher for ContentEngine {
    fn overlap(&self) -> usize {
        self.overlap
    }

    fn scan(&self, window: &[u8], carry: usize, last: bool, out: &mut HitAcc) {
        self.each_hit(window, carry, last, |pattern| out.hit(pattern));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::vec;

    use proptest::prelude::*;

    use super::*;

    pub(crate) fn engine(literals: &[(&str, Boundary)]) -> ContentEngine {
        let literals: Vec<Literal<'_>> = literals
            .iter()
            .enumerate()
            .map(|(index, &(text, boundary))| Literal {
                pattern: PatternId(index as u32),
                bytes: text.as_bytes(),
                boundary,
            })
            .collect();
        ContentEngine::new(&literals).unwrap()
    }

    /// Feeds `data` to `matcher` the way a reader does, with `window` fresh
    /// bytes per call.
    pub(crate) fn windowed<M: ContentMatcher>(matcher: &M, data: &[u8], window: usize) -> HitAcc {
        let mut hits = HitAcc::new();
        let mut buffer: Vec<u8> = Vec::new();
        let mut rest = data;
        loop {
            let carry = buffer.len();
            let fresh = rest.len().min(window);
            buffer.extend_from_slice(&rest[..fresh]);
            rest = &rest[fresh..];
            // Like a reader, this only learns that the stream has ended from
            // a short read, so a stream that ends on a window edge gets one
            // more call with nothing but the carry.
            let last = fresh < window;
            matcher.scan(&buffer, carry, last, &mut hits);
            if last {
                return hits;
            }
            let keep = matcher.overlap().min(buffer.len());
            buffer.drain(..buffer.len() - keep);
        }
    }

    pub(crate) fn whole<M: ContentMatcher>(matcher: &M, data: &[u8]) -> HitAcc {
        let mut hits = HitAcc::new();
        matcher.scan(data, 0, true, &mut hits);
        hits
    }

    fn counts(hits: &HitAcc) -> Vec<u32> {
        hits.iter().map(|(_, count)| count).collect()
    }

    #[test]
    fn an_empty_engine_asks_for_nothing_and_finds_nothing() {
        let engine = engine(&[]);
        assert!(engine.is_empty());
        assert_eq!(engine.overlap(), 0);
        assert!(whole(&engine, b"doubleclick.net google-analytics.com").is_empty());
        assert!(whole(&NoContent, b"doubleclick.net google-analytics.com").is_empty());
        assert_eq!(NoContent.overlap(), 0);
    }

    #[test]
    fn the_overlap_is_the_longest_literal_minus_one_plus_the_boundary_context() {
        let engine = engine(&[("0123456789", Boundary::None), ("abc", Boundary::Host)]);
        assert_eq!(engine.len(), 2);
        assert_eq!(engine.overlap(), 9 + 3);
    }

    /// Build plan, task 5: "Overlapping tokens are both reported."
    #[test]
    fn overlapping_literals_are_all_reported() {
        // One literal ends another, one is inside another, two cross, and
        // two are equal.
        let engine = engine(&[
            ("us.i.posthog.com", Boundary::Host),
            ("i.posthog.com", Boundary::Host),
            ("posthog", Boundary::None),
            ("abcd", Boundary::None),
            ("cdef", Boundary::None),
            ("posthog", Boundary::None),
        ]);
        let hits = whole(&engine, b"https://us.i.posthog.com/ abcdef");
        assert_eq!(counts(&hits), [1, 1, 1, 1, 1, 1]);
        for window in 1..40 {
            let data = b"https://us.i.posthog.com/ abcdef";
            assert_eq!(windowed(&engine, data, window), hits, "window {window}");
        }
    }

    #[test]
    fn a_literal_that_overlaps_itself_is_counted_at_every_position() {
        let engine = engine(&[("aa", Boundary::None), ("aba", Boundary::None)]);
        let hits = whole(&engine, b"aaaa abababa");
        assert_eq!(hits.count(PatternId(0)), 3);
        assert_eq!(hits.count(PatternId(1)), 3);
    }

    #[test]
    fn the_edges_of_a_stream_are_boundaries() {
        let engine = engine(&[("sentry.javascript.", Boundary::Word)]);
        for data in [
            &b"sentry.javascript."[..],
            b"sentry.javascript. ",
            b" sentry.javascript.",
            b"sentry.javascript.$",
        ] {
            assert_eq!(whole(&engine, data).count(PatternId(0)), 1);
        }
        for data in [&b"sentry.javascript.x"[..], b"xsentry.javascript."] {
            assert!(whole(&engine, data).is_empty());
        }
    }

    /// The byte that decides a boundary may lie in the next window, or in
    /// the previous one. Every cut gives the answer of the uncut stream.
    #[test]
    fn a_boundary_is_judged_the_same_wherever_the_window_edge_falls() {
        let engine = engine(&[
            ("i.posthog.com", Boundary::Host),
            ("sentry.javascript.", Boundary::Word),
            ("posthog", Boundary::None),
        ]);
        let streams: [(&[u8], [u32; 3]); 8] = [
            (b"((i.posthog.com))", [1, 0, 1]),
            (b"((i.posthog.com.))", [1, 0, 1]),
            (b"((i.posthog.com.evil))", [0, 0, 1]),
            (b"((xi.posthog.com))", [0, 0, 1]),
            (b"((i.posthog.com", [1, 0, 1]),
            (b"((i.posthog.com.", [1, 0, 1]),
            (b"((sentry.javascript.x((sentry.javascript.((", [0, 1, 0]),
            (b"i.posthog.comsentry.javascript.", [0, 0, 1]),
        ];
        for (data, expected) in streams {
            let text = core::str::from_utf8(data).unwrap();
            let uncut = whole(&engine, data);
            let found: Vec<u32> = (0..3).map(|index| uncut.count(PatternId(index))).collect();
            assert_eq!(found, expected, "{text}");
            for window in 1..=data.len() + 1 {
                assert_eq!(windowed(&engine, data, window), uncut, "{text} window {window}");
            }
        }
    }

    #[test]
    fn a_stream_that_ends_on_a_window_edge_still_reports_its_last_literal() {
        let engine = engine(&[("posthog", Boundary::Word)]);
        // 14 bytes in windows of 7: the literal ends exactly where the
        // second window ends, and only the closing call can judge it.
        let data = b"-------posthog";
        assert_eq!(engine.overlap(), 9);
        let mut hits = HitAcc::new();
        engine.scan(&data[..7], 0, false, &mut hits);
        engine.scan(data, 7, false, &mut hits);
        assert!(hits.is_empty());
        engine.scan(&data[5..], 9, true, &mut hits);
        assert_eq!(hits.count(PatternId(0)), 1);
        assert_eq!(windowed(&engine, data, 7), hits);
    }

    #[test]
    fn patterns_in_a_value_are_reported_once_each() {
        let engine = engine(&[("posthog", Boundary::None), ("i.posthog.com", Boundary::Host)]);
        let value = b"https://us.i.posthog.com https://eu.i.posthog.com";
        assert_eq!(engine.patterns_in(value), vec![PatternId(0), PatternId(1)]);
        assert!(engine.patterns_in(b"nothing here").is_empty());
    }

    /// What a boundary means, written out a second time and in a different
    /// shape, so that the property test below does not compare the engine
    /// with itself.
    fn sits_on(boundary: Boundary, data: &[u8], start: usize, end: usize) -> bool {
        let word = |byte: u8| matches!(byte, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_');
        let label = |byte: u8| word(byte) || byte == b'-';
        let previous = if start == 0 { None } else { Some(data[start - 1]) };
        let next = data.get(end).copied();
        let after_next = data.get(end + 1).copied();
        match boundary {
            Boundary::None => true,
            Boundary::Word => {
                previous.is_none_or(|byte| !word(byte)) && next.is_none_or(|byte| !word(byte))
            }
            Boundary::Host => {
                let left = match previous {
                    None | Some(b'.') => true,
                    Some(byte) => !label(byte),
                };
                let right = match (next, after_next) {
                    (None, _) | (Some(b'.'), None) => true,
                    (Some(b'.'), Some(byte)) => !label(byte),
                    (Some(byte), _) => !label(byte),
                };
                left && right
            }
            Boundary::Prefix | Boundary::Exact => unreachable!("not searched for in a stream"),
        }
    }

    /// Every position of every literal, checked one by one.
    fn reference(literals: &[(Vec<u8>, Boundary)], data: &[u8]) -> HitAcc {
        let mut hits = HitAcc::new();
        for (index, (literal, boundary)) in literals.iter().enumerate() {
            for (start, candidate) in data.windows(literal.len()).enumerate() {
                if candidate == literal && sits_on(*boundary, data, start, start + literal.len()) {
                    hits.hit(PatternId(index as u32));
                }
            }
        }
        hits
    }

    /// A stream piece: filler, or one of the literals.
    #[derive(Debug, Clone)]
    enum Piece {
        Filler(Vec<u8>),
        Literal(prop::sample::Index),
    }

    /// Bytes that decide boundaries, so that literals and filler collide
    /// with each other often: letters, the dot, the hyphen, the underscore,
    /// a space and a byte that is not ASCII.
    fn boundary_byte() -> impl Strategy<Value = u8> {
        prop::sample::select(&b"ab.-_ \xc3"[..])
    }

    fn literals() -> impl Strategy<Value = Vec<(Vec<u8>, Boundary)>> {
        let boundary = prop::sample::select(&[Boundary::None, Boundary::Word, Boundary::Host][..]);
        let literal = (prop::collection::vec(boundary_byte(), 1..7), boundary);
        prop::collection::vec(literal, 1..9)
    }

    fn pieces() -> impl Strategy<Value = Vec<Piece>> {
        let piece = prop_oneof![
            prop::collection::vec(boundary_byte(), 0..5).prop_map(Piece::Filler),
            prop::collection::vec(any::<u8>(), 0..5).prop_map(Piece::Filler),
            any::<prop::sample::Index>().prop_map(Piece::Literal),
        ];
        prop::collection::vec(piece, 0..60)
    }

    proptest! {
        /// Build plan, task 5: "Chunked and whole-buffer scans agree on
        /// random input." Both also agree with a search that checks every
        /// position of every literal on its own.
        #[test]
        fn chunked_and_whole_buffer_scans_agree(
            literals in literals(),
            pieces in pieces(),
            window in 1..90usize,
        ) {
            let mut data: Vec<u8> = Vec::new();
            for piece in &pieces {
                match piece {
                    Piece::Filler(bytes) => data.extend_from_slice(bytes),
                    Piece::Literal(index) => data.extend_from_slice(&index.get(&literals).0),
                }
            }
            let listed: Vec<Literal<'_>> = literals
                .iter()
                .enumerate()
                .map(|(index, (bytes, boundary))| Literal {
                    pattern: PatternId(index as u32),
                    bytes,
                    boundary: *boundary,
                })
                .collect();
            let engine = ContentEngine::new(&listed).unwrap();

            let uncut = whole(&engine, &data);
            prop_assert_eq!(&uncut, &reference(&literals, &data));
            // The drawn window, and the smallest ones, where every byte is
            // a window edge.
            for window in [window, 1, 2, 3] {
                prop_assert_eq!(&windowed(&engine, &data, window), &uncut, "window {}", window);
            }
        }
    }
}
