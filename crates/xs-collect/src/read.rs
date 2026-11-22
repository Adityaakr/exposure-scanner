//! Reading a file once, in bounded windows, for both its hash and its hits.
//!
//! Design report, section 6.2:
//!
//! * **Bounded sequential reads, not `mmap`.** One window-sized buffer per
//!   thread. Measured faster than mapping, with a fortieth of the memory, no
//!   `unsafe`, and no way to crash when an app is updated mid-scan (a mapped
//!   file that gets truncated raises SIGBUS).
//! * **One pass.** The same bytes feed the SHA-256 and the matcher. Reading
//!   is the dominant cost, so nothing reads a file twice.
//! * **Carry.** The last bytes of each window are repeated at the start of
//!   the next, as many as the matcher asks for: the longest token minus one,
//!   so a literal that straddles two windows is still found, plus the few
//!   bytes around a literal that its boundary rule looks at. The matcher is
//!   also told which window is the last. With both, the result does not
//!   depend on where windows fall.
//!
//! A file that is searched as one stream goes through [`one_pass`]. A file
//! with structure, where which bytes are searched for what depends on what
//! the file says about itself, goes through [`pass`] with a [`Sink`] that
//! keeps state from window to window.

use std::io::{self, Read};

use xs_match::{ContentMatcher, HitAcc};
use xs_model::{Sha256Digest, Sha256Stream};

/// How many fresh bytes one window holds: 1 MiB.
pub const WINDOW: usize = 1 << 20;

/// How many leading bytes the caller gets to look at before deciding whether
/// the file is worth reading.
pub const HEAD: usize = 16;

/// What one pass over a file produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnePass {
    /// SHA-256 of the whole file.
    pub sha256: Sha256Digest,
    /// Number of bytes read.
    pub bytes: u64,
    /// What the content matcher found.
    pub hits: HitAcc,
}

/// What the windows of one file are fed to.
///
/// The contract is that of [`ContentMatcher`], for a receiver that keeps
/// state: [`window`](Self::window) is called once per window, in order. Each
/// window after the first starts with a copy of the last
/// [`overlap`](Self::overlap) bytes read so far, or of all of them if the
/// file has been shorter than that; those repeated bytes are the `carry`.
/// Exactly one call has `last` set, the final one, and its window may hold
/// nothing but the carry.
pub trait Sink {
    /// How many bytes of each window are repeated at the start of the next.
    /// It is asked once, before the first window.
    fn overlap(&self) -> usize;

    /// Takes one window, whose first `carry` bytes repeat the end of what
    /// was read before.
    fn window(&mut self, view: &[u8], carry: usize, last: bool);
}

/// A [`Sink`] that searches the whole file as one stream.
struct Search<'m, M: ?Sized> {
    matcher: &'m M,
    hits: HitAcc,
}

impl<M: ContentMatcher + ?Sized> Sink for Search<'_, M> {
    fn overlap(&self) -> usize {
        self.matcher.overlap()
    }

    fn window(&mut self, view: &[u8], carry: usize, last: bool) {
        self.matcher.scan(view, carry, last, &mut self.hits);
    }
}

/// The buffer size [`one_pass`] needs for a given matcher and window.
#[must_use]
pub fn buffer_len<M: ContentMatcher + ?Sized>(matcher: &M, window: usize) -> usize {
    buffer_len_for(matcher.overlap(), window)
}

/// The buffer size [`pass`] needs for a sink with this overlap and window.
#[must_use]
pub fn buffer_len_for(overlap: usize, window: usize) -> usize {
    overlap.saturating_add(window.max(HEAD))
}

/// Reads until `buf` is full or the stream ends. A short count means the end
/// of the stream was reached.
pub(crate) fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match reader.read(rest) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Hashes and searches a stream in one pass.
///
/// The first [`HEAD`] bytes are shown to `wanted` before anything else is
/// read. If it returns `false` the stream is abandoned and `Ok(None)` comes
/// back, having cost one small read. This is how files are classified by
/// magic number without a second open.
///
/// `buf` is scratch space of at least [`buffer_len`] bytes; its content on
/// entry and exit is meaningless. `window` is [`WINDOW`] in production and
/// small in tests that exercise window boundaries.
///
/// # Errors
///
/// Passes on the first read error. `InvalidInput` if `buf` is too small.
pub fn one_pass<M: ContentMatcher + ?Sized>(
    reader: &mut impl Read,
    buf: &mut [u8],
    window: usize,
    matcher: &M,
    wanted: impl FnOnce(&[u8]) -> bool,
) -> io::Result<Option<OnePass>> {
    let mut search = Search { matcher, hits: HitAcc::new() };
    let hashed = pass(reader, buf, window, First::Head, &mut search, wanted)?;
    Ok(hashed.map(|(sha256, bytes)| OnePass { sha256, bytes, hits: search.hits }))
}

/// How much of a file is read before the caller is asked whether it wants
/// the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum First {
    /// The first [`HEAD`] bytes, so that a file turned down costs one small
    /// read. For files told apart by their magic number.
    Head,
    /// A whole window, for a caller that takes any file: one read fewer,
    /// which for a small file is a third of what reading it costs.
    Window,
}

/// Hashes a stream in one pass and feeds its windows to `sink`.
///
/// This is [`one_pass`] for a receiver that keeps state. It returns the
/// SHA-256 of the whole stream and its length, or `Ok(None)` if `wanted`
/// turned the stream down after its first [`HEAD`] bytes, in which case
/// `sink` saw nothing.
///
/// `buf` is scratch space of at least [`buffer_len_for`] bytes. `first`
/// says how much is read before `wanted` sees the first [`HEAD`] bytes;
/// what is hashed and what `sink` is given do not depend on it.
///
/// # Errors
///
/// Passes on the first read error. `InvalidInput` if `buf` is too small.
pub fn pass<S: Sink + ?Sized>(
    reader: &mut impl Read,
    buf: &mut [u8],
    window: usize,
    first: First,
    sink: &mut S,
    wanted: impl FnOnce(&[u8]) -> bool,
) -> io::Result<Option<(Sha256Digest, u64)>> {
    let window = window.max(HEAD);
    let overlap = sink.overlap();
    if buf.len() < overlap.saturating_add(window) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "scratch buffer is too small"));
    }

    // First window: a small read to classify, then the rest of the window;
    // or the whole window at once.
    let mut got = match first {
        First::Head => {
            let (head_buf, _) = buf.split_at_mut(HEAD);
            let head = read_full(reader, head_buf)?;
            if !wanted(head_buf.get(..head).unwrap_or_default()) {
                return Ok(None);
            }
            if head == HEAD {
                head + read_full(reader, buf.get_mut(HEAD..window).unwrap_or_default())?
            } else {
                head
            }
        }
        First::Window => {
            let got = read_full(reader, buf.get_mut(..window).unwrap_or_default())?;
            if !wanted(buf.get(..got.min(HEAD)).unwrap_or_default()) {
                return Ok(None);
            }
            got
        }
    };

    let mut hasher = Sha256Stream::new();
    let mut bytes: u64 = 0;
    let mut carry = 0;
    loop {
        // buf = [carry bytes repeated from the last window | got fresh bytes]
        let filled = carry + got;
        let Some(view) = buf.get(..filled) else { break };
        hasher.update(view.get(carry..).unwrap_or_default());
        bytes += got as u64;

        // A short window is the end of the stream. A stream that ends on a
        // window edge is only found out by the next read, which returns
        // nothing; its last window then holds the carry alone, and the
        // matcher still has to see it to judge what ended at that edge.
        let last = got < window;
        sink.window(view, carry, last);
        if last {
            break;
        }
        let keep = overlap.min(filled);
        buf.copy_within(filled - keep..filled, 0);
        carry = keep;
        got = read_full(reader, buf.get_mut(carry..carry + window).unwrap_or_default())?;
    }
    Ok(Some((hasher.finish(), bytes)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Mutex;

    use proptest::prelude::*;
    use xs_match::{Matchers, NoContent, PatternId};
    use xs_model::Pack;
    use xs_model::matcher::{Boundary, MatcherKind};
    use xs_model::pack::{Category, Layer, LoadedLayer, Rule, Token};
    use xs_model::record::{Scope, V1};

    use super::*;

    /// A naive substring matcher that honours the carry contract. It is the
    /// simplest possible reference: any windowing mistake in `one_pass` shows
    /// up as a wrong count. Its literals have no boundary rule, so it asks
    /// for the longest one minus one and counts what ends after the carry.
    struct Naive(Vec<&'static [u8]>);

    impl ContentMatcher for Naive {
        fn overlap(&self) -> usize {
            self.0.iter().map(|pattern| pattern.len()).max().unwrap_or(0).saturating_sub(1)
        }

        fn scan(&self, window: &[u8], carry: usize, _last: bool, out: &mut HitAcc) {
            for (index, pattern) in self.0.iter().enumerate() {
                for (start, candidate) in window.windows(pattern.len()).enumerate() {
                    if candidate == *pattern && start + pattern.len() > carry {
                        out.hit(PatternId(u32::try_from(index).unwrap()));
                    }
                }
            }
        }
    }

    /// A reader that returns at most `step` bytes per call, like a pipe.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let count = self.step.min(buf.len()).min(self.data.len());
            buf[..count].copy_from_slice(&self.data[..count]);
            self.data = &self.data[count..];
            Ok(count)
        }
    }

    fn run<M: ContentMatcher>(data: &[u8], window: usize, matcher: &M) -> OnePass {
        let mut buf = vec![0xAA; buffer_len(matcher, window)];
        one_pass(&mut Cursor::new(data), &mut buf, window, matcher, |_| true).unwrap().unwrap()
    }

    /// Deterministic filler with planted patterns, so tests need no RNG.
    fn corpus(len: usize) -> Vec<u8> {
        let mut data: Vec<u8> =
            (0..len).map(|i| b"abcdefghijklmnopqrstuvwxyz"[i * 7 % 26]).collect();
        for (at, pattern) in
            [(0, &b"doubleclick"[..]), (len / 3, b"sentry.javascript."), (len - 5, b"posth")]
        {
            if at + pattern.len() <= len {
                data[at..at + pattern.len()].copy_from_slice(pattern);
            }
        }
        data
    }

    fn matcher() -> Naive {
        Naive(vec![b"doubleclick", b"sentry.javascript.", b"posth", b"aa", b"hov"])
    }

    #[test]
    fn hash_and_length_match_a_one_shot_hash_at_every_size_around_a_window() {
        let window = 64;
        for len in [1, HEAD - 1, HEAD, HEAD + 1, 63, 64, 65, 127, 128, 129, 1000] {
            let data = corpus(len.max(32))[..len].to_vec();
            let pass = run(&data, window, &NoContent);
            assert_eq!(pass.sha256, Sha256Digest::of(&data), "len {len}");
            assert_eq!(pass.bytes, len as u64, "len {len}");
            assert!(pass.hits.is_empty());
        }
    }

    /// Design report, section 6.4 rule 4: window boundaries cannot change
    /// results.
    #[test]
    fn hits_do_not_depend_on_the_window_size() {
        let data = corpus(4096);
        let matcher = matcher();
        let whole = run(&data, data.len() * 2, &matcher);
        assert!(whole.hits.count(PatternId(0)) == 1 && whole.hits.count(PatternId(1)) == 1);
        assert_eq!(whole.hits.count(PatternId(2)), 1);
        for window in [HEAD, 17, 18, 19, 31, 32, 33, 64, 100, 1000, 4095, 4096, 4097] {
            let chunked = run(&data, window, &matcher);
            assert_eq!(chunked.hits, whole.hits, "window {window}");
            assert_eq!(chunked.sha256, whole.sha256, "window {window}");
        }
    }

    #[test]
    fn a_pattern_straddling_every_boundary_position_is_found_once() {
        let pattern = b"sentry.javascript.";
        let matcher = Naive(vec![pattern]);
        let window = 32;
        // Slide the pattern across the first window boundary byte by byte.
        for offset in window - pattern.len() - 1..=window + 1 {
            let mut data = vec![b'-'; window * 3];
            data[offset..offset + pattern.len()].copy_from_slice(pattern);
            let pass = run(&data, window, &matcher);
            assert_eq!(pass.hits.count(PatternId(0)), 1, "offset {offset}");
        }
    }

    #[test]
    fn overlapping_occurrences_are_all_counted_across_boundaries() {
        // "aaaa…" holds len − 1 overlapping occurrences of "aa".
        let data = vec![b'a'; 200];
        let matcher = Naive(vec![b"aa"]);
        for window in [HEAD, 17, 50, 199, 200, 201] {
            assert_eq!(
                run(&data, window, &matcher).hits.count(PatternId(0)),
                199,
                "window {window}"
            );
        }
    }

    #[test]
    fn short_reads_change_nothing() {
        let data = corpus(1000);
        let matcher = matcher();
        let reference = run(&data, 64, &matcher);
        for step in [1, 2, 7, 63, 64, 65] {
            let mut buf = vec![0; buffer_len(&matcher, 64)];
            let mut reader = Trickle { data: &data, step };
            let pass = one_pass(&mut reader, &mut buf, 64, &matcher, |_| true).unwrap().unwrap();
            assert_eq!(pass, reference, "step {step}");
        }
    }

    #[test]
    fn an_unwanted_file_costs_one_small_read() {
        struct Counting<'a>(Cursor<&'a [u8]>, usize);
        impl Read for Counting<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.1 += 1;
                self.0.read(buf)
            }
        }
        let data = corpus(100_000);
        let mut reader = Counting(Cursor::new(&data), 0);
        let mut buf = vec![0; buffer_len(&NoContent, WINDOW)];
        let mut seen = Vec::new();
        let result = one_pass(&mut reader, &mut buf, WINDOW, &NoContent, |head| {
            seen = head.to_vec();
            false
        });
        assert_eq!(result.unwrap(), None);
        assert_eq!(seen, &data[..HEAD]);
        assert_eq!(reader.1, 1);
        assert_eq!(reader.0.position(), HEAD as u64);
    }

    /// Reading a whole window first changes nothing but the number of reads:
    /// the same hash, length and hits at every size around a window, the
    /// classifier shown the same head, and one read fewer for any file
    /// longer than the head.
    #[test]
    fn a_window_first_gives_what_a_head_first_gives_in_one_read_fewer() {
        struct Counting<'a>(Cursor<&'a [u8]>, usize);
        impl Read for Counting<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.1 += 1;
                self.0.read(buf)
            }
        }
        let window = 64;
        let matcher = matcher();
        for len in [0, 1, HEAD - 1, HEAD, HEAD + 1, 63, 64, 65, 128, 129, 1000] {
            let data = corpus(len.max(32))[..len].to_vec();
            let mut seen = Vec::new();
            let mut by = |first: First| {
                let mut search = Search { matcher: &matcher, hits: HitAcc::new() };
                let mut buf = vec![0x5a; buffer_len(&matcher, window)];
                let mut reader = Counting(Cursor::new(&data), 0);
                let hashed = pass(&mut reader, &mut buf, window, first, &mut search, |head| {
                    seen.push(head.to_vec());
                    true
                });
                (hashed.unwrap().unwrap(), search.hits, reader.1)
            };
            let (head, head_hits, head_reads) = by(First::Head);
            let (whole, whole_hits, whole_reads) = by(First::Window);
            assert_eq!((head, head_hits), (whole, whole_hits), "len {len}");
            assert_eq!(seen[0], seen[1], "len {len}");
            // A file of at most HEAD bytes is read whole by the first read
            // either way, and its end found by the next.
            if len > HEAD {
                assert_eq!(whole_reads + 1, head_reads, "len {len}");
            } else {
                assert_eq!(whole_reads, head_reads, "len {len}");
            }
        }
        // A file turned down after a whole window was read is not hashed.
        let data = corpus(300);
        let mut buf = vec![0; buffer_len_for(0, window)];
        let mut sink = Search { matcher: &NoContent, hits: HitAcc::new() };
        let refused =
            pass(&mut Cursor::new(&data), &mut buf, window, First::Window, &mut sink, |_| false);
        assert_eq!(refused.unwrap(), None);
    }

    #[test]
    fn empty_and_tiny_files_reach_the_classifier() {
        let mut buf = vec![0; buffer_len(&NoContent, 64)];
        let mut lengths = Vec::new();
        for data in [&b""[..], b"ab"] {
            let pass = one_pass(&mut Cursor::new(data), &mut buf, 64, &NoContent, |head| {
                lengths.push(head.len());
                true
            });
            let pass = pass.unwrap().unwrap();
            assert_eq!(pass.sha256, Sha256Digest::of(data));
            assert_eq!(pass.bytes, data.len() as u64);
        }
        assert_eq!(lengths, [0, 2]);
    }

    #[test]
    fn a_buffer_that_is_too_small_is_an_error_not_a_panic() {
        let mut buf = vec![0; 8];
        let error =
            one_pass(&mut Cursor::new(b"data"), &mut buf, 64, &NoContent, |_| true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn read_errors_are_passed_on() {
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        }
        let mut buf = vec![0; buffer_len(&NoContent, 64)];
        let error = one_pass(&mut Failing, &mut buf, 64, &NoContent, |_| true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    /// Records every call, to check what a matcher is promised.
    struct Recording {
        overlap: usize,
        calls: Mutex<Vec<(Vec<u8>, usize, bool)>>,
    }

    impl ContentMatcher for Recording {
        fn overlap(&self) -> usize {
            self.overlap
        }

        fn scan(&self, window: &[u8], carry: usize, last: bool, _out: &mut HitAcc) {
            self.calls.lock().unwrap().push((window.to_vec(), carry, last));
        }
    }

    /// The contract of `ContentMatcher`, from the caller's side.
    #[test]
    fn a_matcher_sees_every_byte_once_fresh_the_overlap_repeated_and_one_last_window() {
        let window = 32;
        for overlap in [0, 1, 5, 31, 32, 33, 80] {
            for len in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 96, 200] {
                let data = corpus(len.max(32))[..len].to_vec();
                let matcher = Recording { overlap, calls: Mutex::new(Vec::new()) };
                run(&data, window, &matcher);
                let calls = matcher.calls.into_inner().unwrap();

                let mut seen: Vec<u8> = Vec::new();
                for (index, (bytes, carry, last)) in calls.iter().enumerate() {
                    let context = format!("overlap {overlap} len {len} call {index}");
                    // The carry is the last `overlap` bytes read so far, or
                    // all of them while there are fewer.
                    assert_eq!(*carry, overlap.min(seen.len()), "{context}");
                    assert_eq!(&bytes[..*carry], &seen[seen.len() - carry..], "{context}");
                    seen.extend_from_slice(&bytes[*carry..]);
                    // Only the final call is the last one.
                    assert_eq!(*last, index + 1 == calls.len(), "{context}");
                    // Every window but the last is full.
                    assert!(*last || bytes.len() - carry == window, "{context}");
                }
                assert_eq!(seen, data, "overlap {overlap} len {len}");
                assert!(!calls.is_empty());
            }
        }
    }

    /// A pack with one rule whose script literals are `tokens`.
    fn script_pack(tokens: &[(&str, Boundary)]) -> Pack {
        let rule = Rule {
            id: "sdk/scripted".into(),
            name: "Scripted".into(),
            entity: None,
            category: "component".into(),
            sources: vec![],
            notes: vec![],
            matchers: BTreeMap::from([(
                MatcherKind::ContentLiteral,
                tokens.iter().map(|&(lit, at)| Token { lit: lit.into(), at }).collect(),
            )]),
            min_distinct: BTreeMap::new(),
        };
        let layer = Layer {
            format: V1,
            fixes: xs_model::fix::Fixes::default(),
            layer: "core".into(),
            version: 1,
            license: "CC-BY-4.0".into(),
            categories: vec![Category {
                id: "component".into(),
                name: "Component".into(),
                headline: false,
            }],
            entities: vec![],
            rules: vec![rule],
        };
        Pack::new(vec![LoadedLayer { layer, sha256: Sha256Digest::of(b"") }]).unwrap()
    }

    const SCRIPT_TOKENS: [(&str, Boundary); 4] = [
        ("us.i.posthog.com", Boundary::Host),
        ("i.posthog.com", Boundary::Host),
        ("sentry.javascript.", Boundary::Word),
        ("posthog", Boundary::None),
    ];

    /// The real engine through the real reader: a boundary byte that lies in
    /// the next window, or a stream that ends on a window edge, changes
    /// nothing.
    #[test]
    fn the_engine_finds_anchored_literals_at_every_window_size() {
        let pack = script_pack(&SCRIPT_TOKENS);
        let matchers = Matchers::build(&pack).unwrap();
        let engine = matchers.content(MatcherKind::ContentLiteral, Scope::AppCode);

        let script = b"api_host:\"https://us.i.posthog.com\",name:`sentry.javascript.${n}`,\
            decoy:\"us.i.posthog.community\",other:\"sentry.javascript.browser\";posthog";
        let mut data = script.to_vec();
        data.resize(512, b' ');
        data.extend_from_slice(b"sentry.javascript.");
        let found = |pass: &OnePass| -> Vec<u32> {
            (0..4).map(|index| pass.hits.count(PatternId(index))).collect()
        };

        let whole = run(&data, data.len() * 2, engine);
        // Both hosts in the first literal, one template, and `posthog`
        // inside the host, inside the decoy and alone. The decoy host and
        // the longer identifier are not hits.
        assert_eq!(found(&whole), [1, 1, 2, 3]);
        for window in (HEAD..=96).chain([255, 256, 257, 511, 512, 513, 530, 531, 2000]) {
            let chunked = run(&data, window, engine);
            assert_eq!(chunked.hits, whole.hits, "window {window}");
            assert_eq!(chunked.sha256, whole.sha256, "window {window}");
        }

        // A file of a runtime scope is hashed with an engine that looks for
        // nothing.
        let idle = matchers.content(MatcherKind::ContentLiteral, Scope::Runtime);
        let hashed = run(&data, 64, idle);
        assert!(hashed.hits.is_empty());
        assert_eq!(hashed.sha256, whole.sha256);
        assert_eq!(buffer_len(idle, 64), 64);
    }

    proptest! {
        /// Build plan, task 5: "Chunked and whole-buffer scans agree on
        /// random input", here through the reader, with short reads.
        #[test]
        fn engine_hits_through_the_reader_equal_a_whole_buffer_scan(
            pieces in prop::collection::vec(
                prop_oneof![
                    prop::sample::select(&SCRIPT_TOKENS[..]).prop_map(|(lit, _)| lit.as_bytes().to_vec()),
                    prop::collection::vec(prop::sample::select(&b"ab.-_ /\"\xc3"[..]), 0..6),
                    prop::collection::vec(any::<u8>(), 0..40),
                ],
                0..80,
            ),
            window in HEAD..160usize,
            step in 1..200usize,
        ) {
            let data = pieces.concat();
            let pack = script_pack(&SCRIPT_TOKENS);
            let matchers = Matchers::build(&pack).unwrap();
            let engine = matchers.content(MatcherKind::ContentLiteral, Scope::AppCode);

            let mut expected = HitAcc::new();
            engine.scan(&data, 0, true, &mut expected);

            let mut buf = vec![0x55; buffer_len(engine, window)];
            let mut reader = Trickle { data: &data, step };
            let pass = one_pass(&mut reader, &mut buf, window, engine, |_| true).unwrap().unwrap();
            prop_assert_eq!(pass.hits, expected);
            prop_assert_eq!(pass.sha256, Sha256Digest::of(&data));
            prop_assert_eq!(pass.bytes, data.len() as u64);
        }
    }
}
