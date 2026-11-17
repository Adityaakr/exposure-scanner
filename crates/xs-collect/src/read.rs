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
//! * **Carry.** The last `longest token − 1` bytes of each window are repeated
//!   at the start of the next, so a literal that straddles two windows is
//!   still found, and the result does not depend on where windows fall.

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

/// The buffer size [`one_pass`] needs for a given matcher and window.
#[must_use]
pub fn buffer_len<M: ContentMatcher + ?Sized>(matcher: &M, window: usize) -> usize {
    carry_len(matcher).saturating_add(window.max(HEAD))
}

fn carry_len<M: ContentMatcher + ?Sized>(matcher: &M) -> usize {
    matcher.max_token_len().saturating_sub(1)
}

/// Reads until `buf` is full or the stream ends. A short count means the end
/// of the stream was reached.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
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
    let window = window.max(HEAD);
    let carry_max = carry_len(matcher);
    if buf.len() < carry_max.saturating_add(window) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "scratch buffer is too small"));
    }

    // First window: a small read to classify, then the rest of the window.
    let (head_buf, _) = buf.split_at_mut(HEAD);
    let head = read_full(reader, head_buf)?;
    if !wanted(head_buf.get(..head).unwrap_or_default()) {
        return Ok(None);
    }
    let mut got = head;
    if head == HEAD {
        got += read_full(reader, buf.get_mut(HEAD..window).unwrap_or_default())?;
    }

    let mut hasher = Sha256Stream::new();
    let mut hits = HitAcc::new();
    let mut bytes: u64 = 0;
    let mut carry = 0;
    loop {
        // buf = [carry bytes repeated from the last window | got fresh bytes]
        let filled = carry + got;
        let Some(view) = buf.get(..filled) else { break };
        hasher.update(view.get(carry..).unwrap_or_default());
        matcher.scan(view, carry, &mut hits);
        bytes += got as u64;

        if got < window {
            // A short window is the end of the stream; no further read needed.
            break;
        }
        let keep = carry_max.min(filled);
        buf.copy_within(filled - keep..filled, 0);
        carry = keep;
        got = read_full(reader, buf.get_mut(carry..carry + window).unwrap_or_default())?;
        if got == 0 {
            break;
        }
    }
    Ok(Some(OnePass { sha256: hasher.finish(), bytes, hits }))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use xs_match::{NoContent, PatternId};

    use super::*;

    /// A naive substring matcher that honours the carry contract. It is the
    /// simplest possible reference: any windowing mistake in `one_pass` shows
    /// up as a wrong count.
    struct Naive(Vec<&'static [u8]>);

    impl ContentMatcher for Naive {
        fn max_token_len(&self) -> usize {
            self.0.iter().map(|pattern| pattern.len()).max().unwrap_or(0)
        }

        fn scan(&self, window: &[u8], carry: usize, out: &mut HitAcc) {
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
}
