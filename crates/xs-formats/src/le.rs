//! Little-endian integers at a byte offset, without indexing.
//!
//! The Android formats (zip, DEX, binary XML) are little-endian throughout.
//! Every read here is bounds-checked and returns `None` past the end, so a
//! parser built on these cannot panic on a truncated or hostile input.

/// The `N` bytes of `bytes` that start at `at`.
fn array_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..)?.first_chunk::<N>().copied()
}

/// The unsigned 16-bit integer at `at`.
pub(crate) fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    array_at(bytes, at).map(u16::from_le_bytes)
}

/// The unsigned 32-bit integer at `at`.
pub(crate) fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    array_at(bytes, at).map(u32::from_le_bytes)
}

/// The unsigned 32-bit integer at `at`, as an offset or a count.
pub(crate) fn usize_at(bytes: &[u8], at: usize) -> Option<usize> {
    u32_at(bytes, at).and_then(|value| usize::try_from(value).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_refuses_to_read_past_the_end() {
        let bytes = [0x78, 0x56, 0x34, 0x12, 0xff];
        assert_eq!(u16_at(&bytes, 0), Some(0x5678));
        assert_eq!(u32_at(&bytes, 0), Some(0x1234_5678));
        assert_eq!(usize_at(&bytes, 1), Some(0xff12_3456));
        assert_eq!(u16_at(&bytes, 3), Some(0xff12));
        assert_eq!(u16_at(&bytes, 4), None);
        assert_eq!(u32_at(&bytes, 2), None);
        assert_eq!(u32_at(&bytes, usize::MAX), None);
        assert_eq!(u16_at(&[], 0), None);
    }
}
