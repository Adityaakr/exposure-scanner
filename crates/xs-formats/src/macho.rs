//! Recognising Mach-O files by their first bytes.
//!
//! Executables in an app bundle carry no file extension, so the only reliable
//! way to find them is the magic number. Parsing of load commands and
//! sections arrives with the macOS collector; this module only answers "is
//! this a Mach-O file, and of which shape".

/// How many leading bytes [`sniff`] looks at.
pub const SNIFF_BYTES: usize = 8;

/// The shape of a Mach-O file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachOKind {
    /// A single-architecture file.
    Thin,
    /// A universal file holding one slice per architecture.
    Fat,
}

/// `MH_MAGIC`, `MH_MAGIC_64` and their byte-swapped forms, as stored on disk.
const THIN_MAGICS: [[u8; 4]; 4] = [
    [0xfe, 0xed, 0xfa, 0xce],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xcf],
    [0xcf, 0xfa, 0xed, 0xfe],
];

/// `FAT_MAGIC` and `FAT_MAGIC_64`. Fat headers are always big-endian.
const FAT_MAGICS: [[u8; 4]; 2] = [[0xca, 0xfe, 0xba, 0xbe], [0xca, 0xfe, 0xba, 0xbf]];

/// A universal file lists at most a handful of architectures. A Java class
/// file starts with the same four bytes as `FAT_MAGIC`, followed by a version
/// number that is never below 45, so a small count tells the two apart.
const MAX_FAT_ARCHES: u32 = 30;

/// Classifies a file from its first [`SNIFF_BYTES`] bytes.
///
/// Returns `None` if the bytes are not the start of a Mach-O file, including
/// when fewer than eight bytes are given.
#[must_use]
pub fn sniff(header: &[u8]) -> Option<MachOKind> {
    let (magic, rest) = header.split_first_chunk::<4>()?;
    let (count, _) = rest.split_first_chunk::<4>()?;
    if THIN_MAGICS.contains(magic) {
        return Some(MachOKind::Thin);
    }
    if FAT_MAGICS.contains(magic) {
        let arches = u32::from_be_bytes(*count);
        if (1..=MAX_FAT_ARCHES).contains(&arches) {
            return Some(MachOKind::Fat);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn recognises_every_thin_magic() {
        for magic in THIN_MAGICS {
            let mut header = magic.to_vec();
            header.extend_from_slice(&[0x0c, 0, 0, 1]);
            assert_eq!(sniff(&header), Some(MachOKind::Thin));
        }
    }

    #[test]
    fn recognises_universal_files_but_not_java_classes() {
        // Two architectures.
        assert_eq!(sniff(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]), Some(MachOKind::Fat));
        assert_eq!(sniff(&[0xca, 0xfe, 0xba, 0xbf, 0, 0, 0, 1]), Some(MachOKind::Fat));
        // Java 8 class file: minor 0, major 52.
        assert_eq!(sniff(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]), None);
        // Zero architectures is not a usable universal file.
        assert_eq!(sniff(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0]), None);
    }

    #[test]
    fn rejects_short_and_foreign_input() {
        assert_eq!(sniff(&[]), None);
        assert_eq!(sniff(&[0xcf, 0xfa, 0xed, 0xfe]), None, "needs eight bytes");
        assert_eq!(sniff(b"#!/bin/sh\n"), None);
        assert_eq!(sniff(b"\x7fELF\x02\x01\x01\x00"), None);
        assert_eq!(sniff(b"PK\x03\x04\x14\x00\x00\x00"), None);
    }

    proptest! {
        #[test]
        fn never_panics(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
            let _ = sniff(&bytes);
        }
    }
}
