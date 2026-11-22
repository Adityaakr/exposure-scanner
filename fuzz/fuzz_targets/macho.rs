//! The Mach-O reader: the walker over load commands, sections and slices of
//! a universal file, fed in pieces, and the reader of the names in a
//! binary's string tables.
//!
//! The first byte of the input is the size of the pieces, so the fuzzer
//! also finds what breaks only when a structure is split between two
//! reads. Whatever the bytes are, the spans an image hands out are in
//! order, do not overlap and lie inside the image, and no name is longer
//! than the budget.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::macho::{self, Names, Walker};

fuzz_target!(|input: &[u8]| {
    let Some((&step, file)) = input.split_first() else { return };
    let step = usize::from(step).max(1);
    let _ = macho::sniff(file);
    let mut walker = Walker::new();
    let mut images = Vec::new();
    for piece in file.chunks(step) {
        walker.push(piece);
        images.extend(walker.take_images());
    }
    let _ = walker.finish();
    for image in &images {
        for list in [&image.masked, &image.class_names, &image.scripts] {
            for pair in list.windows(2) {
                assert!(pair[0].end <= pair[1].start, "spans in order and apart");
            }
            for span in list.iter() {
                assert!(span.start <= span.end);
                if let Some(end) = image.end {
                    assert!(span.end <= end, "a span inside its image");
                }
            }
        }
    }
    let mut names = Names::new();
    for piece in file.chunks(step) {
        names.push(piece, |name| assert!(name.len() <= macho::MAX_NAME_BYTES));
    }
    names.finish(|name| assert!(name.len() <= macho::MAX_NAME_BYTES));
});
