//! The DEX reader: header, string table, type table, class definitions.
//!
//! Whatever the bytes are, both walks must end, and neither may hand out
//! more string bytes than the file holds: that budget is what keeps the
//! work linear on a file whose every id points at one long string.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::dex::{self, Dex};

fuzz_target!(|data: &[u8]| {
    // The header alone decides what the whole file is refused for, and an
    // empty layout means both walks hand out nothing.
    let layout = dex::Layout::read(&data[..data.len().min(dex::HEADER_BYTES)], data.len());
    let dex = match Dex::parse(data) {
        Ok(dex) => dex,
        Err(error) => {
            assert_eq!(layout.err(), Some(error));
            return;
        }
    };
    let layout = layout.expect("the header accepts what the whole file does");
    if layout.is_empty() {
        assert_eq!(dex.strings().count(), 0);
        assert_eq!(dex.class_descriptors().count(), 0);
    }

    let mut handed_out = 0usize;
    for string in dex.strings() {
        let Ok(string) = string else { break };
        handed_out += string.len() + 1;
    }
    assert!(handed_out <= data.len());

    let mut handed_out = 0usize;
    let mut name = Vec::new();
    for descriptor in dex.class_descriptors() {
        let Ok(descriptor) = descriptor else { break };
        handed_out += descriptor.len() + 1;
        // Every descriptor the walk yields is a class descriptor.
        assert!(dex::class_name(descriptor, &mut name));
        assert_eq!(name.len() + 2, descriptor.len());
    }
    assert!(handed_out <= data.len());
});
