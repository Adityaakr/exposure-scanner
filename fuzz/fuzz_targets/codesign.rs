//! The code signature reader: the superblob, fed in pieces, its Team ID
//! and the entitlements it grants.
//!
//! The first byte of the input is the size of the pieces. Whatever the
//! bytes are, a Team ID handed out is within its budget, and so is the
//! number of entitlements.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::codesign::{self, Reader};

fuzz_target!(|input: &[u8]| {
    let Some((&step, blob)) = input.split_first() else { return };
    let mut reader = Reader::new();
    for piece in blob.chunks(usize::from(step).max(1)) {
        reader.push(piece);
    }
    if let Ok(Some(team)) = &reader.finish().team_id {
        assert!(team.len() <= codesign::MAX_TEAM_ID_BYTES);
    }
    if let Ok(list) = codesign::entitlements(blob) {
        assert!(list.len() <= codesign::MAX_ENTITLEMENTS);
    }
});
