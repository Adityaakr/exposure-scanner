//! The lookup of a string in the resource table of an APK
//! (`resources.arsc`): the table's chunks, its package and type chunks in
//! every entry layout, entries plain and compact, and chains of references.
//!
//! Whatever the bytes are, the lookup must return, and the text it gives
//! must stay within its budget.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::android_resources::{self, MAX_TEXT_BYTES};

fuzz_target!(|data: &[u8]| {
    // The id is taken from the input, so every package, type and entry can
    // be reached; the rest is the table.
    let Some((id, table)) = data.split_first_chunk::<4>() else { return };
    let Ok(Some(text)) = android_resources::string(table, u32::from_le_bytes(*id)) else {
        return;
    };
    assert!(text.len() <= MAX_TEXT_BYTES);
});
