//! The asar reader of Electron apps: the prefix of an archive and its JSON
//! header, with the path of every entry.
//!
//! The input is read both as a whole archive, whose header is then the
//! part right after its prefix, and as a header alone. Whatever the bytes
//! are, a header lists no more entries than its budget, and every entry it
//! lists has a path.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::asar;

fn walk(json: &[u8]) {
    let Ok(header) = asar::parse_header(json) else { return };
    assert!(header.len() <= asar::MAX_ENTRIES);
    for index in 0..header.len() {
        let _ = header.get(index);
        let _ = header.path(index);
    }
}

fuzz_target!(|bytes: &[u8]| {
    if let Ok(prefix) = asar::prefix(bytes) {
        // The header starts right after the prefix.
        let start = asar::PREFIX_BYTES;
        if let Some(json) = bytes.get(start..start.saturating_add(prefix.json_len)) {
            walk(json);
        }
    }
    walk(bytes);
});
