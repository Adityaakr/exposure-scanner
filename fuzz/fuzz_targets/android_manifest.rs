//! The reader of compiled Android manifests: chunks, string pool in both
//! encodings, resource map, element attributes.
//!
//! Whatever the bytes are, the reader must return, and the text it takes
//! out of the string pool must stay within its budget.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::android_manifest::{self, MAX_BYTES};

fuzz_target!(|data: &[u8]| {
    let Ok(manifest) = android_manifest::parse(data) else { return };
    let text: usize = manifest.components.iter().map(|component| component.name.len()).sum();
    // A relative class name is prefixed with the package, once per name.
    let package = manifest.package.as_ref().map_or(0, String::len);
    assert!(text <= MAX_BYTES + manifest.components.len() * (package + 1));
});
