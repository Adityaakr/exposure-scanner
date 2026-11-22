//! The readers of an app bundle's protocol buffers: the manifest
//! (`XmlNode`) and the lookup of a string in the resource table
//! (`ResourceTable`). Varints, length-delimited fields, nesting.
//!
//! Whatever the bytes are, both must return, and the text they give must
//! stay within its budget.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::android_manifest::MAX_BYTES;
use xs_formats::android_proto;
use xs_formats::android_resources::MAX_TEXT_BYTES;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = android_proto::manifest(data) {
        let text: usize = [&manifest.package, &manifest.version_name, &manifest.label]
            .into_iter()
            .flatten()
            .chain(manifest.components.iter().map(|component| &component.name))
            .chain(manifest.permissions.iter().map(|permission| &permission.name))
            .map(String::len)
            .sum();
        assert!(text <= MAX_BYTES);
    }
    for id in [0x7f0f_0000, 0x7f0f_0001] {
        if let Ok(Some(text)) = android_proto::string(data, id) {
            assert!(text.len() <= MAX_TEXT_BYTES);
        }
    }
});
