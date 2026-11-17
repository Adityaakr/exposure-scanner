//! The reader of browser extension manifests: comment blanking, the lenient
//! object reader, message catalogues and site patterns.
//!
//! Whatever the bytes are, the reader must return. What it keeps of a
//! manifest stays within its entry budget, and a locale it keeps is one
//! safe path component.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::extension_manifest::{self, MAX_ENTRIES};

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = extension_manifest::parse(data) {
        let scripts: usize =
            manifest.content_scripts.iter().map(|script| script.matches.len()).sum();
        let entries = manifest.permissions.len()
            + manifest.optional_permissions.len()
            + manifest.host_permissions.len()
            + manifest.optional_host_permissions.len()
            + manifest.content_scripts.len()
            + scripts;
        assert!(entries <= MAX_ENTRIES);
        if let Some(locale) = &manifest.default_locale {
            assert!(!locale.is_empty() && !locale.contains(['/', '\\', '.']));
        }
        let patterns = manifest.permissions.iter().chain(&manifest.host_permissions);
        for entry in patterns {
            let _ = extension_manifest::site_pattern(entry);
        }
        if let Some(key) = manifest.name.as_deref().and_then(extension_manifest::message_key) {
            let _ = extension_manifest::message(data, key);
        }
    }
    let _ = extension_manifest::message(data, "extName");
});
