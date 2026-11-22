//! The property list readers: a bundle's `Info.plist` and a privacy
//! manifest, in XML or binary form.
//!
//! Whatever the bytes are, both readers return, and a privacy manifest
//! keeps no more tracking domains than its budget.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::{info_plist, privacy_manifest};

fuzz_target!(|bytes: &[u8]| {
    let _ = info_plist::parse(bytes);
    if let Ok(manifest) = privacy_manifest::parse(bytes) {
        assert!(manifest.tracking_domains.len() <= privacy_manifest::MAX_DOMAINS);
    }
});
