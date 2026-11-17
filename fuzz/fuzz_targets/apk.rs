//! The Android collector, end to end, on a package held in memory: the
//! plan made from the directory, the one pass that copies entries out, the
//! parsers, and the records.
//!
//! Whatever the bytes are, the scan must succeed, and every record it emits
//! must be one the evidence format accepts, under the hash of the input.
#![no_main]

use std::io::Cursor;
use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use xs_collect::android;
use xs_match::Matchers;
use xs_model::record::Record;
use xs_model::{EvidenceSet, Pack, Sha256Digest, SubjectDigest};
use xs_rules::{SignedLayer, TRUSTED_KEYS};

/// The signed pack the scanner ships with.
static PACK: LazyLock<Pack> = LazyLock::new(|| {
    let layer = SignedLayer {
        bytes: include_bytes!("../../rules/dist/core.pack.json"),
        signature: include_str!("../../rules/dist/core.pack.json.minisig"),
    };
    xs_rules::load_pack(&[layer], TRUSTED_KEYS).expect("the committed pack is signed")
});
static MATCHERS: LazyLock<Matchers<'static>> =
    LazyLock::new(|| Matchers::build(&PACK).expect("the committed pack compiles"));

fuzz_target!(|apk: &[u8]| {
    let records = android::scan_reader(&mut Cursor::new(apk), apk.len() as u64, &MATCHERS)
        .expect("reading from memory cannot fail");

    let digest = SubjectDigest::Sha256(Sha256Digest::of(apk));
    let mut artifacts = 0;
    let mut evidence = EvidenceSet::new();
    for record in records {
        assert_eq!(record.subject().digest, digest);
        artifacts += usize::from(matches!(record, Record::Artifact(_)));
        evidence.insert(record).expect("a collector emits only valid records");
    }
    assert_eq!(artifacts, 1, "one artifact record per package");
});
