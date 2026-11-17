//! The zip reader: end record, central directory, local headers, inflate.
//!
//! The input is taken as a whole archive and read the way the collector
//! reads a file. Whatever the bytes are, the reader must return and must
//! never hand out more than the inflate budget.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xs_formats::zip;

/// Small, so that the fuzzer reaches the budget checks.
const BUDGET: usize = 1 << 16;

fuzz_target!(|archive: &[u8]| {
    let tail = &archive[archive.len().saturating_sub(zip::MAX_TAIL_BYTES)..];
    let Ok(end) = zip::locate(tail, archive.len() as u64) else { return };
    // `locate` promises a directory that lies inside the file.
    let start = usize::try_from(end.directory_offset).unwrap();
    let directory = &archive[start..start + end.directory_bytes];
    let Ok(entries) = zip::directory(directory, &end) else { return };
    assert_eq!(entries.len(), usize::from(end.entries));
    for entry in &entries {
        // `directory` promises an entry that starts before the directory.
        let local = &archive[entry.offset as usize..];
        let _ = zip::data_offset(local);
        let Ok(data) = zip::data(entry, local) else { continue };
        assert_eq!(data.len(), entry.compressed_bytes as usize);
        if let Ok(content) = zip::content(entry, data, BUDGET) {
            assert_eq!(content.len(), entry.bytes as usize);
            assert!(content.len() <= BUDGET);
        }
    }
});
