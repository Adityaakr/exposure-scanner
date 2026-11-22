//! The zip reader: end record, central directory, local headers, inflate.
//!
//! The input is taken as a whole archive and read the way the collector
//! reads a file. Whatever the bytes are, the reader must return and must
//! never hand out more than the inflate budget. And inflating an entry in a
//! window, keeping only its head, must decide what inflating it whole does.
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
    // One buffer for every entry, as the collector reads them.
    let mut inflated = Vec::new();
    let (mut head, mut window) = (Vec::new(), Vec::new());
    for entry in &entries {
        // `directory` promises an entry that starts before the directory.
        let local = &archive[entry.offset as usize..];
        let _ = zip::data_offset(local);
        // Each entry the way both of Android's readers read it.
        for reader in [zip::Reader::Code, zip::Reader::Resources] {
            let entry = entry.read_by(reader);
            let Ok(data) = zip::data(&entry, local) else { continue };
            assert_eq!(data.len(), entry.compressed_bytes as usize);
            let whole = zip::content(&entry, data, BUDGET, &mut inflated);
            if let Ok(content) = whole {
                assert_eq!(content.len(), entry.bytes as usize);
                assert!(content.len() <= BUDGET);
            }
            if matches!(entry.method, zip::Method::Deflated) && (entry.bytes as usize) <= BUDGET {
                let keep = dex_header_or_all(entry.bytes as usize);
                let windowed =
                    zip::inflate_head(data, entry.bytes as usize, keep, &mut head, &mut window);
                match zip::content(&entry, data, BUDGET, &mut inflated) {
                    Ok(content) => {
                        assert_eq!(windowed, Ok(()));
                        assert_eq!(head.as_slice(), &content[..keep.min(content.len())]);
                    }
                    Err(error) => assert_eq!(windowed, Err(error)),
                }
            }
            assert!(inflated.capacity() <= BUDGET, "the buffer never outgrows the budget");
        }
    }
});

/// How much of an entry's head to keep: what the collector keeps of a DEX
/// file, or all of a small entry, so both ends of the window are reached.
fn dex_header_or_all(declared: usize) -> usize {
    if declared % 2 == 0 { xs_formats::dex::HEADER_BYTES } else { declared }
}
