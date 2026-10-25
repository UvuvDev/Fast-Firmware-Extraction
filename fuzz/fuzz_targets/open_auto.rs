//! Whole-pipeline fuzzing: raw bytes straight through signature detection
//! into whichever format claims them, exactly as a real caller would. Needs
//! no changes as formats are added or removed - `registry::detect` already
//! walks whatever `native/src/formats/*.rs` discovers at build time.
#![no_main]
use firmware_unpack::archive::Archive;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Archive::open_auto(data.to_vec());
});
