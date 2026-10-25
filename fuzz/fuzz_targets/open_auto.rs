//! Whole-pipeline fuzzing: raw bytes straight through signature detection
//! into whichever format claims them, exactly as a real caller would. Needs
//! no changes as formats are added or removed - `registry::detect` already
//! walks whatever `native/src/formats/*.rs` discovers at build time.
//!
//! Reads every discovered member (capped, so one archive with a huge member
//! count can't stall every iteration) rather than just opening and
//! discarding: `open()` alone never reaches most formats' actual
//! decompression/extraction code (squashfs, ubifs, jffs2, cramfs, lz4_frame,
//! lzma_alone), since that only runs when something reads a member.
#![no_main]
use firmware_unpack::archive::Archive;
use libfuzzer_sys::fuzz_target;

const MAX_MEMBERS_READ: usize = 64;

fuzz_target!(|data: &[u8]| {
    let Ok(archive) = Archive::open_auto(data.to_vec()) else {
        return;
    };
    for index in 0..archive.names().len().min(MAX_MEMBERS_READ) {
        let _ = archive.read(index);
    }
});
