//! Per-format fuzzing that skips signature detection entirely: the first
//! byte picks a format id from whatever `registry::formats()` currently
//! returns, and every remaining byte is that format's input. Undirected
//! mutation essentially never reproduces a multi-byte magic (e.g.
//! `ANDROID!`), so without this a corpus-guided fuzzer spends almost all of
//! its time failing detection instead of exercising any parser's actual
//! logic. Needs no changes as formats are added or removed - the format
//! list, and the valid range for that first byte, are both read at runtime.
//!
//! Reads every discovered member (capped, so one archive with a huge member
//! count can't stall every iteration) rather than just opening and
//! discarding: `open()` alone never reaches most formats' actual
//! decompression/extraction code (squashfs, ubifs, jffs2, cramfs, lz4_frame,
//! lzma_alone), since that only runs when something reads a member.
#![no_main]
use firmware_unpack::{archive::Archive, registry};
use libfuzzer_sys::fuzz_target;

const MAX_MEMBERS_READ: usize = 64;

fuzz_target!(|data: &[u8]| {
    let formats = registry::formats();
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    if formats.is_empty() {
        return;
    }
    let format = &formats[selector as usize % formats.len()];
    let Ok(archive) = Archive::open(format.id, payload.to_vec()) else {
        return;
    };
    for index in 0..archive.names().len().min(MAX_MEMBERS_READ) {
        let _ = archive.read(index);
    }
});
