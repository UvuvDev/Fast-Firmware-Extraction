//! Per-format fuzzing that skips signature detection entirely: the first
//! byte picks a format id from whatever `registry::formats()` currently
//! returns, and every remaining byte is that format's input. Undirected
//! mutation essentially never reproduces a multi-byte magic (e.g.
//! `ANDROID!`), so without this a corpus-guided fuzzer spends almost all of
//! its time failing detection instead of exercising any parser's actual
//! logic. Needs no changes as formats are added or removed - the format
//! list, and the valid range for that first byte, are both read at runtime.
#![no_main]
use firmware_unpack::{archive::Archive, registry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let formats = registry::formats();
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    if formats.is_empty() {
        return;
    }
    let format = &formats[selector as usize % formats.len()];
    let _ = Archive::open(format.id, payload.to_vec());
});
