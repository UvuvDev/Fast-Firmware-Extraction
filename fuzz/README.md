# Fuzzing

Two libFuzzer targets, both format-agnostic: neither names a specific
format, so adding or removing one under `native/src/formats/` changes what
gets fuzzed with zero edits here.

- `open_auto` — raw bytes through `Archive::open_auto`, i.e. signature
  detection first, same as a real caller.
- `open_format` — the first input byte selects a format id from
  `registry::formats()` at runtime; the rest is that format's input. Skips
  detection, since undirected mutation essentially never reproduces a
  multi-byte magic like `ANDROID!` on its own.

## Running

```sh
rustup toolchain install nightly   # libFuzzer needs nightly's sanitizer support
cargo install cargo-fuzz           # once

cargo build --release                      # needed by seed_fuzz_corpus.py
python3 ../scripts/seed_fuzz_corpus.py      # from fuzz/, or adjust the path
cargo +nightly fuzz run open_auto
cargo +nightly fuzz run open_format
```

Add `-- -max_total_time=300` (seconds) for a bounded run instead of forever.
A crash reproduces directly: `cargo +nightly fuzz run open_format fuzz/artifacts/open_format/<name>`.

## Corpus

`scripts/seed_fuzz_corpus.py` seeds both targets from every real,
non-corrupt sample under `tests/fixtures/`, re-runnable any time new
fixtures land. `open_format`'s seeds need a leading format-selector byte
matching that fixture's own format id (see the target's doc comment); the
script derives it from `--list-formats`, so it stays correct as formats are
added, removed, or reordered without anyone updating a byte value by hand.
