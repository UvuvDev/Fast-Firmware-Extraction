# Adding a Rust format

Add laterally: **one file under `native/src/formats/` plus fixtures**.
Do not add an enum variant, Python adapter, registration call, CLI branch,
Cargo test target, or edit another parser. `build.rs` discovers sibling `.rs`
files and generates the module list and registry. Python and the CLI consume
that registry. Dependencies genuinely needed by a new reader belong in Cargo.

## Start from the template

Copy `native/templates/format.rs` to `native/src/formats/<format_id>.rs`.
Use a lowercase identifier such as `vendor_image` for both the filename and
`FORMAT.id`. Give `FORMAT.name` a unique Binary Ninja transform name.
The template's EXMP layout is illustrative: replace its signature and `open`
implementation with the verified format, and record the reference source,
license, supported versions/compression, and fixture provenance in the module.
`native/src/formats/netgear_chk.rs` is a real offset-container example;
`lzma_alone.rs` is a decoded stream; `squashfs.rs` is a filesystem reader.

Each module exports one `pub const FORMAT: FormatDescriptor`:

```rust
pub const FORMAT: FormatDescriptor = FormatDescriptor {
    id: "vendor_image",
    name: "VendorImage",
    description: "Vendor firmware image",
    signatures: &[Signature::new(0, b"MAGC")],
    probe: None,
    open,
};
```

Signatures support nonzero offsets and alternatives. A format without fixed
magic can use `Signature::byte_range` plus a discriminator in `probe` (see
LZMA). Probes receive at most 1 MiB and must bound their own allocations and
work. Python queries the backend for its probe limit. Detection indexes signatures by offset and first byte, tests only those
buckets, and invokes probes only for matching signatures. Longer exact
signatures win; equal lengths resolve by stable ID. Use a discriminator for
overlapping formats; a full parse failure propagates without trying another
format. Broad signatures should be exceptional.

## Return a reader

`open(Vec<u8>) -> Result<Box<dyn ArchiveReader>>` owns input and returns an
in-memory session. It has no Binary Ninja, Python, CLI, or disk dependency.

- Offset tables: return `RangeArchive::new(data, Vec<Member>)`.
- One selectable decoded file: return `RangeArchive::single(name, decoded_bytes)`.
- One automatic decoded stream: return `RangeArchive::decoded_stream(name, bytes)`.
  Binary Ninja exposes an unnamed child, preserving normal decode-transform
  behavior; the CLI uses `name` for the output file.
- Filesystems/custom layouts: implement `ArchiveReader::names` and `read`.
  Keep the index and any decompressor state in that reader.

Optional analysis text (such as a load-address/memory-map report) can be
attached with `RangeArchive::with_diagnostics(text)` or returned by
`ArchiveReader::diagnostics`. The generic adapter logs it during extraction;
the CLI prints it to stderr. Format code needs no Binary Ninja dependency.

Use checked helpers from `crate::bytes` and checked arithmetic. RangeArchive
validates every range before discovery. The common Archive wrapper rejects
unsafe/duplicate names, caps input at 1 GiB, members at one million, and returned
file bytes at 512 MiB. Readers must also bound decompression and metadata
allocation **before** allocating them. Emit regular files; skip firmware
symlinks and special nodes. Fail on malformed data rather than clamping ranges.

Nested unpacking uses content detection automatically. A format does not add
child dispatch rules to shared code or need to know which other formats exist.

## Add fixtures

Create directories under `tests/fixtures/`, each with a sample and
`expected.json`. Both the Rust fixture runner and Python bridge runner discover
native fixtures automatically; the Binary Ninja runner uses the same data.

```json
{
  "native_format": "vendor_image",
  "sample": "sample.bin",
  "children": {
    "payload.bin": {"length": 4, "sha256": "<independently computed hash>"}
  }
}
```

Add at least one valid fixture and one corrupt/truncated fixture:

```json
{
  "native_format": "vendor_image",
  "sample": "sample.bin",
  "expect_failure": true
}
```

The Rust runner requires both kinds for every registered format. Child records
can contain `children` to verify nested archives. Set `transform` to the native
transform name only when Binary Ninja also offers a competing decoder (TRX is
an example). Keep fixtures small. Prefer official producers; record exact tool
versions/commands. Verify real firmware locally without committing vendor blobs.
Expected bytes/hashes must come from inputs or an independent reference tool,
rather than this parser's output. Format-specific mutation tests can live in
an inline `#[cfg(test)] mod tests` in the new module.

## Check the result

```sh
cargo test --locked
cargo build --release --locked
python3 -m unittest discover -s native/tests -v
cargo clippy --all-targets -- -D warnings
BN_DISABLE_USER_PLUGINS=1 ./scripts/run_tests.sh -q --confcutdir=tests
```

The final command needs a licensed Binary Ninja installation. Restart/reload
the plugin after rebuilding the native library. The optional
`python3 scripts/check_format_extension.py` proves the extension contract in
an isolated copy: it adds the example module and fixtures, and checks generated
registration, the Rust fixture runner, Python detection/extraction, and CLI.
It never edits the working source or replaces its library.

## Architecture boundaries

There is one native Binary Ninja detection callback, regardless of format
count. Named adapters for explicit selection are generated from Rust metadata.
The C ABI uses stable string IDs and opaque reader handles; it has no
format-specific functions. The CLI recursively extracts every recognized
format, using sibling `<member>.unpacked/` directories and `.ffe-paths.tsv`
mappings. It limits recursion to 16 nested layers, 100,000 extracted files,
and 4 GiB total output. Files that collide by case receive suffixes.

The registry test exercises 1,000 descriptors and checks that only the matching
candidate's probe runs. This verifies candidate selection, not a performance
claim for 1,000 fully implemented parsers. Shared capabilities should grow only
when multiple formats need them; adding a parser does not require a shared
change by default.

Existing Python implementations under `formats/` remain supported during
migration and still auto-import. DTBO and SquashFS retain their Python fallback
when the native library is absent. New unpackers should follow the Rust path.
