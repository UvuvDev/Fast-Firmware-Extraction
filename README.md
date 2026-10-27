# Container Browser Extension Plugin

Tired of spending an hour per firmware image doing endless extraction? Use Binary Ninja's builtin container browser and have it automated instead!

## Supported formats

- **SamsungPit** — Samsung PIT partition descriptors (Rust)

Formats land one at a time, each as its own PR. Add a new unpacker with
**one Rust module under `native/src/formats/` plus fixtures**. Build
discovery, Python registration, and recursive CLI dispatch are automatic.
See [the contributor guide](docs/ADDING_A_FORMAT.md) and
[the copyable template](native/templates/format.rs).

## Rust unpacking

Every format module shares one native core. Tests run without Python or
Binary Ninja:

```sh
cargo test --locked
```

Build the optional native backend for the current platform, then test its
Python bridge against the existing fixture lengths and SHA-256 hashes:

```sh
cargo build --release --locked
python3 -m unittest discover -s native/tests -v
```

The ported Binary Ninja transforms use the library in
`target/release/` after a plugin reload/restart. Python fallback readers remain
available without the library; Rust-only formats require the native build. A present but incompatible library or
a Rust parse error is reported as a failure. Use the default Cargo target
directory when building for the plugin. Parsing/extraction runs in Rust;
Python adapts Container Browser's discovery and file-selection protocol.
Legacy Python readers remain as fallbacks and parity references where a
format has one.

Embedded signature detection (bounded, indexed) shares `aho-corasick`
crate-wide; it's the one dependency every build needs regardless of which
formats are registered. A format's own additional dependencies (if any) are
documented alongside that format. No external extraction program is
required at runtime. Dependencies are pinned in Cargo.lock.

For standalone extraction, independent of Binary Ninja:

```sh
target/release/firmware-unpack /path/to/firmware-image /path/to/new-output-directory
```

The CLI detects the input and recursively unpacks all supported native layers.
Each nested archive gets a sibling `<member>.unpacked/` directory. Each
archive directory contains `.ffe-paths.tsv`, mapping original paths to
disk paths and nested directories. Case collisions receive suffixes. The
output directory must be new. A detected-but-unopenable nested member (an
unsupported sub-feature, or genuine corruption) is left un-recursed-into with
a warning on stderr, rather than aborting the rest of the extraction. Total
output across one run is capped at 64 GiB / 1,000,000 files. Use
`--list-formats` to view the built registry.

Most formats cap both the whole input and any single member at 512 MiB/1 GiB
(`MAX_FILE_SIZE`/`MAX_INPUT_SIZE`), since a firmware partition or header has
no legitimate reason to exceed that; a format can override either bound
(`FormatDescriptor::max_file_size`/`max_input_size`) where routinely exceeding
it is normal rather than a sign of a hostile input — a disk/partition image
or an individual multi-GiB filesystem nested inside one (e.g. a Linux live
ISO's squashfs/erofs) is exactly that case. See each format's own notes for
which ones do.

Member names are rejected if they contain `\` or `:`, are empty, control
characters, `.`/`..` path segments, or exceed 4096 bytes — both are unsafe to
write verbatim on Windows (a path separator and a drive-letter/NTFS-stream
marker, respectively) even though they're ordinary on Linux (multiarch dpkg
lists like `pkg:arm64.list`, systemd `\x2d`-escaped generated unit names).
One such name, or a duplicate, is skipped rather than failing the whole
archive. The skipped names are reported via `diagnostics()`/stderr, capped
at 5 shown plus a count.

Run the Binary Ninja integration suite (requires a licensed local install):

```sh
BN_DISABLE_USER_PLUGINS=1 ./scripts/run_tests.sh -v --confcutdir=tests
```

This isolates unrelated user plugins and keeps pytest from importing the
hyphenated checkout directory as a Python package.

Samsung PIT exposes each named partition's raw 132-byte descriptor. A standalone
PIT contains no partition payloads; device geometry and obsolete file offsets
are never used to carve imaginary contents.
