# Container Browser Extension Plugin

Tired of spending an hour per firmware image doing endless extraction? Use Binary Ninja's builtin container browser and have it automated instead!

## Supported formats

- **FBPack** — Fastboot Package (FBPK) v1/v2 (Rust)
- **AndroidBootImage** — Android Boot / Vendor Boot Image (Rust)
- **AndroidSparse** — Android Sparse Image (Rust)
- **AndroidSelfExtract** — Android self-extracting vendor blob (Rust)
- **Dtbo** — DTBO / DT Table Image
- **Qcdt** — Qualcomm Device Tree Table (QCDT v1/v2/v3, Rust)
- **QcomMbn** — Qualcomm Legacy MBN Firmware Header (Rust)
- **ShannonTOC** — Samsung Shannon Baseband TOC (Rust)
- **UnisocMECP** — Unisoc CP memory-decoupling modem image
- **FwTypeHeader** — Vendor fw-type Header
- **Gpt** — GUID Partition Table (GPT)
- **Ext4** — ext4 filesystem
- **Erofs** — EROFS filesystem
- **F2fs** — F2FS filesystem
- **Squashfs** — SquashFS filesystem
- **Ubi** — UBI flash image
- **NetgearChk** — NETGEAR CHK firmware wrapper (Rust)
- **Trx** — Broadcom TRX v1/v2 partitions with CRC32 verification (Rust)
- **LzmaAlone** — LZMA-alone compressed images (Rust)

Add a new unpacker with **one Rust module under `native/src/formats/` plus
fixtures**. Build discovery, Python registration, and recursive CLI dispatch
are automatic. See [the contributor guide](docs/ADDING_A_FORMAT.md) and
[the copyable template](native/templates/format.rs).

## Rust unpacking

The formats marked Rust above share one native core. It also handles the
complete **NETGEAR R7000** chain:
**CHK → TRX → LZMA kernel + SquashFS v4/XZ filesystem**. CHK/TRX
parsers validate bounds, and TRX verifies CRC32. LZMA has dictionary and
output limits; SquashFS exposes regular files and skips symlinks/specials.
Tests run without Python or Binary Ninja:

```sh
cargo test --locked
```

Build the optional native backend for the current platform, then test its
Python bridge against the existing fixture lengths and SHA-256 hashes:

```sh
cargo build --release --locked
python3 -m unittest discover -s native/tests -v
```

The Binary Ninja FBPK, sparse, boot, self-extract, DTBO, and SquashFS transforms use the library in
`target/release/` after a plugin reload/restart. If the library is absent,
the existing Python parser is used. A present but incompatible library or
a Rust parse error is reported as a failure. Use the default Cargo target
directory when building for the plugin. CHK, TRX and LZMA require the Rust
library. Parsing/extraction runs in Rust; Python adapts Container Browser's
discovery and file-selection protocol. Other unpackers remain Python.

The native build uses `backhand` (MIT/Apache-2.0) with XZ enabled, statically
links liblzma, and uses `lzma-rust2` (Apache-2.0). No external extraction
program is required at runtime. A C compiler is required to build liblzma.
The optional GPL LZO backend is disabled. Dependencies are pinned in Cargo.lock.

For standalone extraction, independent of Binary Ninja:

```sh
target/release/firmware-unpack /path/to/R7000-V1.0.9.88_10.2.88.chk /path/to/new-output-directory
```

The CLI detects the input and recursively unpacks all supported native layers.
Each nested archive gets a sibling `<member>.unpacked/` directory. For R7000,
the kernel is under `firmware.trx.unpacked/kernel.lzma.unpacked/kernel.bin`
and filesystem files under `firmware.trx.unpacked/rootfs.squashfs.unpacked/`.
Each archive directory contains `.ffe-paths.tsv`, mapping original paths to
disk paths and nested directories. Case collisions receive suffixes. The
output directory must be new. Use `--list-formats` to view the built registry.
See [R7000 validation and fixture provenance](docs/R7000.md).

Boot v0–v4 and vendor boot v3/v4 extract kernel/ramdisk, legacy second-stage
and DTBO/DTB segments, v4 signature bytes, fragmented vendor ramdisks, and
bootconfig in memory. Fixtures use the official AOSP producer; see
[boot fixture provenance](tests/fixture_sources/boot/README.md).

Self-extracting vendor wrappers scan at most 1 MiB for the `tail -n +N $0 | tar`
marker and expose the remaining bytes as `payload.gz`. Scripts are never run.
Payload targets at or before the marker are rejected to prevent recursion;
Python retains the legacy fallback when the Rust library is absent.

Android sparse preserves the automatic decoded child in Container Browser.
Its CLI output is `image.raw`. RAW, FILL, DONT_CARE, and CRC32 chunks are
validated, including supplied checksums, before exposing output; expansion
uses the common 512 MiB per-file limit.

The DTBO Rust implementation extracts stored payload bytes and ignores v1
compression flags; it does not decompress overlays. It validates every
payload before discovery, so an out-of-bounds payload rejects the whole
table earlier than the Python parser's extraction-time check. Coverage includes
v0/v1 images generated and independently extracted with a pinned copy of
AOSP's official `mkdtboimg.py`, containing valid overlays compiled with dtc.
See [fixture provenance and regeneration](tests/fixture_sources/dtbo/README.md).
The R7000 implementation is verified against the vendor's real 1.0.9.88 image;
see the linked validation document for its hash and independent comparison.

Run the Binary Ninja integration suite (requires a licensed local install):

```sh
BN_DISABLE_USER_PLUGINS=1 ./scripts/run_tests.sh -v --confcutdir=tests
```

This isolates unrelated user plugins and keeps pytest from importing the
hyphenated checkout directory as a Python package.
