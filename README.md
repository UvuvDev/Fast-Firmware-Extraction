# Container Browser Extension Plugin

Tired of spending an hour per firmware image doing endless extraction? Use Binary Ninja's builtin container browser and have it automated instead!

## Supported formats

- **FBPack** — Fastboot Package (FBPK) v1/v2 (Rust)
- **AndroidBootImage** — Android Boot / Vendor Boot Image (Rust)
- **AndroidSparse** — Android Sparse Image (Rust)
- **AndroidSelfExtract** — Android self-extracting vendor blob (Rust)
- **Dtbo** — DTBO / DT Table Image (Rust)
- **Qcdt** — Qualcomm Device Tree Table (QCDT v1/v2/v3, Rust)
- **QcomMbn** — Qualcomm Legacy MBN Firmware Header (Rust)
- **ShannonTOC** — Samsung Shannon Baseband TOC (Rust)
- **UnisocMECP** — Unisoc CP memory-decoupling modem image (Rust)
- **FwTypeHeader** — Vendor fw-type Header (Rust)
- **SamsungPit** — Samsung PIT partition descriptors (Rust)
- **Gpt** — GUID Partition Table (512-byte sectors, Rust)
- **Ext4** — ext4 filesystem (Rust)
- **Erofs** — EROFS filesystem (uncompressed, Rust)
- **F2fs** — F2FS static-NAT filesystem, 4 KiB (Rust)
- **Squashfs** — SquashFS filesystem (Rust)
- **Ubifs** — UBIFS committed filesystem, none/raw DEFLATE (Rust)
- **Ubi** — UBI flash image (Rust)
- **NetgearChk** — NETGEAR CHK firmware wrapper (Rust)
- **Trx** — Broadcom TRX v1/v2 partitions with CRC32 verification (Rust)
- **Apbl** — Google APBL v2 wrapper with SHA-384 verification (Rust)
- **Blfs** — standalone/embedded BLFS v1 bootloader resource archives (Rust)
- **Lz4Frame** — modern LZ4 frames, linked/independent blocks and checksums (Rust)
- **LzmaAlone** — LZMA-alone compressed images (Rust)
- **UBootLegacyImage** — U-Boot legacy image (uImage), single and multi-file, CRC32-verified (Rust)
- **UBootFit** — U-Boot Flattened Image Tree (FIT) devicetree images (Rust)
- **CpioNewc** — CPIO "newc" (070701) archives, e.g. Linux initramfs (Rust)
- **Cramfs** — CramFS filesystem, zlib-compressed (Rust)

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

The ported Binary Ninja transforms use the library in
`target/release/` after a plugin reload/restart. Python fallback readers remain
available without the library; Rust-only formats require the native build. A present but incompatible library or
a Rust parse error is reported as a failure. Use the default Cargo target
directory when building for the plugin. CHK, TRX and LZMA require the Rust
library. Parsing/extraction runs in Rust; Python adapts Container Browser's
discovery and file-selection protocol. All 28 current format modules have Rust
implementations; legacy Python readers remain as fallbacks and parity references.

The native build uses `backhand` (MIT/Apache-2.0) with XZ enabled, statically
links liblzma, and uses `lzma-rust2` (Apache-2.0). No external extraction
program is required at runtime. A C compiler is required to build liblzma.
The optional GPL LZO backend is disabled. LZ4 uses pure Rust `lz4_flex`,
embedded signatures share `aho-corasick`, and APBL integrity uses `sha2`.
Dependencies are pinned in Cargo.lock.

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

MECP extracts the embedded modem, CP bootstrap, and optional AVB vbmeta.
Sibling memory regions are reported in the memory map rather than emitted as
files. The adjusted modem load address is logged by Binary Ninja and printed
by the CLI. Recognized AVB footers with invalid lengths/ranges are rejected;
cryptographic signatures are not verified.

GPT currently uses 512-byte logical sectors and checks both header and
partition-array CRC32s. Extended header/entry sizes and UTF-16LE partition
names are supported; backup-table recovery and 4 KiB sectors are not yet implemented.

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

UBI reorders logical eraseblocks and extracts named static/dynamic volumes.
It uses the first layout-table copy and rejects missing/duplicate data LEBs;
update recovery and UBI header/data CRC verification are not implemented.

Ext4 supports standard/padless superblocks, extent trees, direct through
triple-indirect mappings, sparse/unwritten blocks, and small inline files.
Inline directories/xattr overflow, journal replay, meta_bg, encryption, casefold,
and checksum verification are outside the current implementation.

EROFS handles flat files, inline tails, compact/extended inodes and single-device
chunk mappings. Compressed inodes, metabox, global 48BIT addressing, multiple
devices and checksum verification remain unsupported. Filesystem readers expose
regular files and skip symlinks and special nodes.

Samsung PIT exposes each named partition's raw 132-byte descriptor. A standalone
PIT contains no partition payloads; device geometry and obsolete file offsets
are never used to carve imaginary contents.

UBIFS checks node CRCs and reconstructs the committed index with uncompressed
or raw DEFLATE data. Dirty/diverging masters, journal replay, authentication,
LZO and ZSTD are unsupported. DEFLATE uses pure Rust `miniz_oxide`; each data
node expands to at most 4 KiB. UBI volumes chain into UBIFS automatically.

F2FS handles 4 KiB blocks, checkpoint pack/version selection, NAT copy selection,
inline files/directories, extra attributes, sparse data and indirect node tiers.
It reads static NAT entries only: inline xattrs, compression/encryption,
checkpoint-payload overflow, NAT journal/roll-forward replay and checksums are
unsupported. F2FS/UBIFS validation uses synthetic fixtures, not device images.

BLFS detects a standalone table or one embedded within the first 4 MiB of an
executable. It preserves member names and stored bytes; LZ4 members recursively
decode through the normal registry. The v1 layout is verified against the real
Cubs spacecraft ABL image and independent extraction of all 28 resource files.

APBL supports the observed Google v2 layout with a 0x5000-byte prefix. It checks
the stored SHA-384 payload digest and exposes payload.bin; cryptographic signing
metadata is not authenticated. The executable can then expose embedded BLFS
resources, whose LZ4 streams decode automatically. See
[Cubs ABL validation](tests/fixture_sources/cubs_abl/README.md).

UBootLegacyImage verifies both the 64-byte header's CRC32 and the data CRC32
(plain zlib CRC32, checked against real `mkimage`/`dumpimage` output) before
exposing the payload. A multi-file image (kernel+initrd+dtb combined with
`-T multi`) is split into `data00.bin`, `data01.bin`, ... using the embedded
big-endian size table and its 4-byte inter-image padding; every other type is
exposed as one named file (`kernel.bin`, `ramdisk.bin`, `fdt.bin`, ...).
Compressed payloads (ih_comp != none) are returned as stored bytes; nested
detection decodes any payload this crate otherwise recognizes.

UBootFit walks a Flattened Image Tree's devicetree structure block far enough
to read each `/images/*` subnode's `data` property, without being a general
FDT/overlay reader. A devicetree blob sharing the same magic but lacking an
`/images` node (an ordinary `.dtb`, say) is rejected rather than misreported.
External-data FIT images, whose image data lives outside the devicetree
blob instead of inline, are not supported. See
[U-Boot fixture provenance](tests/fixture_sources/uboot/README.md).

CpioNewc exposes every regular file in a "070701" stream as a byte range;
cpio never compresses entries, so no decoder is needed. A leading "./" (from
a `find .`-style archive) is stripped from member names. Directories,
symlinks, device nodes, and hardlink bookkeeping are not represented as
members, and the "070702" CRC variant is unsupported. See
[CPIO fixture provenance](tests/fixture_sources/cpio_newc/README.md).

Cramfs walks the modern FSID_VERSION_2 superblock layout and decompresses
each file's zlib-wrapped 4 KiB blocks on read, verifying each block's
Adler-32 trailer. A zero-length block is treated as a hole (zero bytes)
regardless of the advisory HOLES flag; any other flag bit, including the
legacy pre-FSID_VERSION_2 superblock, SHIFTED_ROOT_OFFSET, or
WRONG_SIGNATURE, is rejected rather than guessed at. See
[CramFS fixture provenance](tests/fixture_sources/cramfs/README.md).
