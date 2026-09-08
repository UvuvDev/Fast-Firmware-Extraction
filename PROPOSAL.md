# pixel_firmware_formats — architecture proposal

Status: **implemented and validated against real Pixel/Tensor firmware.**
See [Implementation status](#implementation-status) at the end for what
shipped, what changed from the original plan, and how the open questions
below were resolved.

## 1. What this plugin needs to cover

From `~/Downloads/google_devices-tegu-extraction.md` (Pixel Tablet `tegu`
vendor blob extraction), the formats Binary Ninja's core does **not** already
handle (core already covers tar/gzip/zip/ELF per
`api/docs/dev/containertransforms.md`) are:

| Format | Where it shows up | Notes |
|---|---|---|
| Android self-extracting vendor shell blob | `extract-google_devices-tegu.sh` | bash script + license banner, gzip'd tar appended at a `tail -n +N` offset that varies per script |
| **FBPACK v2** (`FBPK`) | `bootloader.img` | header_size/entry_header_size/platform/pack_version struct, 17 named sub-images |
| **FBPACK v1** (`FBPK`) | `radio.img` | different, older struct (no header_size/platform; `img_version` + `next_offset`-linked entries) |
| **ext4** (standard, superblock @ 1024) | `vendor.img`, `vendor_dlkm.img` | tree of files/symlinks |
| **ext4** (non-standard, superblock @ 0) | modem tar's `.ext4` | same filesystem, missing 1024-byte boot pad |
| **Shannon TOC** baseband container | `modem.bin` | named regions (`BOOT`/`MAIN`/`VSS`/...), 32-byte TOC entries — not yet parsed even in the notes |
| AVB (`vbmeta_vendor.img`) | terminal, informational only | not a container — optionally worth annotating metadata, no children to extract |

This is a good forcing function for the architecture: it's five real formats
spanning three genuinely different shapes (offset/entry-table, filesystem
tree, and an offset-scan-for-embedded-payload case), which is enough to
validate the abstractions before scaling to hundreds of formats.

## 2. The constraint driving everything

> Adding format #101 must cost one new file. Zero edits to any existing file,
> zero edits to a shared registry, zero risk of merging conflicts with
> whoever is adding format #102 at the same time.

Everything below is in service of that one sentence — including making it
easy for an AI coding agent to do correctly on the first try, since the
volume of formats means most additions won't get deep human review.

## 3. Directory layout

```
pixel_firmware_formats/
  plugin.json                 # BN plugin manifest
  __init__.py                 # auto-discovery: import every formats/*.py, nothing else
  formats/
    fbpack.py                 # FBPACK v1 + v2 (one Transform, version-dispatch table inside)
    ext4.py                   # ext4, offset-1024 and offset-0 (one Transform, probes both)
    shannon_toc.py             # Shannon baseband TOC
    android_selfextract.py     # self-extracting vendor shell blob
    avb_footer.py               # metadata-only annotator (no children)
  common/
    container_base.py          # ContainerTransform / OffsetTableContainer / FilesystemContainer
    binstruct.py                # declarative struct-field descriptor helper
    sanitize.py                  # entry-name -> safe child filename
  tests/
    conftest.py
    test_formats.py             # generic runner, parametrized over fixtures/*
    fixtures/
      fbpack_v1/{sample.bin, expected.json}
      fbpack_v2/{sample.bin, expected.json}
      ext4/{sample.img, expected.json}
      shannon_toc/{sample.bin, expected.json}
  docs/
    ADDING_A_FORMAT.md          # the recipe — see §6
```

No file lists "all formats." `__init__.py` walks `formats/*.py` and imports
each module; every format registers itself at import time (module-level
`SomeTransform.register()`, matching the GC gotcha called out in
`ADDING_FORMATS_PLUGIN.md`). BN's own transform dispatch already tries every
registered transform's `can_decode()` — so there is no dispatch table to
maintain either. Registration and dispatch are both already O(1) per format
by construction of the existing Transform API; the plugin just needs to not
reintroduce a bottleneck on top of that.

## 4. Three base classes cover (almost) everything

Nearly every container format is one of two shapes, so two base classes in
`common/container_base.py` absorb the entire two-phase discovery/extraction
protocol, leaving each format file with only the parsing logic that's unique
to it:

### `OffsetTableContainer`
For "fixed/variable header, then a flat table of (name, offset, size)
entries" — FBPACK v1, FBPACK v2, Shannon TOC all fit this exactly. A format
author implements:

```python
class FBPack(OffsetTableContainer):
    MAGIC = b"FBPK"
    name = "FBPack"
    long_name = "Fastboot Package (FBPK)"

    def parse_entries(self, data: bytes) -> list[Entry]:
        version = struct.unpack_from("<I", data, 4)[0]
        parser = _VERSION_PARSERS.get(version)
        if parser is None:
            raise UnsupportedVariant(f"FBPK version {version}")
        return parser(data)

_VERSION_PARSERS = {2: _parse_v2, 1: _parse_v1}   # add v3 by adding an entry here

FBPack.register()
```

The base class handles: discovery (`set_available_files` from
`parse_entries`), extraction (slice `data[offset:offset+size]` per requested
entry, wrapped in try/except that maps any exception to
`TransformResult.TransformFailure` with the exception text as the message),
and routes every entry name through `common/sanitize.py` before it becomes a
child filename. A version-variant format (FBPACK v1 vs v2, and any future
v3) stays **one file, one registered Transform**, with variants living as
small functions in an internal dict — that dict is local to `fbpack.py`, so
it never becomes a second shared registry.

### `FilesystemContainer`
For tree-shaped filesystems — both ext4 cases. A format author implements:

```python
class Ext4(FilesystemContainer):
    name = "Ext4"
    long_name = "ext4 filesystem"

    def can_decode(self, input) -> bool:
        return _probe_superblock(input, offset=1024) or _probe_superblock(input, offset=0)

    def open_filesystem(self, data: bytes) -> Ext4FS:
        return Ext4FS(data)  # auto-detects offset internally

    def list_paths(self, fs) -> list[str]:
        return fs.walk()

    def read_file(self, fs, path: str) -> bytes:
        return fs.read(path)

Ext4.register()
```

Base class handles discovery/extraction identically to `OffsetTableContainer`
but keyed by path instead of a flat entry list, and still routes every path
through the same sanitizer (directory traversal from a crafted symlink/path
is exactly as real a risk here as a crafted entry name in FBPACK).

### The one-off case: `android_selfextract.py`
The self-extracting shell blob doesn't fit either shape cleanly — detection
is "is this a shell script with a `tail -n +N ... | tar` line," and
extraction is "carve from the parsed offset to EOF, then hand the resulting
bytes back into the transform chain as a plain gzip stream" (which core
already knows how to decode further — this format only needs to produce
*one* child, the carved payload, not enumerate a table). This is a legitimate
third, simpler shape: single-child passthrough. Proposal: give
`ContainerTransform` (the common parent both other bases derive from) a
trivial `SingleChildContainer` sibling for this "detect + carve one child"
pattern, since it's a plausible recurring shape (any other "self-extracting
wrapper" format would fit it too) — but only add it if the architecture
agent agrees it'll recur; otherwise this format can implement
`perform_decode_with_context` directly against the raw base, since it's a
single instance, not a pattern to optimize yet.

### `binstruct.py`
A small declarative helper so struct-heavy formats (FBPACK entry structs,
Shannon TOC's 32-byte entries, ext4 superblock fields) are a field-name list
rather than hand-written `struct.unpack_from` calls with fixed offsets
scattered through the parser — reduces transcription-error surface, which
matters most exactly when volume is high and review depth per file is low.

```python
class FbpkV2Entry(BinStruct):
    _format = "<32sQQQI"
    _fields = ("name", "offset", "load_addr", "size", "crc")
```

This is genuinely optional sugar, not a hard requirement — the architecture
agent should feel free to veto it if it doesn't pull its weight once 3-4
formats are using it.

## 5. Security posture (matters more here than in a typical plugin)

Every one of these parsers runs on **untrusted third-party firmware images**.
Two concrete rules, enforced in the base classes so individual formats can't
forget them:

1. Every container-entry name / filesystem path becomes a child filename
   only after passing through `common/sanitize.py` (rejects `../`, absolute
   paths, embedded nulls, and duplicate-after-sanitization collisions).
2. Every offset/size/count field read from the container header is
   validated against the actual input length before it's used to slice or
   loop — the base classes do this once for the "offset+size into buffer"
   pattern so format authors don't each re-derive bounds-checking.

The code-quality agent's review checklist is built around exactly these two
points, since they're the ones most likely to be missed in a fast,
high-volume, possibly-AI-authored addition.

## 6. `docs/ADDING_A_FORMAT.md` — the recipe

This is the artifact that makes "simple for humans and AI" concrete. It will
contain: the decision tree (offset-table vs filesystem vs one-off), the
copy-paste template for each base class, the fixture/expected.json template,
and the one-line checklist:

- [ ] one new file under `formats/`
- [ ] `MAGIC` declared (or justified custom `can_decode`)
- [ ] subclasses an existing base, or the architecture agent signed off on a
      new one
- [ ] `.register()` at module level
- [ ] fixture + `expected.json` added (happy path + one corrupt case)
- [ ] `pytest tests/` passes

## 7. Testing — data-driven, not per-format code

`tests/test_formats.py` is a single parametrized test that walks
`tests/fixtures/*/`, runs each `sample.*` through `TransformSession` per the
pattern in `containertransforms.md` / `ADDING_FORMATS_PLUGIN.md` §Testing,
and diffs discovered/extracted children against that directory's
`expected.json`. Adding test coverage for format #101 is "add a fixture
directory," not "write a test function" — same lateral-only property as the
format code itself. Real multi-megabyte firmware images never get checked
in; fixtures are minimal synthetic samples built to exercise 2-3 entries plus
one corrupt-header case.

## 8. The four project agents (already created)

Living in `~/plugins/.claude/agents/`, scoped to this repo:

- **architecture** — gatekeeps `common/`, decides when a new base class is
  actually warranted, checks MAGIC/name collisions, is the one who can
  approve deviating from "one file per format."
- **coding** — implements one format per invocation, strictly one new file,
  follows `ADDING_A_FORMAT.md`, never touches `common/`.
- **code-quality** — reviews a landed format for scope discipline, reuse vs.
  reinvention, and the two security rules above.
- **testing** — builds the minimal synthetic fixture + `expected.json` for a
  new format, or a regression fixture when a real sample surfaces a bug.

## 9. Open questions for you

1. **AVB footer** (`vbmeta_vendor.img`) — worth a metadata-only annotator
   (no children, just decorates `context.metadata_obj`), or skip it entirely
   since there's nothing to extract? Leaning skip until something needs it.
2. **`SingleChildContainer` base** (§4, the self-extracting-script case) —
   add it now speculatively, or wait until a second format needs the same
   shape and only then extract the abstraction? Leaning wait.
3. **Real-firmware regression tests** — in addition to synthetic fixtures,
   do you want an opt-in (env-var gated, not run in normal CI) test that
   points at your actual extracted `tegu` blobs on disk, to catch anything
   a synthetic fixture wouldn't? Useful signal, but ties tests to files that
   won't exist on another machine/CI runner.
4. Confirm **Python-only** (the "fastest path" per
   `ADDING_FORMATS_PLUGIN.md`) is right for this — the C++ path exists but
   has no in-tree example plugin to build from, and given the volume of
   formats you want to support, iteration speed probably matters more than
   the performance difference for parsing firmware headers.

Once you sign off (or redirect any of the above), the coding agent starts on
`common/container_base.py` + `common/binstruct.py` + `common/sanitize.py`
first, then one format at a time: FBPACK → ext4 → Shannon TOC →
self-extracting script, each followed by the testing and code-quality agents
before moving to the next.

## Implementation status

All five layers from §1 are implemented (`formats/fbpack.py`,
`formats/ext4.py`, `formats/shannon_toc.py`,
`formats/android_selfextract.py`; AVB skipped per §9). Every one was
validated against the *real* `google_devices-tegu` firmware tar still
sitting in `~/Downloads` — not just synthetic fixtures — by running each
transform through `TransformSession` and diffing byte-for-byte against the
source images:

- **FBPack** (v2 on `bootloader.img`, v1 on `radio.img`): all 17 v2
  sub-images extracted with SHA-256-exact content versus manual offset
  slices (including the deduped `ufs`/`ufs~1` pair); v1's linked-list
  chain correctly resolved `radio.img → modem (Tar, core) → the exact two
  files the original extraction notes recorded by hand.
- **Ext4**: `vendor.img` (2613 files, 776,177,334 bytes) and
  `vendor_dlkm.img` (68 files, 19,387,220 bytes) both matched the
  original notes' file/byte counts exactly, with every `.ko` a valid ELF
  and `build.prop` valid text.
- **Shannon TOC**: extracted `BOOT`/`MAIN`/`VSS`/`APM`/`INFO` from the
  real `modem.bin` (105,373,576 bytes); every region tiles exactly
  edge-to-edge (`entry[i].offset + entry[i].size == entry[i+1].offset`)
  all the way to the file's exact length, with zero slack.
- **AndroidSelfExtract**: the real 390 MB `extract-google_devices-tegu.sh`
  chains automatically through this transform → core's Gzip → core's Tar
  → core's Zip (for the embedded APKs), entirely via auto-detection — no
  glue code needed beyond this one file.

Real-firmware validation surfaced two things worth recording:

- **Ext4 needed indirect-block support after all.** §4 assumed extents
  only ("every Android vendor partition observed so far is 100%
  extent-based"). True for `vendor.img`/`vendor_dlkm.img`, but the small
  filesystem holding the Shannon modem image (nested inside
  `radio.img → modem → *.ext4`) turned out to use classic
  direct/single/double/triple-indirect block pointers with no extents at
  all. `ext4.py` implements both per-inode (not per-filesystem) rather
  than assuming one layout filesystem-wide.
- **Shannon TOC's field ordering was verified, not guessed** — the
  extraction notes explicitly flagged this as unresolved risk. Rather than
  reverse-engineer it from the hex dump alone (offset vs. load address
  vs. an unlabeled fourth field are easy to transpose and all "look
  plausible"), the struct was cross-checked against
  `grant-h/ShannonBaseband`'s `reversing/modem/parse_modem.py` and
  `TOCSectionHeader.java` (SPDX MIT) — then confirmed independently
  against the real `modem.bin`'s own internal consistency (contiguous
  region offsets). Reimplemented from scratch; not vendored.

Open questions from §9, resolved:

1. **AVB footer** — skipped, per the original leaning; nothing needs it yet.
2. **`SingleChildContainer` base** — not extracted. Only one format
   (`android_selfextract.py`) needed the "detect and carve one child"
   shape, so it's implemented directly against `ContainerTransform` with a
   docstring note for whoever adds the second such format.
3. **Real-firmware regression tests** — not added to the committed suite,
   per the "ties tests to files that won't exist elsewhere" concern. Real
   firmware was used for *development-time validation* (see above); the
   checked-in `tests/fixtures/*/` are all small, synthetic, hand-built
   samples exercising the same code paths (including one fixture each for
   ext4's extent-tree path, its indirect-block path, and its
   boot-pad-stripped offset-0 path).
4. **Python-only** — confirmed; no C++ format was needed or written.

Zero pip dependencies at runtime (`plugin.json`'s `dependencies.pip` is
empty) — every parser is pure Python stdlib, and the dev-only test runner
(`pytest`, MIT licensed) lives in a gitignored `.venv/`, consistent with
the MIT/BSD-only preference for anything this plugin depends on.

## Round 2: a real Pixel phone factory image (`cubs`)

A second real sample (`~/Downloads/cubs-cd1a.260618.001.a7/`, a current-gen
Pixel factory image — much larger and richer than the tegu tablet vendor
blob) surfaced five more candidate formats. Four are now implemented and
validated against that real image the same way as round 1:

- **`formats/sparse_image.py`** (Android Sparse Image, `0xED26FF3A` magic).
  Struct confirmed against AOSP's `libsparse/sparse_format.h` (Apache-2.0).
  Reconstructs to one flat blob, so — unlike every other format here —
  it's a plain (non-container) decode `Transform`, matching how core's own
  Gzip/Zlib work, not a `ContainerTransform` subclass. Validated by a
  streaming structural walk of the real 6.8 GB `userdata_exp.ai.img`
  (byte-for-byte chunk accounting: consumed bytes == file size, covered
  blocks == declared total, zero trailing garbage) — a full in-memory
  decode wasn't practical at that size, but the same code path was
  round-tripped exactly on a small synthetic fixture.
- **`formats/dtbo.py`** (DTBO / DT table, `0xD7B7AB1E` magic — the one
  **big-endian** struct in this whole plugin). Struct confirmed against
  AOSP's `mkdtboimg.py` (Apache-2.0). Validated against the real
  `dtbo.img`: all 55 device-tree overlay entries extracted, each starting
  with the correct FDT magic (`d00dfeed`).
- **`formats/boot_image.py`** (`ANDROID!`/`VNDRBOOT` magic — boot.img,
  init_boot.img, pvmfw.img, vendor_boot.img, vendor_kernel_boot.img).
  Per your instruction to lean on a permissively-licensed dependency where
  one exists rather than reimplement: this **vendors AOSP's own
  `unpack_bootimg.py` verbatim** (Apache-2.0;
  `third_party/aosp_mkbootimg/`, see its `NOTICE.md`) and calls its real
  `unpack_boot_image()`/`unpack_vendor_boot_image()` functions through a
  temp directory, rather than re-deriving the page-alignment/
  per-header-version (0-4) offset math independently. Validated against
  all five real boot-family images in the factory zip.
- **liblp / super partition metadata** — investigated, not implemented.
  The only sample (`super_empty.img`) is metadata-only (no partition data
  embedded — this factory image ships partitions as separate flashable
  files instead), so there's nothing to round-trip-validate extraction
  against yet. Revisit if a real non-empty `super.img` turns up.

**EROFS is scoped but not yet implemented.** It's the filesystem
`system.img`/`vendor.img`/`product.img`/etc. actually use on this device
(confirmed via magic `0xE0F5E1E2` at superblock offset 1024 — not ext4).
Findings so far, against AOSP's `erofs-utils` (`include/erofs_fs.h`,
confirmed MIT — the dual GPL-2.0+/MIT split in its COPYING applies to the
whole `lib`/`include` tree, so this is fair to lean on the same way the
boot image work did):

- This specific device's partitions use **no compression at all**
  (`feature_incompat` and `available_compr_algs` both `0x0` in the real
  superblock) — good news, since EROFS's compressed-cluster path
  (LZ4/LZMA/DEFLATE/ZSTD, z_erofs lcluster indices) is the genuinely large
  part of the spec and would otherwise need a compression-library
  dependency decision. Flat/uncompressed inodes alone cover this real
  device.
- Superblock (144 bytes) and both inode forms (32-byte compact, 64-byte
  extended) are struct-confirmed and spot-checked against the real root
  inode (correctly resolves as a directory, mode `0755`).
- Directory parsing needs more care than initially scoped: small
  directories use `EROFS_INODE_FLAT_INLINE`, where entries are packed
  immediately after the inode's own bytes rather than in a separate
  block — and that placement shifts if the inode has inline extended
  attributes (`i_xattr_icount != 0`, which adds a header + entries before
  the real tail data starts). Getting this boundary wrong would silently
  misread directory contents rather than fail loudly, so it needs
  cross-checking against `erofs-utils`' actual directory-reading logic
  (not just the struct header) before writing it — deliberately not
  rushed in the same pass as the four formats above.

This is a comparable-or-larger scope to the ext4 work in round 1. Given
where the effort naturally forked, I stopped here to report back rather
than push a possibly-subtly-wrong directory parser through without that
verification step.

## EROFS: implemented

`formats/erofs.py` landed after the checkpoint above, once the
inline-tail/xattr-offset subtlety was pinned down against the actual
algorithm (not just the struct header) in AOSP's `erofs-utils` — `lib/data.c`'s
`__erofs_map_blocks` confirms the tail-packed region for
`EROFS_INODE_FLAT_INLINE` starts at `iloc(nid) + inode_size + xattr_size`,
and `lib/namei.c`/`lib/dir.c` confirm the dirent-count/nameoff scheme.
Ported by hand (not vendored, unlike `boot_image.py`) since the reference
is disk-I/O-oriented C with no Python bindings to call as a black box —
see the module docstring for exactly which files were used and why they're
fair to lean on under MIT (erofs-utils' own COPYING dual-licenses `lib`/
`include` as GPL-2.0+ OR MIT).

Scope ended up one step broader than planned: real files on the target
device use **chunk-based inodes** (`EROFS_INODE_CHUNK_BASED`) alongside
flat ones — not just a multi-device-stacking corner case as the format
docs suggest, but a layout `mkfs.erofs` reaches for on plenty of ordinary
regular files even in a single-device, uncompressed image. Single-device
chunk-based support is included; multi-device chunks, compressed inodes,
and metabox/48BIT addressing remain explicit `NotImplementedError`s.

Validated against real Pixel factory-image partitions, byte-for-byte
(every extracted file's length matches its inode's declared size, every
`.ko`/`.so` valid ELF except the same `etc/chre/*.so` custom-format
exception already confirmed on a different device in round 1):

| Partition | Files | Bytes |
|---|---|---|
| `system_dlkm.img` | 81 | 12,411,774 |
| `vendor_dlkm.img` | 136 | 41,097,754 |
| `system_ext.img` | 313 | 508,318,852 |
| `vendor.img` | 1,402 | 1,207,095,818 |
| `system.img` | 2,389 | 1,198,204,960 |

One real bug caught and fixed along the way during this validation: the
dirent-count read used the wrong byte offset for a dirent's `nameoff`
field (8, not 10 — `nid` is 8 bytes, not 6) — caught immediately by the
very first real-file test rather than shipped silently wrong.

Test fixtures for this format were delegated to a background agent
(prompted to search the web for known/public EROFS test vectors first,
then hand-build synthetic ones covering flat-plain, flat-inline with a
tail-shifting xattr, chunk-based, and a corrupt case). No public EROFS
test vectors turned up anywhere (checked erofs-utils' own repo, the AOSP
mirror, kernel selftests/fstests, CTF/blog writeups) — it independently
re-verified the struct offsets against the same upstream sources during
that search and, in doing so, **found a second real bug**: the extended
(64-byte) inode branch read `i_nb`/`startblk_hi` at byte offset 20 instead
of 6 (offset 20 is actually `i_ino`; reading its low 16 bits as
`startblk_hi` corrupts the resolved block address whenever `i_ino` is
nonzero — silently correct only by coincidence when `i_ino == 0`, which is
apparently why it never surfaced against the real Pixel partitions this
was validated on, all of which happen to use compact 32-byte inodes or
extended ones with `i_ino == 0`). Fixed and confirmed against the agent's
own repro case plus a full real-firmware re-validation (identical
file/byte counts across all five partitions, no regression) and the full
23-fixture suite (19 prior + the 4 new EROFS ones), all passing.

**Deployed for interactive testing:** symlinked into
`~/Library/Application Support/Binary Ninja/plugins/`. Confirmed via a
fresh `import binaryninja` (no explicit plugin import) that all 8
transforms auto-register through Binary Ninja's own user-plugin loader —
the same mechanism the GUI app uses at startup.
