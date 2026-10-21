# Official-tool U-Boot fixtures

Run `python3 scripts/generate_uboot_fixtures.py` (or `--check`). It requires
**mkimage 2026.10** (u-boot-tools) and **dtc 1.8.1** on PATH. Neither tool's
GPL-2.0 source is vendored in this repository, the same policy already
applied to the dtc-compiled DTBO overlays under `tests/fixture_sources/dtbo`:
only the generated fixture bytes are committed.

`uboot_legacy/sample.img` is a plain `mkimage -T kernel` legacy image.
`uboot_legacy_multi/sample.img` is a `-T multi` image with three unevenly
sized sub-images (23, 7, and 9 bytes), chosen to exercise the sub-image size
table's zero terminator and the 4-byte padding mkimage inserts between
entries (never after the last one). `uboot_legacy_corrupt/sample.img` flips
one payload byte so the stored `ih_dcrc` no longer matches.

`uboot_fit/sample.itb` is built from `fixture.its` (recorded verbatim in
`provenance.json`) with `mkimage -f`, which compiles the source with libfdt.
It has two `/images` entries, `kernel-1` and `fdt-1`. `uboot_fit_corrupt/sample.itb`
is the same file truncated to 64 bytes, before any embedded image data is
reachable.

`expected.json` lengths and SHA-256 hashes come from the original synthetic
input files, independently of this plugin's parser. `provenance.json` records
the exact `mkimage`/`dtc` commands, input hashes, the `.its` source, and a
hash of every committed artifact.
