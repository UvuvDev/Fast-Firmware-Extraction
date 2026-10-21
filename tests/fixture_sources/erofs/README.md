# EROFS fixtures

These are hand-built regression images, not output from official erofs-utils.
The original fixtures cover flat plain data, inline tails (including inline
xattrs), plain chunk tables, and a corrupt directory. Their bytes and expected
hashes are unchanged by the Rust port.

Regenerate the additional fixture with:

    python3 tests/fixture_sources/erofs/generate.py

`erofs_mapped` contains an inline subdirectory with xattrs, an extended inode
spanning a metadata block boundary, indexed chunks including a sparse hole,
and a skipped symlink. Expected bytes/hashes come from the generator's literal
source payloads rather than parser output. Unused/checksum fields are left zero;
this image is intended for reader regression tests, not mounting.

Python parity covers the original fixtures plus `erofs_mapped`. Inline Rust
tests additionally cover zero-length inline files, sparse flat files, inline
bounds, malformed directory offsets/cycles, device rejection, unsupported
features/layouts, and oversized inodes.

The layout/mapping reference for the original Python port is AOSP erofs-utils
(`include/erofs_fs.h`, `lib/namei.c`, `lib/dir.c`, `lib/data.c`), available under
`GPL-2.0+ OR MIT` and used under its MIT option. The Rust reader ports that
existing reader's uncompressed subset; it does not implement EROFS compression.
