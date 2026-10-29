# ext4 fixtures

These images are hand-built regression fixtures, not output from mke2fs.
The original `ext4`, `ext4_offset0`, and `ext4_indirect` fixtures cover extent,
padless, and classic direct-pointer layouts. Their root directory size was
corrected to 1024 during the Rust port (it was previously zero despite having
a block of entries); their extracted file bytes and expected hashes are unchanged.
`ext4_corrupt` truncates the inode table.

Regenerate the additional image with:

    python3 tests/fixture_sources/ext4/generate.py

`ext4_mapped` exercises a second, partial block group, 64-byte descriptors, a
nested directory, a small inline file, an external extent leaf, holes, and an
unwritten extent containing nonzero backing bytes. Expected contents are built
independently in the generator from literal payloads and zeroes. It deliberately
omits allocation bitmaps, checksums and other metadata unused by this reader;
it is not intended as a mountable ext4 filesystem.

Inline Rust tests additionally cover all three indirect pointer levels, extent
cycles/overlap, corrupt directory lengths, oversized inodes and inline bounds.
Python parity covers the original three fixtures: the old Python implementation
reads unwritten extents as backing bytes, so it is not an oracle for that case.
The Rust implementation follows the original Python port's verified layouts and
does not copy kernel implementation code.
