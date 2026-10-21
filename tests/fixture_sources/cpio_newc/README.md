# Official-tool CPIO newc fixtures

Run `python3 scripts/generate_cpio_fixtures.py` (or `--check`). It requires
`cpio` (macOS's built-in bsdcpio/libarchive) on PATH.

`cpio_newc/sample.cpio` is three files -- `file1.txt`, `subdir/nested.bin`
(exercises a nested directory and the leading "./" prefix stripping), and
`empty.bin` (exercises a zero-length regular file) -- archived with
`cpio -o -H newc`. `cpio_newc_corrupt/sample.cpio` truncates the real archive
two bytes into its first entry's name, before the 110-byte fixed header
is even complete.

The advisory header fields this parser never reads (ino, uid, gid, nlink,
mtime, dev{major,minor}, rdev{major,minor}, check) are zeroed by the
generator after bsdcpio writes them, so the committed bytes don't depend on
the local user's uid/gid or the current time. `expected.json` lengths and
SHA-256 hashes come from the original synthetic input files, independently
of this plugin's parser. `provenance.json` records the exact command, input
hashes, and a hash of every committed artifact.
