# Official-tool CramFS fixtures

Run `python3 scripts/generate_cramfs_fixtures.py` (or `--check`). It requires
`docker` able to pull and run `alpine:latest`. Alpine's `cramfs` package
(1.1-r7 at generation time) ships the real `mkcramfs`/`cramfsck`; neither
tool's GPL-2.0+ source is vendored here, the same policy already applied to
mkimage/dtc and bsdcpio -- only the generated image bytes are committed.
`cramfsck -v` must confirm the built image ("... OK") before the generator
accepts it, mirroring the independent-round-trip requirement the DTBO/boot
generators already use.

`cramfs/sample.img` holds `small.txt`, `subdir/nested.txt` (a nested
directory), `big.bin` (9000 non-zero bytes, spanning three 4 KiB blocks to
exercise the block-pointer table across block boundaries), an empty
`emptydir/`, and `empty.bin` (a zero-length regular file). Because the whole
tree is built and archived as root inside the container, the image's
uid/gid fields are deterministic without any extra normalization; cramfs
inodes have no mtime field at all. `cramfs_corrupt/sample.img` overwrites the
superblock's declared size with a value far beyond the real buffer, caught
during open()/discovery. A pure content corruption (flipping a byte inside a
compressed block) would not be: like erofs/ubifs, this parser only decodes a
file's bytes lazily when read, so open() alone never touches them.

`expected.json` lengths and SHA-256 hashes come from the original synthetic
input files, independently of this plugin's parser. `provenance.json` records
the exact commands, input hashes, the cramfs package version, and a hash of
every committed artifact.
