# Official-tool JFFS2 fixtures

Run `python3 scripts/generate_jffs2_fixtures.py` (or `--check`). It requires
`docker` able to pull and run `alpine:latest`. Alpine's `mtd-utils-jffs`
package (2.2.1-r0 at generation time) ships the real `mkfs.jffs2`/
`jffs2dump`; neither tool's GPL-2.0+ source is vendored here, the same
policy already applied to mkimage/dtc/mkcramfs/bsdcpio -- only the generated
image bytes are committed. `jffs2dump -c` must describe the expected
Dirent/Inode node layout before the generator accepts the image, mirroring
the independent-round-trip requirement the DTBO/boot/cramfs generators
already use.

The image is built with `-l` (little-endian), `-q` (squash permissions and
ownership to root:root) and `-f` (fake all timestamps to 0), so it is
reproducible regardless of the local user or clock -- JFFS2 has no other
non-deterministic fields the way cpio/uImage/FIT do. `-x rtime` disables
JFFS2's own "rtime" compressor, which this parser does not implement; every
file therefore ends up stored either uncompressed or zlib-compressed.

`jffs2/sample.img` holds `small.txt`, `subdir/nested.txt` (a nested
directory), `big.bin` (9000 non-zero bytes, split across two 4 KiB data
nodes), an empty `emptydir/`, and `empty.bin` (a zero-length regular file).
`jffs2_corrupt/sample.img` flips one byte in the root dirent's name, which
this parser's own CRC32 (the format's own variant, not the zlib one used
elsewhere in this crate -- see the module doc comment) catches eagerly
during open(), unlike a pure compressed-block corruption.

`expected.json` lengths and SHA-256 hashes come from the original synthetic
input files, independently of this plugin's parser. `provenance.json`
records the exact commands, input hashes, the mtd-utils-jffs package
version, and a hash of every committed artifact.
