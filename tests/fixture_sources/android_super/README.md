# Official-tool Android super.img fixtures

Run `python3 scripts/generate_android_super_fixtures.py` (or `--check`). It
requires `docker` able to pull and run `alpine:latest`. Alpine's
`android-tools-lpmake`/`-lpunpack`/`-lpdump`/`-img2simg` packages (35.0.2 at
generation time) ship AOSP's actual partition_tools and liblp (Apache-2.0);
that source is not vendored here, the same policy already applied to
mkimage/dtc/mkcramfs/mkfs.jffs2/bsdcpio -- only the generated image bytes
are committed. `lpunpack`'s own extraction must reproduce the original
`system.img`/`vendor.img` inputs byte for byte, and `lpdump` must describe
both partitions, before the generator accepts the image -- the same
independent-round-trip requirement the DTBO/boot/cramfs/jffs2 generators
already use.

`android_super/sample.img` is a 64 KiB non-sparse, non-retrofit, single-slot
image (`-d 65536 -m 4096 -s 1 --alignment=4096`) holding two 8 KiB
partitions, `system` and `vendor`. The small size only works because of the
explicit `--alignment=4096`; a real device's default alignment is often
1 MiB, which would make even this minimal two-partition image megabytes in
size. Partition payloads are padded to exact 4 KiB multiples before being
sparse-encoded with `img2simg`, which this package build's libsparse
otherwise asserts on for non-aligned sizes.

`android_super_corrupt/sample.img` flips one byte in each of the two
geometry copies' magic (offsets 4096 and 8192). Unlike the metadata header,
which has a backup copy this parser falls back to (see
`falls_back_to_the_backup_metadata_copy_when_the_primary_is_corrupt` in the
module's own tests), geometry has no further fallback once it can't be read
at all, so corrupting both copies is what actually leaves no way to parse
the image, rather than just one.

`expected.json` lengths and SHA-256 hashes come from the original synthetic
input files, independently of this plugin's parser. `provenance.json`
records the exact commands, input hashes, the android-tools-lpmake package
version, and a hash of every committed artifact.
