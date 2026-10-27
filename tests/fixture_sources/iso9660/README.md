# Official-tool ISO 9660 fixtures

Run `python3 scripts/generate_iso9660_fixtures.py` (or `--check`). It
requires `xorriso` (`brew install xorriso`; GPL-3.0, not vendored here --
only the generated image bytes are committed, the same policy already
applied to every other producer tool in this project). `xorriso -indev
... -find` lists the built image's own files as an independent check
before the generator accepts it. `--modification-date=` pins the PVD's
timestamp fields (otherwise the only non-deterministic bytes xorriso
writes, confirmed by diffing two un-pinned builds a second apart) so
regenerated fixtures stay reproducible.

`iso9660/sample.iso` is built with `-J -R` (Joliet + Rock Ridge both
present) holding `small.txt`, `subdir/nested.txt` (a nested directory),
and `big.bin` (9000 non-zero bytes). `iso9660_rockridge_only/sample.iso`
is the same tree built with `-R` only (no Joliet), exercising this
parser's Rock Ridge "NM"-name fallback path -- xorriso's `-as mkisofs`
emulation adds Rock Ridge SUSP data by default regardless of `-R`, so
there's no simple way to get a truly extension-free image from it; the
"no Rock Ridge either" fallback (plain uppercase 8.3 names with the
";version" suffix stripped) is covered by a unit test instead.
`iso9660_corrupt/sample.iso` flips the Primary Volume Descriptor's own
version byte, rejected before any directory is read.

`expected.json` lengths and SHA-256 hashes come from the original
synthetic input files, independently of this plugin's parser.
`provenance.json` records the exact commands, input hashes, the xorriso
version, and a hash of every committed artifact.
