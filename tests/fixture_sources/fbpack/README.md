# FBPK target variants

`generate.py` builds a synthetic v2 package with repeated flash targets,
product variants, `partition:N` target names, and name collisions. Its ABL
member uses the existing synthetic APBL/BLFS/LZ4 fixtures. No vendor bytes
are included. Run `python3 tests/fixture_sources/fbpack/generate.py` to rebuild.

The real Cubs bootloader has 34 entries, including two `ufs` records and
multiple `partition:1`/`partition:2` records for different products. These
are valid FBPK targets, rather than unique host filesystem paths. The Rust
reader preserves all records, encodes `:` as `%3A`, and appends `~N` when a
name is already used. Suffixes follow table order and are checked against
both literal names and previously generated names. Other unsafe path
components remain rejected by the shared archive contract.

Set `FFE_CUBS_BOOTLOADER` to the original
`bootloader-cubs-spacecraft-17.4-15768489.img` when running
`tests/test_fbpack_native.py` to validate all 34 original byte ranges plus
the nested ABL resource chain through Binary Ninja.
