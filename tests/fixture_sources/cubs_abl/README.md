# Real Cubs ABL validation

Source: `cubs-cd1a.260618.001.a7`, component `abl` inside
`bootloader-cubs-spacecraft-17.4-15768489.img`. The open Binary Ninja component
was read through MCP. Its SHA-256, payload hash, all original member offsets,
stored hashes, decoded hashes and BMP dimensions are in `provenance.json`.
No vendor firmware/artwork is committed.

The inspection independently confirmed before implementation:

- APBL at 0x463c, executable at 0x5000; stored SHA-384 matches that payload.
- BLFS at 0x1fb430, size 93200, with 28 named records.
- 27 LZ4 frames decode to BMPs using official LZ4 CLI v1.10.0.
- The remaining member is a 11940-byte Roboto TrueType font with 14 valid tables.

Validate a local copy of this exact component with the real native backend and
Binary Ninja Container Browser:

    FFE_CUBS_ABL=/path/to/abl BN_DISABLE_USER_PLUGINS=1 ./scripts/run_tests.sh -q --confcutdir=tests tests/test_cubs_abl.py

The test checks APBL -> executable -> embedded BLFS -> LZ4 -> BMP against the
independent hashes, plus the uncompressed font. It also ensures anchored APBL
recognition takes priority over the embedded archive. For standalone recursive
extraction:

    target/release/firmware-unpack /path/to/abl /path/to/new-output

The payload remains available as `payload.bin`; resources are under
`payload.bin.unpacked/`, with each BMP in its LZ4 member's sibling `.unpacked`
directory as `payload.bin`. Every archive directory has `.ffe-paths.tsv`.
Only the observed APBL/BLFS layouts are supported. Payload hash verification
does not authenticate the signing chain.
