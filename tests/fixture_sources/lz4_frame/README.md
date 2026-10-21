# LZ4 fixtures

Generated with the official LZ4 CLI v1.10.0 (BSD-2-Clause); run
`python3 tests/fixture_sources/lz4_frame/generate.py` to regenerate.
The producer uses `-B4 -BX --content-size` and either `-BI` or `-BD`.
Source payloads span multiple blocks. Expected hashes come from source bytes,
and official CLI decompression independently confirms each encoded fixture.
`lz4_frame_empty_block` inserts a valid zero-length stored block into an
otherwise CLI-generated empty stream and is also checked by the CLI.
`lz4_frame_corrupt` removes the checksum footer.

Rust tests cover truncation, header/block/content checksums, content/output
limits, reserved flags, dictionaries, concatenation and skippable records.
The parser supports modern frames, not legacy LZ4 or externally supplied
dictionaries. It returns an automatic decoded child; CLI output is payload.bin.

Reference: https://github.com/lz4/lz4/blob/v1.10.0/doc/lz4_Frame_format.md
Independent real-image validation uses all 27 LZ4 BMP members from the Cubs
spacecraft ABL resource archive; vendor bytes are not committed here.
