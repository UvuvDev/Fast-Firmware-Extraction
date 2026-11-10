# Samsung Shannon TOC

The native `shannon_toc` reader exposes Samsung Shannon modem regions through
the generated `ShannonTOC` Binary Ninja adapter and the standalone CLI. Build
with `cargo build --release --locked`; there is no Python parser or fallback.

Each 32-byte record contains a 12-byte name (NUL-terminated when shorter), then five
little-endian `u32` values: file offset, load address, stored size, unknown
metadata, and ID. The leading `TOC` record's size describes the whole table.
An empty name ends the table; unused padding after that sentinel need not be
record-aligned. Without a sentinel, partial records are rejected. Zero-offset
virtual regions are skipped even if their declared sizes exceed the input.

`BOOT` exposes `max(stored_size - 528, 0)` bytes at its file offset. The entire
stored region, including the omitted bytes, must fit in the input. Load
addresses, metadata, and IDs do not affect extraction. The layout and trimming
behavior were cross-checked against grant-h/ShannonBaseband's MIT-licensed
`parse_modem.py` and `TOCSectionHeader.java`, as recorded in the Rust module.

The fixtures are synthetic. Expected lengths and SHA-256 hashes describe the
input payloads independently of the parser. `shannon_toc_nested` checks that
the QCOM MBN bytes in MAIN survive extraction unchanged; it does not require
the separate QCOM MBN, QCDT, or DTBO readers. Recursive decoding becomes
available when those readers are included in a build.

Rust tests cover truncation, invalid table and payload bounds, virtual entries,
sentinel padding, BOOT trimming, and unsafe or duplicate names. The Python
bridge and Binary Ninja tests verify the same fixture bytes and native
registration. BOOT boundary cases cover stored sizes 0, 527, 528, and 529,
including complete ranges ending at EOF and nonempty ranges one byte past it.
The 101-member bridge regression uses distinct payloads and lengths to catch
incorrect member indexing. Fixture hashes are checked by the shared runners;
the format-specific Python tests cover empty tables, member indexing, and
diagnostics after closing an archive. Run the commands under "Check the result" in
[the contributor guide](ADDING_A_FORMAT.md).
