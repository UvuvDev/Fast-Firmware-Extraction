# BLFS resource archives

The v1 on-disk layout was measured in the real, unencrypted Cubs ABL component
through Binary Ninja MCP. Its table is at 0x1fb430, magic `sFlB`, version 1,
two matching count fields of 28, and total size 93200. The header is 32 bytes;
each 64-byte record has a 48-byte name, little-endian size/relative-offset words,
and eight metadata bytes (zero in ABL). All 28 resource extents were independently
extracted before implementing the Rust reader; official LZ4 v1.10.0 decoded
all 27 BMP streams and the remaining member is a TrueType font.

No public producer/reference implementation was available. Only this observed
layout is supported: count fields must agree and header reserved fields must be zero.
Other versions/layouts are rejected. No implementation source was copied.
Vendor firmware and artwork are not committed.

The same layout occurs in thirteen DRAM/PHY components, with nonzero entry
metadata: `(0xffffffff, 4)` or `(0, 4)` as little-endian words. These bytes
are opaque and do not change member carving; their semantics are unknown.
The original image and standalone archive retain them. Independent validation
of all 378 members is recorded in `../cubs_blfs/`.

Run `python3 tests/fixture_sources/blfs/generate.py` to regenerate the synthetic
fixtures. One member is the official-CLI LZ4 fixture; the other is a literal
text payload. Expected hashes and nested hashes come from those independent
inputs. `blfs_embedded` adds a small executable-like prefix; a Rust test creates
a larger prefix in memory to prove detection beyond the old 1 MiB probe limit.
`blfs_entry_metadata` covers both observed DRAM metadata patterns.
Mutation tests cover counts/version/header fields, unsafe and duplicate names, metadata
overlap, bounds and truncation.

Embedded detection is opt-in, bounded to 4 MiB, and uses the generic registry
matcher. APBL, LZ4 and BLFS need no parser-specific dispatch between them.
