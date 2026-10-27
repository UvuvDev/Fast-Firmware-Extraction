# APBL v2 fixtures

This is the fixed-prefix layout observed in the real Cubs spacecraft ABL
component through Binary Ninja MCP, not a claimed universal APBL specification.
The outer word and APBL header version are 2, the APBL tag is at 0x463c, a
little-endian payload size is at 0x4648, a 48-byte SHA-384 digest is at 0x4674,
and payload bytes start at 0x5000. The digest was verified against the complete
real payload before implementation. Other layouts/versions are unsupported.
Opaque signing metadata is skipped, not cryptographically authenticated.
No public producer/reference implementation was available; no code was copied.

Regenerate fixtures with `python3 tests/fixture_sources/apbl/generate.py`.
They are hand-built envelopes, with digests/hashes independently produced by
Python hashlib. `apbl_resources` contains a small executable-like prefix plus
the synthetic BLFS archive and its official-producer LZ4 member, proving
APBL -> embedded BLFS -> LZ4 without parser-specific dispatch.
`apbl_corrupt` truncates that payload. Rust mutation tests check versions,
lengths, payload/digest corruption and opaque-prefix handling.
