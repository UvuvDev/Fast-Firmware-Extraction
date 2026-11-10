Synthetic TOC constructed from 32-byte little-endian records (`<12s5I`).
The 128-byte table contains TOC, BOOT, MAIN, and an empty-name sentinel.
BOOT stores 72 ASCII `B` bytes followed by a 528-byte allowance; MAIN is the
17-byte ASCII string `MAIN_PAYLOAD_DATA`. The manifest hashes these known
payloads independently of the reader. Nonzero load addresses and metadata
ensure file offsets come from the offset field. No vendor firmware is included.
