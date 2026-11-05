# Cubs DRAM BLFS validation

`provenance.json` records an independent Python `struct` walk of all thirteen
DRAM/PHY BLFS tables inside the original Cubs bootloader FBPK. Each table was
checked for matching counts, unique UTF-8 names, member bounds and disjoint
member ranges. No vendor firmware bytes are committed.

The tables start at component offset `0x5000`. The final eight bytes of each
64-byte record contain two nonzero metadata patterns: `(0xffffffff, 4)` and
`(0, 4)`, as little-endian words. Their semantics are unknown. Extraction uses
the independently verified size/offset fields at record offsets 48/52 and
retains the complete host and standalone archive bytes. Those metadata words
are not interpreted as relocation, compression or execution instructions.

Each `members_sha256` hashes the following sequence in original table order:
UTF-8 member name, NUL, eight-byte little-endian member length, then the member
bytes. This covers all 378 names and payloads across the thirteen tables.

Run the optional real-package regression with `FFE_CUBS_BOOTLOADER` pointing to
`bootloader-cubs-spacecraft-17.4-15768489.img`. It verifies these independent
hashes, all Image/Unpacked contents branches, and successful completion of
the entire Binary Ninja extraction tree.
