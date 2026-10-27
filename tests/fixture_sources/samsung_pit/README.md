# Samsung PIT fixtures

The existing `samsung_pit/sample.pit` is hand-built, not produced by Heimdall
or dumped from a Samsung device. It contains a 28-byte header and two
132-byte records named BOOT and SYSTEM. Expected hashes cover the raw records,
not partition contents: a standalone PIT stores descriptors only.
`samsung_pit_corrupt` truncates the record table. Native tests cover truncation,
entry limits, empty/full-width names, duplicate/unsafe names and obsolete
file offsets that deliberately point outside the file.

The original Python reader verified the on-disk fields against Heimdall's
MIT-licensed `libpit/source/libpit.h` and `libpit/source/libpit.cpp` parser.
The Rust implementation ports that existing layout. Python parity compares
both named records byte-for-byte, independently of native output hashes.
