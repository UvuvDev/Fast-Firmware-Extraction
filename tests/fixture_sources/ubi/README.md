# UBI fixtures

`tests/fixtures/ubi/sample.bin` is the existing hand-built fixture, not output
from an official producer. It has two 512-byte PEBs, EC/VID/data offsets
0/64/128, a layout-table LEB naming volume 0 `data`, and a static data LEB
containing 108 bytes. CRC fields are placeholders; CRC verification is outside
the current reader's scope. `ubi_corrupt` is the single-PEB case, whose eraseblock
geometry cannot be inferred.

Rust tests mutate this fixture to cover reordered LEBs, dynamic capacity and
padding, duplicate/missing logical blocks, truncation, oversized static lengths,
unsafe names, and a misleading UBI magic inside the layout payload. Python
parity compares the original reader's extracted bytes with the native reader.
The original Python layout was independently checked against real router UBI
images; these synthetic files are regression fixtures, not vendor firmware.
