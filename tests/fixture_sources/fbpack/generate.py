"""Synthetic FBPK v2 target variants, modeled on the Cubs bootloader table.

No vendor bytes: every target has a distinct synthetic payload, with an ABL
assembled from the existing synthetic APBL/BLFS/LZ4 fixtures.
"""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[3]
source = ROOT / "tests/fixtures/apbl_resources"
records = [
    ("ufs", "", "ufs", b"first UFS target"),
    ("ufs", "", "ufs~1", b"second UFS target"),
    ("ufs~1", "", "ufs~1~1", b"literal suffix target"),
    ("partition:1", "default", "partition%3A1", b"default partition table"),
    ("partition:1", "board", "partition%3A1~1", b"board partition table"),
    ("partition%3A1", "", "partition%3A1~2", b"literal encoded target"),
    ("abl", "", "abl", (source / "sample.bin").read_bytes()),
]
offset = 112 + 104 * len(records)
table, payload = bytearray(), bytearray()
children = {}
for name, product, output, data in records:
    table += struct.pack("<I36s40sQQII", 1, name.encode(), product.encode(), offset, len(data), 0, 0)
    payload += data
    offset += len(data)
    children[output] = {"length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
children["abl"]["children"] = json.loads((source / "expected.json").read_text())["children"]
header = struct.pack("<IIII16s64sIIII", 0x4b504246, 2, 112, 104, b"fixture", b"variants", 0, 1, len(records), offset)
out = ROOT / "tests/fixtures/fbpack_variants"
out.mkdir(exist_ok=True)
(out / "sample.bin").write_bytes(header + table + payload)
(out / "expected.json").write_text(json.dumps({
    "native_format": "fbpack", "sample": "sample.bin", "children": children,
}, indent=2) + "\n")
