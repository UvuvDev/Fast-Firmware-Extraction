"""Generate a hand-built EROFS mapping fixture, without official erofs-utils."""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[3]
data = bytearray(16 * 512)
struct.pack_into('<I', data, 1024, 0xe0f5e1e2)
data[1036] = 9  # 512-byte blocks
struct.pack_into('<H', data, 1038, 0)  # root nid
struct.pack_into('<I', data, 1060, 16)
struct.pack_into('<I', data, 1064, 3)  # metadata base

def inode(nid, fmt, mode, size, block):
    off = 1536 + nid * 32
    struct.pack_into('<HHHH', data, off, fmt, 0, mode, 2 if mode == 0x41ed else 1)
    if fmt & 1:
        # Extended i_nb is startblk_hi, not nlink.
        struct.pack_into('<H', data, off + 6, 0)
        struct.pack_into('<Q', data, off + 8, size)
    else:
        struct.pack_into('<I', data, off + 8, size)
    struct.pack_into('<I', data, off + 16, block)
    return off + (64 if fmt & 1 else 32)

def directory(records):
    records = sorted(records, key=lambda item: item[1])
    entries = bytearray()
    names = bytearray()
    for nid, name, kind in records:
        entries += struct.pack('<QHBB', nid, len(records)*12 + len(names), kind, 0)
        names += name.encode()
    return entries + names

root = directory([(0, '.', 2), (0, '..', 2), (1, 'nested', 2), (6, 'chunked.bin', 1), (8, 'link', 7)])
sub = directory([(1, '.', 2), (0, '..', 2), (15, 'extended.bin', 1)])
inode(0, 0, 0x41ed, len(root), 8)
data[4096:4096 + len(root)] = root
pos = inode(1, 4, 0x41ed, len(sub), 0)  # directory with inline tail
# xattr header + one entry. The inline directory must skip these 16 bytes.
struct.pack_into('<H', data, pos - 32 + 2, 2)
pos += 16
data[pos:pos + len(sub)] = sub
pos = inode(6, 8, 0x81a4, 1124, 0x20)  # eight-byte chunk indexes
for i, block in enumerate([12, 0xffffffff, 14]):
    struct.pack_into('<HHI', data, pos + i*8, 0, 0, block)
inode(8, 0, 0xa1ff, 0, 0)
inode(15, 1, 0x81a4, 600, 10)  # starts at 2016; 64 bytes cross block boundary
payload = bytes(range(200)) * 3
data[5120:5120 + len(payload)] = payload
data[6144:6656] = b'C' * 512
data[7168:7268] = b'D' * 100
expected = {'chunked.bin': b'C'*512 + bytes(512) + b'D'*100, 'nested/extended.bin': payload}
out = ROOT / 'tests/fixtures/erofs_mapped'
out.mkdir(exist_ok=True)
(out / 'sample.img').write_bytes(data)
(out / 'expected.json').write_text(json.dumps({
    'native_format': 'erofs', 'sample': 'sample.img',
    'children': {name: {'length': len(content), 'sha256': hashlib.sha256(content).hexdigest()} for name, content in expected.items()},
}, indent=2) + '\n')
