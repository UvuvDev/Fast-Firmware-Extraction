"""Build a small synthetic ext4 regression image; no official producer used."""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[3]
data = bytearray(18 * 1024)

def u16(off, value):
    struct.pack_into('<H', data, off, value)

def u32(off, value):
    struct.pack_into('<I', data, off, value)

# Two groups: the second has only one block according to the superblock.
for off, value in {0: 16, 4: 18, 20: 1, 24: 0, 32: 16, 40: 8, 76: 1, 96: 0xc2}.items():
    u32(1024 + off, value)
u16(1024 + 56, 0xef53)
u16(1024 + 88, 128)
u16(1024 + 254, 64)
u32(2048 + 8, 3)
u32(2048 + 64 + 8, 17)

def inode(ino, mode, size, flags=0):
    group, index = divmod(ino - 1, 8)
    off = (3 if group == 0 else 17) * 1024 + index * 128
    u16(off, mode)
    u32(off + 4, size)
    u32(off + 32, flags)
    return off + 40

def extents(off, records, depth=0):
    struct.pack_into('<HHHHI', data, off, 0xf30a, len(records), (1024 - 12)//12 if off == 8192 else (60 - 12)//12, depth, 0)
    for i, record in enumerate(records):
        struct.pack_into('<IHHI', data, off + 12 + i * 12, *record)

extents(inode(2, 0x41ed, 1024, 0x80000), [(0, 1, 0, 4)])
u32(inode(3, 0x41ed, 1024), 5)
# Inode 9 lives in group 1 and points to an external extent leaf.
index = inode(9, 0x81a4, 3 * 1024 + 37, 0x80000)
extents(index, [(0, 8, 0, 0)], depth=1)
extents(8 * 1024, [(0, 1, 0, 10), (1, 0x8001, 0, 12), (2, 1, 0, 11)])
payload = b'inline data from group two\n'
off = inode(10, 0x81a4, len(payload), 0x10000000)
data[off:off + len(payload)] = payload
inode(11, 0xa1ff, 0)

def directory(block, records):
    pos = block * 1024
    for i, (ino, name, kind) in enumerate(records):
        name = name.encode()
        length = ((8 + len(name) + 3)//4)*4 if i + 1 < len(records) else (block + 1)*1024 - pos
        struct.pack_into('<IHBB', data, pos, ino, length, len(name), kind)
        data[pos + 8:pos + 8 + len(name)] = name
        pos += length

directory(4, [(2, '.', 2), (2, '..', 2), (3, 'nested', 2), (9, 'mapped.bin', 1), (11, 'link', 7)])
directory(5, [(3, '.', 2), (2, '..', 2), (10, 'inline.txt', 1)])
data[10*1024:11*1024] = b'A' * 1024
data[11*1024:12*1024] = b'B' * 1024
data[12*1024:13*1024] = b'secret!!' * 128  # Must not escape an unwritten extent.
expected = {'nested/inline.txt': payload, 'mapped.bin': b'A'*1024 + bytes(1024) + b'B'*1024 + bytes(37)}
out = ROOT / 'tests/fixtures/ext4_mapped'
out.mkdir(exist_ok=True)
(out / 'sample.img').write_bytes(data)
(out / 'expected.json').write_text(json.dumps({
    'native_format': 'ext4', 'sample': 'sample.img',
    'children': {name: {'length': len(content), 'sha256': hashlib.sha256(content).hexdigest()} for name, content in expected.items()},
}, indent=2) + '\n')
