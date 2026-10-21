"""Hand-build UBIFS regression nodes and a UBI wrapper, without mkfs.ubifs."""
from pathlib import Path
import hashlib
import json
import struct
import zlib

ROOT = Path(__file__).resolve().parents[3]
# Correct the original synthetic fixture's placeholder branch keys, without
# changing any file payload. The Python reader never inspected those keys.
for original in ['ubifs']:
    path = ROOT / 'tests/fixtures' / original / 'sample.ubifs'
    original_image = bytearray(path.read_bytes())
    for i in range(12):
        branch = 12288 + 28 + i*20
        lnum, off, length = struct.unpack_from('<III', original_image, branch)
        original_image[branch+12:branch+20] = original_image[lnum*4096+off+24:lnum*4096+off+32]
    struct.pack_into('<I', original_image, 12288+4, zlib.crc32(original_image[12288+8:12288+268]) ^ 0xffffffff)
    path.write_bytes(original_image)

LEB = 16384
image = bytearray(b'\xff' * (5 * LEB))

def node(kind, body, sequence=1):
    raw = bytearray(struct.pack('<IIQIBB2x', 0x06101831, 0, sequence, 24 + len(body), kind, 0) + body)
    struct.pack_into('<I', raw, 4, zlib.crc32(raw[8:]) ^ 0xffffffff)
    return raw

def key(ino, kind, block=0):
    return struct.pack('<II', ino, kind << 29 | block) + bytes(8)

def inode(ino, mode, size):
    body = bytearray(136)
    body[:16] = key(ino, 0)
    struct.pack_into('<Q', body, 24, size)
    struct.pack_into('<I', body, 80, mode)
    return node(0, body)

def dent(parent, name, ino, kind):
    name = name.encode()
    return node(2, key(parent, 2) + struct.pack('<QBBHI', ino, 0, kind, len(name), 0) + name + b'\0')

def block(ino, number, payload, compressed=False):
    plain_size = len(payload)
    if compressed:
        encoder = zlib.compressobj(level=9, wbits=-11)
        payload = encoder.compress(payload) + encoder.flush()
    return node(1, key(ino, 1, number) + struct.pack('<IHH', plain_size, 2 if compressed else 0, 0) + payload)

first = bytes(range(256)) * 16
last = b'last sparse block\n' * 44 + b'EOF!'
assert len(last) == 796
content = first + bytes(4096) + last
leaves = [
    inode(1, 0x41ed, 0),
    dent(1, 'multi.bin', 2, 0),
    dent(1, 'empty', 3, 0),
    dent(1, 'alias.bin', 2, 0),
    dent(1, 'link', 4, 2),
    inode(2, 0x81a4, len(content)),
    block(2, 0, first, compressed=True),
    block(2, 2, last),
    inode(3, 0x81a4, 0),
    inode(4, 0xa1ff, 0),
]
branches = []
offset = 0
for raw in leaves:
    image[4*LEB + offset:4*LEB + offset + len(raw)] = raw
    branches.append(struct.pack('<III', 4, offset, len(raw)) + raw[24:32])
    offset = (offset + len(raw) + 7) & ~7
index = node(9, struct.pack('<HH', len(branches), 0) + b''.join(branches))
image[3*LEB + 256:3*LEB + 256 + len(index)] = index
root = node(9, struct.pack('<HHIII', 1, 1, 3, 256, len(index)) + leaves[0][24:32])
image[3*LEB:3*LEB + len(root)] = root
sb = bytearray(4096 - 24)
struct.pack_into('<IIII', sb, 8, 512, LEB, 5, 5)
struct.pack_into('<I', sb, 56, 5)  # format version
image[:4096] = node(6, sb)

def master(root_leb, sequence):
    body = bytearray(512 - 24)
    struct.pack_into('<III', body, 24, root_leb, 0, len(root))
    return node(7, body, sequence)

for number in [1, 2]:
    image[number*LEB:number*LEB + 512] = master(99, 1)  # superseded record
    image[number*LEB + 512:number*LEB + 1024] = master(3, 2 + number)
expected = {'multi.bin': content, 'empty': b'', 'alias.bin': content}
children = {name: {'length': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()} for name, payload in expected.items()}

def fixture(name, filename, raw, format_id, children):
    path = ROOT / 'tests/fixtures' / name
    path.mkdir(exist_ok=True)
    (path / filename).write_bytes(raw)
    (path / 'expected.json').write_text(json.dumps({'native_format': format_id, 'sample': filename, 'children': children}, indent=2) + '\n')

fixture('ubifs_multiblock', 'sample.ubifs', image, 'ubifs', children)
# Dynamic UBI volume: physical blocks can reorder LEBs without any parser-specific
# dispatch. Place the data LEBs in reverse order to exercise reassembly too.
PEB = 32768
wrapped = bytearray(b'\xff' * (6 * PEB))
for physical in range(6):
    base = physical * PEB
    ec = bytearray(64)
    ec[:4] = b'UBI#'
    ec[4] = 1
    struct.pack_into('>III', ec, 16, 64, 16384, 1)
    vid = bytearray(64)
    vid[:4] = b'UBI!'
    vid[4:6] = bytes([1, 1])
    logical = 0 if physical == 0 else 5 - physical
    struct.pack_into('>II', vid, 8, 0x7fffefff if physical == 0 else 0, logical)
    wrapped[base:base+64] = ec
    wrapped[base+64:base+128] = vid
    if physical == 0:
        table = bytearray(LEB)
        struct.pack_into('>H', table, 14, 12)
        table[16:28] = b'rootfs.ubifs'
        wrapped[base+16384:base+PEB] = table
    else:
        wrapped[base+16384:base+PEB] = image[logical*LEB:(logical+1)*LEB]
fixture('ubi_ubifs', 'sample.ubi', wrapped, 'ubi', {
    'rootfs.ubifs': {'length': len(image), 'sha256': hashlib.sha256(image).hexdigest(), 'children': children},
})
