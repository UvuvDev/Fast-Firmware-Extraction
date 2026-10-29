"""Hand-built F2FS fixtures; source payloads, not native output, are the oracle."""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[3]
BS = 4096
ADDRS = (BS - 360 - 20 - 24)//4
PTRS = (BS - 24)//4
path = ROOT / 'tests/fixtures/f2fs/sample.img'
original = bytearray(path.read_bytes())
# Normalize the old synthetic fixture once: directory bitmaps had incorrectly
# used NAT's MSB order, and node footer IDs were left as placeholders.
if original[40*BS + BS - 24:40*BS + BS - 20] == bytes(4):
    for start, capacity in [(40*BS + 364, (ADDRS-1)*4), (48*BS, BS)]:
        count = capacity*8//153
        bitmap_size = (count+7)//8
        for offset in range(start, start+bitmap_size):
            original[offset] = int(f'{original[offset]:08b}'[::-1], 2)
    for nid, block in [(3, 40), (4, 41), (5, 42), (6, 43), (7, 44)]:
        struct.pack_into('<II', original, block*BS + BS - 24, nid, nid)
# The original encoder marked only the first slot of long names. Occupied
# continuation slots must also be set. This repair is idempotent.
for start, capacity in [(40*BS + 364, (ADDRS-1)*4), (48*BS, BS)]:
    count = capacity*8//153
    records = capacity-count*19
    slot = 0
    while slot < count:
        if not original[start+slot//8] & (1 << (slot%8)):
            slot += 1
            continue
        length = struct.unpack_from('<H', original, start+records+slot*11+8)[0]
        assert 0 < length <= 255
        slots = (length+7)//8
        for index in range(slot, slot+slots):
            original[start+index//8] |= 1 << (index%8)
        slot += slots
path.write_bytes(original)
assert struct.unpack_from('<I', original, 40*BS+BS-24)[0] == 3
image = original + bytearray(11*BS)

def u32(offset, value):
    struct.pack_into('<I', image, offset, value)

def node(nid, owner, block):
    image[block*BS:(block+1)*BS] = bytes(BS)
    struct.pack_into('<II', image, block*BS+BS-24, nid, owner)
    struct.pack_into('<BII', image, 32*BS+nid*9, 0, owner, block)

# Checkpoint 11 selects the second NAT segment; stale copy points nowhere.
image[32*BS:33*BS] = image[24*BS:25*BS]
image[24*BS:25*BS] = bytes(BS)
image[16*BS+193] = 0x80
u32(16*BS+132, 1)
image[23*BS:24*BS] = image[16*BS:17*BS]

inline = b'inline file from the current NAT copy\n'
u32(41*BS+16, len(inline))
image[41*BS+364:41*BS+364+len(inline)] = inline

for nid, owner, block in [(8, 8, 50), (9, 9, 51), (10, 10, 55), (11, 8, 52), (12, 9, 53), (13, 9, 54)]:
    node(nid, owner, block)

# Direct-node file has holes in every inode pointer, then two data blocks.
first = bytes(range(256))*16
tail = b'direct-node-tail: ' + bytes(range(19))
assert len(tail) == 37
direct = bytes(ADDRS*BS) + first + tail
struct.pack_into('<H', image, 50*BS, 0x81a4)
struct.pack_into('<Q', image, 50*BS+16, len(direct))
u32(50*BS+360, 0xffffffff)
u32(50*BS+360+ADDRS*4, 11)
u32(52*BS, 56)
u32(52*BS+4, 57)
image[56*BS:57*BS] = first
image[57*BS:57*BS+len(tail)] = tail

# The indirect-node tier starts after both direct-node address spans.
last = b'indirect payload: ' + bytes(range(79))
assert len(last) == 97
indirect = bytes((ADDRS+2*PTRS)*BS) + last
struct.pack_into('<H', image, 51*BS, 0x81a4)
struct.pack_into('<Q', image, 51*BS+16, len(indirect))
u32(51*BS+360+ADDRS*4+2*4, 12)
u32(53*BS, 13)
u32(54*BS, 58)
image[58*BS:58*BS+len(last)] = last
struct.pack_into('<H', image, 55*BS, 0xa1ff)

# Inline directory with long names consuming multiple consecutive LSB bitmap bits.
capacity = (ADDRS-1)*4
payload = bytearray(capacity)
count = capacity*8//153
records = capacity - count*19
names = capacity - count*8
slot = 0
for nid, name, kind in [(3, '.', 2), (3, '..', 2), (8, 'direct-node.bin', 1), (9, 'indirect-node.bin', 1), (4, 'inline.txt', 1), (10, 'link', 7)]:
    name = name.encode()
    slots = (len(name)+7)//8
    for index in range(slot, slot+slots):
        payload[index//8] |= 1 << (index%8)
    struct.pack_into('<IIHB', payload, records+slot*11, 0, nid, len(name), kind)
    payload[names+slot*8:names+slot*8+len(name)] = name
    slot += slots
image[40*BS+364:40*BS+364+capacity] = payload
expected = {'direct-node.bin': direct, 'indirect-node.bin': indirect, 'inline.txt': inline}
children = {name: {'length': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} for name, raw in expected.items()}

def fixture(name, raw):
    out = ROOT / 'tests/fixtures' / name
    out.mkdir(exist_ok=True)
    (out / 'sample.img').write_bytes(raw)
    (out / 'expected.json').write_text(json.dumps({'native_format': 'f2fs', 'sample': 'sample.img', 'children': children}, indent=2) + '\n')

fixture('f2fs_mapped', image)
image[1024:1028] = bytes(4)
fixture('f2fs_secondary', image)
