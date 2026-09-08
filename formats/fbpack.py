"""FBPACK ("FBPK") — Google's Fastboot Package container used to bundle
named sub-partition images into one flashable file on Tensor/Pixel devices
(bootloader.img, radio.img).

Two incompatible on-disk versions share the same magic and are told apart
by the 4-byte `version` field right after it:

- **v2** (`bootloader.img`): fixed header carries `header_size`/
  `entry_header_size`/`platform`/`pack_version`; each entry stores its own
  absolute `offset`+`size` directly.
- **v1** (`radio.img`): older, simpler header; entries form a linked list
  via a 64-bit `next_offset` split across `next_offset_h`/`next_offset`,
  with each entry's data placed immediately after its own header rather
  than at a stored offset. Entries of `type == 0` are partition-table
  markers with no data of their own — they exist purely to carry the link
  to the next real entry, per the reference tool's own handling.

Both versions fit the same "header + flat table of named (offset, size)
entries" shape, so this is one registered Transform with an internal
version-dispatch table (`_VERSION_PARSERS`) rather than two formats — add a
v3 by adding one parser function and one dict entry here, not a new file.

Struct layouts and traversal logic verified against the reference tools
(Apache-2.0 licensed): Google's `fbpacktool.py`/`fbpack.py`
(source.android.com, AOSP `fw_unpack`) for v2, and CalyxOS's fork
(gitlab.com/CalyxOS/scripts) which added v1 support. Reimplemented from
scratch below — this plugin vendors neither tool and has no runtime
dependency on them.
"""

from __future__ import annotations

import struct
from typing import Callable

from ..common.binstruct import BinStruct, cstr
from ..common.container_base import Entry, OffsetTableContainer

MAGIC = b"FBPK"
_PARTITION_TABLE_TYPE = 0


class _HeaderV2(BinStruct):
    _format = "<IIII16s64sIIII"
    _fields = (
        "magic", "version", "header_size", "entry_header_size",
        "platform", "pack_version", "slot_type", "data_align",
        "total_entries", "total_size",
    )


class _EntryV2(BinStruct):
    _format = "<I36s40sQQII"
    _fields = ("type", "name", "product", "offset", "size", "slotted", "crc32")


class _HeaderV1(BinStruct):
    _format = "<II68sII"
    _fields = ("magic", "version", "img_version", "total_entries", "total_size")


class _EntryV1(BinStruct):
    _format = "<I32sIIIII"
    _fields = ("type", "name", "size_h", "size", "next_offset_h", "next_offset", "crc32")


def _parse_v2(data: bytes) -> list[Entry]:
    header = _HeaderV2.unpack_from(data, 0)
    entries = []
    offset = _HeaderV2.size()
    for _ in range(header.total_entries):
        raw = _EntryV2.unpack_from(data, offset)
        offset += _EntryV2.size()
        entries.append(Entry(name=cstr(raw.name), offset=raw.offset, size=raw.size))
    return entries


def _parse_v1(data: bytes) -> list[Entry]:
    header = _HeaderV1.unpack_from(data, 0)
    entries = []
    next_offset = _HeaderV1.size()
    for _ in range(header.total_entries):
        raw = _EntryV1.unpack_from(data, next_offset)
        data_offset = next_offset + _EntryV1.size()
        next_offset = (raw.next_offset_h << 32) | raw.next_offset
        if raw.type == _PARTITION_TABLE_TYPE:
            continue
        size = (raw.size_h << 32) | raw.size
        entries.append(Entry(name=cstr(raw.name), offset=data_offset, size=size))
    return entries


_VERSION_PARSERS: dict[int, Callable[[bytes], list[Entry]]] = {
    1: _parse_v1,
    2: _parse_v2,
}


class FBPack(OffsetTableContainer):
    MAGIC = MAGIC
    name = "FBPack"
    long_name = "Fastboot Package (FBPK)"

    def can_decode(self, input) -> bool:
        head = input.read(0, 8)
        if len(head) < 8 or head[:4] != MAGIC:
            return False
        version = struct.unpack_from("<I", head, 4)[0]
        return version in _VERSION_PARSERS

    def parse_entries(self, data: bytes) -> list[Entry]:
        version = struct.unpack_from("<I", data, 4)[0]
        parser = _VERSION_PARSERS.get(version)
        if parser is None:
            raise ValueError(f"unsupported FBPK version {version}")
        return parser(data)


FBPack.register()
