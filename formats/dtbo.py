"""DTBO / DT table format ("dt table", `dtbo.img`) — a table of Device
Tree Blob overlays (or ACPI tables, the sibling "ACPIO" variant sharing the
same layout) packed into one image.

Struct layout — confirmed against AOSP's own `mkdtboimg.py`
(`platform/system/libufdt`, Apache-2.0; read for reference, not vendored —
the format is a simple enough offset table that porting the struct beats
the complexity of wrapping that tool's CLI-oriented, file-writing API the
way `boot_image.py` wraps `unpack_bootimg.py`):

Unlike every other format in this plugin, DT table fields are
**big-endian** — worth calling out explicitly since it's the one place a
contributor copying another format's `BinStruct` as a template would get
it wrong by default.

Header (32 bytes): magic, total_size, header_size, dt_entry_size,
dt_entry_count, dt_entries_offset, page_size, version. Followed by
`dt_entry_count` entries (32 bytes each): size, offset, id, rev, then
either 4 "custom" fields (version 0) or flags+3 "custom" fields
(version 1) — none of which this plugin needs, since we only extract each
blob by its declared offset+size.
"""

from __future__ import annotations

from ..common.binstruct import BinStruct
from ..common.container_base import Entry, OffsetTableContainer
from ..common.native import formats

_DTBO_MAGIC = 0xD7B7AB1E
_ACPIO_MAGIC = 0x41435049
MAGIC = _DTBO_MAGIC.to_bytes(4, "big")


class _Header(BinStruct):
    _format = ">8I"
    _fields = (
        "magic", "total_size", "header_size", "dt_entry_size",
        "dt_entry_count", "dt_entries_offset", "page_size", "version",
    )


class _Entry(BinStruct):
    _format = ">8I"
    _fields = ("size", "offset", "id", "rev", "c0", "c1", "c2", "c3")


def _parse_entries(data: bytes) -> list[Entry]:
    header = _Header.unpack_from(data, 0)
    if header.magic not in (_DTBO_MAGIC, _ACPIO_MAGIC):
        raise ValueError(f"unexpected DT table magic {header.magic:#x}")
    if header.header_size != _Header.size() or header.dt_entry_size != _Entry.size():
        raise ValueError("unexpected DT table header/entry size — not a standard v0/v1 layout")

    entries = []
    for i in range(header.dt_entry_count):
        raw = _Entry.unpack_from(data, header.dt_entries_offset + i * header.dt_entry_size)
        entries.append(Entry(name=f"dt{i:02d}", offset=raw.offset, size=raw.size))
    return entries


class Dtbo(OffsetTableContainer):
    MAGIC = MAGIC
    name = "Dtbo"
    long_name = "DTBO / DT Table Image"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(0, 4)
        except Exception:
            return False
        if len(head) < 4:
            return False
        magic = int.from_bytes(head, "big")
        return magic in (_DTBO_MAGIC, _ACPIO_MAGIC)

    def parse_entries(self, data: bytes) -> list[Entry]:
        return _parse_entries(data)


if not any(info["id"] == "dtbo" for info in formats()):
    Dtbo.register()
