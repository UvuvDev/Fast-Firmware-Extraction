"""Samsung Shannon baseband TOC (Table of Contents) firmware container —
the format `modem.bin` is packaged in on Pixel/Tensor devices (Shannon is
Samsung's modem SoC family used behind Google's own Tensor branding). A
leading 32-byte entry named "TOC" describes the table itself (its `size`
field is the byte length of the whole table, not a data section); it's
followed by more 32-byte entries — one per named region (`BOOT`, `MAIN`,
`VSS`, `APM`, `NV_NORM`, `NV_PROT`, `REPLAY`, `INFO` on this device) — until
either a blank (all-zero name) entry or the table's own declared size is
reached.

Struct layout confirmed against the reference (MIT licensed) rather than
guessed from the hexdump alone — this plugin's own extraction notes flagged
the field ordering as genuinely ambiguous without a parser to check against
(offset vs. load address vs. an unlabeled fourth field are easy to
transpose and all "look like" plausible 32-bit values). Cross-checked here
against grant-h/ShannonBaseband's `reversing/modem/parse_modem.py` and
`TOCSectionHeader.java` (SPDX-License-Identifier: MIT) and against this
plugin's own real `modem.bin` sample: BOOT's `offset` (1040) lines up
exactly with the end of the leading TOC table, and BOOT's `offset + size`
lines up exactly with MAIN's `offset`. Reimplemented from scratch below —
not vendored, no runtime dependency on that project.

Two behaviors are carried over from that same reference tool rather than
invented independently:

- An entry with `offset <= 0` is "virtual" (declared in the table but not
  actually embedded in this file — e.g. an NV partition that lives
  elsewhere on the device) and is skipped rather than extracted as an
  empty/garbage child.
- `BOOT`'s declared `size` includes a fixed 512 + 4*4 = 528 bytes of
  header/footer that isn't part of its actual payload; the reference
  extractor trims it, so this does too.
"""

from __future__ import annotations

from ..common.binstruct import BinStruct, cstr
from ..common.container_base import Entry, OffsetTableContainer

MAGIC = b"TOC\x00"
_BOOT_TRIM = 512 + 4 * 4


class _TocEntry(BinStruct):
    _format = "<12sIIIII"
    _fields = ("name", "offset", "load_address", "size", "unk1", "id")


def _parse_entries(data: bytes) -> list[Entry]:
    header = _TocEntry.unpack_from(data, 0)
    if cstr(header.name) != "TOC":
        raise ValueError(f"expected a leading 'TOC' entry, got {cstr(header.name)!r}")

    toc_size = header.size
    entries: list[Entry] = []
    pos = _TocEntry.size()
    while pos < toc_size:
        raw = _TocEntry.unpack_from(data, pos)  # bounds-checked against len(data)
        pos += _TocEntry.size()

        name = cstr(raw.name)
        if not name:
            break
        if raw.offset <= 0:
            continue

        size = raw.size
        if name == "BOOT":
            size = max(0, size - _BOOT_TRIM)
        entries.append(Entry(name=name, offset=raw.offset, size=size))
    return entries


class ShannonTOC(OffsetTableContainer):
    MAGIC = MAGIC
    name = "ShannonTOC"
    long_name = "Samsung Shannon Baseband TOC"

    def parse_entries(self, data: bytes) -> list[Entry]:
        return _parse_entries(data)


ShannonTOC.register()
