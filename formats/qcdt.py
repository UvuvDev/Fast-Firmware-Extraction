"""QCDT ("QCDT") — Qualcomm Device Tree Table, the format found on the
`dtb`/`dt` partition (commonly `dtb.img`) of essentially every Qualcomm/
Snapdragon-based Android device. It packs multiple embedded Flattened
Device Tree (FDT) blobs — one per board/SoC-revision/PMIC combination a
single build needs to support — behind a small header + flat entry table,
so the bootloader can pick the right FDT for the hardware it's running on.
This is the direct Qualcomm-chipset analog of `formats/dtbo.py` (DTBO):
same "header + flat table of (offset, size) entries pointing at embedded
FDT blobs" shape, but little-endian and with a per-version entry layout
instead of a per-version *field count within one entry size*.

Three incompatible on-disk entry layouts exist (v1/v2/v3), identified by
the `version` field right after the magic; each simply adds fields onto
the previous one, which is also why every subsequent field shifts and
getting one identifier field's width/count wrong silently corrupts every
later entry's offset — exactly the case this plugin's docs call out as a
"verify, don't guess" requirement.

Struct layout verified against two independent, permissively-licensed,
non-vendored sources whose field lists, field counts and byte sizes agree
exactly:

- Code Aurora Forum / Qualcomm's own `dtbtool.c`, as shipped in AOSP-style
  device trees (BSD-3-Clause, "Copyright (c) 2012-2013, The Linux
  Foundation"), e.g.
  https://github.com/CyanogenMod/android_device_qcom_common/blob/cm-13.0/dtbtool/dtbtool.c
  — the *build-time* tool that writes this exact header/entry sequence
  field-by-field via `write()`, confirming: 12-byte header (4-byte ASCII
  magic "QCDT" + `version` uint32 + `dtb_count`/entry-count uint32), then
  for each entry: `chipset`, `platform`, (`subtype` — v2+ only), `revNum`,
  (`pmic_model[0..3]` — v3 only), `offset`, `size`, with every field a
  native (i.e. little-endian on the real, x86 build hosts this tool runs
  on) `uint32_t`.
- EFIDroid's `libboot` QCDT *reader* (BSD-3-Clause, same original
  "Copyright (c) 2012-2014, The Linux Foundation" header — an independent
  downstream copy of the same Qualcomm-authored code, but transcribed by a
  different project for the opposite purpose (parsing on a real
  bootloader, not generating at build time), so it still catches a
  transcription slip either side could otherwise have made):
  https://raw.githubusercontent.com/efidroid/modules_libboot/master/include/lib/boot/qcdt.h
  and .../include_private/lib/boot/internal/qcdt.h — defines
  `dt_table_t {magic, version, num_entries}` (`DEV_TREE_HEADER_SIZE == 12`,
  `DEV_TREE_MAGIC == 0x54444351`, which is exactly the ASCII bytes "QCDT"
  read little-endian) and, field-for-field matching `dtbtool.c` above:
  `dt_entry_v1_t {platform_id, variant_id, soc_rev, offset, size}` (20B),
  `dt_entry_v2_t {platform_id, variant_id, board_hw_subtype, soc_rev,
  offset, size}` (24B), `dt_entry_t {platform_id, variant_id,
  board_hw_subtype, soc_rev, pmic_rev[4], offset, size}` (40B).

Both sources agree on every field's position and width for v1/v2/v3, so
all three are implemented here (`_VERSION_PARSERS`, same one-file-per-new-
version pattern as `formats/fbpack.py`). This plugin reimplements the
struct layout from scratch below — it vendors neither source and has no
runtime dependency on them. Only `offset`/`size` are used; the
identifier fields (platform/variant/soc-rev/subtype/pmic) are parsed only
insofar as they must be skipped correctly to keep the table walk aligned,
and are not surfaced — a real per-entry FDT big-endian magic
(`0xD00DFEED`) sanity check was considered but is unnecessary since
`common/container_base.py` already bounds-checks the offset+size slice
for every entry regardless.
"""

from __future__ import annotations

import struct
from typing import Callable

from ..common.binstruct import BinStruct
from ..common.container_base import Entry, OffsetTableContainer
from ..common.native import formats

MAGIC = b"QCDT"


class _Header(BinStruct):
    _format = "<4sII"
    _fields = ("magic", "version", "num_entries")


class _EntryV1(BinStruct):
    _format = "<IIIII"
    _fields = ("platform_id", "variant_id", "soc_rev", "offset", "size")


class _EntryV2(BinStruct):
    _format = "<IIIIII"
    _fields = ("platform_id", "variant_id", "board_hw_subtype", "soc_rev", "offset", "size")


class _EntryV3(BinStruct):
    _format = "<IIII4III"
    _fields = (
        "platform_id", "variant_id", "board_hw_subtype", "soc_rev",
        "pmic_rev0", "pmic_rev1", "pmic_rev2", "pmic_rev3",
        "offset", "size",
    )


def _parse_with(entry_cls) -> Callable[[bytes], list[Entry]]:
    def _parse(data: bytes) -> list[Entry]:
        header = _Header.unpack_from(data, 0)
        entries = []
        offset = _Header.size()
        for i in range(header.num_entries):
            raw = entry_cls.unpack_from(data, offset)
            offset += entry_cls.size()
            entries.append(Entry(name=f"dt{i:02d}", offset=raw.offset, size=raw.size))
        return entries

    return _parse


_VERSION_PARSERS: dict[int, Callable[[bytes], list[Entry]]] = {
    1: _parse_with(_EntryV1),
    2: _parse_with(_EntryV2),
    3: _parse_with(_EntryV3),
}


class Qcdt(OffsetTableContainer):
    MAGIC = MAGIC
    name = "Qcdt"
    long_name = "Qualcomm Device Tree Table (QCDT)"

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
            raise ValueError(f"unsupported QCDT version {version}")
        return parser(data)


if not any(info["id"] == "qcdt" for info in formats()):
    Qcdt.register()
