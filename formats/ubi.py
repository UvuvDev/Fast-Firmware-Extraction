"""UBI (Unsorted Block Images) — the standard container format for raw
NAND/MTD flash on embedded Linux devices (routers, IoT, NVR/camera
systems). Each physical eraseblock (PEB) carries its own erase-counter
(EC) header and volume-ID (VID) header; a reserved "layout volume" (a
fixed, well-known volume ID) holds the volume table naming every other
volume. A volume's data isn't necessarily contiguous — wear-leveling can
place its logical eraseblocks (LEBs) at any physical eraseblock, so
reconstructing one means scanning every PEB's VID header, grouping by
volume ID, sorting by logical eraseblock number, and concatenating — the
same "walk a mapping, gather segments" shape as ext4/EROFS's block-mapped
files, just one layer further down the stack.

Unlike every little-endian format elsewhere in this plugin, UBI headers
are **big-endian** (shares that distinction with `dtbo.py` alone so far).

Struct layout and the EC/VID header field semantics were **verified against
a real router firmware sample**, not copied from any reference source —
this project's established priority order (see `docs/ADDING_A_FORMAT.md`)
puts a real-sample cross-check above a reference implementation, and here
it was especially warranted: the canonical implementation (the Linux
kernel's `drivers/mtd/ubi` and the `mtd-utils` package) is GPL-only, not
available under a permissive license the way ext4/EROFS's references
were, so this plugin doesn't lean on it at all, not even for reference
reading. Every field below was cross-checked against known-good UBI
semantics visible in the sample itself: the layout volume's ID
(`0x7FFFEFFF`) and its `compat` value (5, "reject if not understood") are
well-known fixed constants, and both matched exactly; the volume table
this plugin parsed out named three sane, real-looking volumes
(`uboot`, `kernel`, `rootfs`) with LEB counts that summed correctly
against the image's total eraseblock count.

Physical eraseblock (PEB) size is not stored anywhere in the format
itself (it's flash geometry, constant for the whole image) — it's
recovered here by measuring the byte distance between the first two "UBI#"
magics in the image, then sanity-checked.

Deliberately out of scope: dynamic-volume "used bytes" tracking beyond
what's needed for read-only extraction, and picking the newest of the
layout volume's redundant copies by sequence number (both copies were
identical in the sample validated against; a corrupt/mid-update image with
diverging copies isn't handled — this reads the first valid copy found).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..common.container_base import FilesystemContainer
from ..common.native import formats

MAGIC = b"UBI#"
_VID_MAGIC = b"UBI!"
_EC_HDR_SIZE = 64
_VID_HDR_SIZE = 64
_VTBL_RECORD_SIZE = 172
_LAYOUT_VOLUME_ID = 0x7FFFEFFF
_VOL_TYPE_DYNAMIC = 1
_VOL_TYPE_STATIC = 2
_PEB_SCAN_LIMIT = 1 << 22  # 4 MiB is generously more than any real PEB size


@dataclass
class _Segment:
    lnum: int
    offset: int
    length: int


def _detect_peb_size(data: bytes) -> int:
    if data[:4] != MAGIC:
        raise ValueError("no UBI erase-counter header at offset 0")
    second = data.find(MAGIC, 4, _PEB_SCAN_LIMIT)
    if second == -1:
        raise ValueError("could not find a second PEB to measure eraseblock size")
    if second < _EC_HDR_SIZE:
        raise ValueError(f"implausible PEB size {second}")
    return second


class UbiFS:
    def __init__(self, data: bytes):
        self.data = data
        self.peb_size = _detect_peb_size(data)

        vid_hdr_offset, data_offset = struct.unpack_from(">II", data, 16)
        if not (0 < vid_hdr_offset < data_offset < self.peb_size):
            raise ValueError(f"implausible header offsets vid={vid_hdr_offset} data={data_offset} peb={self.peb_size}")
        self.vid_hdr_offset = vid_hdr_offset
        self.data_offset = data_offset

        volumes: dict[int, list[_Segment]] = {}
        layout_leb0 = None

        peb_count = len(data) // self.peb_size
        for i in range(peb_count):
            peb_off = i * self.peb_size
            if data[peb_off:peb_off + 4] != MAGIC:
                continue  # free/unformatted/spare eraseblock

            vid_off = peb_off + self.vid_hdr_offset
            if vid_off + _VID_HDR_SIZE > len(data) or data[vid_off:vid_off + 4] != _VID_MAGIC:
                continue  # mapped but no valid volume yet

            vol_type = data[vid_off + 5]
            vol_id, lnum = struct.unpack_from(">II", data, vid_off + 8)
            data_size = struct.unpack_from(">I", data, vid_off + 20)[0]

            leb_data_off = peb_off + self.data_offset
            leb_capacity = self.peb_size - self.data_offset
            length = data_size if vol_type == _VOL_TYPE_STATIC and data_size else leb_capacity
            if length > leb_capacity:
                raise ValueError(f"LEB {lnum} of volume {vol_id} claims {length} bytes, capacity is {leb_capacity}")

            volumes.setdefault(vol_id, []).append(_Segment(lnum, leb_data_off, length))
            if vol_id == _LAYOUT_VOLUME_ID and lnum == 0 and layout_leb0 is None:
                layout_leb0 = self.data[leb_data_off:leb_data_off + leb_capacity]

        if layout_leb0 is None:
            raise ValueError("no layout volume (volume table) found in this UBI image")

        self.volumes = {vid: sorted(segs, key=lambda s: s.lnum) for vid, segs in volumes.items()}
        self.names_by_id = self._parse_vtbl(layout_leb0)

    @staticmethod
    def _parse_vtbl(layout_data: bytes) -> dict[int, str]:
        names: dict[int, str] = {}
        max_records = len(layout_data) // _VTBL_RECORD_SIZE
        for vol_id in range(max_records):
            off = vol_id * _VTBL_RECORD_SIZE
            if off + _VTBL_RECORD_SIZE > len(layout_data):
                break
            name_len = struct.unpack_from(">H", layout_data, off + 14)[0]
            if name_len == 0 or name_len > 127:
                continue  # empty/unused volume table slot
            name = layout_data[off + 16:off + 16 + name_len].decode("utf-8", "replace")
            names[vol_id] = name
        return names

    def read_volume(self, vol_id: int) -> bytes:
        segments = self.volumes.get(vol_id)
        if not segments:
            raise ValueError(f"no data found for volume id {vol_id}")
        return b"".join(self.data[s.offset:s.offset + s.length] for s in segments)


class Ubi(FilesystemContainer):
    name = "Ubi"
    long_name = "UBI flash image"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(0, 4)
        except Exception:
            return False
        return bytes(head) == MAGIC

    def open_filesystem(self, data: bytes) -> UbiFS:
        return UbiFS(data)

    def list_paths(self, fs: UbiFS) -> list[str]:
        return [name for vol_id, name in fs.names_by_id.items() if vol_id in fs.volumes]

    def read_file(self, fs: UbiFS, path: str) -> bytes:
        vol_id = next((vid for vid, name in fs.names_by_id.items() if name == path), None)
        if vol_id is None:
            raise ValueError(f"'{path}' not found in volume table")
        return fs.read_volume(vol_id)


if not any(info["id"] == "ubi" for info in formats()):
    Ubi.register()
