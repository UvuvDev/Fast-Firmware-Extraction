"""Android initramfs: legacy LZ4 wrapping a newc/CRC CPIO filesystem.

Verified against the Redmi A5 A15.0.31.0 vendor_boot.img: its sole vendor
ramdisk has nine independent LZ4 blocks expanding to 67,392,512 bytes of
newc CPIO. Layouts were cross-checked against Linux usr/gen_init_cpio.c
(GPL-2.0, reference only; no code copied) and lz4's programs/lz4io.c and
doc/lz4_{Frame,Block}_format.md (BSD-2-Clause implementation, reference
only). The pure-Python decoder avoids a native library or tool dependency.

This is a FilesystemContainer: compressed ramdisks expose their regular
files directly. Directories, symlinks and device nodes are skipped, as in
the other filesystem formats. Hard links share their archive payload;
concatenated archives reset the hard-link table at each TRAILER!!!.
Binary Ninja already handles plain CPIO; detection here only claims legacy
LZ4. Old binary/odc CPIO and modern LZ4 frames are unsupported by this handler.
Filenames must be UTF-8, as required by Binary Ninja's child-name API.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ..common.container_base import FilesystemContainer

_CPIO_MAGICS = (b"070701", b"070702")
_LZ4_MAGIC = b"\x02\x21\x4c\x18"
_BLOCK_LIMIT = 8 * 1024 * 1024
_COMPRESSED_LIMIT = _BLOCK_LIMIT + _BLOCK_LIMIT // 255 + 16
_RAMDISK_LIMIT = 1024 * 1024 * 1024
_HEX = frozenset(b"0123456789abcdefABCDEF")


def _lz4_block(data: bytes) -> bytes:
    """Decode an independent block, checking every read and output growth."""
    out = bytearray()
    pos = 0

    def length(base: int) -> int:
        nonlocal pos
        if base == 15:
            while True:
                if pos >= len(data):
                    raise ValueError("truncated LZ4 extended length")
                extra = data[pos]
                pos += 1
                base += extra
                if base > _BLOCK_LIMIT:
                    raise ValueError("LZ4 length exceeds 8 MiB block limit")
                if extra != 255:
                    break
        return base

    while pos < len(data):
        token = data[pos]
        pos += 1
        literals = length(token >> 4)
        if pos + literals > len(data) or len(out) + literals > _BLOCK_LIMIT:
            raise ValueError("invalid LZ4 literal length")
        out.extend(data[pos:pos + literals])
        pos += literals
        if pos == len(data):
            return bytes(out)
        if pos + 2 > len(data):
            raise ValueError("truncated LZ4 match offset")
        distance = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if not 0 < distance <= len(out):
            raise ValueError("invalid LZ4 match offset")
        count = length(token & 15) + 4
        if len(out) + count > _BLOCK_LIMIT:
            raise ValueError("LZ4 match exceeds 8 MiB block limit")
        # Overlapping matches repeat the preceding distance-byte pattern.
        start = len(out) - distance
        pattern = out[start:start + min(distance, count)]
        repeats, tail = divmod(count, len(pattern))
        out.extend(pattern * repeats)
        out.extend(pattern[:tail])
    raise ValueError("LZ4 block must end with a literal sequence")


def _legacy_lz4(data: bytes) -> bytes:
    if data[:4] != _LZ4_MAGIC:
        raise ValueError("not a legacy LZ4 stream")
    out = bytearray()
    pos = 4
    blocks = 0
    while pos < len(data):
        if pos + 4 > len(data):
            raise ValueError("truncated legacy LZ4 block size")
        size = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if size == int.from_bytes(_LZ4_MAGIC, "little"):
            # The legacy format also permits concatenated legacy frames.
            continue
        if size == 0:
            # Linux also accepts a zero terminator; require zero padding.
            if any(data[pos:]):
                raise ValueError("nonzero data after legacy LZ4 terminator")
            break
        if size > _COMPRESSED_LIMIT or pos + size > len(data):
            raise ValueError("invalid legacy LZ4 compressed block size")
        block = _lz4_block(data[pos:pos + size])
        if len(out) + len(block) > _RAMDISK_LIMIT:
            raise ValueError("legacy LZ4 ramdisk exceeds 1 GiB limit")
        out.extend(block)
        blocks += 1
        pos += size
    if not blocks:
        raise ValueError("empty legacy LZ4 stream")
    return bytes(out)


@dataclass
class _CpioFS:
    data: bytes
    files: dict[str, tuple[int, int]]


def _parse_cpio(data: bytes) -> _CpioFS:
    files: dict[str, tuple[int, int]] = {}
    # Values are shared mutable payload descriptors, so a hard-link record
    # with data can occur before or after records that carry no payload.
    records: dict[str, list[int]] = {}
    links: dict[tuple[int, int, int], list[int]] = {}
    pos = 0
    archives = 0
    in_archive = False
    while pos < len(data):
        # initramfs allows zero padding between concatenated CPIO archives.
        if not in_archive:
            while pos < len(data) and data[pos] == 0:
                pos += 1
            if pos == len(data):
                break
        if pos + 110 > len(data) or data[pos:pos + 6] not in _CPIO_MAGICS:
            raise ValueError(f"invalid/truncated CPIO header at {pos:#x}")
        magic = data[pos:pos + 6]
        header = data[pos + 6:pos + 110]
        if any(c not in _HEX for c in header):
            raise ValueError("non-hexadecimal CPIO header field")
        fields = [int(header[i:i + 8], 16) for i in range(0, 104, 8)]
        ino, mode, _, _, nlink, _, size, major, minor, _, _, namesize, checksum = fields
        name_start = pos + 110
        name_end = name_start + namesize
        payload = (name_end + 3) & ~3
        end = payload + size
        next_pos = (end + 3) & ~3
        if namesize < 1 or name_end > len(data) or next_pos > len(data):
            raise ValueError("CPIO name or payload exceeds archive length")
        raw_name = data[name_start:name_end]
        if raw_name[-1:] != b"\0" or b"\0" in raw_name[:-1]:
            raise ValueError("CPIO filename is not a single NUL-terminated string")
        name = raw_name[:-1].decode("utf-8")
        if magic == b"070702" and (sum(data[payload:end]) & 0xFFFFFFFF) != checksum:
            raise ValueError(f"CPIO checksum mismatch for {name!r}")
        pos = next_pos
        if name == "TRAILER!!!":
            if size:
                raise ValueError("CPIO trailer has a payload")
            archives += 1
            in_archive = False
            links.clear()
            continue
        in_archive = True
        if mode & 0xF000 != 0x8000:
            continue
        record = [payload, size]
        if nlink > 1:
            key = (major, minor, ino)
            previous = links.get(key)
            if previous is None:
                links[key] = record
            else:
                if size:
                    previous_end = previous[0] + previous[1]
                    if previous[1] and data[previous[0]:previous_end] != data[payload:end]:
                        raise ValueError("conflicting CPIO hard-link payloads")
                    previous[:] = record
                record = previous
        records[name] = record
    if in_archive or not archives:
        raise ValueError("missing CPIO TRAILER!!!")
    files.update((name, (record[0], record[1])) for name, record in records.items())
    return _CpioFS(data, files)


class LegacyLz4Ramdisk(FilesystemContainer):
    MAGIC = _LZ4_MAGIC
    name = "LegacyLz4Ramdisk"
    long_name = "Legacy LZ4 Android Ramdisk (CPIO)"

    def open_filesystem(self, data: bytes) -> _CpioFS:
        return _parse_cpio(_legacy_lz4(bytes(data)))

    def list_paths(self, fs: _CpioFS) -> list[str]:
        return list(fs.files)

    def read_file(self, fs: _CpioFS, path: str) -> bytes:
        offset, size = fs.files[path]
        return fs.data[offset:offset + size]


LegacyLz4Ramdisk.register()
