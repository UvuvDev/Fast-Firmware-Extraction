"""EROFS (Enhanced Read-Only File System) — the filesystem Pixel factory
images actually use for `system.img`/`vendor.img`/`product.img`/etc. on
current-generation devices (superblock magic `0xE0F5E1E2` at byte offset
1024, same convention as ext4's offset-1024 superblock but a different
on-disk format entirely — this plugin's `Ext4` transform does not match
these images).

Deliberately scoped to **uncompressed inodes** — flat (`EROFS_INODE_FLAT_PLAIN`,
`EROFS_INODE_FLAT_INLINE`) and single-device chunk-based
(`EROFS_INODE_CHUNK_BASED`) all handled, confirmed sufficient for real
Pixel factory-image partitions (`feature_incompat` and
`available_compr_algs` both `0x0` in the real superblock: this device
uses no compression at all, though some of its regular files still use
the chunk-based layout). Compressed inodes (`EROFS_INODE_COMPRESSED_FULL`/
`_COMPACT`, the z_erofs LZ4/LZMA/DEFLATE/ZSTD cluster machinery),
multi-device chunks, and the "metabox" indirection are all out of scope —
each raises `NotImplementedError` rather than guessing, per this plugin's
convention for genuinely unimplemented cases (see ext4.py's docstring for
the same pattern). Symlinks are skipped from listings, same policy as
every other filesystem format here.

Struct layout and the inode/data-location algorithm below are ported from
AOSP's own `erofs-utils` (`include/erofs_fs.h`, `include/erofs/internal.h`,
`lib/namei.c`, `lib/dir.c`, `lib/data.c` — all
`SPDX-License-Identifier: GPL-2.0+ OR MIT`, used here under the MIT
option per that project's own COPYING file). Reimplemented from scratch in
Python, not vendored — unlike `boot_image.py`, this one didn't lend itself
to calling the real C code as a black box (no Python bindings, and the
reference tool is disk-I/O-oriented C, not something `ctypes` makes
sensible to wrap for this), so the actual algorithm (not just the struct
field names) is ported by hand. Two points worth flagging since a
subtly-wrong port here is a silent-wrong-answer failure mode:

1. Directory/file data for a flat inode is **not necessarily one
   contiguous run**. `EROFS_INODE_FLAT_INLINE` files place every full
   block normally (starting at the inode's own `i_u.startblk`) but the
   final, sub-block-sized "tail" is packed immediately after the inode's
   own bytes (skipping past any inline extended attributes) rather than
   in a separate block — see `_data_segments`, ported from
   `__erofs_map_blocks` in `lib/data.c`.
2. A 64-byte extended inode can straddle a block boundary (the metadata
   region packs inodes/xattrs/tails back-to-back with no per-inode
   alignment beyond the fixed 32-byte slot size) — `_read_inode` handles
   this the same way `erofs_read_inode_from_disk` does, by reading the
   remainder from the next block rather than assuming an inode's bytes
   never cross one.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from binaryninja import log_error

from ..common.container_base import FilesystemContainer

_EROFS_MAGIC = 0xE0F5E1E2
_ROOT_MODE_CHECK_LEN = 0x60  # superblock bytes needed up through rootnid_2b/blocks_lo etc.

_SLOT_SIZE = 32  # EROFS_ISLOTBITS = 5
_INODE_COMPACT_SIZE = 32
_INODE_EXTENDED_SIZE = 64
_DIRENT_SIZE = 12
_NULL_ADDR = 0xFFFFFFFF
_MAX_DIR_DEPTH = 256

_S_IFMT = 0xF000
_S_IFDIR = 0x4000
_S_IFREG = 0x8000

_CHUNK_FORMAT_BLKBITS_MASK = 0x001F
_CHUNK_FORMAT_INDEXES = 0x0020
_CHUNK_FORMAT_48BIT = 0x0040

_DATALAYOUT_FLAT_PLAIN = 0
_DATALAYOUT_COMPRESSED_FULL = 1
_DATALAYOUT_FLAT_INLINE = 2
_DATALAYOUT_COMPRESSED_COMPACT = 3
_DATALAYOUT_CHUNK_BASED = 4

_I_NLINK_1_BIT = 1 << 4

_FT_REG_FILE = 1
_FT_DIR = 2
_FT_SYMLINK = 7

_FEATURE_INCOMPAT_METABOX = 0x100
_FEATURE_INCOMPAT_48BIT = 0x80


@dataclass
class _Superblock:
    blkszbits: int
    meta_blkaddr: int
    root_nid: int


@dataclass
class _Inode:
    mode: int
    size: int
    datalayout: int
    blkaddr: int  # i_u.startblk (block-mapped start, or NULL_ADDR) — flat layouts only
    inode_pos: int  # this inode's own absolute byte position (erofs_iloc)
    inode_size: int  # 32 or 64
    xattr_size: int
    chunk_blkbits: int = 0        # chunk-based layout only
    chunk_use_indexes: bool = False
    chunk_use_48bit: bool = False


def _round_up(value: int, unit: int) -> int:
    return ((value + unit - 1) // unit) * unit


def _probe_superblock(data: bytes, base_offset: int) -> Optional[_Superblock]:
    if base_offset + _ROOT_MODE_CHECK_LEN > len(data):
        return None
    if struct.unpack_from("<I", data, base_offset)[0] != _EROFS_MAGIC:
        return None

    blkszbits = data[base_offset + 12]
    if blkszbits > 20:  # sanity bound; real filesystems use 9-16
        return None

    feature_incompat = struct.unpack_from("<I", data, base_offset + 80)[0]
    if feature_incompat & (_FEATURE_INCOMPAT_METABOX | _FEATURE_INCOMPAT_48BIT):
        # Both change how nid -> byte-position resolves; neither is exercised
        # by real Pixel factory-image partitions seen so far, so this is an
        # explicit non-goal rather than a guess at their semantics.
        raise NotImplementedError("EROFS metabox/48BIT-addressing images are not supported")

    meta_blkaddr = struct.unpack_from("<I", data, base_offset + 40)[0]
    root_nid = struct.unpack_from("<H", data, base_offset + 14)[0]

    return _Superblock(blkszbits=blkszbits, meta_blkaddr=meta_blkaddr, root_nid=root_nid)


class ErofsFS:
    def __init__(self, data: bytes):
        self.data = data
        sb = _probe_superblock(data, 1024)
        if sb is None:
            raise ValueError("no EROFS superblock found at offset 1024")
        self.sb = sb
        self.blksz = 1 << sb.blkszbits

    def _iloc(self, nid: int) -> int:
        return self.sb.meta_blkaddr * self.blksz + nid * _SLOT_SIZE

    def _read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > len(self.data):
            raise ValueError(f"read of {length} bytes at offset {offset} exceeds image length {len(self.data)}")
        return self.data[offset:offset + length]

    def read_inode(self, nid: int) -> _Inode:
        inode_pos = self._iloc(nid)
        blk_start = (inode_pos // self.blksz) * self.blksz
        ofs = inode_pos - blk_start

        head = self._read(inode_pos, _INODE_COMPACT_SIZE)
        i_format = struct.unpack_from("<H", head, 0)[0]
        version = i_format & 0x1
        datalayout = (i_format >> 1) & 0x7

        if version == 1:  # EROFS_INODE_LAYOUT_EXTENDED
            inode_size = _INODE_EXTENDED_SIZE
            if ofs + inode_size <= self.blksz:
                raw = self._read(inode_pos, inode_size)
            else:
                # Straddles a block boundary: read what's left of this
                # block, then the remainder from the start of the next.
                gotten = self.blksz - ofs
                first = self._read(inode_pos, gotten)
                rest = self._read(blk_start + self.blksz, inode_size - gotten)
                raw = first + rest
            i_xattr_icount = struct.unpack_from("<H", raw, 2)[0]
            i_mode = struct.unpack_from("<H", raw, 4)[0]
            i_nb = struct.unpack_from("<H", raw, 6)[0]  # always startblk_hi for extended inodes
            i_size = struct.unpack_from("<Q", raw, 8)[0]
            i_u = struct.unpack_from("<I", raw, 16)[0]
            blkaddr = i_u | (i_nb << 32)
        elif version == 0:  # EROFS_INODE_LAYOUT_COMPACT
            inode_size = _INODE_COMPACT_SIZE
            raw = head
            i_xattr_icount = struct.unpack_from("<H", raw, 2)[0]
            i_mode = struct.unpack_from("<H", raw, 4)[0]
            i_nb = struct.unpack_from("<H", raw, 6)[0]
            i_size = struct.unpack_from("<I", raw, 8)[0]
            i_u = struct.unpack_from("<I", raw, 16)[0]
            if not (i_mode & _S_IFMT == _S_IFDIR) and (i_format & _I_NLINK_1_BIT):
                blkaddr = i_u | (i_nb << 32)
            else:
                blkaddr = i_u  # i_nb holds nlink here, not startblk_hi
        else:
            raise ValueError(f"unexpected inode version bits in i_format {i_format:#x}")

        if datalayout >= 5:
            raise ValueError(f"reserved/unknown EROFS datalayout {datalayout} for nid {nid}")
        if datalayout in (_DATALAYOUT_COMPRESSED_FULL, _DATALAYOUT_COMPRESSED_COMPACT):
            raise NotImplementedError(f"compressed EROFS inodes are not supported (nid {nid})")

        xattr_size = 0 if i_xattr_icount == 0 else 12 + 4 * (i_xattr_icount - 1)

        chunk_blkbits, chunk_use_indexes, chunk_use_48bit = 0, False, False
        if datalayout == _DATALAYOUT_CHUNK_BASED:
            # i_u is reinterpreted as a 2-byte "chunk format" (+2 bytes reserved)
            # rather than a block address for this layout — same on-disk slot,
            # different meaning, per erofs_inode_chunk_info.
            chunk_format = struct.unpack_from("<H", raw, 16)[0]
            chunk_blkbits = chunk_format & _CHUNK_FORMAT_BLKBITS_MASK
            chunk_use_indexes = bool(chunk_format & _CHUNK_FORMAT_INDEXES)
            chunk_use_48bit = bool(chunk_format & _CHUNK_FORMAT_48BIT)

        return _Inode(
            mode=i_mode, size=i_size, datalayout=datalayout, blkaddr=blkaddr,
            inode_pos=inode_pos, inode_size=inode_size, xattr_size=xattr_size,
            chunk_blkbits=chunk_blkbits,
            chunk_use_indexes=chunk_use_indexes,
            chunk_use_48bit=chunk_use_48bit,
        )

    def _data_segments(self, inode: _Inode) -> list[tuple[int, int, int]]:
        """Returns [(logical_offset, physical_offset, length), ...] covering
        the inode's full `size` bytes."""
        if inode.datalayout == _DATALAYOUT_CHUNK_BASED:
            return self._chunk_segments(inode)

        # Flat layouts (PLAIN / INLINE), ported from __erofs_map_blocks.
        tailpacking = inode.datalayout == _DATALAYOUT_FLAT_INLINE
        if not tailpacking and inode.blkaddr == _NULL_ADDR:
            return []  # entirely sparse; no physical data (rare edge case)

        nblocks = -(-inode.size // self.blksz)  # ceil
        boundary = (nblocks - (1 if tailpacking else 0)) * self.blksz

        segments = []
        if boundary > 0:
            segments.append((0, inode.blkaddr * self.blksz, min(boundary, inode.size)))
        if inode.size > boundary:
            tail_pos = inode.inode_pos + inode.inode_size + inode.xattr_size
            segments.append((boundary, tail_pos, inode.size - boundary))
        return segments

    def _chunk_segments(self, inode: _Inode) -> list[tuple[int, int, int]]:
        """Chunk-based layout: the logical range is divided into fixed-size
        chunks, each with its own entry (either a plain 4-byte block number,
        or an 8-byte {startblk_hi, device_id, startblk_lo} struct when
        EROFS_CHUNK_FORMAT_INDEXES is set) in a table right after the
        inode+xattrs. Multi-device chunks (device_id != 0) aren't supported —
        every chunk on real Pixel factory-image partitions seen so far
        resolves against the same single device this image already is."""
        unit = 8 if inode.chunk_use_indexes else 4
        chunk_size = self.blksz << inode.chunk_blkbits
        base = _round_up(inode.inode_pos + inode.inode_size + inode.xattr_size, unit)
        addrmask = (1 << 48) - 1 if inode.chunk_use_48bit else (1 << 32) - 1

        segments = []
        nchunks = -(-inode.size // chunk_size)
        for i in range(nchunks):
            entry = self._read(base + i * unit, unit)
            if inode.chunk_use_indexes:
                startblk_hi, device_id, startblk_lo = struct.unpack_from("<HHI", entry, 0)
                if device_id != 0:
                    raise NotImplementedError(f"multi-device EROFS chunk (device_id={device_id}) is not supported")
                startblk = ((startblk_hi << 32) | startblk_lo) & addrmask
            else:
                startblk = struct.unpack_from("<I", entry, 0)[0] & addrmask

            if startblk == (_NULL_ADDR & addrmask):
                continue  # hole — leave zero-filled

            logical = i * chunk_size
            length = min(chunk_size, inode.size - logical)
            segments.append((logical, startblk * self.blksz, length))
        return segments

    def read_file_content(self, inode: _Inode) -> bytes:
        buf = bytearray(inode.size)
        for logical, physical, length in self._data_segments(inode):
            buf[logical:logical + length] = self._read(physical, length)
        return bytes(buf)

    def _iter_dirents(self, inode: _Inode) -> list[tuple[str, int, int]]:
        entries: list[tuple[str, int, int]] = []
        pos = 0
        while pos < inode.size:
            maxsize = min(inode.size - pos, self.blksz)
            block = b""
            for logical, physical, length in self._data_segments(inode):
                seg_start = max(pos, logical)
                seg_end = min(pos + maxsize, logical + length)
                if seg_start < seg_end:
                    block += self._read(physical + (seg_start - logical), seg_end - seg_start)

            if len(block) < _DIRENT_SIZE:
                break
            next_nameoff = struct.unpack_from("<H", block, 8)[0]
            if next_nameoff < _DIRENT_SIZE or next_nameoff > maxsize or next_nameoff % _DIRENT_SIZE:
                raise ValueError(f"bogus dirent nameoff {next_nameoff}")

            count = next_nameoff // _DIRENT_SIZE
            for i in range(count):
                nid = struct.unpack_from("<Q", block, i * _DIRENT_SIZE)[0]
                nameoff, file_type = struct.unpack_from("<HB", block, i * _DIRENT_SIZE + 8)
                if i + 1 < count:
                    next_off = struct.unpack_from("<H", block, (i + 1) * _DIRENT_SIZE + 8)[0]
                    name = block[nameoff:next_off]
                else:
                    name = block[nameoff:maxsize].split(b"\x00", 1)[0]
                entries.append((name.decode("utf-8", "replace"), nid, file_type))

            pos += maxsize
        return entries

    def walk(self) -> list[str]:
        paths: list[str] = []
        self._walk_dir(self.sb.root_nid, "", paths, visited=set())
        return paths

    def _walk_dir(self, nid: int, prefix: str, out: list[str], visited: set[int], depth: int = 0) -> None:
        if nid in visited or depth > _MAX_DIR_DEPTH:
            return
        visited.add(nid)

        inode = self.read_inode(nid)
        if inode.mode & _S_IFMT != _S_IFDIR:
            return

        for name, child_nid, file_type in self._iter_dirents(inode):
            if name in (".", ".."):
                continue
            child_path = f"{prefix}/{name}" if prefix else name

            if file_type == _FT_DIR:
                self._walk_dir(child_nid, child_path, out, visited, depth + 1)
            elif file_type == _FT_REG_FILE:
                out.append(child_path)
            elif file_type == _FT_SYMLINK:
                continue  # nothing to decompile independently
            else:
                try:
                    child_mode = self.read_inode(child_nid).mode & _S_IFMT
                except (ValueError, NotImplementedError):
                    continue
                if child_mode == _S_IFDIR:
                    self._walk_dir(child_nid, child_path, out, visited, depth + 1)
                elif child_mode == _S_IFREG:
                    out.append(child_path)

    def resolve(self, path: str) -> _Inode:
        nid = self.sb.root_nid
        for part in path.split("/"):
            if not part:
                continue
            inode = self.read_inode(nid)
            if inode.mode & _S_IFMT != _S_IFDIR:
                raise ValueError(f"'{part}' is not a directory in path '{path}'")
            match = next((c_nid for name, c_nid, _ft in self._iter_dirents(inode) if name == part), None)
            if match is None:
                raise ValueError(f"'{part}' not found in path '{path}'")
            nid = match
        return self.read_inode(nid)


class Erofs(FilesystemContainer):
    name = "Erofs"
    long_name = "EROFS filesystem"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(0, 1024 + _ROOT_MODE_CHECK_LEN)
        except Exception:
            log_error("Erofs: failed to read input for signature check")
            return False
        try:
            return _probe_superblock(head, 1024) is not None
        except NotImplementedError:
            return False

    def open_filesystem(self, data: bytes) -> ErofsFS:
        return ErofsFS(data)

    def list_paths(self, fs: ErofsFS) -> list[str]:
        return fs.walk()

    def read_file(self, fs: ErofsFS, path: str) -> bytes:
        inode = fs.resolve(path)
        return fs.read_file_content(inode)


Erofs.register()
