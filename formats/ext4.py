"""ext4 filesystem container — read-only extraction for Container Browser.

Handles both on-disk layouts seen in Pixel/Tensor vendor firmware:
standard (superblock at the usual byte offset 1024, e.g. ``vendor.img``)
and the boot-pad-less variant found inside the Shannon modem image
(superblock at offset 0). ``can_decode`` and filesystem-open both probe
1024 first, then 0.

Correctness notes (these three are exactly the bugs a prior Go
implementation of this same format hit on real Pixel/Tensor images, per
this plugin's extraction notes — each is a silent-wrong-answer failure
mode, not a crash, so they're called out explicitly rather than left to be
rediscovered):

1. Block group descriptors are 32 bytes unless ``INCOMPAT_64BIT`` is set,
   in which case they're ``s_desc_size`` bytes (typically 64). Assuming
   64 unconditionally misaligns every group lookup past the first.
2. The block group count must round *up*
   (``ceil((total_blocks - first_data_block) / blocks_per_group)``); floor
   division silently drops the filesystem's last, partial group.
3. Each inode's containing block group must be recomputed per inode
   (``(ino - 1) // inodes_per_group``) — reusing one fixed group's
   descriptor (e.g. the root inode's) for every child inode resolves
   unrelated inodes for anything outside that one group.

Both extent-tree inodes (``INCOMPAT_EXTENTS`` — the vendor.img/
vendor_dlkm.img case) and classic direct/single/double/triple-indirect
block-pointer inodes are supported per-inode (not per-filesystem): the
small filesystem holding the Shannon modem image was built without the
extents feature at all, while the vendor partitions are 100% extent-based,
so both paths get exercised on real firmware.

Deliberately out of scope (raises ``NotImplementedError`` rather than
guessing): inline-data files larger than the 60 bytes that fit directly in
``i_block`` (the extended-attribute overflow case); inline-data
directories. Symlinks are not exposed as extractable entries — a symlink
has no independent content to decompile, only regular files are listed.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from binaryninja import log_error

from ..common.container_base import FilesystemContainer
from ..common.native import formats

_MAGIC_OFFSET = 0x38
_EXT4_MAGIC = 0xEF53
_ROOT_INODE = 2
_MAX_DIR_DEPTH = 256

_S_IFMT = 0xF000
_S_IFDIR = 0x4000
_S_IFREG = 0x8000

_INCOMPAT_EXTENTS = 0x40
_INCOMPAT_64BIT = 0x80

_EXT4_EXTENTS_FL = 0x00080000
_EXT4_INLINE_DATA_FL = 0x10000000

_EXTENT_HEADER_MAGIC = 0xF30A

_FILETYPE_REG = 1
_FILETYPE_DIR = 2
_FILETYPE_SYMLINK = 7


@dataclass
class _Superblock:
    base_offset: int
    block_size: int
    blocks_per_group: int
    inodes_per_group: int
    inode_size: int
    desc_size: int
    gdt_start_block: int
    block_pad: int  # byte offset of block 0 in this buffer; see Ext4FS.block_offset


@dataclass
class _Inode:
    mode: int
    size: int
    flags: int
    block_raw: bytes  # the 60-byte i_block area, raw


def _probe_superblock(data: bytes, base_offset: int) -> Optional[_Superblock]:
    if base_offset + 0x160 > len(data):
        return None
    if struct.unpack_from("<H", data, base_offset + _MAGIC_OFFSET)[0] != _EXT4_MAGIC:
        return None

    (blocks_count_lo,) = struct.unpack_from("<I", data, base_offset + 0x04)
    (first_data_block,) = struct.unpack_from("<I", data, base_offset + 0x14)
    (log_block_size,) = struct.unpack_from("<I", data, base_offset + 0x18)
    (blocks_per_group,) = struct.unpack_from("<I", data, base_offset + 0x20)
    (inodes_per_group,) = struct.unpack_from("<I", data, base_offset + 0x28)
    (rev_level,) = struct.unpack_from("<I", data, base_offset + 0x4C)

    if log_block_size > 16 or blocks_per_group == 0 or inodes_per_group == 0:
        return None
    block_size = 1024 << log_block_size

    inode_size = 128
    desc_size = 32
    blocks_count_hi = 0
    if rev_level >= 1:
        (inode_size,) = struct.unpack_from("<H", data, base_offset + 0x58)
        (feature_incompat,) = struct.unpack_from("<I", data, base_offset + 0x60)
        (raw_desc_size,) = struct.unpack_from("<H", data, base_offset + 0xFE)
        if feature_incompat & _INCOMPAT_64BIT and raw_desc_size >= 32:
            desc_size = raw_desc_size
        (blocks_count_hi,) = struct.unpack_from("<I", data, base_offset + 0x150)
        if inode_size == 0:
            inode_size = 128

    total_blocks = (blocks_count_hi << 32) | blocks_count_lo
    if total_blocks <= first_data_block:
        return None

    gdt_start_block = first_data_block + 1
    # The superblock always sits 1024 bytes into block 0, by convention,
    # regardless of block_size. When it's found at base_offset 0 instead of
    # the usual 1024, the image is missing that leading 1024-byte pad (seen
    # on the Shannon modem filesystem) — every block-number-to-byte-offset
    # conversion has to shift by the same amount or every lookup past block
    # 0 silently lands 1024 bytes into the wrong place.
    block_pad = base_offset - 1024
    return _Superblock(
        base_offset=base_offset,
        block_size=block_size,
        blocks_per_group=blocks_per_group,
        inodes_per_group=inodes_per_group,
        inode_size=inode_size,
        desc_size=desc_size,
        gdt_start_block=gdt_start_block,
        block_pad=block_pad,
    )


class Ext4FS:
    def __init__(self, data: bytes):
        self.data = data
        sb = _probe_superblock(data, 1024) or _probe_superblock(data, 0)
        if sb is None:
            raise ValueError("no ext4 superblock found at offset 1024 or 0")
        self.sb = sb

    def block_offset(self, block_num: int) -> int:
        return block_num * self.sb.block_size + self.sb.block_pad

    def read_block(self, block_num: int) -> bytes:
        return self.read_blocks(block_num, 1)

    def read_blocks(self, block_num: int, count: int) -> bytes:
        bs = self.sb.block_size
        start = self.block_offset(block_num)
        end = start + count * bs
        if block_num < 0 or count < 0 or start < 0 or end > len(self.data):
            raise ValueError(f"block range {block_num}+{count} (bytes {start}:{end}) exceeds image length {len(self.data)}")
        return self.data[start:end]

    def _inode_table_block(self, group: int) -> int:
        off = self.block_offset(self.sb.gdt_start_block) + group * self.sb.desc_size
        if off + self.sb.desc_size > len(self.data):
            raise ValueError(f"group descriptor {group} at {off} exceeds image length {len(self.data)}")
        (lo,) = struct.unpack_from("<I", self.data, off + 0x08)
        hi = 0
        if self.sb.desc_size >= 64:
            (hi,) = struct.unpack_from("<I", self.data, off + 0x28)
        return (hi << 32) | lo

    def read_inode(self, ino: int) -> _Inode:
        group = (ino - 1) // self.sb.inodes_per_group
        index = (ino - 1) % self.sb.inodes_per_group
        table_block = self._inode_table_block(group)  # recomputed per inode: see module docstring, bug #3
        off = self.block_offset(table_block) + index * self.sb.inode_size
        if off + 128 > len(self.data):
            raise ValueError(f"inode {ino} at {off} exceeds image length {len(self.data)}")

        mode, = struct.unpack_from("<H", self.data, off + 0x00)
        size_lo, = struct.unpack_from("<I", self.data, off + 0x04)
        flags, = struct.unpack_from("<I", self.data, off + 0x20)
        block_raw = self.data[off + 0x28:off + 0x28 + 60]
        size_high, = struct.unpack_from("<I", self.data, off + 0x6C)

        size = size_lo
        if mode & _S_IFMT == _S_IFREG:
            size = size_lo | (size_high << 32)

        return _Inode(mode=mode, size=size, flags=flags, block_raw=block_raw)

    def _walk_extents(self, block_bytes: bytes) -> list[tuple[int, int, int]]:
        if len(block_bytes) < 12:
            raise ValueError("extent header truncated")
        magic, entry_count, _max_entries, depth, _gen = struct.unpack_from("<HHHHI", block_bytes, 0)
        if magic != _EXTENT_HEADER_MAGIC:
            raise ValueError(f"bad extent header magic {magic:#x}")

        needed = 12 + entry_count * 12
        if needed > len(block_bytes):
            raise ValueError("extent entry table truncated")

        result: list[tuple[int, int, int]] = []
        if depth == 0:
            for i in range(entry_count):
                off = 12 + i * 12
                ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from("<IHHI", block_bytes, off)
                length = ee_len - 32768 if ee_len > 32768 else ee_len  # high bit of ee_len marks an unwritten extent
                phys = (ee_start_hi << 32) | ee_start_lo
                result.append((ee_block, phys, length))
        else:
            for i in range(entry_count):
                off = 12 + i * 12
                _ei_block, ei_leaf_lo, ei_leaf_hi, _unused = struct.unpack_from("<IIHH", block_bytes, off)
                leaf = (ei_leaf_hi << 32) | ei_leaf_lo
                result.extend(self._walk_extents(self.read_block(leaf)))
        return result

    def _indirect_extents(self, inode: _Inode) -> list[tuple[int, int, int]]:
        ptrs = struct.unpack_from("<15I", inode.block_raw, 0)
        ppb = self.sb.block_size // 4
        result: list[tuple[int, int, int]] = []
        counter = [0]

        def emit(phys: int) -> None:
            if phys != 0:
                result.append((counter[0], phys, 1))
            counter[0] += 1

        def walk(block_num: int, depth: int) -> None:
            if depth == 0:
                emit(block_num)
                return
            if block_num == 0:
                counter[0] += ppb ** depth
                return
            block = self.read_block(block_num)
            for i in range(ppb):
                (child,) = struct.unpack_from("<I", block, i * 4)
                walk(child, depth - 1)

        for p in ptrs[0:12]:
            emit(p)
        walk(ptrs[12], 1)
        walk(ptrs[13], 2)
        walk(ptrs[14], 3)
        return result

    def _extents_for(self, inode: _Inode) -> list[tuple[int, int, int]]:
        if inode.flags & _EXT4_EXTENTS_FL:
            extents = self._walk_extents(inode.block_raw)
        else:
            extents = self._indirect_extents(inode)
        extents.sort(key=lambda e: e[0])
        return extents

    def read_file_content(self, inode: _Inode) -> bytes:
        if inode.flags & _EXT4_INLINE_DATA_FL:
            if inode.size > len(inode.block_raw):
                raise NotImplementedError("inline data larger than i_block (xattr overflow) is not supported")
            return inode.block_raw[:inode.size]

        extents = self._extents_for(inode)
        buf = bytearray(inode.size)
        bs = self.sb.block_size
        for logical, phys, length in extents:
            start = logical * bs
            if start >= inode.size:
                continue
            chunk = self.read_blocks(phys, length)
            end = min(start + len(chunk), inode.size)
            buf[start:end] = chunk[:end - start]
        return bytes(buf)

    def _iter_dirents(self, inode: _Inode) -> list[tuple[str, int, int]]:
        entries: list[tuple[str, int, int]] = []
        bs = self.sb.block_size
        for logical, phys, length in self._extents_for(inode):
            for b in range(length):
                block = self.read_block(phys + b)
                pos = 0
                while pos + 8 <= bs:
                    rec_ino, rec_len, name_len, file_type = struct.unpack_from("<IHBB", block, pos)
                    if rec_len < 8 or pos + rec_len > bs:
                        break
                    if rec_ino != 0 and name_len > 0:
                        name = block[pos + 8:pos + 8 + name_len].decode("utf-8", "replace")
                        if name not in (".", ".."):
                            entries.append((name, rec_ino, file_type))
                    pos += rec_len
        return entries

    def walk(self) -> list[str]:
        paths: list[str] = []
        self._walk_dir(_ROOT_INODE, "", paths, visited=set())
        return paths

    def _walk_dir(self, ino: int, prefix: str, out: list[str], visited: set[int], depth: int = 0) -> None:
        if ino in visited or depth > _MAX_DIR_DEPTH:
            return
        visited.add(ino)

        inode = self.read_inode(ino)
        if inode.mode & _S_IFMT != _S_IFDIR:
            return

        for name, child_ino, file_type in self._iter_dirents(inode):
            child_path = f"{prefix}/{name}" if prefix else name
            if file_type == _FILETYPE_SYMLINK:
                continue
            if file_type == 0:
                # INCOMPAT_FILETYPE not set (or an unrecognized value) — fall back to the inode's own mode.
                try:
                    child_mode = self.read_inode(child_ino).mode & _S_IFMT
                except ValueError:
                    continue
                if child_mode == _S_IFDIR:
                    self._walk_dir(child_ino, child_path, out, visited, depth + 1)
                elif child_mode == _S_IFREG:
                    out.append(child_path)
                continue

            if file_type == _FILETYPE_DIR:
                self._walk_dir(child_ino, child_path, out, visited, depth + 1)
            elif file_type == _FILETYPE_REG:
                out.append(child_path)

    def resolve(self, path: str) -> _Inode:
        ino = _ROOT_INODE
        for part in path.split("/"):
            if not part:
                continue
            inode = self.read_inode(ino)
            if inode.mode & _S_IFMT != _S_IFDIR:
                raise ValueError(f"'{part}' is not a directory in path '{path}'")
            match = next((c_ino for name, c_ino, _ft in self._iter_dirents(inode) if name == part), None)
            if match is None:
                raise ValueError(f"'{part}' not found in path '{path}'")
            ino = match
        return self.read_inode(ino)


class Ext4(FilesystemContainer):
    name = "Ext4"
    long_name = "ext4 filesystem"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(0, 2048)
        except Exception:
            log_error("Ext4: failed to read input for signature check")
            return False
        return _probe_superblock(head, 1024) is not None or _probe_superblock(head, 0) is not None

    def open_filesystem(self, data: bytes) -> Ext4FS:
        return Ext4FS(data)

    def list_paths(self, fs: Ext4FS) -> list[str]:
        return fs.walk()

    def read_file(self, fs: Ext4FS, path: str) -> bytes:
        inode = fs.resolve(path)
        return fs.read_file_content(inode)


if not any(info["id"] == "ext4" for info in formats()):
    Ext4.register()
