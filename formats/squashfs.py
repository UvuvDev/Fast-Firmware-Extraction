"""SquashFS — a compressed, read-only Linux filesystem used almost
universally for router/IoT/embedded root filesystems (found here as the
`rootfs` volume inside a UBI image, see `ubi.py`).

Scoped to **SquashFS 4.0 with XZ compression** (`compression == 4` in the
superblock) — the only variant validated against a real sample so far
(the router firmware this plugin was built against). Other compression
IDs (gzip/LZO/LZ4/ZSTD) raise `NotImplementedError` rather than silently
producing wrong bytes; adding one is a small, contained change (extend
`_decompress`'s dispatch) once a real sample using it shows up. Pre-4.0
layouts aren't handled either.

Every struct and offset convention below — including two easy-to-get-wrong
quirks — was verified against the real sample, not taken on faith from a
single source (this format has no single canonical public spec the way
FBPACK/DTBO do; the layout is documented consistently across several
independent, neutral technical write-ups, cross-checked here against the
real squashfs image byte-for-byte the same way this project checks
contiguity on offset-table formats):

1. A directory inode's `file_size` field is the real directory-listing
   byte length **plus 3** — reading exactly `file_size` bytes runs 3 bytes
   past the actual data (confirmed: doing so read exactly 3 bytes past
   the end of the real metadata block).
2. A directory entry's inode-number field is a **signed** 16-bit delta
   from its containing header's base inode number, not an absolute value
   — the header changes every so often within a large listing, which is
   why a single directory's listing can contain more than one
   header+entries group.

Symlinks and device/fifo/socket special files are skipped from
listings — nothing to decompile independently, same policy as every
other filesystem format in this plugin.
"""

from __future__ import annotations

import lzma
import struct
from dataclasses import dataclass

from ..common.container_base import FilesystemContainer

MAGIC = b"hsqs"
_SUPERBLOCK_FORMAT = "<4sIIIIHHHHHHQQQQQQQQ"
_SUPERBLOCK_FIELDS = (
    "magic", "inodes", "mkfs_time", "block_size", "fragments",
    "compression", "block_log", "flags", "no_ids", "s_major", "s_minor",
    "root_inode", "bytes_used", "id_table_start", "xattr_id_table_start",
    "inode_table_start", "directory_table_start", "fragment_table_start",
    "lookup_table_start",
)
_NO_FRAGMENT = 0xFFFFFFFF
_FRAGMENT_ENTRY_SIZE = 16
_METADATA_BLOCK_MAX = 8192
_DIR_SIZE_OVERHEAD = 3  # a directory inode's file_size counts 3 bytes that aren't really there

_COMPRESSION_XZ = 4

_INODE_BASIC_DIR = 1
_INODE_BASIC_FILE = 2
_INODE_EXTENDED_DIR = 8
_INODE_EXTENDED_FILE = 9

_FT_SYMLINK = 3  # squashfs dirent type numbering matches inode type numbering for basic types

_MAX_DIR_DEPTH = 256


def _decompress(compression: int, chunk: bytes) -> bytes:
    if compression != _COMPRESSION_XZ:
        raise NotImplementedError(f"SquashFS compression id {compression} is not supported (only XZ/4)")
    return lzma.decompress(chunk, format=lzma.FORMAT_XZ)


@dataclass
class _Superblock:
    inodes: int
    block_size: int
    compression: int
    root_block: int
    root_offset: int
    inode_table_start: int
    directory_table_start: int
    fragment_table_start: int


@dataclass
class _Inode:
    inode_type: int
    mode: int
    inode_block: int = 0  # metadata-block offset (within inode table) this inode itself was read from
    dir_offset: int = 0
    dir_size: int = 0
    file_start: int = 0
    file_fragment: int = _NO_FRAGMENT
    file_frag_offset: int = 0
    file_size: int = 0
    block_list_block: int = 0  # _MetaCursor resume point (block_off, pos) for the block list
    block_list_pos: int = 0


class _MetaCursor:
    """Reads a fixed number of bytes at a time from a metadata-block
    stream, transparently advancing to the next block once the current
    one is exhausted. Used for directory listings, which can span more
    than one metadata block."""

    def __init__(self, fs: "SquashFS", base: int, block_off: int, start_pos: int):
        self._fs = fs
        self._base = base
        self._block_off = block_off
        self._content = fs._read_metadata_block(base, block_off)
        self._pos = start_pos

    def read(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            available = len(self._content) - self._pos
            if available <= 0:
                self._block_off += self._fs._metadata_block_disk_size(self._base, self._block_off)
                self._content = self._fs._read_metadata_block(self._base, self._block_off)
                self._pos = 0
                available = len(self._content)
            take = min(available, n - len(out))
            out += self._content[self._pos:self._pos + take]
            self._pos += take
        return bytes(out)

    def tell(self) -> tuple[int, int]:
        """Current (block_off, pos-within-block) — resumable via a new _MetaCursor."""
        return self._block_off, self._pos


def _parse_superblock(data: bytes) -> _Superblock:
    size = struct.calcsize(_SUPERBLOCK_FORMAT)
    if len(data) < size:
        raise ValueError("file too short for a SquashFS superblock")
    values = dict(zip(_SUPERBLOCK_FIELDS, struct.unpack_from(_SUPERBLOCK_FORMAT, data, 0)))
    if values["magic"] != MAGIC:
        raise ValueError("bad SquashFS magic")
    if values["s_major"] != 4:
        raise ValueError(f"unsupported SquashFS major version {values['s_major']} (only 4.x)")
    return _Superblock(
        inodes=values["inodes"], block_size=values["block_size"], compression=values["compression"],
        root_block=(values["root_inode"] >> 16) & 0xFFFFFFFF, root_offset=values["root_inode"] & 0xFFFF,
        inode_table_start=values["inode_table_start"], directory_table_start=values["directory_table_start"],
        fragment_table_start=values["fragment_table_start"],
    )


class SquashFS:
    def __init__(self, data: bytes):
        self.data = data
        self.sb = _parse_superblock(data)
        self._metadata_cache: dict[tuple[int, int], bytes] = {}

    def _read_metadata_block(self, base: int, block_off: int) -> bytes:
        key = (base, block_off)
        cached = self._metadata_cache.get(key)
        if cached is not None:
            return cached

        pos = base + block_off
        if pos + 2 > len(self.data):
            raise ValueError(f"metadata block header at {pos} exceeds image length")
        header = struct.unpack_from("<H", self.data, pos)[0]
        compressed = not (header & 0x8000)
        length = header & 0x7FFF
        chunk = self.data[pos + 2:pos + 2 + length]
        if len(chunk) != length:
            raise ValueError(f"truncated metadata block at {pos}")
        content = _decompress(self.sb.compression, chunk) if compressed else chunk
        self._metadata_cache[key] = content
        return content

    def _metadata_block_disk_size(self, base: int, block_off: int) -> int:
        pos = base + block_off
        header = struct.unpack_from("<H", self.data, pos)[0]
        return 2 + (header & 0x7FFF)

    def _read_data_block(self, offset: int, size_field: int) -> bytes:
        compressed = not (size_field & 0x1000000)
        length = size_field & 0xFFFFFF
        if offset < 0 or offset + length > len(self.data):
            raise ValueError(f"data block at {offset}+{length} exceeds image length")
        chunk = self.data[offset:offset + length]
        return _decompress(self.sb.compression, chunk) if compressed else chunk

    def read_inode(self, block_off: int, offset: int) -> _Inode:
        # An inode record isn't guaranteed to fit within one metadata
        # block any more than a directory listing is — read through the
        # same spanning cursor rather than indexing into one block's
        # decompressed content directly.
        cursor = _MetaCursor(self, self.sb.inode_table_start, block_off, offset)
        inode_type, mode = struct.unpack_from("<HH", cursor.read(16), 0)

        if inode_type == _INODE_BASIC_DIR:
            start_block, _nlink, file_size, dir_offset, _parent = struct.unpack_from("<IIHHI", cursor.read(16), 0)
            return _Inode(inode_type=inode_type, mode=mode, inode_block=start_block, dir_offset=dir_offset, dir_size=file_size)
        if inode_type == _INODE_EXTENDED_DIR:
            _nlink, file_size, start_block, _parent = struct.unpack_from("<IIII", cursor.read(16), 0)
            _i_count, dir_offset = struct.unpack_from("<HH", cursor.read(8), 0)
            return _Inode(inode_type=inode_type, mode=mode, inode_block=start_block, dir_offset=dir_offset, dir_size=file_size)

        if inode_type == _INODE_BASIC_FILE:
            start_block, fragment, frag_offset, file_size = struct.unpack_from("<IIII", cursor.read(16), 0)
            block, pos = cursor.tell()
            return _Inode(
                inode_type=inode_type, mode=mode, file_start=start_block,
                file_fragment=fragment, file_frag_offset=frag_offset, file_size=file_size,
                block_list_block=block, block_list_pos=pos,
            )
        if inode_type == _INODE_EXTENDED_FILE:
            start_block, file_size = struct.unpack_from("<QQ", cursor.read(16), 0)
            _sparse, _nlink, fragment, frag_offset = struct.unpack_from("<QII", cursor.read(16), 0)
            block, pos = cursor.tell()
            return _Inode(
                inode_type=inode_type, mode=mode, file_start=start_block,
                file_fragment=fragment, file_frag_offset=frag_offset, file_size=file_size,
                block_list_block=block, block_list_pos=pos,
            )

        return _Inode(inode_type=inode_type, mode=mode)  # symlink or special file — not read further

    def _fragment_entry(self, fragment_index: int) -> tuple[int, int]:
        entries_per_block = _METADATA_BLOCK_MAX // _FRAGMENT_ENTRY_SIZE
        block_index, entry_in_block = divmod(fragment_index, entries_per_block)
        table_slot = self.sb.fragment_table_start + block_index * 8
        meta_block_pos = struct.unpack_from("<Q", self.data, table_slot)[0]
        content = self._read_metadata_block(0, meta_block_pos)  # the pointer is an absolute file offset
        start_block, size_field = struct.unpack_from("<QI", content, entry_in_block * _FRAGMENT_ENTRY_SIZE)
        return start_block, size_field

    def read_file_content(self, inode: _Inode) -> bytes:
        block_size = self.sb.block_size
        uses_fragment = inode.file_fragment != _NO_FRAGMENT
        full_blocks = (inode.file_size // block_size) if uses_fragment else -(-inode.file_size // block_size)

        cursor = _MetaCursor(self, self.sb.inode_table_start, inode.block_list_block, inode.block_list_pos)
        buf = bytearray()
        pos = inode.file_start
        for i in range(full_blocks):
            size_field = struct.unpack_from("<I", cursor.read(4), 0)[0]
            if size_field == 0:
                buf += b"\x00" * min(block_size, inode.file_size - len(buf))
            else:
                buf += self._read_data_block(pos, size_field)
                pos += size_field & 0xFFFFFF

        if uses_fragment:
            frag_start, frag_size_field = self._fragment_entry(inode.file_fragment)
            frag_block = self._read_data_block(frag_start, frag_size_field)
            tail_len = inode.file_size - len(buf)
            buf += frag_block[inode.file_frag_offset:inode.file_frag_offset + tail_len]

        return bytes(buf[:inode.file_size])

    def _iter_dirents(self, inode: _Inode) -> list[tuple[str, int, int, int]]:
        """Returns (name, inode_block, inode_offset, dirent_type) per entry.

        A directory's listing is a byte-stream that can span more than one
        metadata block once it's large enough (unlike a single inode
        record, which mksquashfs guarantees fits within one) — read
        through `_MetaCursor` rather than assuming it fits in one block.
        """
        cursor = _MetaCursor(self, self.sb.directory_table_start, inode.inode_block, inode.dir_offset)
        remaining = inode.dir_size - _DIR_SIZE_OVERHEAD
        entries = []
        while remaining > 0:
            count, hdr_block, _hdr_inode_num = struct.unpack_from("<III", cursor.read(12), 0)
            remaining -= 12
            for _ in range(count + 1):
                d_offset, _d_inode_delta, d_type, d_name_size = struct.unpack_from("<HhHH", cursor.read(8), 0)
                remaining -= 8
                name = cursor.read(d_name_size + 1).decode("utf-8", "replace")
                remaining -= d_name_size + 1
                entries.append((name, hdr_block, d_offset, d_type))
        return entries

    def root_inode(self) -> _Inode:
        return self.read_inode(self.sb.root_block, self.sb.root_offset)

    def walk(self) -> list[str]:
        paths: list[str] = []
        self._walk_dir(self.root_inode(), "", paths, depth=0)
        return paths

    def _walk_dir(self, inode: _Inode, prefix: str, out: list[str], depth: int) -> None:
        if depth > _MAX_DIR_DEPTH:
            return
        for name, blk, off, dtype in self._iter_dirents(inode):
            child_path = f"{prefix}/{name}" if prefix else name
            if dtype == _INODE_BASIC_DIR or dtype == _INODE_EXTENDED_DIR:
                child_inode = self.read_inode(blk, off)
                self._walk_dir(child_inode, child_path, out, depth + 1)
            elif dtype == _INODE_BASIC_FILE or dtype == _INODE_EXTENDED_FILE:
                out.append(child_path)
            # symlinks/specials (any other dirent type) intentionally skipped

    def resolve(self, path: str) -> _Inode:
        inode = self.root_inode()
        for part in path.split("/"):
            if not part:
                continue
            match = next(((blk, off) for name, blk, off, _t in self._iter_dirents(inode) if name == part), None)
            if match is None:
                raise ValueError(f"'{part}' not found in path '{path}'")
            inode = self.read_inode(*match)
        return inode


class Squashfs(FilesystemContainer):
    name = "Squashfs"
    long_name = "SquashFS filesystem"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(0, 4)
        except Exception:
            return False
        return bytes(head) == MAGIC

    def open_filesystem(self, data: bytes) -> SquashFS:
        return SquashFS(data)

    def list_paths(self, fs: SquashFS) -> list[str]:
        return fs.walk()

    def read_file(self, fs: SquashFS, path: str) -> bytes:
        return fs.read_file_content(fs.resolve(path))


Squashfs.register()
