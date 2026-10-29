"""F2FS (Flash-Friendly File System) — read-only extraction for Container
Browser. F2FS is Samsung's log-structured flash filesystem; it ships as the
`userdata`/`metadata` (and sometimes other) partition format on a large
fraction of Android phones, including some Pixel models.

Struct layouts and algorithms below were verified against the **Linux
kernel mainline source** (all GPL-2.0), fetched from
`torvalds/linux` on GitHub during development:

  - `include/linux/f2fs_fs.h` — on-disk structs (`f2fs_super_block`,
    `f2fs_checkpoint`, `f2fs_nat_entry`, `f2fs_node`/`f2fs_inode`,
    `f2fs_dentry_block`/`f2fs_dir_entry`), the `F2FS_SUPER_MAGIC` value,
    `NULL_ADDR`/`NEW_ADDR`, `DEF_ADDRS_PER_INODE`/`OFFSET_OF_END_OF_I_EXT`/
    `SIZE_OF_I_NID`/`DEF_INLINE_RESERVED_SIZE`, `MAX_INLINE_DATA`/
    `NR_INLINE_DENTRY`/`INLINE_DENTRY_BITMAP_SIZE`, `GET_DENTRY_SLOTS`,
    the `F2FS_INLINE_*`/`F2FS_EXTRA_ATTR` bit values, and
    `CP_*` checkpoint flags.
  - `fs/f2fs/node.h` — `current_nat_addr()` (the NAT double-buffering
    formula) and `NAT_BLOCK_OFFSET()`.
  - `fs/f2fs/f2fs.h` — `BLKS_PER_SEG()`.
  - `fs/f2fs/inode.c` — confirms storage of `i_inline_xattr_size`; the
    v6.12 on-disk header documents its four-byte slot unit.

Cross-checked against two independent, separately-licensed
reimplementations for the handful of facts the kernel excerpts above
didn't directly show (both also GPL-2.0, read for facts only, not
vendored or copied):

  - `jaegeuk/f2fs-tools` (`lib/libf2fs.c`) — confirmed `f2fs_test_bit()`'s
    exact bit order: MSB-first within each byte (`mask = 1 << (7 - (nr &
    7))`), used for the NAT version bitmap. Directory bitmaps instead use
    LSB-first order, confirmed by Linux v6.12 fs/f2fs/dir.c.
  - `cgsecurity/testdisk` (`src/f2fs_fs.h`) and the Linux `uapi/linux/
    magic.h` — both independently confirm `F2FS_SUPER_MAGIC = 0xF2F52010`.

**No real F2FS image was available to validate against.** `mkfs.f2fs`
is not installed in this environment, and this task's sandbox has no
package-manager/root access to install it (`f2fs-tools` has an apt
candidate but installing it requires `sudo`, which is disabled here);
Homebrew was likewise unavailable. So unlike `ext4.py`/`erofs.py` (both
validated against real Pixel/Tensor partitions), the fixtures under
`tests/fixtures/f2fs*/` are **entirely hand-built from the spec above,
not cross-checked against a real mkfs.f2fs image byte-for-byte.** Treat
this implementation as "matches the documented on-disk format as best as
could be verified from source," not as "confirmed against hardware."

Deliberately out of scope (raises ``NotImplementedError`` rather than
guessing):

1. **Compressed inodes** (``i_flags & FS_COMPR_FL``). F2FS supports
   per-file LZO/LZ4/zstd/LZMA compression and none of those have a
   stdlib decoder in Python — attempting to "decompress" would either
   crash or (worse) silently return garbage, so this is a hard,
   deliberate limitation, not an oversight.
2. **Inline extended attributes** (``i_inline & F2FS_INLINE_XATTR``).
   They reserve trailing direct-address slots; the field's unit is four
   bytes per slot (Linux v6.12 f2fs_fs.h). This reader's supported subset
   excludes these layouts, so such inodes raise ``NotImplementedError``.
   Real Android images commonly use inline xattrs for SELinux labels and
   will therefore be rejected rather than misread.
3. **Checkpoint payload overflow** (superblock `cp_payload != 0`). When
   the SIT/NAT version bitmaps are too large to fit in the checkpoint's
   own block, F2FS spills them into `cp_payload` extra blocks with a
   layout this task's research window didn't turn up a verbatim,
   confirmed source for. Only `cp_payload == 0` (bitmaps fit inline
   after the checkpoint's fixed fields) is supported; anything else
   raises `NotImplementedError`.
4. **NAT/SIT journal** (the small in-checkpoint cache of very recent,
   not-yet-flushed NAT/SIT updates). This extractor reads only the
   static NAT area. Journal entries may override those entries even in
   a stable checkpoint, so this is a limited static-NAT view rather than
   a complete recovery implementation. It has only synthetic coverage;
   real-device compatibility is not established.
5. **The SIT (Segment Information Table) itself is never parsed.** It
   tracks segment/block *validity* for the allocator and garbage
   collector; a read-only extractor that only follows already-committed
   NAT → node → data pointers never needs it.
6. Symlinks are not exposed as extractable entries (nothing to
   decompile independently), matching every other filesystem format in
   this plugin.

Two subtleties worth flagging explicitly, because both are exactly the
"silent wrong answer, not a crash" failure mode this plugin's other
filesystem formats warn about:

- **NAT blocks are double-buffered.** Each logical NAT block has two
  candidate physical locations (a fixed segment-pair scheme — see
  `_current_nat_addr`, ported directly from `current_nat_addr()` in
  `fs/f2fs/node.h`); a per-block bit in the checkpoint's NAT version
  bitmap says which copy is current. Always reading the "old" copy
  (ignoring the bitmap) would silently resolve roughly half of all node
  IDs to a stale, wrong physical block on any real, non-freshly-minted
  filesystem — it would still return *bytes*, just not the current ones.
- **Dentry bitmap bits are per 8-byte name-slot, not per directory
  entry.** A dentry whose name is longer than `F2FS_SLOT_LEN` (8 bytes —
  i.e. almost every real filename) consumes `GET_DENTRY_SLOTS(name_len)`
  consecutive bitmap bits and filename slots, not one. Advancing the
  scan by one slot per entry instead of by its actual slot count would
  silently misparse every directory entry after the first one whose name
  exceeds 8 bytes.

Only plain files and directories are handled; direct block addressing
(923 slots in the inode itself) and both levels of indirection through
node blocks (the two "direct node" pointers, the two "indirect node"
pointers, and the one "double indirect node" pointer, each ported
generically via one recursive walk — see `_walk_data`) are implemented,
matching this task's "direct + at least single-indirect" minimum. The
synthetic fixtures exercise direct multi-block and direct/indirect node tiers.
The native port also tests double-indirect subtree traversal without allocating
files beyond the common 512 MiB extraction limit. Fixtures remain synthetic;
no formatter-generated or hardware image has been validated.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from binaryninja import log_error

from ..common.container_base import FilesystemContainer
from ..common.native import formats

# --- Superblock -------------------------------------------------------

_F2FS_SUPER_MAGIC = 0xF2F52010
_SB_OFFSET_PRIMARY = 1024  # F2FS_SUPER_OFFSET

_S_IFMT = 0xF000
_S_IFDIR = 0x4000
_S_IFREG = 0x8000

# i_inline bit flags (include/linux/f2fs_fs.h)
_F2FS_INLINE_XATTR = 0x01
_F2FS_INLINE_DATA = 0x02
_F2FS_INLINE_DENTRY = 0x04
_F2FS_EXTRA_ATTR = 0x20

_FS_COMPR_FL = 0x00000004  # i_flags bit (generic Linux FS_COMPR_FL, reused by F2FS)

_NULL_ADDR = 0x0
_NEW_ADDR = 0xFFFFFFFF

_NODE_FOOTER_SIZE = 24  # nid(4) + ino(4) + flag(4) + cp_ver(8) + next_blkaddr(4)
_OFFSET_END_I_EXT = 360  # OFFSET_OF_END_OF_I_EXT: byte offset right after f2fs_inode.i_ext
_SIZE_I_NID = 20  # SIZE_OF_I_NID: DEF_NIDS_PER_INODE(5) * sizeof(__le32)
_DEF_INLINE_RESERVED_SIZE = 1  # word

_SIZE_OF_DIR_ENTRY = 11  # hash_code(4) + ino(4) + name_len(2) + file_type(1)
_F2FS_SLOT_LEN = 8

_FT_UNKNOWN = 0
_FT_REG_FILE = 1
_FT_DIR = 2
_FT_SYMLINK = 7

_MAX_DIR_DEPTH = 256


def _addrs_per_block(block_size: int) -> int:
    """DEF_ADDRS_PER_BLOCK == NIDS_PER_BLOCK: pointer slots in a direct_node
    or indirect_node block (they're the same size, both derived the same
    way from the shared node_footer)."""
    return (block_size - _NODE_FOOTER_SIZE) // 4


def _def_addrs_per_inode(block_size: int) -> int:
    """DEF_ADDRS_PER_INODE: direct block-address slots inside the inode's
    own node block, before any extra-attribute/inline-xattr shrinkage."""
    return (block_size - _OFFSET_END_I_EXT - _SIZE_I_NID - _NODE_FOOTER_SIZE) // 4


def _test_bit(bitmap: bytes, nr: int) -> bool:
    """NAT version bit: MSB-first (directory entries use LSB-first)."""
    byte_idx = nr >> 3
    if byte_idx < 0 or byte_idx >= len(bitmap):
        return False
    return bool(bitmap[byte_idx] & (1 << (7 - (nr & 7))))


@dataclass
class _Superblock:
    block_size: int
    blocks_per_seg: int
    cp_blkaddr: int
    segment_count_ckpt: int
    nat_blkaddr: int
    root_ino: int
    cp_payload: int


def _probe_superblock(data: bytes, base_offset: int) -> Optional[_Superblock]:
    # Fields used here, with their byte offsets from base_offset (computed
    # by hand-tallying every preceding field's declared size in
    # include/linux/f2fs_fs.h's struct f2fs_super_block — see module
    # docstring for the source): magic@0, log_blocksize@16,
    # log_blocks_per_seg@20, segment_count_ckpt@52, cp_blkaddr@76,
    # nat_blkaddr@84, root_ino@96, cp_payload@1664.
    if base_offset < 0 or base_offset + 1668 > len(data):
        return None
    (magic,) = struct.unpack_from("<I", data, base_offset + 0)
    if magic != _F2FS_SUPER_MAGIC:
        return None

    (log_blocksize,) = struct.unpack_from("<I", data, base_offset + 16)
    (log_blocks_per_seg,) = struct.unpack_from("<I", data, base_offset + 20)
    (segment_count_ckpt,) = struct.unpack_from("<I", data, base_offset + 52)
    (cp_blkaddr,) = struct.unpack_from("<I", data, base_offset + 76)
    (nat_blkaddr,) = struct.unpack_from("<I", data, base_offset + 84)
    (root_ino,) = struct.unpack_from("<I", data, base_offset + 96)
    (cp_payload,) = struct.unpack_from("<I", data, base_offset + 1664)

    if log_blocksize > 20 or log_blocks_per_seg > 20:
        return None
    block_size = 1 << log_blocksize
    blocks_per_seg = 1 << log_blocks_per_seg
    if segment_count_ckpt == 0 or blocks_per_seg == 0:
        return None

    return _Superblock(
        block_size=block_size,
        blocks_per_seg=blocks_per_seg,
        cp_blkaddr=cp_blkaddr,
        segment_count_ckpt=segment_count_ckpt,
        nat_blkaddr=nat_blkaddr,
        root_ino=root_ino,
        cp_payload=cp_payload,
    )


@dataclass
class _Inode:
    nid: int
    mode: int
    size: int
    direct_addrs: list  # direct data-block addresses stored in the inode itself (empty if inline)
    node_nids: list  # the 5 i_nid[] slots: [dir_node1, dir_node2, ind_node1, ind_node2, dind_node]
    inline_payload: Optional[bytes] = None  # raw inline-data/inline-dentry bytes, or None


class F2fsFS:
    def __init__(self, data: bytes):
        self.data = data
        sb = _probe_superblock(data, _SB_OFFSET_PRIMARY)
        if sb is None:
            # Second copy lives one block after the first, at the same
            # 1024-byte in-block offset — but without a valid first copy
            # we don't yet know the real block size, so fall back to the
            # universal default (4096, i.e. PAGE_SIZE on every real
            # Android/Pixel target) to locate it.
            sb = _probe_superblock(data, _SB_OFFSET_PRIMARY + 4096)
        if sb is None:
            raise ValueError("no F2FS superblock found at offset 1024 or 5120")
        self.sb = sb
        self.nat_bitmap = b""
        self._load_checkpoint()

    # -- raw block access -------------------------------------------------

    def read_block(self, block_num: int) -> bytes:
        bs = self.sb.block_size
        start = block_num * bs
        end = start + bs
        if block_num < 0 or start < 0 or end > len(self.data):
            raise ValueError(f"block {block_num} (bytes {start}:{end}) exceeds image length {len(self.data)}")
        return self.data[start:end]

    # -- checkpoint ---------------------------------------------------------

    def _load_checkpoint(self) -> None:
        sb = self.sb
        pack_blocks = (sb.segment_count_ckpt * sb.blocks_per_seg) // 2
        if pack_blocks <= 0:
            raise ValueError("F2FS checkpoint area is empty (segment_count_ckpt too small)")

        candidates = []
        for pack_index in (0, 1):
            start = sb.cp_blkaddr + pack_index * pack_blocks
            try:
                header = self.read_block(start)
            except ValueError:
                continue
            (ver_header,) = struct.unpack_from("<Q", header, 0)
            (total_blocks,) = struct.unpack_from("<I", header, 136)  # cp_pack_total_block_count
            if total_blocks <= 0 or total_blocks > pack_blocks:
                continue
            try:
                footer = self.read_block(start + total_blocks - 1)
            except ValueError:
                continue
            (ver_footer,) = struct.unpack_from("<Q", footer, 0)
            # A valid pack has matching header/footer checkpoint_ver (the
            # standard f2fs crash-consistency check: a torn write leaves
            # the two out of sync). Between two valid packs, the higher
            # version is current. (No 64-bit wraparound handling — not a
            # realistic concern for any image this plugin will see.)
            if ver_header == ver_footer:
                candidates.append((ver_header, header))

        if not candidates:
            raise ValueError("no valid F2FS checkpoint pack found (header/footer checkpoint_ver mismatch in both packs)")
        candidates.sort(key=lambda c: c[0])
        _, best_header = candidates[-1]

        if sb.cp_payload != 0:
            raise NotImplementedError(
                "F2FS images whose checkpoint bitmaps overflow into cp_payload blocks are not supported"
            )

        (sit_bm_size,) = struct.unpack_from("<I", best_header, 156)  # sit_ver_bitmap_bytesize
        (nat_bm_size,) = struct.unpack_from("<I", best_header, 160)  # nat_ver_bitmap_bytesize
        bitmap_off = 192  # offset of the flexible sit_nat_version_bitmap[] array
        end = bitmap_off + sit_bm_size + nat_bm_size
        if sit_bm_size < 0 or nat_bm_size < 0 or end > len(best_header):
            raise ValueError("F2FS checkpoint SIT/NAT bitmap sizes exceed the checkpoint block")
        # Layout assumed (cp_payload == 0 only, see module docstring):
        # [sit bitmap][nat bitmap], matching the struct's own field order.
        self.nat_bitmap = best_header[bitmap_off + sit_bm_size:end]

    # -- NAT ------------------------------------------------------------

    def _current_nat_addr(self, block_off: int) -> int:
        """Ported from current_nat_addr() in fs/f2fs/node.h: NAT blocks are
        stored in pairs of segments (an "old" and a "new" copy of each
        logical NAT block), and the checkpoint's NAT version bitmap says
        which copy is current for a given logical NAT block index."""
        mask = self.sb.blocks_per_seg - 1
        addr = self.sb.nat_blkaddr + (block_off << 1) - (block_off & mask)
        if _test_bit(self.nat_bitmap, block_off):
            addr += self.sb.blocks_per_seg
        return addr

    def _nat_lookup(self, nid: int) -> int:
        entries_per_block = self.sb.block_size // 9  # sizeof(f2fs_nat_entry), packed
        block_off = nid // entries_per_block
        index = nid % entries_per_block
        block = self.read_block(self._current_nat_addr(block_off))
        off = index * 9
        if off + 9 > len(block):
            raise ValueError(f"NAT entry for nid {nid} exceeds NAT block length")
        _version, _ino, block_addr = struct.unpack_from("<BII", block, off)
        return block_addr

    def read_node_block(self, nid: int) -> bytes:
        addr = self._nat_lookup(nid)
        if addr in (_NULL_ADDR, _NEW_ADDR):
            raise ValueError(f"nid {nid} has no valid physical node block (NAT block_addr={addr:#x})")
        return self.read_block(addr)

    # -- inode ------------------------------------------------------------

    def read_inode(self, nid: int) -> _Inode:
        block = self.read_node_block(nid)
        bs = self.sb.block_size

        (mode,) = struct.unpack_from("<H", block, 0)
        (i_inline,) = struct.unpack_from("<B", block, 3)
        (size,) = struct.unpack_from("<Q", block, 16)
        (i_flags,) = struct.unpack_from("<I", block, 80)

        if i_flags & _FS_COMPR_FL:
            raise NotImplementedError(f"F2FS nid {nid}: compressed inodes are not supported")
        if i_inline & _F2FS_INLINE_XATTR:
            raise NotImplementedError(
                f"F2FS nid {nid}: inline xattr (F2FS_INLINE_XATTR) is not supported — see module docstring"
            )

        def_addrs = _def_addrs_per_inode(bs)
        extra_words = 0
        if i_inline & _F2FS_EXTRA_ATTR:
            (extra_isize,) = struct.unpack_from("<H", block, _OFFSET_END_I_EXT)
            if extra_isize % 4 != 0:
                raise ValueError(f"F2FS nid {nid}: i_extra_isize {extra_isize} is not word-aligned")
            extra_words = extra_isize // 4

        cur_addrs = def_addrs - extra_words
        if cur_addrs < 0:
            raise ValueError(f"F2FS nid {nid}: i_extra_isize leaves no room for addresses")

        addr_region_start = _OFFSET_END_I_EXT + extra_words * 4
        nid_region_start = _OFFSET_END_I_EXT + def_addrs * 4  # fixed: right after the (fixed-size) union
        node_nids = list(struct.unpack_from("<5I", block, nid_region_start))

        inline_payload = None
        direct_addrs: list = []
        if i_inline & (_F2FS_INLINE_DATA | _F2FS_INLINE_DENTRY):
            inline_off = addr_region_start + 4 * _DEF_INLINE_RESERVED_SIZE
            inline_cap = 4 * (cur_addrs - _DEF_INLINE_RESERVED_SIZE)
            if inline_cap < 0 or inline_off + inline_cap > nid_region_start:
                raise ValueError(f"F2FS nid {nid}: inline data/dentry region computed out of bounds")
            inline_payload = block[inline_off:inline_off + inline_cap]
        elif cur_addrs > 0:
            direct_addrs = list(struct.unpack_from(f"<{cur_addrs}I", block, addr_region_start))

        return _Inode(nid=nid, mode=mode, size=size, direct_addrs=direct_addrs, node_nids=node_nids, inline_payload=inline_payload)

    # -- data-block resolution (direct + 2-level node indirection) --------

    def _walk_data(self, inode: _Inode) -> list:
        """Returns [(logical_block_index, physical_block_addr), ...] for
        every allocated (non-hole) block of the inode's content, covering
        the direct addresses stored in the inode itself plus both "direct
        node" pointers (one extra hop), both "indirect node" pointers (two
        hops), and the "double indirect node" pointer (three hops) — see
        NODE_DIR1_BLOCK..NODE_DIND_BLOCK in include/linux/f2fs_fs.h for the
        i_nid[] slot ordering this follows."""
        ptrs_per_node = _addrs_per_block(self.sb.block_size)
        result: list = []
        counter = [0]

        def emit(addr: int) -> None:
            if addr not in (_NULL_ADDR, _NEW_ADDR):
                result.append((counter[0], addr))
            counter[0] += 1

        def walk(nid: int, depth: int) -> None:
            if nid == _NULL_ADDR:
                counter[0] += ptrs_per_node ** (depth + 1)
                return
            block = self.read_node_block(nid)
            if depth == 0:
                for i in range(ptrs_per_node):
                    (addr,) = struct.unpack_from("<I", block, i * 4)
                    emit(addr)
            else:
                for i in range(ptrs_per_node):
                    (child_nid,) = struct.unpack_from("<I", block, i * 4)
                    walk(child_nid, depth - 1)

        for a in inode.direct_addrs:
            emit(a)
        walk(inode.node_nids[0], 0)  # direct node 1
        walk(inode.node_nids[1], 0)  # direct node 2
        walk(inode.node_nids[2], 1)  # indirect node 1
        walk(inode.node_nids[3], 1)  # indirect node 2
        walk(inode.node_nids[4], 2)  # double-indirect node
        return result

    def read_file_content(self, inode: _Inode) -> bytes:
        if inode.inline_payload is not None:
            if inode.size > len(inode.inline_payload):
                raise ValueError(f"F2FS nid {inode.nid}: inline size {inode.size} exceeds inline capacity {len(inode.inline_payload)}")
            return inode.inline_payload[:inode.size]

        bs = self.sb.block_size
        buf = bytearray(inode.size)
        for logical, phys in self._walk_data(inode):
            start = logical * bs
            if start >= inode.size:
                continue
            chunk = self.read_block(phys)
            end = min(start + bs, inode.size)
            buf[start:end] = chunk[:end - start]
        return bytes(buf)

    # -- directory entries --------------------------------------------------

    def _parse_dentry_region(self, payload: bytes) -> list:
        n = len(payload)
        nr = (n * 8) // ((_SIZE_OF_DIR_ENTRY + _F2FS_SLOT_LEN) * 8 + 1)  # NR_(INLINE_)DENTRY formula
        if nr <= 0:
            return []
        bitmap_size = -(-nr // 8)  # ceil
        reserved = n - ((_SIZE_OF_DIR_ENTRY + _F2FS_SLOT_LEN) * nr + bitmap_size)
        if reserved < 0:
            raise ValueError("F2FS dentry region size is inconsistent with its own entry-count formula")
        bitmap = payload[:bitmap_size]
        dentry_off = bitmap_size + reserved
        filename_off = dentry_off + _SIZE_OF_DIR_ENTRY * nr

        entries = []
        i = 0
        while i < nr:
            if not (bitmap[i >> 3] & (1 << (i & 7))):
                i += 1
                continue
            doff = dentry_off + i * _SIZE_OF_DIR_ENTRY
            if doff + _SIZE_OF_DIR_ENTRY > len(payload):
                break
            _hash_code, ino, name_len, file_type = struct.unpack_from("<IIHB", payload, doff)
            # GET_DENTRY_SLOTS: a name longer than F2FS_SLOT_LEN(8) bytes
            # consumes multiple consecutive bitmap bits/filename slots —
            # advancing by 1 here instead would misparse every entry after
            # the first long name (see module docstring).
            slots = max(1, (name_len + _F2FS_SLOT_LEN - 1) // _F2FS_SLOT_LEN)
            noff = filename_off + i * _F2FS_SLOT_LEN
            name = payload[noff:noff + name_len].decode("utf-8", "replace")
            if name not in (".", ".."):
                entries.append((name, ino, file_type))
            i += slots
        return entries

    def _iter_dirents(self, inode: _Inode) -> list:
        if inode.inline_payload is not None:
            return self._parse_dentry_region(inode.inline_payload)

        bs = self.sb.block_size
        nblocks = -(-inode.size // bs)
        addr_by_block = dict(self._walk_data(inode))
        entries = []
        for b in range(nblocks):
            phys = addr_by_block.get(b)
            if phys is None:
                continue  # hole: no entries in this block
            entries.extend(self._parse_dentry_region(self.read_block(phys)))
        return entries

    def walk(self) -> list:
        paths: list = []
        self._walk_dir(self.sb.root_ino, "", paths, visited=set())
        return paths

    def _walk_dir(self, nid: int, prefix: str, out: list, visited: set, depth: int = 0) -> None:
        if nid in visited or depth > _MAX_DIR_DEPTH:
            return
        visited.add(nid)

        inode = self.read_inode(nid)
        if inode.mode & _S_IFMT != _S_IFDIR:
            return

        for name, child_nid, file_type in self._iter_dirents(inode):
            child_path = f"{prefix}/{name}" if prefix else name
            if file_type == _FT_SYMLINK:
                continue
            if file_type == _FT_DIR:
                self._walk_dir(child_nid, child_path, out, visited, depth + 1)
            elif file_type == _FT_REG_FILE:
                out.append(child_path)
            elif file_type == _FT_UNKNOWN:
                try:
                    child_mode = self.read_inode(child_nid).mode & _S_IFMT
                except (ValueError, NotImplementedError):
                    continue
                if child_mode == _S_IFDIR:
                    self._walk_dir(child_nid, child_path, out, visited, depth + 1)
                elif child_mode == _S_IFREG:
                    out.append(child_path)

    def resolve(self, path: str) -> _Inode:
        nid = self.sb.root_ino
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


class F2fs(FilesystemContainer):
    name = "F2fs"
    long_name = "F2FS filesystem"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(0, 8192)
        except Exception:
            log_error("F2fs: failed to read input for signature check")
            return False
        return _probe_superblock(head, _SB_OFFSET_PRIMARY) is not None or _probe_superblock(head, _SB_OFFSET_PRIMARY + 4096) is not None

    def open_filesystem(self, data: bytes) -> F2fsFS:
        return F2fsFS(data)

    def list_paths(self, fs: F2fsFS) -> list:
        return fs.walk()

    def read_file(self, fs: F2fsFS, path: str) -> bytes:
        inode = fs.resolve(path)
        return fs.read_file_content(inode)


if not any(info["id"] == "f2fs" for info in formats()):
    F2fs.register()
