"""UBIFS (UBI File System) -- the log-structured flash filesystem that
almost always lives *inside* a UBI volume (see `ubi.py` in this same
directory, which splits a raw UBI image into its constituent volumes'
raw bytes). UBIFS itself doesn't know or care whether its LEBs come from
a real UBI-managed MTD partition or from `ubi.py`'s reassembled volume
buffer -- both look the same to it: a flat array of fixed-size logical
eraseblocks (LEBs), each holding a sequence of 8-byte-aligned "nodes".
This module is a standalone `FilesystemContainer` that recognizes a UBIFS
superblock node at offset 0 of *whatever buffer it's handed* -- which
means Binary Ninja's normal container-browser chaining already covers
both real-world shapes: a raw `.ubifs` dd-style image handed to this
plugin directly, and a UBI volume that `ubi.py` has already extracted as
a child (whose bytes then get re-probed against every registered format,
this one included). No coordination with `ubi.py` beyond that generic
chaining is implemented or needed.

Every on-disk struct and constant below was verified against the Linux
kernel's own UBIFS source (all GPL-2.0-only), fetched from
`torvalds/linux` on GitHub during development:

  - `fs/ubifs/ubifs-media.h` -- the authoritative on-disk layout: node
    magic (`UBIFS_NODE_MAGIC`), the common node header (`ubifs_ch`),
    every node struct used here (`ubifs_sb_node`, `ubifs_mst_node`,
    `ubifs_ino_node`, `ubifs_dent_node`, `ubifs_data_node`,
    `ubifs_idx_node`/`ubifs_branch`), the node-type enum, the simple key
    format's bit layout (`UBIFS_S_KEY_BLOCK_BITS`=29,
    `UBIFS_S_KEY_BLOCK_MASK`), the fixed LEB numbering for the
    superblock/master areas (`UBIFS_SB_LNUM`=0, `UBIFS_MST_LNUM`=1,
    `UBIFS_MST_LEBS`=2), `UBIFS_ROOT_INO`=1, `UBIFS_BLOCK_SIZE`=4096, and
    `UBIFS_CRC32_INIT`.
  - `fs/ubifs/key.h` -- the exact key-field bit packing (`key_type =
    key.u32[1] >> 29`, `key_block`/`key_hash = key.u32[1] & 0x1FFFFFFF`,
    `key_inum = key.u32[0]`) and confirmation that a full-tree walk never
    needs the name-hash function at all (only point lookups by name do).
  - `fs/ubifs/io.c` (`ubifs_check_node`/`ubifs_crc_node`) -- the exact
    CRC placement and algorithm, which is the one place a "it's just
    CRC-32" assumption would be silently wrong (see below).
  - `fs/ubifs/sb.c` -- confirms `c->key_len = UBIFS_SK_LEN` (8 bytes) for
    the only supported key format (`UBIFS_SIMPLE_KEY_FMT`), i.e. each
    on-disk branch's trailing key field is 8 bytes, not the 16-byte
    `UBIFS_MAX_KEY_LEN` used inside leaf nodes -- getting this wrong
    would silently misalign every branch after the first one in any
    index node with more than one child.
  - `fs/ubifs/master.c` (`ubifs_compare_master_node`, `scan_for_master`)
    -- confirms the master node is duplicated across two fixed LEBs
    (LEB 1 and 2) which a clean unmount leaves byte-identical apart from
    their own header (sqnum/CRC/HMAC), and that within a single master
    LEB the *last* valid node found (not the first) is authoritative,
    since a LEB is appended to in place across commits until it fills up
    and gets re-erased.
  - `fs/ubifs/file.c` (`read_block`) -- confirms regular file data is
    always resolved via `data_key_init(inum, block)` lookups against
    out-of-line data nodes, one per `UBIFS_BLOCK_SIZE` (4096-byte) block,
    never inlined into the inode node itself (inode-embedded `data[]` is
    used only for symlink targets and device-node major:minor, neither
    of which this module extracts -- see below); a data node with no
    corresponding block key is a hole, read back as zeroes.
  - `crypto/deflate.c` (`DEFLATE_DEF_WINBITS`, `zlib_inflateInit2(...,
    -DEFLATE_DEF_WINBITS)`) -- this is the second place a naive
    assumption would be silently wrong. UBIFS's "zlib" compression type
    goes through the Linux crypto API's `"deflate"` transform, which is
    **raw DEFLATE with a negative (11-bit) window**, not the zlib-wrapped
    stream `zlib.decompress()` expects by default and not gzip either. A
    reader that just called `zlib.decompress(data)` on `UBIFS_COMPR_ZLIB`
    payloads would get `zlib.error: Error -3 while decompressing`, not a
    silently-wrong answer -- but it's still exactly the kind of
    format-detail that's easy to get wrong from the name alone ("zlib"
    compression that isn't the zlib format). This module decompresses
    with `zlib.decompressobj(wbits=-15)`: still raw deflate (negative
    wbits), just requesting the largest window Python's zlib will accept
    for raw streams -- safe for decoding data produced with any smaller
    real window (including the kernel's own -11), since decompression
    only needs an upper bound on the window, not an exact match.

**CRC algorithm -- verified by hand, not just by reading the C.**
`ubifs_check_node()`/`ubifs_crc_node()` both compute
`crc32(UBIFS_CRC32_INIT, node + 8, node_len - 8)` using Linux's
`crc32_le()`, which -- unlike `zlib.crc32()` -- applies **no final
complement**: it starts the register at the caller's seed
(`UBIFS_CRC32_INIT` = `0xFFFFFFFF`) and returns the raw register value
after the standard poly-`0xEDB88320` table update, with no `^
0xFFFFFFFF` at the end. Ported that exact table+loop by hand and
compared it against Python's `zlib.crc32` on a test buffer to confirm
the relationship rather than assume it (this is the identical situation
already documented in this plugin's `trx.py`, down to the same
off-by-one-complement quirk, encountered independently in an unrelated
codebase -- a useful cross-check that the derivation technique itself is
sound): `ubifs_crc(body) == zlib.crc32(body) ^ 0xFFFFFFFF`. Every node's
CRC (superblock, master, index, and every leaf) is verified with this
formula against `node[8:node_len]`; a mismatch is a hard failure.

**`mtd-utils`' `ubifs-utils`, mentioned as a suggested independent
cross-check, was consulted for the CRC *call site*** (its `io.c` uses
the identical `crc32(UBIFS_CRC32_INIT, buf + 8, node_len - 8)` pattern,
confirming the kernel and the userspace `mkfs.ubifs`/`fsck.ubifs` tool
agree on where the CRC applies) **but its own `crc32()` *implementation*
file could not be located in the mirrored source tree available during
this task**, so the "no final complement" detail rests on the kernel
source (`fs/ubifs/io.c` calling `include/linux/crc32.h`'s documented
`crc32_le`) plus the hand-verified table derivation, not an independent
confirmation from `mtd-utils` specifically. Flagging this rather than
implying a cross-check that wasn't actually completed.

No real UBIFS image (mkfs.ubifs-produced or extracted from real router
firmware) was available in this environment to validate against --
`mkfs.ubifs`/`ubinize` are not installed and could not be installed here
(no `apt`/`brew` package located). Unlike `ubi.py` (validated against a
real router firmware sample) or `ext4.py`/`erofs.py` (real Pixel/Tensor
partitions), the fixtures under `tests/fixtures/ubifs*/` are **entirely
hand-built from the spec above**, using this module's own encoder logic
as the test's oracle -- the same caveat `f2fs.py` already carries in this
plugin, for the same reason. One thing that IS a deliberate divergence
from any real image: `mkfs.ubifs` enforces `UBIFS_MIN_LEB_SZ` (15360
bytes) at *creation* time, but that minimum is a policy decision of the
formatter, not a structural requirement this reader depends on anywhere
-- so the fixtures here use a smaller 4096-byte LEB purely to keep the
sample small, which a real device image would never actually use.

Deliberately out of scope (raises `NotImplementedError` rather than
guessing), matching this project's established precedent
(`f2fs.py`, `docs/ADDING_A_FORMAT.md`):

1. **LZO- and ZSTD-compressed data nodes.** Neither has a Python stdlib
   decoder; per this task's explicit instruction, this is a hard,
   deliberate limitation rather than a crash or silently-wrong output.
   Only `UBIFS_COMPR_NONE` and `UBIFS_COMPR_ZLIB` (raw deflate, see
   above) are supported.
2. **The journal / log area is never replayed.** This reader goes
   straight from the master node's `root_lnum`/`root_offs` to the
   already-committed on-flash index B-tree, the same "trust the last
   clean commit" assumption `f2fs.py` documents for its own checkpoint
   handling. A UBIFS image captured mid-write (uncleanly unmounted) can
   have recent changes sitting only in journal "bud" LEBs, not yet
   folded into the index -- those would be silently invisible to this
   reader. The master node's own `UBIFS_MST_DIRTY` flag is checked and
   raises `NotImplementedError` when set, since that flag is exactly
   UBIFS's own signal that the on-flash state needs journal replay
   before it's a complete/consistent view.
3. **Two diverging master node copies.** `fs/ubifs/master.c`'s own
   `ubifs_compare_master_node()` requires the two redundant copies (LEB 1
   and 2) to be byte-identical (aside from header/HMAC fields) on a
   clean image; if they're both individually CRC-valid but disagree,
   that's exactly the "-EUCLEAN, needs recovery" case in the kernel, and
   this reader raises `NotImplementedError` rather than picking a side.
   This mirrors `ubi.py`'s identical, already-documented choice for its
   own redundant layout-volume copies.
4. **Authenticated UBIFS images** (`UBIFS_FLG_AUTHENTICATION`, per-node
   HMACs/hashes, signed superblocks). Supporting these would need the
   actual signing key material (to verify anything meaningfully) and
   changes the on-disk branch layout (an extra hash trails each key);
   detected via the superblock's `flags` field and raises
   `NotImplementedError`.
5. **Extended attributes** (`UBIFS_XENT_NODE`/`UBIFS_XENT_KEY` entries)
   are not walked or exposed as extractable content -- xattrs hang off
   an inode by a separate key type, not the regular directory namespace,
   and (like symlinks) there's nothing there to decompile independently.
6. **Symlinks and device/FIFO/socket nodes are not exposed as
   extractable entries** -- their content lives inline in the *inode*
   node (`ubifs_ino_node.data[]`, confirmed via `fs/ubifs/dir.c`), which
   this reader never decodes, matching every other filesystem format in
   this plugin's treatment of symlinks.
7. **Multi-block files and holes** are supported. The Rust port adds a
   multi-block sparse fixture, also checked against this Python reader, and
   a nested UBI-to-UBIFS fixture. Fixtures remain synthetic, not formatter-
   generated or hardware-validated.
8. **The LEB Properties Tree (LPT), orphan area, and free-space
   accounting are never read.** A read-only extractor that only follows
   already-committed index-node branches to leaf nodes never needs any
   of them -- they exist to let a real read-write mount manage
   wear-leveling and space reclamation.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Optional

from ..common.container_base import FilesystemContainer
from ..common.native import formats

UBIFS_NODE_MAGIC = 0x06101831

# Node types (fs/ubifs/ubifs-media.h) -- for the three leaf kinds this
# reader cares about, these are numerically identical to the
# corresponding key types (the kernel header calls this out explicitly).
_INO_NODE = 0
_DATA_NODE = 1
_DENT_NODE = 2
_XENT_NODE = 3
_SB_NODE = 6
_MST_NODE = 7
_IDX_NODE = 9

_CH_SIZE = 24  # sizeof(struct ubifs_ch): magic(4)+crc(4)+sqnum(8)+len(4)+node_type(1)+group_type(1)+padding(2)
_SK_LEN = 8  # UBIFS_SK_LEN -- on-disk key size for the only supported ("simple") key format
_BRANCH_FIXED_SZ = 12  # sizeof(struct ubifs_branch) sans the flexible key: lnum(4)+offs(4)+len(4)
_BRANCH_SZ = _BRANCH_FIXED_SZ + _SK_LEN  # verified via fs/ubifs/sb.c: c->key_len = UBIFS_SK_LEN for simple keys

_SB_NODE_SZ = 4096
_MST_NODE_SZ = 512

_UBIFS_SB_LNUM = 0
_UBIFS_MST_LNUM = 1
_UBIFS_MST_LEBS = 2

_UBIFS_ROOT_INO = 1
_UBIFS_BLOCK_SIZE = 4096
_UBIFS_SIMPLE_KEY_FMT = 0
_UBIFS_S_KEY_BLOCK_BITS = 29
_UBIFS_S_KEY_BLOCK_MASK = 0x1FFFFFFF

_UBIFS_MST_DIRTY = 0x1
_UBIFS_FLG_AUTHENTICATION = 0x20

_COMPR_NONE = 0
_COMPR_LZO = 1
_COMPR_ZLIB = 2
_COMPR_ZSTD = 3

_ITYPE_REG = 0
_ITYPE_DIR = 1

_MAX_INDEX_LEVELS = 512  # UBIFS_MAX_LEVELS -- sanity cap for recursive index descent
_MAX_DIR_DEPTH = 256


def _ubifs_crc(body: bytes) -> int:
    """crc32(UBIFS_CRC32_INIT, body) per fs/ubifs/io.c -- see module
    docstring for the hand-verified "no final complement" derivation."""
    return zlib.crc32(body) ^ 0xFFFFFFFF


@dataclass
class _CommonHeader:
    magic: int
    crc: int
    sqnum: int
    len: int
    node_type: int
    group_type: int


def _read_node(data: bytes, off: int, expect_type: Optional[int] = None) -> tuple:
    """Read and CRC-verify one node's common header at `off`. Returns
    (header, node_bytes) where node_bytes is the full node (header
    included), bounds- and CRC-checked."""
    if off < 0 or off + _CH_SIZE > len(data):
        raise ValueError(f"UBIFS node header at offset {off} exceeds buffer length {len(data)}")
    magic, crc, sqnum, length, node_type, group_type = struct.unpack_from("<IIQIBB2x", data, off)
    if magic != UBIFS_NODE_MAGIC:
        raise ValueError(f"no UBIFS node magic at offset {off}")
    if length < _CH_SIZE or off + length > len(data):
        raise ValueError(f"UBIFS node at offset {off} declares length {length}, exceeds buffer")
    if expect_type is not None and node_type != expect_type:
        raise ValueError(f"UBIFS node at offset {off}: expected node_type {expect_type}, got {node_type}")
    node = data[off:off + length]
    computed = _ubifs_crc(node[8:])
    if computed != crc:
        raise ValueError(f"UBIFS node at offset {off}: CRC32 mismatch (stored {crc:#010x}, computed {computed:#010x})")
    return _CommonHeader(magic, crc, sqnum, length, node_type, group_type), node


@dataclass
class _Superblock:
    leb_size: int
    key_fmt: int
    flags: int


def _parse_superblock(node: bytes) -> _Superblock:
    # Offsets below are hand-tallied from struct ubifs_sb_node in
    # ubifs-media.h (see module docstring): key_fmt@27, flags@28, leb_size@36.
    key_fmt = node[27]
    (flags,) = struct.unpack_from("<I", node, 28)
    (leb_size,) = struct.unpack_from("<I", node, 36)
    if key_fmt != _UBIFS_SIMPLE_KEY_FMT:
        raise NotImplementedError(f"UBIFS key format {key_fmt} is not supported (only the simple key format is)")
    if flags & _UBIFS_FLG_AUTHENTICATION:
        raise NotImplementedError("authenticated UBIFS images (per-node HMACs) are not supported")
    if leb_size < _SB_NODE_SZ:
        raise ValueError(f"UBIFS leb_size {leb_size} is smaller than the superblock node itself ({_SB_NODE_SZ})")
    return _Superblock(leb_size=leb_size, key_fmt=key_fmt, flags=flags)


@dataclass
class _Master:
    root_lnum: int
    root_offs: int
    root_len: int


def _parse_master(node: bytes) -> _Master:
    # Offsets hand-tallied from struct ubifs_mst_node (see module
    # docstring): flags@40, root_lnum@48, root_offs@52, root_len@56.
    (flags,) = struct.unpack_from("<I", node, 40)
    if flags & _UBIFS_MST_DIRTY:
        raise NotImplementedError("UBIFS master node is marked dirty (unclean unmount) -- journal replay is not supported")
    root_lnum, root_offs, root_len = struct.unpack_from("<III", node, 48)
    return _Master(root_lnum=root_lnum, root_offs=root_offs, root_len=root_len)


def _scan_leb_for_last_node(data: bytes, leb_size: int, lnum: int, expect_type: int):
    """Walk LEB `lnum` from offset 0, 8-byte-aligned node by node, and
    return the *last* structurally valid `expect_type` node found (or
    None). A LEB in an area like this is appended to in place across
    commits until it fills up and is re-erased, so only the most recent
    write is live -- see fs/ubifs/master.c's scan_for_master(). Other
    node types (e.g. a padding node written to round up to the next
    min_io_size boundary) can legitimately appear between writes and are
    skipped rather than treated as the end of the valid sequence -- only
    a node that fails to parse/CRC-check at all ends the scan."""
    base = lnum * leb_size
    off = 0
    last = None
    while off + _CH_SIZE <= leb_size:
        try:
            header, node = _read_node(data, base + off)
        except ValueError:
            break  # erased/padding tail, or genuine corruption -- either way, scanning stops here
        if header.node_type == expect_type:
            last = node
        off += (header.len + 7) & ~7
    return last


def _decompress(compr_type: int, payload: bytes, plain_size: int) -> bytes:
    if compr_type == _COMPR_NONE:
        return payload
    if compr_type == _COMPR_ZLIB:
        # Raw DEFLATE (Linux crypto API "deflate"), not the zlib-wrapped
        # format -- see module docstring. wbits=-15 requests the largest
        # raw-deflate window Python's zlib supports; safe for data
        # compressed with any smaller window (including the kernel's -11).
        out = zlib.decompressobj(wbits=-15).decompress(payload)
        return out
    if compr_type == _COMPR_LZO:
        raise NotImplementedError("UBIFS data node uses LZO compression, which has no Python stdlib decoder")
    if compr_type == _COMPR_ZSTD:
        raise NotImplementedError("UBIFS data node uses ZSTD compression, which has no Python stdlib decoder")
    raise ValueError(f"unknown UBIFS compression type {compr_type}")


@dataclass
class _Inode:
    size: int


class UbifsFS:
    def __init__(self, data: bytes):
        self.data = data

        # The superblock node always sits at the very start of LEB 0, i.e.
        # absolute offset 0 regardless of leb_size (which isn't known until
        # after we've parsed it) -- so it can always be read directly,
        # unlike everything else here.
        _sb_hdr, sb_node = _read_node(data, 0, expect_type=_SB_NODE)
        self.sb = _parse_superblock(sb_node)

        mst_a = _scan_leb_for_last_node(data, self.sb.leb_size, _UBIFS_MST_LNUM, _MST_NODE)
        mst_b = _scan_leb_for_last_node(data, self.sb.leb_size, _UBIFS_MST_LNUM + _UBIFS_MST_LEBS - 1, _MST_NODE)
        if mst_a is None and mst_b is None:
            raise ValueError("no valid UBIFS master node found in either redundant copy")
        if mst_a is not None and mst_b is not None:
            # A clean image's two copies are identical apart from their own
            # header (sqnum/crc) -- compare everything else, matching
            # fs/ubifs/master.c's ubifs_compare_master_node(). Diverging
            # copies mean "needs recovery": out of scope, see module docstring.
            if mst_a[_CH_SIZE:] != mst_b[_CH_SIZE:]:
                raise NotImplementedError(
                    "UBIFS's two redundant master node copies disagree -- this image needs recovery, which is not supported"
                )
        mst_node = mst_a if mst_a is not None else mst_b
        self.mst = _parse_master(mst_node)

        self._inodes: dict[int, _Inode] = {}
        self._children: dict[int, list[tuple[str, int, int]]] = {}  # parent_inum -> [(name, child_inum, itype)]
        self._data_blocks: dict[int, dict[int, tuple[int, bytes, int]]] = {}  # inum -> block -> (compr_type, payload, plain_size)
        self._walked = False
        self._path_to_inum: dict[str, int] = {}

    # -- index B-tree walk --------------------------------------------------

    def _read_index_node(self, lnum: int, offs: int) -> tuple:
        base = lnum * self.sb.leb_size + offs
        header, node = _read_node(self.data, base, expect_type=_IDX_NODE)
        child_cnt, level = struct.unpack_from("<HH", node, _CH_SIZE)
        branches = []
        branch_off = _CH_SIZE + 4
        for i in range(child_cnt):
            b_off = branch_off + i * _BRANCH_SZ
            if b_off + _BRANCH_FIXED_SZ > len(node):
                raise ValueError(f"UBIFS index node at LEB {lnum}:{offs}: branch {i} exceeds node length")
            b_lnum, b_offs, b_len = struct.unpack_from("<III", node, b_off)
            branches.append((b_lnum, b_offs, b_len))
        return level, branches

    def _walk_index(self, lnum: int, offs: int, depth: int = 0) -> None:
        if depth > _MAX_INDEX_LEVELS:
            raise ValueError("UBIFS index tree exceeds UBIFS_MAX_LEVELS -- probably a corrupt/cyclic tree")
        level, branches = self._read_index_node(lnum, offs)
        for b_lnum, b_offs, _b_len in branches:
            if level == 0:
                self._read_leaf(b_lnum, b_offs)
            else:
                self._walk_index(b_lnum, b_offs, depth + 1)

    def _read_leaf(self, lnum: int, offs: int) -> None:
        base = lnum * self.sb.leb_size + offs
        header, node = _read_node(self.data, base)
        if header.node_type == _INO_NODE:
            (inum,) = struct.unpack_from("<I", node, _CH_SIZE)
            (size,) = struct.unpack_from("<Q", node, _CH_SIZE + 16 + 8)  # key(16) + creat_sqnum(8), then size
            self._inodes[inum] = _Inode(size=size)
        elif header.node_type == _DENT_NODE:
            (parent_inum,) = struct.unpack_from("<I", node, _CH_SIZE)
            key_off = _CH_SIZE + 16
            (child_inum,) = struct.unpack_from("<Q", node, key_off)
            itype = node[key_off + 9]
            (nlen,) = struct.unpack_from("<H", node, key_off + 10)
            name_off = key_off + 16
            if name_off + nlen > len(node):
                raise ValueError(f"UBIFS dent node at LEB {lnum}:{offs}: name exceeds node length")
            name = node[name_off:name_off + nlen].decode("utf-8", "replace")
            self._children.setdefault(parent_inum, []).append((name, child_inum, itype))
        elif header.node_type == _DATA_NODE:
            (inum,) = struct.unpack_from("<I", node, _CH_SIZE)
            key_off = _CH_SIZE + 16
            u1 = struct.unpack_from("<I", node, _CH_SIZE + 4)[0]
            block = u1 & _UBIFS_S_KEY_BLOCK_MASK
            (plain_size, compr_type, compr_size) = struct.unpack_from("<IHH", node, key_off)
            payload_off = key_off + 8
            payload = node[payload_off:]
            if plain_size < 0 or plain_size > _UBIFS_BLOCK_SIZE:
                raise ValueError(f"UBIFS data node at LEB {lnum}:{offs}: implausible plain size {plain_size}")
            self._data_blocks.setdefault(inum, {})[block] = (compr_type, payload, plain_size)
        # XENT_NODE and anything else: not part of the regular filesystem
        # namespace/content this reader exposes -- see module docstring.

    def _ensure_walked(self) -> None:
        if self._walked:
            return
        self._walk_index(self.mst.root_lnum, self.mst.root_offs)
        self._walked = True

    # -- public API used by the FilesystemContainer base class --------------

    def walk(self) -> list[str]:
        self._ensure_walked()
        paths: list[str] = []
        self._walk_dir(_UBIFS_ROOT_INO, "", paths, visited=set())
        return paths

    def _walk_dir(self, inum: int, prefix: str, out: list[str], visited: set, depth: int = 0) -> None:
        if inum in visited or depth > _MAX_DIR_DEPTH:
            return
        visited.add(inum)
        for name, child_inum, itype in self._children.get(inum, []):
            child_path = f"{prefix}/{name}" if prefix else name
            if itype == _ITYPE_DIR:
                self._walk_dir(child_inum, child_path, out, visited, depth + 1)
            elif itype == _ITYPE_REG:
                out.append(child_path)
                self._path_to_inum[child_path] = child_inum
            # symlinks/device/fifo/socket entries: skipped, see module docstring

    def read_file_content(self, path: str) -> bytes:
        self._ensure_walked()
        inum = self._path_to_inum.get(path)
        if inum is None:
            raise ValueError(f"'{path}' not found in UBIFS directory tree")
        inode = self._inodes.get(inum)
        if inode is None:
            raise ValueError(f"UBIFS inode {inum} (for '{path}') has no inode node in the index")

        size = inode.size
        buf = bytearray(size)
        blocks = self._data_blocks.get(inum, {})
        for block, (compr_type, payload, plain_size) in blocks.items():
            start = block * _UBIFS_BLOCK_SIZE
            if start >= size:
                continue
            plain = _decompress(compr_type, payload, plain_size)
            if len(plain) != plain_size:
                raise ValueError(
                    f"UBIFS inode {inum} block {block}: decompressed to {len(plain)} bytes, header declares {plain_size}"
                )
            end = min(start + len(plain), size)
            buf[start:end] = plain[:end - start]
        # Blocks with no data node at all are holes -- already zero-filled.
        return bytes(buf)


class Ubifs(FilesystemContainer):
    """FilesystemContainer for UBIFS. See module docstring for the
    on-disk format sources and this reader's documented scope."""

    name = "Ubifs"
    long_name = "UBIFS filesystem"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(0, 32)
        except Exception:
            return False
        if len(head) < 32 or bytes(head[0:4]) != UBIFS_NODE_MAGIC.to_bytes(4, "little"):
            return False
        # Byte 20 is ubifs_ch.node_type (magic(4)+crc(4)+sqnum(8)+len(4));
        # require this to actually be a superblock node, not some other
        # UBIFS node that happens to have been carved out starting at
        # offset 0.
        return head[20] == _SB_NODE

    def open_filesystem(self, data: bytes) -> UbifsFS:
        return UbifsFS(data)

    def list_paths(self, fs: UbifsFS) -> list[str]:
        return fs.walk()

    def read_file(self, fs: UbifsFS, path: str) -> bytes:
        return fs.read_file_content(path)


if not any(info["id"] == "ubifs" for info in formats()):
    Ubifs.register()
