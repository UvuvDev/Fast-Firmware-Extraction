"""Unisoc (Spreadtrum) CP memory-decoupling modem image — the ``MECP``
header that sits at the front of the ``l_modem`` / ``nr_modem`` / ``w_modem``
partition on Unisoc-based Android phones. Verified against
``l_modem.img`` from a Xiaomi Redmi A5 (Unisoc T7250 "qogirl6",
``serenity_global_images_A15.0.31.0.VGWMIXM_15.0``), whose payload is an
ARM Spreadtrum CP ("communication processor") baseband image.

The header is **not** an archive: it is the AP bootloader's description of
the *memory map* the CP runs in, plus the small bootstrap the AP pokes
into CP IRAM. Each entry names a DDR region by load address and size, and
a region flagged ``load_t`` is filled from its **own separate partition**
(``PARTITION_PREFIX + name`` — so region ``gdsp`` comes from ``l_gdsp``,
``ldsp`` from ``l_ldsp``, and so on). Only the ``modem`` region's data
actually lives in this file, immediately after the header; every other
region listed is metadata about memory or about a sibling partition, and
is deliberately *not* emitted as a child — there are no bytes here to
emit for it.

Struct layout verified against the vendor bootloader that consumes this
header, read as source (not vendored — nothing below is copied from it,
and this plugin has no runtime dependency on it):
``common/loader/cp_mem_decoupling.h`` and
``common/loader/process_cp_coupling_info.c`` in Unisoc's u-boot15 BSP, as
published at
https://github.com/Veynamer/bsp_bootloader_u-boot15_sharkl5pro (the same
pair of files appears identically in a dozen other mirrored Unisoc BSP
trees, e.g. ``yonglongliu/u-boot15``, ``iscle/ums512_uboot``). That
header defines::

    #define DECOUPLE_MAGIC_INFO 0x5043454D   /* "MECP" little-endian */
    #define MAX_HEADER_SIZE     0x600
    #define MAX_NAME_LEN        0x14
    #define MAX_RSVMEM_NUM      0x4
    #define MAX_REGION_NUM      0x8          /* unless CONFIG_CP_MAX_REGION_NUM */
    #define MAX_RES_NUM         0x4
    #define MAX_CODE_NUM        0x32

    struct mem_resource { char name[MAX_NAME_LEN]; uint64_t base __aligned(8); uint32_t size; };
    struct region_info  { struct mem_resource res; uint32_t flag; };
    struct boot_code    { uint32_t count; uint32_t code[MAX_CODE_NUM]; };

    struct cp_mem_coupling_info {
        uint32_t magic; uint32_t version; uint32_t length; uint32_t ex_info;
        struct rsvmem_info_conf rsvmem_info;   /* region_info rsvmem[MAX_RSVMEM_NUM] */
        struct boot_info_conf   boot_info;     /* boot_code; region_info regions[MAX_REGION_NUM];
                                                  mem_resource res[MAX_RES_NUM]; uint32_t ex_info */
        struct comm_info_conf   comm_info;     /* mem_resource res[MAX_RES_NUM]; uint32_t ex_info */
    };

and ``get_cp_load_table_v0()`` is what establishes the semantics above:
it walks ``boot_info.regions[]``, keeps only entries with
``flag == load_t`` (1, from the ``ignore_t/load_t/clear_t/dump_t/reg_t``
enum), and for each one records "read partition ``l_<name>`` of length
``res.size`` to address ``res.base``".

Every derived offset below was then cross-checked byte-for-byte against
the real sample, which is what makes the C alignment padding (the two
``__aligned(8)`` gaps that make ``mem_resource`` 40 bytes and
``region_info`` 48) trustworthy rather than assumed:

* ``rsvmem[4]`` lands at 0x10..0xd0 — ``sipc-mem`` @0x87800000 and
  ``cp-modem`` @0x89600000 in slots 0-1, slots 2-3 blank.
* ``boot_code.count`` lands exactly at 0xd0 and reads 49, and the 49
  words that follow are a valid ARM bootstrap ending in
  ``ldr pc, [pc, #-4]`` + the literal ``0x8b001acc``.
* ``regions[8]`` lands at 0x1a0 — ``modem``, ``cpcmdline``, ``deltanv``,
  ``fixnv``, ``runnv``, ``gdsp``, ``ldsp``, blank.
* ``boot_info.res[4]`` lands at 0x320 (``cp-mem``, ``mini-dump``) and
  ``comm_info.res[4]`` at 0x3c8 (``smem``, ``ring``).

The payload's load address was confirmed independently of the header: the
bootstrap's jump target 0x8b001acc is byte-for-byte the ``ldr pc, [pc]``
at file offset 0x1acc, and of ~3700 word-aligned values in the first 2 MB
that fall inside ``modem``'s declared range, 834 point at the first byte
of a printable NUL-terminated C string ("Spreadtrum Boot Block version
3.0", "PS/stack/gas/dl/c/dl_entity.c", ...). So file offset 0 maps to
``regions["modem"].base``, header included — consistent with
``get_cp_load_table_v0()`` loading the whole partition to ``res.base``.

**Why the header is excluded from the emitted payload:** a child that
still began with ``MECP`` would be re-detected by this very transform and
extract itself forever. The ``modem`` child therefore starts just past
the header, i.e. it loads at ``regions["modem"].base + header.length``
(0x8b000600 on the verified sample) — that address is logged at
extraction time so it doesn't have to be re-derived by hand.

**AVB footer.** This is a partition image, so the tail carries AOSP's
64-byte big-endian ``AvbFooter`` (``AVBf`` magic, ``libavb/avb_footer.h``,
Apache-2.0) followed by zero padding out to the partition size — on the
sample, 25 MB of partition for a 14 MB image. That footer is the only
*exact* statement of where the image ends, so it is parsed here to trim
the padding (falling back to ``regions["modem"].size`` when absent), and
its ``vbmeta`` blob is emitted rather than silently dropped. None of that
is MECP-specific; if a second format in this plugin ever needs an AVB
footer, this is the piece to lift into a shared helper (or its own
format file) rather than copy.
"""

from __future__ import annotations

from binaryninja import log_info

from ..common.binstruct import BinStruct, cstr
from ..common.container_base import Entry, OffsetTableContainer

MAGIC = b"MECP"

# Constants transcribed from cp_mem_decoupling.h (see module docstring).
_MAX_HEADER_SIZE = 0x600
_MAX_RSVMEM_NUM = 0x4
_MAX_REGION_NUM = 0x8
_MAX_RES_NUM = 0x4
_MAX_CODE_NUM = 0x32

# enum { ignore_t = 0, load_t, clear_t, dump_t, reg_t }
_LOAD_T = 1
_FLAG_NAMES = {0: "ignore", 1: "load", 2: "clear", 3: "dump", 4: "reg"}

# The region whose partition the decoupling header itself is stored in:
# `#define DECOUPLING_INFO_PARTITION "modem"`. That makes "modem" the one
# region whose bytes are in *this* file rather than a sibling partition.
_PAYLOAD_REGION = "modem"

_BOOTCODE_CHILD = "cp_bootcode"
_VBMETA_CHILD = "vbmeta"

_AVB_FOOTER_MAGIC = b"AVBf"


class _Header(BinStruct):
    _format = "<4sIII"
    _fields = ("magic", "version", "length", "ex_info")


class _MemResource(BinStruct):
    # char name[0x14]; <4 bytes pad>; uint64_t base; uint32_t size; <4 bytes tail pad>
    _format = "<20s4xQI4x"
    _fields = ("name", "base", "size")


class _RegionInfo(BinStruct):
    # struct mem_resource res; uint32_t flag; <4 bytes tail pad>
    _format = "<20s4xQI4xI4x"
    _fields = ("name", "base", "size", "flag")


class _AvbFooter(BinStruct):
    # libavb/avb_footer.h — all multi-byte fields big-endian.
    _format = ">4sIIQQQ28s"
    _fields = ("magic", "version_major", "version_minor", "original_image_size", "vbmeta_offset", "vbmeta_size", "reserved")


def _align8(value: int) -> int:
    return (value + 7) & ~7


# Field offsets derived from the constants above rather than hand-typed, so a
# transcription slip shows up as an obviously wrong constant instead of a
# plausible-looking one. Checked against the real sample (see docstring).
_RSVMEM_OFF = 0x10
_BOOT_INFO_OFF = _RSVMEM_OFF + _MAX_RSVMEM_NUM * _RegionInfo.size()
_BCODE_COUNT_OFF = _BOOT_INFO_OFF
_BCODE_CODE_OFF = _BCODE_COUNT_OFF + 4
_REGIONS_OFF = _BOOT_INFO_OFF + _align8(4 + _MAX_CODE_NUM * 4)
_BOOT_RES_OFF = _REGIONS_OFF + _MAX_REGION_NUM * _RegionInfo.size()
_COMM_RES_OFF = _align8(_BOOT_RES_OFF + _MAX_RES_NUM * _MemResource.size() + 4)
_STRUCT_END = _align8(_COMM_RES_OFF + _MAX_RES_NUM * _MemResource.size() + 4)

assert (_RSVMEM_OFF, _BOOT_INFO_OFF, _REGIONS_OFF, _BOOT_RES_OFF, _COMM_RES_OFF) == (
    0x10,
    0xD0,
    0x1A0,
    0x320,
    0x3C8,
), "MECP header layout no longer matches the offsets verified against the reference sample"


def _resources(data: bytes, offset: int, count: int) -> list[_MemResource]:
    """Parse a ``mem_resource[count]`` table, dropping blank (unused) slots."""
    out = []
    for i in range(count):
        res = _MemResource.unpack_from(data, offset + i * _MemResource.size())
        if cstr(res.name):
            out.append(res)
    return out


def _regions(data: bytes, offset: int, count: int) -> list[_RegionInfo]:
    """Parse a ``region_info[count]`` table, dropping blank (unused) slots."""
    out = []
    for i in range(count):
        region = _RegionInfo.unpack_from(data, offset + i * _RegionInfo.size())
        if cstr(region.name):
            out.append(region)
    return out


def _avb_footer(data: bytes) -> _AvbFooter | None:
    """Parse the trailing AvbFooter, or None if this image has no AVB tail."""
    size = _AvbFooter.size()
    if len(data) < size or data[-size:-size + 4] != _AVB_FOOTER_MAGIC:
        return None
    footer = _AvbFooter.unpack_from(data, len(data) - size)
    if not 0 < footer.original_image_size <= len(data):
        return None
    return footer


def _parse_entries(data: bytes, *, log: bool) -> list[Entry]:
    header = _Header.unpack_from(data, 0)
    if header.magic != MAGIC:
        raise ValueError(f"bad magic {header.magic!r}, expected {MAGIC!r}")

    header_length = header.length
    if not _STRUCT_END <= header_length <= min(_MAX_HEADER_SIZE, len(data)):
        raise ValueError(
            f"header length {header_length:#x} outside the valid range "
            f"[{_STRUCT_END:#x}, {min(_MAX_HEADER_SIZE, len(data)):#x}]"
        )

    code_count = int.from_bytes(data[_BCODE_COUNT_OFF:_BCODE_COUNT_OFF + 4], "little")
    if code_count > _MAX_CODE_NUM:
        # Doubles as a structural checksum: MAX_REGION_NUM is build-tunable via
        # CONFIG_CP_MAX_REGION_NUM, and a build that changed it would shift every
        # table after rsvmem[] and land garbage in this field. Fail loudly rather
        # than extract from misaligned offsets.
        raise ValueError(f"boot_code.count {code_count} exceeds MAX_CODE_NUM {_MAX_CODE_NUM}; unexpected header layout")

    regions = _regions(data, _REGIONS_OFF, _MAX_REGION_NUM)
    payload = next((r for r in regions if cstr(r.name) == _PAYLOAD_REGION), None)
    if payload is None:
        raise ValueError(f"no {_PAYLOAD_REGION!r} region in the header; not a modem-partition MECP image")
    if payload.flag != _LOAD_T:
        # get_cp_load_table_v0() only reads a partition for regions flagged
        # load_t; any other flag means nothing is sourced from this file.
        raise ValueError(
            f"{_PAYLOAD_REGION!r} region is flagged "
            f"{_FLAG_NAMES.get(payload.flag, payload.flag)}, not load; no payload is sourced from this partition"
        )

    footer = _avb_footer(data)
    # The AVB footer is the only exact statement of where the image stops; without
    # one, fall back to what the bootloader itself reads from this partition
    # (`s_boot_image_cp_table[j].size = region->res.size`).
    image_end = min(footer.original_image_size if footer else payload.size, len(data))
    if image_end <= header_length:
        raise ValueError(f"image end {image_end:#x} leaves no payload after the {header_length:#x}-byte header")

    if log:
        _log_layout(header, regions, data, payload, header_length, image_end, footer)

    entries = [Entry(name=cstr(payload.name), offset=header_length, size=image_end - header_length)]

    if code_count:
        entries.append(Entry(name=_BOOTCODE_CHILD, offset=_BCODE_CODE_OFF, size=code_count * 4))

    if footer and footer.vbmeta_size and footer.vbmeta_offset + footer.vbmeta_size <= len(data):
        entries.append(Entry(name=_VBMETA_CHILD, offset=footer.vbmeta_offset, size=footer.vbmeta_size))

    return entries


def _log_layout(header, regions, data, payload, header_length, image_end, footer) -> None:
    """Report the CP memory map, which has nowhere else to go.

    Region bases/sizes are the most useful thing in this header for anyone
    reversing the result — they say where each sibling partition is mapped
    and where the shared-memory windows live — but only the payload region
    produces a child, so without this the rest is parsed and discarded.
    """
    raw_version = header.version.to_bytes(4, "little")
    printable = all(0x20 <= b < 0x7F for b in raw_version)
    version = cstr(header.magic + raw_version) if printable else f"MECP({header.version:#010x})"
    log_info(f"MECP: {version} header, {header_length:#x} bytes, payload {header_length:#x}..{image_end:#x}")
    log_info(f"MECP: '{cstr(payload.name)}' child loads at {payload.base + header_length:#x} (region base {payload.base:#x}, reserved {payload.size:#x})")
    for region in regions:
        flag = _FLAG_NAMES.get(region.flag, str(region.flag))
        here = " <- this file" if region is payload else ""
        log_info(f"MECP:   region {cstr(region.name):<12} base {region.base:#012x} size {region.size:#010x} {flag}{here}")
    for label, offset, count in (("boot res", _BOOT_RES_OFF, _MAX_RES_NUM), ("comm res", _COMM_RES_OFF, _MAX_RES_NUM)):
        for res in _resources(data, offset, count):
            log_info(f"MECP:   {label} {cstr(res.name):<12} base {res.base:#012x} size {res.size:#010x}")
    if footer:
        log_info(f"MECP: AVB footer: image {footer.original_image_size:#x}, vbmeta at {footer.vbmeta_offset:#x} ({footer.vbmeta_size:#x} bytes)")


class UnisocMECP(OffsetTableContainer):
    MAGIC = MAGIC
    name = "UnisocMECP"
    long_name = "Unisoc CP memory-decoupling modem image"

    def parse_entries(self, data: bytes) -> list[Entry]:
        return _parse_entries(data, log=self._log_layout_this_pass)

    _log_layout_this_pass = False

    def perform_decode_with_context(self, context, params) -> bool:
        # The base class calls parse_entries once to advertise the child list and
        # again to extract; `has_available_files` is False on the first pass and
        # True on the second, so this reports the memory map exactly once, on the
        # pass that actually produces children.
        self._log_layout_this_pass = context.has_available_files
        return super().perform_decode_with_context(context, params)


UnisocMECP.register()
