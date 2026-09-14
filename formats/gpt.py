"""GUID Partition Table (GPT) — the partition scheme at the start of
essentially any raw full-disk flash dump: EDL/Firehose `lun.bin` images,
JTAG/ISP full-flash reads, and any other whole-storage-device capture,
across phone vendors generally. Unlike the rest of this plugin's formats,
GPT is not vendor-specific firmware packaging — it's the public UEFI
Specification's own partition table format, so there is no licensing
ambiguity and no vendor tool to cross-check against: the "reference" here
is the spec itself (UEFI Specification, version 2.10, section 5.3 "GUID
Partition Table (GPT) Disk Layout" — publicly available from uefi.org,
royalty-free/open specification, no proprietary or copyleft code
involved). Field offsets and semantics below are taken directly from
Table 5.5 (GPT Header) and Table 5.6 (GPT Partition Entry) of that spec.

Verified against a synthetic disk image hand-built for this plugin: a
512-byte protective MBR with boot signature 0x55AA, a GPT header at LBA 1
with every documented field filled in and its `header_crc32` computed the
same way this module recomputes it (`zlib.crc32` over the 92-byte header
with the stored CRC field zeroed), and a partition entry array at LBA 2
with a handful of named entries (including a deliberately-unused
all-zero-type-GUID slot, to confirm it's skipped) followed by a UTF-16LE
partition name — then hand-checked byte-for-byte against the field
offsets from the spec table before writing the parser. No real-world
device dump was available to cross-check against, but GPT's byte layout
is exact and unambiguous in the spec (there is no vendor-specific
variation to guess at, unlike this plugin's other formats), so this is
about as "verified" as a format in this plugin gets without a real
sample.

Known limitations, called out explicitly rather than silently assumed
away:

- **512-byte logical blocks are assumed.** This covers the overwhelming
  majority of phone/embedded flash dumps this plugin targets. A GPT disk
  using 4096-byte logical blocks (native 4Kn drives, some newer eMMC/UFS
  setups) has its header at byte offset 4096 instead of 512 and every
  LBA-based field scales accordingly; this module does not attempt to
  auto-detect that case and will simply fail to find a valid header (or,
  worse in principle, misparse — mitigated by the CRC check below) against
  such an image. Treat 4096-byte-block support as a known gap, not a
  silent correctness guarantee.
- **The header CRC32 (`header_crc32`) *is* verified** — recomputed with
  `zlib.crc32` over the 92-byte header with the stored CRC field zeroed,
  per the spec's own definition of that field. A mismatch is treated as
  "don't trust this table" and raises, rather than extracting from a
  possibly-corrupt/misaligned parse.
- **The partition entry array's own CRC32 (`partition_entry_array_crc32`)
  is *not* verified.** It's not needed for correct extraction (each
  entry's own fields are used directly), and the task this module was
  written for only asked for the header CRC as a nice-to-have; adding the
  entry-array CRC as well would be simple if wanted later, but skipping it
  keeps this module a bit shorter.
- Only the first 128 bytes of each partition-entry slot are ever read,
  even when `size_of_partition_entry` is declared larger — per spec, the
  fields this plugin needs (both GUIDs, first/last LBA, attributes, name)
  always occupy exactly that first 128 bytes; anything past that in a
  larger-than-128 entry is vendor-specific data this plugin has no use
  for. A `size_of_partition_entry` declared *smaller* than 128 is treated
  as corrupt and rejected, since it can't hold the standard fields.
- `num_partition_entries` is sanity-capped (see `_MAX_PARTITION_ENTRIES`)
  well above any real-world value (almost always 128, occasionally a few
  hundred) purely to fail fast and cleanly on a corrupt/garbage header
  instead of looping over a huge bogus count.
- The protective MBR at LBA 0 is only used for `can_decode`'s boot
  signature sanity check (bytes 510-511 == 0x55AA) — this module never
  parses MBR partition entries themselves.
"""

from __future__ import annotations

import zlib

from ..common.binstruct import BinStruct
from ..common.container_base import Entry, OffsetTableContainer

MAGIC = b"EFI PART"

_BLOCK_SIZE = 512
_HEADER_LBA = 1
_HEADER_OFFSET = _HEADER_LBA * _BLOCK_SIZE
_BOOT_SIGNATURE_OFFSET = 510
_ZERO_GUID = b"\x00" * 16
_MAX_PARTITION_ENTRIES = 4096  # generous sanity cap; real tables use 128 (occasionally more)


class _Header(BinStruct):
    _format = "<8sIIII QQQQ 16s QIII"
    _fields = (
        "signature", "revision", "header_size", "header_crc32", "reserved",
        "my_lba", "alternate_lba", "first_usable_lba", "last_usable_lba",
        "disk_guid", "partition_entry_lba", "num_partition_entries",
        "size_of_partition_entry", "partition_entry_array_crc32",
    )


class _Entry(BinStruct):
    _format = "<16s16sQQQ72s"
    _fields = (
        "partition_type_guid", "unique_partition_guid",
        "first_lba", "last_lba", "attributes", "partition_name",
    )


def _verify_header_crc(data: bytes, header) -> None:
    header_bytes = bytearray(data[_HEADER_OFFSET:_HEADER_OFFSET + _Header.size()])
    # header_crc32 sits right after signature(8)+revision(4)+header_size(4)
    header_bytes[16:20] = b"\x00\x00\x00\x00"
    computed = zlib.crc32(bytes(header_bytes)) & 0xFFFFFFFF
    if computed != header.header_crc32:
        raise ValueError(
            f"GPT header CRC32 mismatch (stored {header.header_crc32:#010x}, "
            f"computed {computed:#010x}) -- refusing to trust a possibly-corrupt partition table"
        )


def _decode_partition_name(raw: bytes, index: int) -> str:
    name = raw.decode("utf-16-le", "replace").split("\x00", 1)[0].strip()
    return name if name else f"part{index}"


class Gpt(OffsetTableContainer):
    MAGIC = MAGIC
    name = "Gpt"
    long_name = "GUID Partition Table (GPT)"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(_BOOT_SIGNATURE_OFFSET, 10)
        except Exception:
            return False
        if len(head) < 10:
            return False
        return head[0:2] == b"\x55\xaa" and head[2:10] == MAGIC

    def parse_entries(self, data: bytes) -> list[Entry]:
        header = _Header.unpack_from(data, _HEADER_OFFSET)
        if header.signature != MAGIC:
            raise ValueError(f"unexpected GPT header signature {header.signature!r}")
        if header.header_size < _Header.size():
            raise ValueError(
                f"GPT header_size {header.header_size} is smaller than the "
                f"{_Header.size()}-byte fields this parser reads"
            )

        _verify_header_crc(data, header)

        if header.size_of_partition_entry < _Entry.size():
            raise ValueError(
                f"GPT size_of_partition_entry {header.size_of_partition_entry} is smaller than "
                f"the {_Entry.size()}-byte standard entry fields"
            )
        if header.num_partition_entries > _MAX_PARTITION_ENTRIES:
            raise ValueError(
                f"GPT num_partition_entries {header.num_partition_entries} exceeds sanity cap "
                f"{_MAX_PARTITION_ENTRIES} -- treating as a corrupt header"
            )

        entries = []
        array_offset = header.partition_entry_lba * _BLOCK_SIZE
        for i in range(header.num_partition_entries):
            entry_offset = array_offset + i * header.size_of_partition_entry
            raw = _Entry.unpack_from(data, entry_offset)
            if raw.partition_type_guid == _ZERO_GUID:
                continue
            name = _decode_partition_name(raw.partition_name, i)
            size = (raw.last_lba - raw.first_lba + 1) * _BLOCK_SIZE
            entries.append(Entry(name=name, offset=raw.first_lba * _BLOCK_SIZE, size=size))
        return entries


Gpt.register()
