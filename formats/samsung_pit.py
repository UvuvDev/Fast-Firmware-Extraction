"""Samsung PIT (Partition Information Table) -- the partition table used by
Samsung's Odin flashing protocol, roughly Samsung's own analog of GPT.
A `.pit` file is typically extracted from an Odin-format firmware package,
or dumped directly from a device's download-mode bootloader (e.g. via
Heimdall's `--pit`/`--output-pit` flags); it describes every partition
Odin can flash by name, device type, and block geometry.

Struct layout verified against Heimdall (github.com/Benjamin-Dobell/
Heimdall), a well-known, actively-maintained, cross-platform, open-source
Odin-protocol flashing tool. Heimdall is MIT-licensed -- confirmed by
reading its actual `LICENSE` file at the URL below, not assumed from the
project's README:
https://raw.githubusercontent.com/Benjamin-Dobell/Heimdall/master/LICENSE
("Copyright (c) 2010-2017 Benjamin Dobell, Glass Echidna" / standard MIT
permission-and-liability text).

The struct definitions themselves were read directly from Heimdall's
`libpit` library (its current home for this format -- older references to
standalone `PitEntry.h`/`PitData.cpp` files describe a prior layout of the
same repository; today the identical classes live together in
`libpit/source/libpit.h` and `libpit/source/libpit.cpp`):

  - https://raw.githubusercontent.com/Benjamin-Dobell/Heimdall/master/libpit/source/libpit.h
    `PitEntry::kDataSize = 132` (fixed per-entry record size),
    `PitEntry::kPartitionNameMaxLength = kFlashFilenameMaxLength =
    kFotaFilenameMaxLength = 32`, and `PitData::kFileIdentifier =
    0x12349876` / `kHeaderDataSize = 28` (fixed header size).
  - https://raw.githubusercontent.com/Benjamin-Dobell/Heimdall/master/libpit/source/libpit.cpp
    `PitData::Unpack()` (the actual byte-for-byte parser, not just the
    struct's in-memory field declarations) gives the exact on-disk field
    order and offsets used below:

    Header (28 bytes total, all multi-byte fields little-endian -- see
    endianness note below):
      offset  0: file identifier (uint32, must equal `0x12349876`)
      offset  4: entry count (uint32)
      offset  8: unknown1 (uint32)
      offset 12: unknown2 (uint32)
      offset 16: unknown3 (uint16)
      offset 18: unknown4 (uint16)
      offset 20: unknown5 (uint16)
      offset 22: unknown6 (uint16)
      offset 24: unknown7 (uint16)
      offset 26: unknown8 (uint16)

    Then `entry_count` fixed 132-byte entry records back-to-back,
    starting at file offset 28, each laid out (relative offsets) as:
      0: binary_type (uint32), 4: device_type (uint32),
      8: identifier (uint32), 12: attributes (uint32),
      16: update_attributes (uint32), 20: block_size_or_offset (uint32),
      24: block_count (uint32), 28: file_offset (uint32, "Obsolete" --
      see below), 32: file_size (uint32, "Obsolete" -- see below),
      36: partition_name (32-byte null-padded ASCII),
      68: flash_filename (32-byte null-padded ASCII),
      100: fota_filename (32-byte null-padded ASCII). Total: 132 bytes,
      matching `kDataSize`.

    Heimdall's own `unknown1`-`unknown8` field names (not this module's
    naming choice) are the primary source's own admission that those
    header fields' meanings aren't documented anywhere Heimdall's authors
    found either -- they're preserved (read and, implicitly, left alone)
    rather than reinterpreted here.

**Endianness note:** `PitData::UnpackInteger()`/`UnpackShort()` branch on
`WORDS_BIGENDIAN`; the non-`WORDS_BIGENDIAN` branch (the one that actually
runs on every mainstream little-endian desktop/phone host Heimdall ships
for) assembles each value with the first byte read as the *least*
significant byte -- i.e. a plain little-endian decode. This module reads
the format as little-endian accordingly.

**Why this module does NOT try to carve partition *contents* out of a
`.pit` file, unlike this plugin's `formats/gpt.py`:** GPT sits at a fixed
location on the very disk it describes, so a GPT header's partition
offsets point into the same buffer Binary Ninja has open -- carving real
partition bytes out of it is exactly what makes it a "container." A
standalone Samsung `.pit` file is different: it is pure partition
*metadata*, exchanged as its own small file/protocol object over Odin's
USB transport -- a bare `.pit` file's own length is only
`28 + entry_count * 132` bytes and never includes any actual partition
image data alongside it. Two fields look at first glance like they might
give real byte offsets/sizes into some companion blob --
`file_offset`/`file_size` -- but Heimdall's own source labels both
"Obsolete" right on the struct definition (`libpit.h` lines ~93-94) and
never uses them anywhere in `Unpack()`/`Pack()`/`Matches()` beyond
round-tripping the raw values; and `block_size_or_offset` carries this
exact comment directly on its accessor in the same file: "Different
versions of Loke (secondary bootloaders) on different devices intepret
this differently" [sic] -- i.e. even Heimdall's own maintainer documents
that field's meaning as version-dependent and unresolved. Given the
primary source itself flags all three of the plausible "offset/size"
candidates as obsolete, unused, or ambiguous, this module does not guess
at any of them to carve byte ranges. Instead, each partition entry is
exposed as a browsable child containing that partition's own raw 132-byte
on-disk record (named after its `partition_name`) -- an honest, always-
in-bounds mapping (an entry's own record is by construction fully inside
the file that contains it) that lets Container Browser browse "the PIT's
per-partition descriptors by name" without inventing byte ranges the
format doesn't actually define. Entries whose `partition_name` is empty
are skipped, mirroring Heimdall's own `PitEntry::IsFlashable()`
(`strlen(partitionName) != 0`) and `PitData::FindEntry()`, which treat an
empty name as "not a real/flashable slot."

No real device-dumped `.pit` file was available in this task's
environment to cross-check byte-for-byte; the struct layout above was
verified against Heimdall's actual parsing code (`Unpack()`), not just
its header's field declarations, which is the strongest verification
available without a real sample -- but per the checklist in
`docs/ADDING_A_FORMAT.md`, that caveat is called out explicitly here
rather than presenting it as hardware-confirmed.
"""

from __future__ import annotations

from ..common.binstruct import BinStruct, cstr
from ..common.container_base import Entry, OffsetTableContainer
from ..common.native import formats

_FILE_IDENTIFIER = 0x12349876
MAGIC = _FILE_IDENTIFIER.to_bytes(4, "little")

# Generous sanity cap on entry_count purely to fail fast and cleanly on a
# corrupt/garbage header instead of looping (and bounds-checking) over a
# huge bogus count; real Samsung PIT files carry on the order of a few
# dozen entries.
_MAX_ENTRIES = 4096


class _Header(BinStruct):
    _format = "<IIIIHHHHHH"
    _fields = (
        "file_identifier", "entry_count", "unknown1", "unknown2",
        "unknown3", "unknown4", "unknown5", "unknown6", "unknown7", "unknown8",
    )


class _Entry(BinStruct):
    _format = "<IIIIIIIII32s32s32s"
    _fields = (
        "binary_type", "device_type", "identifier", "attributes", "update_attributes",
        "block_size_or_offset", "block_count", "file_offset", "file_size",
        "partition_name", "flash_filename", "fota_filename",
    )


class SamsungPit(OffsetTableContainer):
    MAGIC = MAGIC
    name = "SamsungPit"
    long_name = "Samsung PIT (Partition Information Table)"

    def parse_entries(self, data: bytes) -> list[Entry]:
        header = _Header.unpack_from(data, 0)
        if header.file_identifier != _FILE_IDENTIFIER:
            raise ValueError(f"unexpected PIT file identifier {header.file_identifier:#010x}")
        if header.entry_count > _MAX_ENTRIES:
            raise ValueError(
                f"PIT entry_count {header.entry_count} exceeds sanity cap {_MAX_ENTRIES} -- "
                f"treating as a corrupt header"
            )

        entries = []
        for i in range(header.entry_count):
            entry_offset = _Header.size() + i * _Entry.size()
            raw = _Entry.unpack_from(data, entry_offset)
            name = cstr(raw.partition_name)
            if not name:
                continue  # not flashable -- mirrors PitEntry::IsFlashable()
            entries.append(Entry(name=name, offset=entry_offset, size=_Entry.size()))
        return entries


if not any(info["id"] == "samsung_pit" for info in formats()):
    SamsungPit.register()
