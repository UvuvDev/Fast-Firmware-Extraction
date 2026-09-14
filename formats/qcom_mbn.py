"""Qualcomm legacy MBN firmware header — the small flat (non-ELF) header
that historically wrapped early Qualcomm boot-chain firmware images (e.g.
`sbl1.mbn`, and `tz.mbn`/`rpm.mbn` before those moved to plain ELF). Many
*modern* Qualcomm firmware blobs are just ELF files, which Binary Ninja's
core already parses directly — this format is specifically the older,
non-ELF "80-byte SBL header" shape, sometimes called `mbn_hdr_v2` /
`MI_BOOT_SBL_HDR` in Qualcomm's own tooling.

Struct layout and magic/codeword constants verified against
`util/qualcomm/mbn_tools.py` as vendored into coreboot (BSD-3-Clause,
`SPDX-License-Identifier: BSD-3-Clause`; this is the same Qualcomm/
CodeAurora BSP `mbn_tools.py` referenced by name in this task — coreboot
carries an unmodified copy under its own tree):
https://raw.githubusercontent.com/coreboot/coreboot/master/util/qualcomm/mbn_tools.py
Its `Sbl_Hdr` class defines this exact header as twenty native-endian
(little-endian on the real hosts/targets involved) `uint32_t` fields, in
order: `codeword, magic, image_id, reserved_1, reserved_2, image_src,
image_dest_ptr, image_size, code_size, sig_ptr, sig_size, cert_chain_ptr,
cert_chain_size, oem_root_cert_sel, oem_num_root_certs,
booting_image_config, reserved_6, reserved_7, reserved_8, reserved_9`
(80 bytes total), identified by the constant pair `FLASH_CODE_WORD =
0x844BDCD1` (`codeword`) and `MAGIC_NUM = 0x73D71034` (`magic`).

Cross-checked (read-only, for the facts — field names/order/widths are
not copyrightable expression, and nothing below is copied from it) against
`openpst/libopenpst`'s `include/qualcomm/mbn.h` (GPLv3) — an independent
transcription of the identical field list under the name
`MbnHeader80byte`, including the same `codeword`/`magic` pair and the same
`MBN_EIGHTY_BYTE_MAGIC = 0x73D71034` value — which agrees field-for-field
with `mbn_tools.py` above. This module reimplements the layout from
scratch against `mbn_tools.py`; it vendors neither source.

**File-offset caveat (the part that actually took verifying, not just
transcribing):** `mbn_tools.py`'s own header-construction code assigns
`sig_ptr = image_dest_ptr + code_size` and `cert_chain_ptr =
image_dest_ptr + code_size + signature_size` — i.e. `sig_ptr` and
`cert_chain_ptr` are **RAM load addresses** relative to `image_dest_ptr`,
not file byte offsets, and `image_dest_ptr` is typically a nonzero
hardware load address (e.g. an SBL RAM base). Using those two fields
directly as file offsets would silently produce nonsense (or, more often,
an out-of-bounds offset that this plugin's base class would reject
outright). The real on-disk layout is instead the plain concatenation
`mbn_tools.py` itself performs when finishing a signed image
(`concat_files(signed_image_out, [binary_in, signature, cert_chain_out])`,
where `binary_in` is the 80-byte header immediately followed by the code —
`image_src` is set to the header's own size, `MI_BOOT_SBL_HDR_SIZE`, i.e.
"code starts right after the header"). So this module derives the three
region offsets purely from the header size and the `*_size` fields —
`code` at `header_size`, `signature` at `header_size + code_size`,
`cert_chain` at `header_size + code_size + sig_size` — rather than
trusting `sig_ptr`/`cert_chain_ptr`.

Single fixed header shape, no version field to dispatch on (unlike
`formats/fbpack.py`/`qcdt.py`) — only this one on-disk layout is
implemented.
"""

from __future__ import annotations

from ..common.binstruct import BinStruct
from ..common.container_base import Entry, OffsetTableContainer

_FLASH_CODE_WORD = 0x844BDCD1
_MAGIC_NUM = 0x73D71034
MAGIC = _FLASH_CODE_WORD.to_bytes(4, "little") + _MAGIC_NUM.to_bytes(4, "little")


class _Header(BinStruct):
    _format = "<20I"
    _fields = (
        "codeword", "magic", "image_id", "reserved_1", "reserved_2",
        "image_src", "image_dest_ptr", "image_size", "code_size",
        "sig_ptr", "sig_size", "cert_chain_ptr", "cert_chain_size",
        "oem_root_cert_sel", "oem_num_root_certs", "booting_image_config",
        "reserved_6", "reserved_7", "reserved_8", "reserved_9",
    )


class QcomMbn(OffsetTableContainer):
    MAGIC = MAGIC
    name = "QcomMbn"
    long_name = "Qualcomm Legacy MBN Firmware Header"

    def parse_entries(self, data: bytes) -> list[Entry]:
        header = _Header.unpack_from(data, 0)
        if header.codeword != _FLASH_CODE_WORD or header.magic != _MAGIC_NUM:
            raise ValueError("unexpected MBN codeword/magic pair")

        code_offset = _Header.size()
        sig_offset = code_offset + header.code_size
        cert_offset = sig_offset + header.sig_size

        return [
            Entry(name="code", offset=code_offset, size=header.code_size),
            Entry(name="signature", offset=sig_offset, size=header.sig_size),
            Entry(name="cert_chain", offset=cert_offset, size=header.cert_chain_size),
        ]


QcomMbn.register()
