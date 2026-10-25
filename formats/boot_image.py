"""Android boot image / vendor_boot image container (`ANDROID!`/`VNDRBOOT`
magic) — boot.img, init_boot.img, pvmfw.img (all header versions 0-4, all
sharing the `ANDROID!` magic) and vendor_boot.img/vendor_kernel_boot.img
(`VNDRBOOT`, versions 3-4, including the v4 fragmented vendor ramdisk
table).

Rather than re-deriving the page-alignment and per-header-version offset
math independently, this wraps AOSP's own `unpack_bootimg.py` (Apache-2.0),
vendored verbatim at `third_party/aosp_mkbootimg/unpack_bootimg.py` — see
that directory's NOTICE.md for provenance. That tool is designed to write
each extracted segment to a real file on disk, so this Transform hands it
a temp directory per call and reads the results back into DataBuffers,
rather than porting its logic to operate on an in-memory buffer — the
tradeoff is re-running the real unpacker (and touching a temp directory)
on both the discovery and extraction phase, which is fine at boot-image
sizes (tens of MB, not hundreds).

Doesn't fit `OffsetTableContainer`: the vendored function computes offsets
and writes files in the same pass rather than handing back an
offset/size table we could bounds-check and slice ourselves, so this is
implemented directly against `ContainerTransform` (like
`android_selfextract.py`).
"""

from __future__ import annotations

import io
import os
import tempfile

from binaryninja import DataBuffer, TransformResult, log_error

from ..common.container_base import ContainerTransform
from ..common.native import formats
from ..third_party.aosp_mkbootimg import unpack_bootimg as aosp

_MAGICS = (b"ANDROID!", b"VNDRBOOT")


def _unpack_to_children(data: bytes) -> dict[str, bytes]:
    magic = data[:8]
    with tempfile.TemporaryDirectory(prefix="pixel_fw_bootimg_") as tmp:
        buf = io.BytesIO(data)
        if magic == b"ANDROID!":
            aosp.unpack_boot_image(buf, tmp)
        elif magic == b"VNDRBOOT":
            aosp.unpack_vendor_boot_image(buf, tmp)
        else:
            raise ValueError(f"not a boot/vendor_boot image, magic={magic!r}")

        # Regular files only — the AOSP tool also writes a
        # vendor-ramdisk-by-name/ directory of convenience symlinks for v4
        # vendor_boot images, which os.scandir here naturally excludes since
        # it isn't a file; nothing to decompile independently there anyway
        # (same call made for ext4 symlinks elsewhere in this plugin).
        return {
            entry.name: open(entry.path, "rb").read()
            for entry in os.scandir(tmp)
            if entry.is_file(follow_symlinks=False)
        }


class BootImage(ContainerTransform):
    name = "AndroidBootImage"
    long_name = "Android Boot / Vendor Boot Image"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(0, 8)
        except Exception:
            log_error("AndroidBootImage: failed to read input for signature check")
            return False
        return bytes(head) in _MAGICS

    def perform_decode_with_context(self, context, params) -> bool:
        data = bytes(context.input.read(0, context.input.length))

        try:
            children = _unpack_to_children(data)
        except Exception as e:
            context.transform_result = TransformResult.TransformFailure
            log_error(f"AndroidBootImage: failed to unpack: {e}")
            return False

        if not context.has_available_files:
            context.set_available_files(list(children.keys()))
            return False

        requested = context.requested_files
        if not requested:
            return False

        complete = True
        for name in requested:
            content = children.get(name)
            if content is None:
                context.create_child(
                    DataBuffer(b""), name, result=TransformResult.TransformFailure, message=f"'{name}' not found"
                )
                complete = False
                continue
            context.create_child(DataBuffer(content), name)
        return complete


if not any(info["id"] == "boot_image" for info in formats()):
    BootImage.register()
