"""Android vendor-blob self-extracting shell wrapper. Google's AOSP vendor
blob distribution scripts (and Pixel factory-image vendor blobs generally)
ship as a bash script: a license banner requiring an interactive
"I ACCEPT" at a TTY, followed by a `tail -n +N $0 | tar zxv` line that
carves everything from line N onward off the end of the script file
itself and pipes it into tar. That carved payload is just a gzip'd tar —
core Binary Ninja already knows how to walk that — so this transform's
only job is finding N and carving from there to EOF as a single child; it
never runs the script or its license prompt.

This is a "detect, then carve exactly one child" shape, different from
every other format in this plugin — implemented directly against
``ContainerTransform`` rather than force-fit into ``OffsetTableContainer``
or ``FilesystemContainer``. If a second format turns up needing the same
shape, that's the trigger to extract a shared ``SingleChildContainer``
base (see PROPOSAL.md); one instance on its own isn't reason enough.

Only a bounded prefix is ever scanned to find the marker line — real
license banners are a few KB, and these scripts can be hundreds of
megabytes once the appended payload is included, so reading the whole
file just to locate a line number near the top would be wasteful.
"""

from __future__ import annotations

import re

from binaryninja import DataBuffer, TransformResult, log_error

from ..common.container_base import ContainerTransform
from ..common.native import formats

_PREFIX_SCAN_LIMIT = 1 << 20  # generously more than any real license banner
_MARKER = re.compile(rb"tail\s+-n\s+\+(\d+)\s+\$0\s*\|\s*tar", re.IGNORECASE)
_CHILD_NAME = "payload.gz"


def _line_start_offset(prefix: bytes, line_number: int) -> int:
    """Byte offset of the start of `line_number` (1-indexed) within `prefix`."""
    pos = 0
    for _ in range(line_number - 1):
        pos = prefix.index(b"\n", pos) + 1
    return pos


def _find_payload_offset(prefix: bytes) -> int | None:
    match = _MARKER.search(prefix)
    if not match:
        return None
    try:
        return _line_start_offset(prefix, int(match.group(1)))
    except ValueError:
        return None  # fewer newlines in the scanned prefix than the script's own line number claims


class AndroidSelfExtract(ContainerTransform):
    name = "AndroidSelfExtract"
    long_name = "Android self-extracting vendor blob"

    def can_decode(self, input) -> bool:
        try:
            prefix = bytes(input.read(0, _PREFIX_SCAN_LIMIT))
        except Exception:
            log_error("AndroidSelfExtract: failed to read input for signature check")
            return False
        return prefix.startswith(b"#!") and _find_payload_offset(prefix) is not None

    def perform_decode_with_context(self, context, params) -> bool:
        total_len = context.input.length
        prefix = bytes(context.input.read(0, min(_PREFIX_SCAN_LIMIT, total_len)))
        offset = _find_payload_offset(prefix)
        if offset is None:
            context.transform_result = TransformResult.TransformFailure
            return False

        if not context.has_available_files:
            context.set_available_files([_CHILD_NAME])
            return False

        requested = context.requested_files
        if not requested or _CHILD_NAME not in requested:
            return False

        payload = context.input.read(offset, total_len - offset)
        context.create_child(DataBuffer(payload), _CHILD_NAME)
        return True


if not any(info["id"] == "android_selfextract" for info in formats()):
    AndroidSelfExtract.register()
