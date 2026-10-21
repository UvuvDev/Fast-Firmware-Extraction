"""A small proprietary vendor header seen wrapping consumer router/mesh-Wi-Fi
firmware update packages (observed on an "X50/X55/X3000"-family device): a
handful of bytes that look like an integrity hash, followed by an ASCII
tag `fw-type:<value>\\n` (`Cloud` in the one real sample this was checked
against — presumably distinguishing OTA-portal-served updates from other
distribution channels; other tag values are plausible but unconfirmed),
then zero padding out to wherever the real payload starts.

This is the one format in this plugin verified against only a **single**
real sample, with no public spec or reference implementation found (this
isn't a widely-documented format the way FBPACK/ext4/EROFS are) — flagged
here explicitly rather than presented as settled, per this project's own
rule for that situation. Detection is deliberately narrow (the literal
`fw-type:` tag within a small prefix) to minimize false positives against
unrelated files, at the cost of only matching this exact vendor
convention.

Like `android_selfextract.py`, this is a "detect and carve exactly one
child" shape: it doesn't try to interpret the header's hash bytes or the
padding, just locates where the real firmware image begins (scanning
forward for a known container magic, currently just `UBI#`) and carves
from there to EOF. Implemented directly against `ContainerTransform` for
the same reason `android_selfextract.py` is — it isn't an offset-table or
a filesystem, and this is the second instance of the "carve one child"
shape, which is worth the architecture agent noting in case a
`SingleChildContainer` base is warranted now.
"""

from __future__ import annotations

from binaryninja import DataBuffer, TransformResult, log_error

from ..common.container_base import ContainerTransform
from ..common.native import formats

_TAG = b"fw-type:"
_TAG_SEARCH_LIMIT = 256  # the tag has been seen within the first ~30 bytes; generous margin
_PAYLOAD_MAGIC_SEARCH_LIMIT = 1 << 16  # payload has been seen starting a few KB in
_CHILD_NAME = "payload.bin"

# Magic bytes of container formats known to appear as this wrapper's payload.
# Add to this list (not a new file) if another payload format shows up under
# the same vendor header — this one small, closed set is the whole point of
# this format's existence, unlike every other format here.
_KNOWN_PAYLOAD_MAGICS = (b"UBI#",)


def _find_payload_offset(prefix: bytes) -> int | None:
    if _TAG not in prefix[:_TAG_SEARCH_LIMIT]:
        return None
    for magic in _KNOWN_PAYLOAD_MAGICS:
        idx = prefix.find(magic)
        if idx != -1:
            return idx
    return None


class FwTypeHeader(ContainerTransform):
    name = "FwTypeHeader"
    long_name = "Vendor fw-type Header"

    def can_decode(self, input) -> bool:
        try:
            prefix = bytes(input.read(0, _PAYLOAD_MAGIC_SEARCH_LIMIT))
        except Exception:
            log_error("FwTypeHeader: failed to read input for signature check")
            return False
        return _find_payload_offset(prefix) is not None

    def perform_decode_with_context(self, context, params) -> bool:
        total_len = context.input.length
        prefix = bytes(context.input.read(0, min(_PAYLOAD_MAGIC_SEARCH_LIMIT, total_len)))
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


if not any(info["id"] == "fwtype_header" for info in formats()):
    FwTypeHeader.register()
