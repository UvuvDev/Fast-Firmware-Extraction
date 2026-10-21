"""Android Sparse Image format ("simg") — the wire format `fastboot flash`
and Android's OTA/imgdiff tooling use for shipping large filesystem images
(ext4, erofs, f2fs, ...) compactly: long runs of zero-filled or
repeated-pattern blocks are described by a chunk header instead of being
stored literally.

Reconstructs the original flat image (raw/fill/don't-care chunks
concatenated in order; CRC32 chunks are verification metadata, not
output). This is a plain decode `Transform`, not a container — a sparse
image always reconstructs to exactly one flat blob, which is itself very
often another format this plugin or Binary Ninja core already knows how to
open (ext4, ...), so it chains automatically the same way core's
Gzip/Zlib do, rather than exposing anything to select.

Struct layout confirmed against AOSP's own
`platform/system/core/libsparse/sparse_format.h` (Apache-2.0).
"""

from __future__ import annotations

import struct
from typing import Optional

from binaryninja import Transform, TransformCapabilities, TransformType, log_error

from ..common.native import formats

MAGIC = b"\x3a\xff\x26\xed"  # 0xed26ff3a, as it appears on disk (little-endian)

_HEADER_FORMAT = "<IHHHHIIII"
_CHUNK_FORMAT = "<HHII"
_CHUNK_HEADER_SIZE = struct.calcsize(_CHUNK_FORMAT)

_CHUNK_RAW = 0xCAC1
_CHUNK_FILL = 0xCAC2
_CHUNK_DONT_CARE = 0xCAC3
_CHUNK_CRC32 = 0xCAC4


def _unsparse(data: bytes) -> bytes:
    (magic, major, _minor, file_hdr_sz, chunk_hdr_sz, blk_sz, total_blks,
     total_chunks, _checksum) = struct.unpack_from(_HEADER_FORMAT, data, 0)
    if magic != 0xED26FF3A:
        raise ValueError(f"bad sparse magic {magic:#x}")
    if major != 1:
        raise ValueError(f"unsupported sparse major version {major}")

    out = bytearray(total_blks * blk_sz)
    out_block = 0
    pos = file_hdr_sz

    for _ in range(total_chunks):
        if pos + chunk_hdr_sz > len(data):
            raise ValueError("truncated chunk header")
        chunk_type, _reserved, chunk_sz, total_sz = struct.unpack_from(_CHUNK_FORMAT, data, pos)
        data_start = pos + chunk_hdr_sz
        data_len = total_sz - chunk_hdr_sz
        out_start = out_block * blk_sz
        out_len = chunk_sz * blk_sz

        if out_start < 0 or out_len < 0 or out_start + out_len > len(out):
            raise ValueError(f"chunk at block {out_block} overruns the declared {total_blks}-block output")

        if chunk_type == _CHUNK_RAW:
            if data_len != out_len or data_start + data_len > len(data):
                raise ValueError("raw chunk size mismatch or truncated input")
            out[out_start:out_start + out_len] = data[data_start:data_start + data_len]
        elif chunk_type == _CHUNK_FILL:
            if data_len != 4 or data_start + 4 > len(data):
                raise ValueError("fill chunk missing its 4-byte pattern")
            pattern = data[data_start:data_start + 4]
            out[out_start:out_start + out_len] = pattern * (out_len // 4)
        elif chunk_type in (_CHUNK_DONT_CARE, _CHUNK_CRC32):
            pass  # don't-care is already zero-filled; CRC32 carries no output bytes
        else:
            raise ValueError(f"unknown sparse chunk type {chunk_type:#x}")

        out_block += chunk_sz
        pos += total_sz

    if out_block != total_blks:
        raise ValueError(f"chunks cover {out_block} blocks, header declares {total_blks}")

    return bytes(out)


class SparseImage(Transform):
    transform_type = TransformType.DecodeTransform
    capabilities = TransformCapabilities.TransformSupportsDetection
    name = "AndroidSparse"
    long_name = "Android Sparse Image"
    group = "Container"

    def can_decode(self, input) -> bool:
        try:
            head = input.read(0, 4)
        except Exception:
            log_error("AndroidSparse: failed to read input for signature check")
            return False
        return bytes(head) == MAGIC

    def perform_decode(self, data: bytes, params: dict) -> Optional[bytes]:
        try:
            return _unsparse(bytes(data))
        except Exception as e:
            log_error(f"AndroidSparse: failed to unsparse image: {e}")
            return None

    def perform_encode(self, data, params):
        return None


if not any(info["id"] == "sparse_image" for info in formats()):
    SparseImage.register()
