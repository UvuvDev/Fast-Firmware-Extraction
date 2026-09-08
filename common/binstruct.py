"""Declarative fixed-layout struct parsing for header/entry-table formats.

Most container formats in this plugin are "read a fixed-size C struct at a
known offset." Declaring the layout once as a ``BinStruct`` subclass (format
string + field names) instead of hand-writing ``struct.unpack_from`` calls
with numeric offsets sprinkled through the parser keeps field-transcription
errors easy to spot in review, which matters most exactly when there are
many small format files and little time to review each one deeply.
"""

from __future__ import annotations

import struct
from typing import Any, ClassVar


class BinStruct:
    _format: ClassVar[str] = ""
    _fields: ClassVar[tuple[str, ...]] = ()

    def __init__(self, *values: Any) -> None:
        if len(values) != len(self._fields):
            raise ValueError(f"{type(self).__name__}: expected {len(self._fields)} fields, got {len(values)}")
        for field, value in zip(self._fields, values):
            setattr(self, field, value)

    def __repr__(self) -> str:
        fields = ", ".join(f"{f}={getattr(self, f)!r}" for f in self._fields)
        return f"{type(self).__name__}({fields})"

    @classmethod
    def size(cls) -> int:
        return struct.calcsize(cls._format)

    @classmethod
    def unpack_from(cls, data: bytes, offset: int) -> "BinStruct":
        """Parse one instance at ``offset``, bounds-checked against ``data``."""
        size = cls.size()
        if offset < 0 or offset + size > len(data):
            raise ValueError(f"{cls.__name__}: {size}-byte read at offset {offset} exceeds buffer length {len(data)}")
        values = struct.unpack_from(cls._format, data, offset)
        return cls(*values)


def cstr(raw: bytes) -> str:
    """Decode a fixed-size, null-padded/terminated C string field."""
    return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
