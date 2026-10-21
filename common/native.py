"""Optional Rust backend. This module has no Binary Ninja dependency.

Build with ``cargo build --release`` at the repository root. Only a missing
library selects the Python fallback; a broken ABI or rejected image raises.
"""

from __future__ import annotations

import ctypes
from functools import lru_cache
from pathlib import Path
import sys
import threading
import weakref


@lru_cache(maxsize=1)
def _load_library():
    filename = {
        "darwin": "libfirmware_unpack.dylib",
        "win32": "firmware_unpack.dll",
    }.get(sys.platform, "libfirmware_unpack.so")
    path = Path(__file__).resolve().parent.parent / "target" / "release" / filename
    if not path.is_file():
        return None
    library = ctypes.CDLL(str(path))
    library.ffe_abi_version.argtypes = []
    library.ffe_abi_version.restype = ctypes.c_uint32
    if library.ffe_abi_version() != 4:
        raise RuntimeError("unsupported firmware-unpack ABI; rebuild with cargo build --release")
    library.ffe_format_count.argtypes = []
    library.ffe_format_count.restype = ctypes.c_size_t
    library.ffe_format_info.argtypes = [ctypes.c_size_t, ctypes.c_uint32, ctypes.POINTER(ctypes.c_size_t)]
    library.ffe_format_info.restype = ctypes.c_void_p
    library.ffe_detect.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    library.ffe_detect.restype = ctypes.c_size_t
    # Older ABI-4 builds predate this additive capability and use 64 KiB.
    if hasattr(library, "ffe_probe_limit"):
        library.ffe_probe_limit.argtypes = []
        library.ffe_probe_limit.restype = ctypes.c_size_t
    library.ffe_archive_open.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_size_t]
    library.ffe_archive_open.restype = ctypes.c_int32
    library.ffe_archive_count.argtypes = [ctypes.c_void_p]
    library.ffe_archive_count.restype = ctypes.c_size_t
    library.ffe_archive_flags.argtypes = [ctypes.c_void_p]
    library.ffe_archive_flags.restype = ctypes.c_uint32
    if hasattr(library, "ffe_archive_embedded_range"):
        library.ffe_archive_embedded_range.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                                     ctypes.POINTER(ctypes.c_size_t)]
        library.ffe_archive_embedded_range.restype = ctypes.c_int32
    if hasattr(library, "ffe_archive_diagnostics"):
        library.ffe_archive_diagnostics.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        library.ffe_archive_diagnostics.restype = ctypes.c_void_p
    library.ffe_archive_name.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    library.ffe_archive_name.restype = ctypes.c_void_p
    library.ffe_archive_read.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t]
    library.ffe_archive_read.restype = ctypes.c_int32
    library.ffe_archive_close.argtypes = [ctypes.c_void_p]
    library.ffe_archive_close.restype = None
    return library


def formats() -> tuple[dict[str, str], ...]:
    """Inventory comes from Rust; Python has no per-format declarations."""
    library = _load_library()
    if library is None:
        return ()
    count = library.ffe_format_count()
    if not count:
        raise RuntimeError("native format registry is empty or invalid; run cargo test before loading the plugin")
    result = []
    for index in range(count):
        info = {}
        for field, key in enumerate(("id", "name", "description")):
            length = ctypes.c_size_t()
            pointer = library.ffe_format_info(index, field, ctypes.byref(length))
            if not pointer:
                raise RuntimeError("invalid native format metadata")
            info[key] = ctypes.string_at(pointer, length.value).decode("utf-8")
        result.append(info)
    return tuple(result)


@lru_cache(maxsize=1)
def _inventory():
    return formats()


def probe_limit() -> int:
    library = _load_library()
    if library is None or not hasattr(library, "ffe_probe_limit"):
        return 65536
    return library.ffe_probe_limit()


def detect(data: bytes) -> dict[str, str] | None:
    library = _load_library()
    if library is None:
        return None
    data = bytes(data[:probe_limit()])
    index = library.ffe_detect(data, len(data))
    inventory = _inventory()
    return inventory[index] if index < len(inventory) else None


class NativeArchive:
    """Own a Rust extraction session; names and reads are safe Python copies."""

    def __init__(self, library, handle):
        self._library = library
        self._handle = handle
        self._lock = threading.RLock()
        self._finalizer = weakref.finalize(self, library.ffe_archive_close, handle)
        try:
            self.is_stream = bool(library.ffe_archive_flags(handle) & 1)
            self.embedded_range = None
            if hasattr(library, "ffe_archive_embedded_range"):
                offset, length = ctypes.c_size_t(), ctypes.c_size_t()
                status = library.ffe_archive_embedded_range(handle, ctypes.byref(offset), ctypes.byref(length))
                if status < 0:
                    raise ValueError("native archive returned invalid embedded extent")
                if status:
                    self.embedded_range = (offset.value, offset.value + length.value)
            self.diagnostics = ""
            if hasattr(library, "ffe_archive_diagnostics"):
                length = ctypes.c_size_t()
                pointer = library.ffe_archive_diagnostics(handle, ctypes.byref(length))
                if length.value and not pointer:
                    raise ValueError("native archive returned invalid analysis text")
                if pointer:
                    self.diagnostics = ctypes.string_at(pointer, length.value).decode("utf-8")
            names = []
            for index in range(library.ffe_archive_count(handle)):
                length = ctypes.c_size_t()
                pointer = library.ffe_archive_name(handle, index, ctypes.byref(length))
                if not pointer:
                    raise ValueError("native archive returned an invalid member name")
                names.append(ctypes.string_at(pointer, length.value).decode("utf-8"))
            self.names = tuple(names)
            self._indices = {name: index for index, name in enumerate(names)}
        except Exception:
            self.close()
            raise

    def read(self, name: str) -> bytes:
        with self._lock:
            if not self._finalizer.alive:
                raise ValueError("native archive is closed")
            index = self._indices[name]
            pointer = ctypes.c_void_p()
            length = ctypes.c_size_t()
            error = ctypes.create_string_buffer(1024)
            status = self._library.ffe_archive_read(self._handle, index, ctypes.byref(pointer),
                                                   ctypes.byref(length), error, len(error))
            if status != 0:
                raise ValueError(error.value.decode("utf-8", "replace") or "native extraction failed")
            return ctypes.string_at(pointer, length.value)

    def close(self):
        with self._lock:
            self._finalizer()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def open_archive(kind: str | None, data: bytes) -> NativeArchive | None:
    """Open by stable Rust ID, or detect with kind=None. None means not built."""
    library = _load_library()
    if library is None:
        return None
    data = bytes(data)
    handle = ctypes.c_void_p()
    error = ctypes.create_string_buffer(1024)
    identifier = (kind or "").encode("utf-8")
    status = library.ffe_archive_open(identifier, len(identifier), data, len(data), ctypes.byref(handle), error, len(error))
    if status != 0:
        raise ValueError(error.value.decode("utf-8", "replace") or "native parser failed")
    return NativeArchive(library, handle)
