"""Shared two-phase discovery/extraction protocol for container transforms.

New formats should subclass :class:`OffsetTableContainer` (fixed/variable
header followed by a flat table of named (offset, size) entries — FBPACK,
Shannon TOC) or :class:`FilesystemContainer` (a tree-walked filesystem —
ext4). Both funnel every container-supplied name through
``common.sanitize`` and bounds-check every offset/size against the actual
input length before slicing, so individual formats can't forget either.
These are the retained Python adapters. New unpackers use the Rust reader
contract described in docs/ADDING_A_FORMAT.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from binaryninja import DataBuffer, Transform, TransformCapabilities, TransformResult, TransformType, log_error

from .sanitize import dedupe_name, sanitize_entry_name


@dataclass(frozen=True)
class Entry:
    name: str
    offset: int
    size: int


class ContainerTransform(Transform):
    transform_type = TransformType.DecodeTransform
    capabilities = TransformCapabilities.TransformSupportsContext | TransformCapabilities.TransformSupportsDetection
    group = "Container"

    MAGIC: bytes = b""

    def can_decode(self, input) -> bool:
        if not self.MAGIC:
            raise NotImplementedError(f"{type(self).__name__}: declare MAGIC or override can_decode()")
        try:
            head = input.read(0, len(self.MAGIC))
            return head == self.MAGIC
        except Exception:
            log_error(f"{type(self).__name__}: failed to read input for signature check")
            return False

    def perform_encode(self, data, params):
        return None

    def perform_decode(self, data: bytes, params: dict) -> Optional[bytes]:
        return None


def _named(raw_names: list[str]) -> dict[str, int]:
    """Sanitize+dedupe a list of raw names, returning safe-name -> original index."""
    named: dict[str, int] = {}
    taken: set[str] = set()
    for index, raw in enumerate(raw_names):
        safe = dedupe_name(sanitize_entry_name(raw, index=index), taken)
        taken.add(safe)
        named[safe] = index
    return named


class OffsetTableContainer(ContainerTransform):
    def parse_entries(self, data: bytes) -> list[Entry]:
        raise NotImplementedError

    def perform_decode_with_context(self, context, params) -> bool:
        data = context.input.read(0, context.input.length)

        try:
            entries = self.parse_entries(data)
        except Exception as e:
            context.transform_result = TransformResult.TransformFailure
            log_error(f"{type(self).__name__}: failed to parse container: {e}")
            return False

        named = _named([e.name for e in entries])

        if not context.has_available_files:
            context.set_available_files(list(named.keys()))
            return False

        requested = context.requested_files
        if not requested:
            return False

        complete = True
        for name in requested:
            index = named.get(name)
            entry = entries[index] if index is not None else None
            if entry is None:
                context.create_child(
                    DataBuffer(b""), name, result=TransformResult.TransformFailure, message=f"'{name}' not found in container"
                )
                complete = False
                continue

            try:
                if entry.offset < 0 or entry.size < 0 or entry.offset + entry.size > len(data):
                    raise ValueError(f"entry '{name}' ({entry.offset}+{entry.size}) exceeds container length {len(data)}")
                content = data[entry.offset:entry.offset + entry.size]
                context.create_child(DataBuffer(content), name)
            except Exception as e:
                context.create_child(DataBuffer(b""), name, result=TransformResult.TransformFailure, message=str(e))
                complete = False

        return complete


class FilesystemContainer(ContainerTransform):
    def configure_child(self, child, path: str) -> None:
        """Optionally select a known decoder for a newly extracted child."""
        pass

    def open_filesystem(self, data: bytes) -> Any:
        raise NotImplementedError

    def list_paths(self, fs: Any) -> list[str]:
        raise NotImplementedError

    def read_file(self, fs: Any, path: str) -> bytes:
        raise NotImplementedError

    def perform_decode_with_context(self, context, params) -> bool:
        data = context.input.read(0, context.input.length)

        # Reopened/re-walked on every call (discovery, then extraction) rather
        # than cached on the context: simplest correct thing, and it keeps
        # this base class stateless. Revisit if a filesystem format's walk
        # time becomes a measured problem on real multi-hundred-MB images.
        try:
            fs = self.open_filesystem(data)
            paths = fs_paths = self.list_paths(fs)
        except Exception as e:
            context.transform_result = TransformResult.TransformFailure
            log_error(f"{type(self).__name__}: failed to open filesystem: {e}")
            return False

        named = _named(fs_paths)
        original_by_index = paths

        if not context.has_available_files:
            context.set_available_files(list(named.keys()))
            return False

        requested = context.requested_files
        if not requested:
            return False

        complete = True
        for name in requested:
            index = named.get(name)
            original_path = original_by_index[index] if index is not None else None
            if original_path is None:
                context.create_child(
                    DataBuffer(b""), name, result=TransformResult.TransformFailure, message=f"'{name}' not found in filesystem"
                )
                complete = False
                continue

            try:
                content = self.read_file(fs, original_path)
                child = context.create_child(DataBuffer(content), name)
                self.configure_child(child, original_path)
            except Exception as e:
                context.create_child(DataBuffer(b""), name, result=TransformResult.TransformFailure, message=str(e))
                complete = False

        return complete
