"""Turn container-supplied entry names/paths into safe, unique child filenames.

Every format in this plugin parses third-party firmware images. An entry
name or filesystem path read from that image is attacker-controlled input,
not a trusted local path, so it must never be used to build a filesystem
path or be handed to ``TransformContext.create_child`` without going
through here first.
"""

from __future__ import annotations

import posixpath

_FALLBACK_NAME = "entry"


class UnsafeEntryNameError(ValueError):
    """Raised when an entry name cannot be sanitized into any safe form."""


def sanitize_entry_name(raw: str, *, index: int) -> str:
    """Normalize a single container-supplied name into a safe relative path.

    Strips null bytes, rejects absolute paths and ``..`` traversal
    components, and collapses empty/whitespace-only results to a
    deterministic fallback name so callers never see an empty child
    filename.

    :param raw: the entry name as read from the container
    :param index: the entry's position in the container, used only to make
        the fallback name deterministic when ``raw`` is unusable
    :return: a safe, relative, forward-slash-separated path
    """
    if raw is None:
        return f"{_FALLBACK_NAME}_{index}"

    name = raw.replace("\x00", "")
    name = name.replace("\\", "/")

    parts = []
    for part in name.split("/"):
        if part in ("", ".", ".."):
            continue
        parts.append(part)

    if not parts:
        return f"{_FALLBACK_NAME}_{index}"

    return posixpath.join(*parts)


def dedupe_name(name: str, taken: set[str]) -> str:
    """Return ``name``, or a numbered variant, that is not already in ``taken``.

    Two distinct raw entries can sanitize to the same safe name (e.g. two
    entries differing only by a null byte or a traversal prefix); silently
    dropping the second would make extraction lossy, so it gets a suffix
    instead.
    """
    if name not in taken:
        return name

    root, ext = posixpath.splitext(name)
    n = 1
    while True:
        candidate = f"{root}~{n}{ext}"
        if candidate not in taken:
            return candidate
        n += 1
