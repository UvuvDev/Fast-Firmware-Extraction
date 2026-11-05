# Adding a format

Adding a new container format to this plugin should cost **one new file
under `formats/`, and nothing else**. Never edit `__init__.py` (it
auto-discovers every module under `formats/`), never edit another format's
file, and only touch `common/` if you've confirmed with the architecture
agent that this format genuinely needs a new shared capability.

## 1. Pick a base class

Almost every container format is one of two shapes:

- **`OffsetTableContainer`** — a header followed by a flat table of named
  `(offset, size)` entries. Examples in this repo: `formats/fbpack.py`
  (FBPACK v1/v2 — a linked-list table and a direct-offset table, both fit),
  `formats/shannon_toc.py` (Shannon baseband TOC).
- **`FilesystemContainer`** — a tree you walk to get paths, then read a
  file by path. Example: `formats/ext4.py`.

If neither fits (rare — one example so far: `formats/android_selfextract.py`,
a "detect and carve exactly one child" shape), implement
`perform_decode_with_context` directly against `ContainerTransform` and
say so in your PR/summary — that's a signal for the architecture agent to
look at whether it's actually a recurring shape worth a third base class,
not something to decide unilaterally.

## 2. Template — `OffsetTableContainer`

```python
"""One paragraph: what real-world artifact is this, where does it show up
(what device/build produces it), and where did you verify the struct
layout — a real sample file, a public reference implementation (name it,
note its license), or both. If you didn't verify against a real sample,
say so explicitly.
"""

from __future__ import annotations

from ..common.binstruct import BinStruct, cstr
from ..common.container_base import Entry, OffsetTableContainer

MAGIC = b"...."


class _HeaderOrEntry(BinStruct):
    _format = "<..."
    _fields = ("field_a", "field_b")


class MyFormat(OffsetTableContainer):
    MAGIC = MAGIC
    name = "MyFormat"
    long_name = "My Format, Spelled Out"

    def parse_entries(self, data: bytes) -> list[Entry]:
        # Parse the header + entry table, return Entry(name, offset, size)
        # per extractable member. Let BinStruct's bounds checking raise on
        # a truncated/corrupt buffer — the base class turns that into
        # TransformResult.TransformFailure for you.
        ...


MyFormat.register()
```

`OffsetTableContainer` handles: the discovery/extraction two-phase
protocol, sanitizing and deduping every entry name before it becomes a
child filename, bounds-checking every `offset`/`size` against the actual
buffer length, and mapping any exception out of `parse_entries` to a
proper extraction failure. You only write the parsing logic.

## 3. Template — `FilesystemContainer`

```python
from ..common.container_base import FilesystemContainer


class MyFilesystem(FilesystemContainer):
    name = "MyFilesystem"
    long_name = "My Filesystem"

    def can_decode(self, input) -> bool:
        ...  # usually a magic/superblock probe; see ext4.py for an
             # example that has to check two possible superblock offsets

    def open_filesystem(self, data: bytes):
        ...  # return whatever object your list_paths/read_file want

    def list_paths(self, fs) -> list[str]:
        ...  # every regular file's full path; skip symlinks — nothing to
             # decompile independently, see ext4.py's rationale

    def read_file(self, fs, path: str) -> bytes:
        ...


MyFilesystem.register()
```

## 4. Struct layouts: verify, don't guess

A wrong byte offset in a firmware parser is a silent-wrong-answer failure
mode, not a crash — it produces plausible-looking garbage. Before writing
`parse_entries`/`read_file`, in priority order:

1. If you have a real sample of the format, hex-dump it and cross-check
   your field offsets against multiple real entries (not just one) —
   e.g. does `entry[i].offset + entry[i].size == entry[i+1].offset` where
   you'd expect contiguity? `ext4.py` and `shannon_toc.py` were both
   validated this way against real Pixel/Tensor firmware.
2. If a public reference implementation exists, read its actual source
   (not just docs/blog posts describing it) and note what you checked it
   against in your module docstring, including its license.
3. If you can do neither, say so explicitly in the docstring rather than
   presenting a guessed layout as settled — see the caution in
   `shannon_toc.py`'s docstring for the tone to match.

**A fourth option, when a permissively-licensed (MIT/BSD/Apache) reference
implementation exists in a form you can actually call:** vendor it
verbatim into `third_party/<project>/` rather than re-deriving its logic.
`formats/boot_image.py` does this with AOSP's own `unpack_bootimg.py` —
see `third_party/aosp_mkbootimg/NOTICE.md` for the provenance-tracking
pattern (fetch the file unmodified, note the exact source URL/commit and
license, never hand-edit it — re-fetch wholesale if it needs to change).
This only works when the reference is something you can realistically
call (a self-contained script, ideally), not when it's deeply
disk-I/O-oriented C with no Python bindings — `erofs.py` hit that wall
with `erofs-utils` and ported the algorithm by hand instead (still reading
the real MIT-available source for the exact logic, just not vendoring it
as a callable dependency). Use your judgment; note which path you took
and why in the module docstring either way.

## 5. Security — every input here is a third-party firmware blob

- Never build a filesystem path or child name directly from a
  container-supplied string — go through `common/sanitize.py`
  (`OffsetTableContainer`/`FilesystemContainer` already do this for you;
  only relevant if you're writing `perform_decode_with_context` by hand).
- Never slice/read using an offset or size from the file without checking
  it against the buffer's actual length first. `BinStruct.unpack_from`
  and the base classes' entry extraction already do this — don't
  reimplement raw `struct.unpack_from` calls with unchecked offsets
  outside of them.
- Prefer failing loudly (`raise`, which the base class turns into
  `TransformResult.TransformFailure`) over guessing/truncating/clamping
  silently.

## 6. Tests — add a fixture, not a test function

Testing is data-driven (`tests/test_formats.py`): every directory under
`tests/fixtures/` with a `sample.*` + `expected.json` gets run through
`TransformSession` automatically. Add a new format's test coverage by
adding a fixture directory, built with a small throwaway script (see any
existing `tests/fixtures/*/` for the shape of `expected.json` — a map of
expected child name to `length`/`sha256`, or `"expect_failure": true` for
a fixture that should fail cleanly). Keep samples minimal and synthetic —
don't check in real multi-megabyte firmware images; validate against real
samples locally during development, but the committed fixture is a
from-scratch minimal file exercising the same code paths.

Run the suite:

```bash
./scripts/run_tests.sh -v
```

(needs a licensed local Binary Ninja install; see `scripts/run_tests.sh`
for the `BN_APP` environment variable if yours isn't at the default path,
and run `python3 -m venv .venv && .venv/bin/pip install pytest` once first.)

## 7. Checklist

- [ ] one new file under `formats/`
- [ ] `MAGIC` declared, or a justified custom `can_decode`
- [ ] subclasses `OffsetTableContainer`/`FilesystemContainer`, or the
      architecture agent signed off on doing it by hand
- [ ] struct layout verified against a real sample and/or a named,
      licensed reference — not guessed
- [ ] `.register()` call at module level (not inside a function)
- [ ] fixture added under `tests/fixtures/` — happy path plus at least
      one corrupt/truncated case
- [ ] `./scripts/run_tests.sh` passes
- [ ] Update README.md to add the format(s) you just added
