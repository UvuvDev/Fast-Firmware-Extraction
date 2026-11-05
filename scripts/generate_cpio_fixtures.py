#!/usr/bin/env python3
"""Generate official bsdcpio "newc" fixtures and check their bytes.

Requires `cpio` (macOS's built-in bsdcpio/libarchive) on PATH. Its structural
encoding (magic, field widths, name/data padding, trailer) comes straight
from that independent tool. The advisory header fields it doesn't matter for
parsing (ino, uid, gid, nlink, mtime, dev{major,minor}, rdev{major,minor},
check) are zeroed afterward so the committed bytes stay reproducible across
machines and users, instead of depending on local uid/gid/mtime.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

ZEROED_FIELD_OFFSETS = [6, 22, 30, 38, 46, 62, 70, 78, 86, 102]  # relative to each header start
HEADER_SIZE = 110


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(info):
    return (json.dumps(info, indent=2) + "\n").encode()


def normalize(archive):
    """Zero the advisory fields of every "070701" header in the stream."""
    archive = bytearray(archive)
    offset = 0
    while True:
        if archive[offset : offset + 6] != b"070701":
            raise RuntimeError(f"expected cpio magic at {offset}")
        for field_offset in ZEROED_FIELD_OFFSETS:
            start = offset + field_offset
            archive[start : start + 8] = b"00000000"
        namesize = int(archive[offset + 94 : offset + 102], 16)
        filesize = int(archive[offset + 54 : offset + 62], 16)
        name_end = offset + HEADER_SIZE + namesize
        name = bytes(archive[offset + HEADER_SIZE : name_end - 1])
        data_start = (name_end + 3) & ~3
        data_end = data_start + filesize
        if name == b"TRAILER!!!":
            return bytes(archive[:data_end])
        offset = (data_end + 3) & ~3


def generate():
    if shutil.which("cpio") is None:
        raise SystemExit("cpio not found on PATH; needed to regenerate fixtures")

    artifacts = {}
    inputs = {
        "file1.txt": b"synthetic cpio file one\n" * 11,
        "subdir/nested.bin": b"synthetic nested cpio payload" * 7,
        "empty.bin": b"",
    }
    with tempfile.TemporaryDirectory(prefix="ffe-cpio-fixtures-") as directory:
        work = Path(directory)
        (work / "subdir").mkdir()
        for name, content in inputs.items():
            (work / name).write_bytes(content)

        file_list = ("\n".join(inputs) + "\n").encode()
        result = subprocess.run(
            ["cpio", "-o", "-H", "newc"],
            cwd=work,
            input=file_list,
            capture_output=True,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
        archive = normalize(result.stdout)

    base = ROOT / "tests/fixtures/cpio_newc"
    artifacts[base / "sample.cpio"] = archive
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.cpio",
        "native_format": "cpio_newc",
        "children": {
            "file1.txt": {"length": len(inputs["file1.txt"]), "sha256": digest(inputs["file1.txt"])},
            "subdir/nested.bin": {
                "length": len(inputs["subdir/nested.bin"]),
                "sha256": digest(inputs["subdir/nested.bin"]),
            },
            "empty.bin": {"length": 0, "sha256": digest(b"")},
        },
    })

    # Corrupt: truncate right after the first entry's header, before its name/data.
    base = ROOT / "tests/fixtures/cpio_newc_corrupt"
    artifacts[base / "sample.cpio"] = archive[: HEADER_SIZE + 2]
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.cpio",
        "native_format": "cpio_newc",
        "expect_failure": True,
    })

    artifacts[ROOT / "tests/fixture_sources/cpio_newc/provenance.json"] = encoded({
        "cpio_version": subprocess.run(["cpio", "--version"], capture_output=True, text=True).stdout.strip(),
        "command": ["cpio", "-o", "-H", "newc"],
        "file_list": list(inputs),
        "inputs": {name: digest(content) for name, content in inputs.items()},
        "zeroed_field_offsets": ZEROED_FIELD_OFFSETS,
        "artifacts": {str(path.relative_to(ROOT)): digest(data) for path, data in artifacts.items()},
    })
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for path, content in generate().items():
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                raise SystemExit(f"fixture differs: {path.relative_to(ROOT)}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    print("Official bsdcpio fixtures verified" if args.check else "Official bsdcpio fixtures generated")


if __name__ == "__main__":
    main()
