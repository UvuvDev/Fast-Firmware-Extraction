#!/usr/bin/env python3
"""Generate official xorriso ISO 9660 fixtures and check their bytes.

Requires `xorriso` (Homebrew's package; GPL-3.0, not vendored here -- only
the generated image bytes are committed, the same policy already used for
every other producer tool in this project). `xorriso -indev ... -find`
round-trips the built image's own file list as an independent check before
the generator accepts it.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(info):
    return (json.dumps(info, indent=2) + "\n").encode()


def run(command, cwd=None):
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def build_tree(work, inputs):
    root = work / "root"
    (root / "subdir").mkdir(parents=True)
    for name, content in inputs.items():
        (root / name).write_bytes(content)
    return root


def generate():
    if shutil.which("xorriso") is None:
        raise SystemExit("xorriso not found on PATH (try: brew install xorriso)")

    artifacts = {}
    inputs = {
        "small.txt": b"synthetic iso9660 payload, repeats repeats repeats repeats\n" * 1,
        "subdir/nested.txt": b"nested synthetic iso9660 payload\n" * 3,
        "big.bin": bytes((i * 53 + 7) % 256 for i in range(9000)),
    }
    with tempfile.TemporaryDirectory(prefix="ffe-iso9660-fixtures-") as directory:
        work = Path(directory)
        root = build_tree(work, inputs)

        # Joliet + Rock Ridge.
        iso_path = work / "test.iso"
        run(["xorriso", "-as", "mkisofs", "-J", "-R", "-V", "FFETEST", "--modification-date=2000010100000000", "-o", str(iso_path), str(root)])
        found = run(["xorriso", "-indev", str(iso_path), "-find", "/", "-type", "f"])
        found_names = sorted(
            line.strip().strip("'").lstrip("/") for line in found.splitlines() if line.strip()
        )
        if found_names != sorted(["small.txt", "subdir/nested.txt", "big.bin"]):
            raise RuntimeError(f"xorriso's own file list didn't match: {found_names}")
        image = iso_path.read_bytes()

        # Rock Ridge only (no Joliet), to exercise the NM-name fallback path.
        rr_path = work / "test_rr.iso"
        run(["xorriso", "-as", "mkisofs", "-R", "-V", "FFERR", "--modification-date=2000010100000000", "-o", str(rr_path), str(root)])
        rr_image = rr_path.read_bytes()

        version = run(["xorriso", "--version"]).splitlines()[0]

    base = ROOT / "tests/fixtures/iso9660"
    artifacts[base / "sample.iso"] = image
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.iso",
        "native_format": "iso9660",
        "children": {name: {"length": len(content), "sha256": digest(content)} for name, content in inputs.items()},
    })

    base = ROOT / "tests/fixtures/iso9660_rockridge_only"
    artifacts[base / "sample.iso"] = rr_image
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.iso",
        "native_format": "iso9660",
        "children": {name: {"length": len(content), "sha256": digest(content)} for name, content in inputs.items()},
    })

    # Corrupt: flip the PVD's own version byte, rejected before any
    # directory is even looked at.
    corrupt = bytearray(image)
    corrupt[16 * 2048 + 6] ^= 0xFF
    base = ROOT / "tests/fixtures/iso9660_corrupt"
    artifacts[base / "sample.iso"] = bytes(corrupt)
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.iso",
        "native_format": "iso9660",
        "expect_failure": True,
    })

    artifacts[ROOT / "tests/fixture_sources/iso9660/provenance.json"] = encoded({
        "xorriso_version": version,
        "commands": [
            ["xorriso", "-as", "mkisofs", "-J", "-R", "-V", "FFETEST", "--modification-date=2000010100000000", "-o", "test.iso", "root"],
            ["xorriso", "-as", "mkisofs", "-R", "-V", "FFERR", "--modification-date=2000010100000000", "-o", "test_rr.iso", "root"],
            ["xorriso", "-indev", "test.iso", "-find", "/", "-type", "f"],
        ],
        "inputs": {name: digest(content) for name, content in inputs.items()},
        "corrupt_field": "PVD version byte (offset 16*2048+6)",
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
    print("Official xorriso ISO 9660 fixtures verified" if args.check else "Official xorriso ISO 9660 fixtures generated")


if __name__ == "__main__":
    main()
