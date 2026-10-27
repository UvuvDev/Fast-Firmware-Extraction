#!/usr/bin/env python3
"""Generate official mkcramfs/cramfsck fixtures and check their bytes.

Requires `docker` able to pull and run `alpine:latest`, whose `cramfs`
package ships the real `mkcramfs`/`cramfsck` (GPL-2.0+, not vendored here --
only their output bytes are committed, the same policy already used for
mkimage/dtc and bsdcpio). `cramfsck` must accept the built image before the
generator writes it out, mirroring the independent-round-trip requirement
already used by the DTBO/boot fixture generators.
"""
import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "alpine:latest"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(info):
    return (json.dumps(info, indent=2) + "\n").encode()


def run_in_alpine(work, script):
    result = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{work}:/work", "-w", "/work", IMAGE, "sh", "-c", script],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(f"{script!r} failed:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def generate():
    if shutil.which("docker") is None:
        raise SystemExit("docker not found on PATH; needed to regenerate fixtures")

    artifacts = {}
    inputs = {
        "small.txt": b"synthetic cramfs payload, repeats repeats repeats repeats\n" * 2,
        "subdir/nested.txt": b"nested synthetic cramfs payload\n" * 3,
        "big.bin": bytes((i * 37) % 256 for i in range(9000)),  # spans 3 blocks, not all-zero
        "empty.bin": b"",
    }
    with tempfile.TemporaryDirectory(prefix="ffe-cramfs-fixtures-") as directory:
        work = Path(directory)
        root = work / "root"
        (root / "subdir").mkdir(parents=True)
        (root / "emptydir").mkdir()
        for name, content in inputs.items():
            (root / name).write_bytes(content)

        log = run_in_alpine(
            work,
            "apk add -q cramfs && mkcramfs root out.cramfs && cramfsck -v out.cramfs",
        )
        if "OK" not in log.splitlines()[-1]:
            raise RuntimeError(f"cramfsck did not confirm the image:\n{log}")
        image = (work / "out.cramfs").read_bytes()
        version = run_in_alpine(work, "apk info cramfs | head -1 | awk '{print $1}'").strip()

    base = ROOT / "tests/fixtures/cramfs"
    artifacts[base / "sample.img"] = image
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.img",
        "native_format": "cramfs",
        "children": {
            "small.txt": {"length": len(inputs["small.txt"]), "sha256": digest(inputs["small.txt"])},
            "subdir/nested.txt": {
                "length": len(inputs["subdir/nested.txt"]),
                "sha256": digest(inputs["subdir/nested.txt"]),
            },
            "big.bin": {"length": len(inputs["big.bin"]), "sha256": digest(inputs["big.bin"])},
            "empty.bin": {"length": 0, "sha256": digest(b"")},
        },
    })

    # Corrupt: claim a superblock size far beyond the actual buffer. This is
    # caught during open()/discovery, unlike corrupting a file's compressed
    # bytes, which this parser (like erofs/ubifs) only decodes lazily on
    # read() -- a pure content-only fixture would be silently accepted by
    # open() alone.
    corrupt = bytearray(image)
    struct.pack_into("<I", corrupt, 4, len(image) + 1_000_000)
    base = ROOT / "tests/fixtures/cramfs_corrupt"
    artifacts[base / "sample.img"] = bytes(corrupt)
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.img",
        "native_format": "cramfs",
        "expect_failure": True,
    })

    artifacts[ROOT / "tests/fixture_sources/cramfs/provenance.json"] = encoded({
        "docker_image": IMAGE,
        "cramfs_package_version": version,
        "commands": [
            ["mkcramfs", "root", "out.cramfs"],
            ["cramfsck", "-v", "out.cramfs"],
        ],
        "inputs": {name: digest(content) for name, content in inputs.items()},
        "corrupt_field": "superblock size (offset 4), set to len(image) + 1_000_000",
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
    print("Official mkcramfs/cramfsck fixtures verified" if args.check else "Official mkcramfs/cramfsck fixtures generated")


if __name__ == "__main__":
    main()
