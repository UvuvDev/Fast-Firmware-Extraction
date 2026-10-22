#!/usr/bin/env python3
"""Generate official mkfs.jffs2/jffs2dump fixtures and check their bytes.

Requires `docker` able to pull and run `alpine:latest`, whose `mtd-utils-jffs`
package ships the real `mkfs.jffs2`/`jffs2dump` (GPL-2.0+, not vendored here
-- only their output bytes are committed, the same policy already used for
mkimage/dtc/mkcramfs/bsdcpio). `jffs2dump` must describe the built image's
node layout before the generator accepts it, mirroring the independent
round-trip requirement the DTBO/boot/cramfs generators already use.

The image is built little-endian (-l), with squashed permissions/ownership
(-q) and faked zero timestamps (-f) so it's deterministic regardless of the
local user or clock, and with rtime disabled (-x rtime) so every file ends
up stored either uncompressed or zlib-compressed -- the two payload
encodings this parser implements.
"""
import argparse
import hashlib
import json
import shutil
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
        "small.txt": b"synthetic jffs2 payload, repeats repeats repeats repeats\n" * 2,
        "subdir/nested.txt": b"nested synthetic jffs2 payload\n" * 3,
        "big.bin": bytes((i * 41 + 11) % 256 for i in range(9000)),  # multiple data nodes
        "empty.bin": b"",
    }
    with tempfile.TemporaryDirectory(prefix="ffe-jffs2-fixtures-") as directory:
        work = Path(directory)
        root = work / "root"
        (root / "subdir").mkdir(parents=True)
        (root / "emptydir").mkdir()
        for name, content in inputs.items():
            (root / name).write_bytes(content)

        # One container, one `apk add`: each run_in_alpine call is a fresh
        # `docker run --rm`, so installing the package in an earlier call
        # would not persist into a later one.
        output = run_in_alpine(
            work,
            "apk add -q mtd-utils-jffs && "
            "mkfs.jffs2 -l -q -f -x rtime -e 65536 -r root -o out.jffs2 && "
            "echo ===DUMP=== && jffs2dump -c out.jffs2 && "
            "echo ===VERSION=== && apk info mtd-utils-jffs | head -1 | awk '{print $1}'",
        )
        dump, version = output.split("===DUMP===\n", 1)[1].split("===VERSION===\n", 1)
        if "Inode" not in dump or "Dirent" not in dump:
            raise RuntimeError(f"jffs2dump did not describe the expected node layout:\n{dump}")
        image = (work / "out.jffs2").read_bytes()
        version = version.strip()

    base = ROOT / "tests/fixtures/jffs2"
    artifacts[base / "sample.img"] = image
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.img",
        "native_format": "jffs2",
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

    # Corrupt: flip a byte inside the first real node's content region (the
    # root dirent's name). This lands inside a field this parser validates
    # eagerly during open() (every node/name/data CRC is checked while
    # scanning, unlike e.g. cramfs's lazily-decoded blocks), so open() alone
    # must already reject it.
    corrupt = bytearray(image)
    corrupt[12 + 40] ^= 0xFF  # one byte into the first dirent's name, after its 40-byte header
    base = ROOT / "tests/fixtures/jffs2_corrupt"
    artifacts[base / "sample.img"] = bytes(corrupt)
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.img",
        "native_format": "jffs2",
        "expect_failure": True,
    })

    artifacts[ROOT / "tests/fixture_sources/jffs2/provenance.json"] = encoded({
        "docker_image": IMAGE,
        "mtd_utils_jffs_package_version": version,
        "commands": [
            ["mkfs.jffs2", "-l", "-q", "-f", "-x", "rtime", "-e", "65536", "-r", "root", "-o", "out.jffs2"],
            ["jffs2dump", "-c", "out.jffs2"],
        ],
        "inputs": {name: digest(content) for name, content in inputs.items()},
        "corrupt_offset": "12 + 40 (one byte into the root dirent's name)",
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
    print("Official mkfs.jffs2/jffs2dump fixtures verified" if args.check else "Official mkfs.jffs2/jffs2dump fixtures generated")


if __name__ == "__main__":
    main()
