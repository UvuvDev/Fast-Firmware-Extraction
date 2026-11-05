#!/usr/bin/env python3
"""Generate official lpmake/lpdump/lpunpack fixtures and check their bytes.

Requires `docker` able to pull and run `alpine:latest`, whose
`android-tools-lpmake`/`android-tools-lpunpack`/`android-tools-lpdump`/
`android-tools-img2simg` packages ship AOSP's actual partition_tools
(Apache-2.0). That source is not vendored here; only the generated image
bytes are committed, the same policy already used for mkimage/dtc/mkcramfs/
mkfs.jffs2/bsdcpio. `lpunpack`'s own extraction must reproduce the original
partition inputs byte for byte before the generator accepts the image,
mirroring the independent-round-trip requirement the DTBO/boot/cramfs/jffs2
generators already use.

Partition payloads must be exact multiples of the 4 KiB block size (an
`img2simg` quirk in this package build asserts otherwise). The image is
built with an explicit --alignment so it doesn't need to be enormous: a
default device/partition alignment on real hardware is often 1 MiB, which
would make even a minimal two-partition image megabytes in size.
A "retrofit" fixture is also generated: lpmake, given --device for more than
one block device, writes one *separate* file per device (named
super_<devicename>.img) rather than one combined image -- there is no
single-file retrofit super.img, on a real device or otherwise. This parser
only ever reads one buffer, so retrofit support means accepting the
concatenation of every device's own file, metadata-holding device first;
the fixture here is exactly that concatenation, byte for byte what AOSP's
own `lpunpack -i <device_b> <device_a>` was separately confirmed to extract
correctly (not concatenated, since lpunpack takes multiple file arguments,
which this parser's single-buffer `open()` cannot).
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
        "system.img": (b"synthetic super-image system payload\n" * 215)[:8192].ljust(8192, b"\0"),
        "vendor.img": (b"synthetic super-image vendor payload\n" * 221)[:8192].ljust(8192, b"\0"),
    }
    with tempfile.TemporaryDirectory(prefix="ffe-android-super-fixtures-") as directory:
        work = Path(directory)
        for name, content in inputs.items():
            (work / name).write_bytes(content)

        output = run_in_alpine(
            work,
            "apk add -q android-tools-lpmake android-tools-lpunpack "
            "android-tools-lpdump android-tools-img2simg && "
            "img2simg system.img system.simg && "
            "img2simg vendor.img vendor.simg && "
            "lpmake -d 65536 -m 4096 -s 1 --alignment=4096 "
            "-p system:none:8192 -p vendor:none:8192 "
            "-i system=system.simg -i vendor=vendor.simg "
            "-F -o super.img && "
            "mkdir unpacked && lpunpack super.img unpacked && "
            "echo ===DUMP=== && lpdump super.img",
        )
        dump = output.split("===DUMP===\n", 1)[1]
        if "system" not in dump or "vendor" not in dump:
            raise RuntimeError(f"lpdump did not describe the expected partitions:\n{dump}")
        image = (work / "super.img").read_bytes()
        for name, content in inputs.items():
            extracted = (work / "unpacked" / name).read_bytes()
            if extracted != content:
                raise RuntimeError(f"independent lpunpack round trip failed for {name}")
        version = run_in_alpine(
            work, "apk info android-tools-lpmake | head -1 | awk '{print $1}'"
        ).strip()

    base = ROOT / "tests/fixtures/android_super"
    artifacts[base / "sample.img"] = image
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.img",
        "native_format": "android_super",
        "children": {
            "system": {"length": len(inputs["system.img"]), "sha256": digest(inputs["system.img"])},
            "vendor": {"length": len(inputs["vendor.img"]), "sha256": digest(inputs["vendor.img"])},
        },
    })

    # Corrupt: flip the magic of *both* the primary and backup geometry
    # copies (offsets 4096 and 8192). There is no further fallback once
    # geometry itself can't be read, unlike the metadata header/tables,
    # which do have a backup copy -- see falls_back_to_the_backup_metadata_
    # copy_when_the_primary_is_corrupt in the module's own tests for that.
    corrupt = bytearray(image)
    corrupt[4096] ^= 0xFF
    corrupt[8192] ^= 0xFF
    base = ROOT / "tests/fixtures/android_super_corrupt"
    artifacts[base / "sample.img"] = bytes(corrupt)
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.img",
        "native_format": "android_super",
        "expect_failure": True,
    })

    # Retrofit: two separate physical block devices (super_a holds the
    # metadata, super_b is pure headerless data), with a third partition
    # sized so its extents genuinely span both devices.
    retrofit_inputs = {
        "system.img": inputs["system.img"],
        "vendor.img": inputs["vendor.img"],
        "big.img": (b"synthetic super-image cross-device payload\n" * 850)[:36864].ljust(36864, b"\0"),
    }
    with tempfile.TemporaryDirectory(prefix="ffe-android-super-retrofit-") as directory:
        work = Path(directory)
        for name, content in retrofit_inputs.items():
            (work / name).write_bytes(content)

        output = run_in_alpine(
            work,
            "apk add -q android-tools-lpmake android-tools-lpunpack "
            "android-tools-lpdump android-tools-img2simg && "
            "img2simg system.img system.simg && "
            "img2simg vendor.img vendor.simg && "
            "img2simg big.img big.simg && mkdir -p outdir && "
            "lpmake -m 4096 -s 1 "
            "--device=super_a:65536:4096 --device=super_b:16384:4096 --super-name=super_a "
            "-p system:none:8192 -p vendor:none:8192 -p big:none:36864 "
            "-i system=system.simg -i vendor=vendor.simg -i big=big.simg "
            "-F -o outdir && "
            "mkdir unpacked && "
            "lpunpack -i outdir/super_super_b.img outdir/super_super_a.img unpacked && "
            "echo ===DUMP=== && lpdump outdir/super_super_a.img",
        )
        dump = output.split("===DUMP===\n", 1)[1]
        if "super_b" not in dump or "big" not in dump:
            raise RuntimeError(f"lpdump did not describe the expected retrofit layout:\n{dump}")
        device_a = (work / "outdir/super_super_a.img").read_bytes()
        device_b = (work / "outdir/super_super_b.img").read_bytes()
        for name, content in retrofit_inputs.items():
            extracted = (work / "unpacked" / name).read_bytes()
            if extracted != content:
                raise RuntimeError(f"independent lpunpack round trip failed for retrofit {name}")

    base = ROOT / "tests/fixtures/android_super_retrofit"
    artifacts[base / "sample.img"] = device_a + device_b
    artifacts[base / "expected.json"] = encoded({
        "sample": "sample.img",
        "native_format": "android_super",
        "children": {
            "system": {"length": len(retrofit_inputs["system.img"]), "sha256": digest(retrofit_inputs["system.img"])},
            "vendor": {"length": len(retrofit_inputs["vendor.img"]), "sha256": digest(retrofit_inputs["vendor.img"])},
            "big": {"length": len(retrofit_inputs["big.img"]), "sha256": digest(retrofit_inputs["big.img"])},
        },
    })

    artifacts[ROOT / "tests/fixture_sources/android_super/provenance.json"] = encoded({
        "docker_image": IMAGE,
        "android_tools_lpmake_version": version,
        "commands": [
            ["img2simg", "system.img", "system.simg"],
            ["img2simg", "vendor.img", "vendor.simg"],
            ["lpmake", "-d", "65536", "-m", "4096", "-s", "1", "--alignment=4096",
             "-p", "system:none:8192", "-p", "vendor:none:8192",
             "-i", "system=system.simg", "-i", "vendor=vendor.simg", "-F", "-o", "super.img"],
            ["lpunpack", "super.img", "unpacked"],
            ["lpdump", "super.img"],
        ],
        "inputs": {name: digest(content) for name, content in inputs.items()},
        "corrupt_field": "one byte flipped in each geometry copy's magic (offsets 4096 and 8192)",
        "retrofit_commands": [
            ["img2simg", "system.img", "system.simg"],
            ["img2simg", "vendor.img", "vendor.simg"],
            ["img2simg", "big.img", "big.simg"],
            ["lpmake", "-m", "4096", "-s", "1",
             "--device=super_a:65536:4096", "--device=super_b:16384:4096", "--super-name=super_a",
             "-p", "system:none:8192", "-p", "vendor:none:8192", "-p", "big:none:36864",
             "-i", "system=system.simg", "-i", "vendor=vendor.simg", "-i", "big=big.simg",
             "-F", "-o", "outdir"],
            ["lpunpack", "-i", "outdir/super_super_b.img", "outdir/super_super_a.img", "unpacked"],
            ["lpdump", "outdir/super_super_a.img"],
        ],
        "retrofit_inputs": {name: digest(content) for name, content in retrofit_inputs.items()},
        "retrofit_note": "tests/fixtures/android_super_retrofit/sample.img is super_super_a.img ++ super_super_b.img concatenated, not a file lpmake itself produces",
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
    print("Official lpmake/lpunpack/lpdump fixtures verified" if args.check else "Official lpmake/lpunpack/lpdump fixtures generated")


if __name__ == "__main__":
    main()
