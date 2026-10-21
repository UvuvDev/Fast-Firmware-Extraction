#!/usr/bin/env python3
"""Generate tiny official-AOSP boot/vendor-boot fixtures and check their bytes.

The producer is pinned to android-16.0.0_r1. The independent AOSP unpacker
must return the exact original payloads before expectations are accepted.
No firmware code, signing tool, or parser under test is executed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "third_party/aosp_mkbootimg"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(info):
    return (json.dumps(info, indent=2) + "\n").encode()


def generate():
    spec = importlib.util.spec_from_file_location("aosp_unpack", TOOLS / "unpack_bootimg.py")
    aosp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(aosp)
    inputs = {"kernel": b"synthetic kernel\n" * 301, "ramdisk": b"synthetic ramdisk\n" * 23,
              "second": b"second stage\n", "recovery_dtbo": b"recovery overlay\n",
              "dtb": b"device tree payload\n", "fragment0": b"platform fragment\n" * 7,
              "fragment1": b"recovery fragment\n" * 11, "bootconfig": b"androidboot.example=1\n"}
    artifacts, commands = {}, []
    with tempfile.TemporaryDirectory(prefix="ffe-boot-fixtures-") as directory:
        work = Path(directory)
        for name, content in inputs.items():
            (work / name).write_bytes(content)

        def fixture(name, arguments, expected):
            filename = name + ".img"
            command = [sys.executable, str(TOOLS / "mkbootimg.py"), *arguments,
                       "--vendor_boot" if name.startswith("vendor_boot") else "--output", filename]
            result = subprocess.run(command, cwd=work, capture_output=True, text=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
            commands.append(["mkbootimg.py", *arguments, command[-2], filename])
            image = (work / filename).read_bytes()
            accept(name, image, expected)
            return image

        def accept(name, image, expected):
            output = work / (name + "-unpacked")
            with (work / (name + "-input.img")).open("wb") as file:
                file.write(image)
            with (work / (name + "-input.img")).open("rb") as file:
                unpack = aosp.unpack_vendor_boot_image if image.startswith(b"VNDRBOOT") else aosp.unpack_boot_image
                unpack(file, str(output))
            actual = {path.name: path.read_bytes() for path in output.iterdir() if path.is_file()}
            assert actual == expected, f"independent AOSP round trip failed: {name}"
            base = ROOT / "tests/fixtures" / name
            artifacts[base / "sample.img"] = image
            artifacts[base / "expected.json"] = encoded({
                "sample": "sample.img", "native_format": "boot_image",
                "children": {key: {"length": len(value), "sha256": digest(value)} for key, value in expected.items()},
            })

        versions = {}
        for version in range(5):
            arguments = ["--header_version", str(version), "--kernel", "kernel", "--ramdisk", "ramdisk"]
            expected = {"kernel": inputs["kernel"], "ramdisk": inputs["ramdisk"]}
            if version <= 2:
                arguments += ["--pagesize", "2048", "--second", "second"]
                expected["second"] = inputs["second"]
            if version in (1, 2):
                arguments += ["--recovery_dtbo", "recovery_dtbo"]
                expected["recovery_dtbo"] = inputs["recovery_dtbo"]
            if version == 2:
                arguments += ["--dtb", "dtb"]
                expected["dtb"] = inputs["dtb"]
            versions[version] = fixture(f"boot_aosp_v{version}", arguments, expected)
        fixture("init_boot_aosp_v4", ["--header_version", "4", "--ramdisk", "ramdisk"],
                {"kernel": b"", "ramdisk": inputs["ramdisk"]})
        signed = bytearray(versions[4])
        signature = b"synthetic signature bytes (not an authenticated signature)"
        struct.pack_into("<I", signed, 1580, len(signature))
        signed.extend(signature)
        accept("boot_aosp_v4_signature", signed,
               {"kernel": inputs["kernel"], "ramdisk": inputs["ramdisk"], "boot_signature": signature})
        fixture("vendor_boot_aosp_v3", ["--header_version", "3", "--vendor_ramdisk", "fragment0", "--dtb", "dtb"],
                {"vendor_ramdisk": inputs["fragment0"], "dtb": inputs["dtb"]})
        fixture("vendor_boot_aosp_v4", ["--header_version", "4", "--dtb", "dtb", "--vendor_bootconfig", "bootconfig",
                "--ramdisk_type", "platform", "--ramdisk_name", "platform", "--vendor_ramdisk_fragment", "fragment0",
                "--ramdisk_type", "recovery", "--ramdisk_name", "recovery", "--vendor_ramdisk_fragment", "fragment1"],
                {"vendor_ramdisk00": inputs["fragment0"], "vendor_ramdisk01": inputs["fragment1"],
                 "bootconfig": inputs["bootconfig"], "dtb": inputs["dtb"]})

    # Independent synthetic wrappers exercise all three native ports together.
    boot = versions[4]
    sparse = (struct.pack("<IHHHHIIII", 0xed26ff3a, 1, 0, 28, 12, 4, len(boot)//4, 1, 0)
              + struct.pack("<HHII", 0xcac1, 0, len(boot)//4, len(boot)+12) + boot)
    start = 224
    header = struct.pack("<IIII16s64sIIII", 0x4b504246, 2, 112, 104, b"fixture", b"1", 0, 16, 1, start+len(sparse))
    entry = struct.pack("<I36s40sQQII", 1, b"boot.sparse", b"", start, len(sparse), 0, 0)
    image = header + entry + b"\0" * (start-len(header)-len(entry)) + sparse

    def child(data, children):
        return {"length": len(data), "sha256": digest(data), "children": children}

    boot_children = {name: {"length": len(inputs[name]), "sha256": digest(inputs[name])} for name in ("kernel", "ramdisk")}
    base = ROOT / "tests/fixtures/fastboot_nested"
    artifacts[base / "sample.bin"] = image
    artifacts[base / "expected.json"] = encoded({"sample": "sample.bin", "native_format": "fbpack",
        "children": {"boot.sparse": child(sparse, {"": child(boot, boot_children)})}})
    artifacts[ROOT / "tests/fixture_sources/boot/provenance.json"] = encoded({
        "producer_tag": "android-16.0.0_r1", "commands": commands,
        "tools_sha256": {name: digest((TOOLS / name).read_bytes()) for name in
                         ("mkbootimg.py", "gki/generate_gki_certificate.py", "unpack_bootimg.py")},
        "inputs": {name: {"length": len(value), "sha256": digest(value)} for name, value in inputs.items()},
        "signature_fixture": "official v4 output with a patched size and synthetic signature bytes; not a signed image",
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
    print("Official AOSP boot fixtures verified" if args.check else "Official AOSP boot fixtures generated")


if __name__ == "__main__":
    main()
