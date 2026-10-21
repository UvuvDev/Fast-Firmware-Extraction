#!/usr/bin/env python3
"""Build independent DTBO fixtures with dtc and pinned AOSP mkdtboimg.py.

Requires dtc on PATH. No network, Binary Ninja, or plugin parsers are used.
Use --check to verify the committed artifacts without changing them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "tests/fixture_sources/dtbo"
TOOL_PATH = Path("third_party/aosp_mkdtboimg/mkdtboimg.py")
AOSP_COMMIT = "7327a003b2588845698b0993c454719a1f7005dc"
TOOL_SHA256 = "04011264802cc566cb994b71344fd20e6f58363293e4ce80757b8176a165d7be"


def json_bytes(value) -> bytes:
    return (json.dumps(value, indent=2) + "\n").encode()


def generate() -> dict[Path, bytes]:
    tool = ROOT / TOOL_PATH
    if hashlib.sha256(tool.read_bytes()).hexdigest() != TOOL_SHA256:
        raise RuntimeError("vendored mkdtboimg.py differs from the pinned AOSP source")

    artifacts = {}
    commands = []
    dtc_version = subprocess.check_output(["dtc", "--version"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="ffe-dtbo-") as directory:
        work = Path(directory)
        inputs = []
        for index in range(2):
            source = f"overlay{index}.dts"
            output = f"overlay{index}.dtbo"
            (work / source).write_bytes((SOURCES / source).read_bytes())
            command = ["dtc", "-@", "-I", "dts", "-O", "dtb", "-o", output, source]
            subprocess.run(command, cwd=work, check=True)
            commands.append(command)
            content = (work / output).read_bytes()
            inputs.append(content)
            artifacts[SOURCES / output] = content

        for version in (0, 1):
            image = f"sample-v{version}.img"
            create = [
                "create", image, f"--version={version}", "--page_size=4096",
                "overlay0.dtbo", "--id=0x100", "--rev=0x10", "--custom0=0x1234",
                "overlay1.dtbo", "--id=0x200", "--rev=0x20", "--custom0=0x5678",
            ]
            if version == 1:
                # Nonzero metadata flags with compression disabled (low nibble 0).
                create.extend(["--flags=0x100"])
            dump = ["dump", image, f"--output=dump-v{version}.txt", f"--dtb=extracted-v{version}"]
            for arguments in (create, dump):
                subprocess.run([sys.executable, str(tool), *arguments], cwd=work, check=True)
                commands.append(["python3", TOOL_PATH.as_posix(), *arguments])

            # The independent AOSP reader must return the original dtc output.
            # Expected hashes come from those inputs, never from our parser.
            children = {}
            for index, original in enumerate(inputs):
                extracted = (work / f"extracted-v{version}.{index}").read_bytes()
                if extracted != original:
                    raise RuntimeError(f"AOSP v{version} round-trip differs for overlay {index}")
                children[f"dt{index:02d}"] = {
                    "length": len(original),
                    "sha256": hashlib.sha256(original).hexdigest(),
                }
            fixture = ROOT / f"tests/fixtures/dtbo_aosp_v{version}"
            artifacts[fixture / "sample.img"] = (work / image).read_bytes()
            artifacts[fixture / "expected.json"] = json_bytes({"sample": "sample.img", "children": children, "native_format": "dtbo"})
            artifacts[fixture / "official_dump.txt"] = (work / f"dump-v{version}.txt").read_bytes()

    artifacts[SOURCES / "provenance.json"] = json_bytes({
        "aosp_project": "platform/system/libufdt",
        "aosp_tag": "android-16.0.0_r1",
        "aosp_commit": AOSP_COMMIT,
        "mkdtboimg_sha256": TOOL_SHA256,
        "dtc_version": dtc_version,
        "commands": commands,
        "artifacts": {
            path.relative_to(ROOT).as_posix(): hashlib.sha256(content).hexdigest()
            for path, content in artifacts.items()
        },
    })
    return artifacts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare without overwriting artifacts")
    args = parser.parse_args()
    mismatches = []
    for path, content in generate().items():
        if args.check:
            if not path.is_file() or path.read_bytes() != content:
                mismatches.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    if mismatches:
        raise SystemExit("Fixture artifacts differ: " + ", ".join(mismatches))
    print("AOSP DTBO v0/v1 fixtures verified" if args.check else "AOSP DTBO v0/v1 fixtures generated")


if __name__ == "__main__":
    main()
