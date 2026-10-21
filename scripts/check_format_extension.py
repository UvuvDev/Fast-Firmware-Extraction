#!/usr/bin/env python3
"""Prove that one Rust file + fixtures extends every native consumer.

Uses an isolated temporary crate; the working source and its built library
are untouched. Dependencies are cached under target/extension-check/.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    cache = ROOT / "target/extension-check"
    with tempfile.TemporaryDirectory(prefix="ffe-extension-") as directory:
        work = Path(directory)
        for name in ("Cargo.toml", "Cargo.lock", "build.rs"):
            shutil.copy2(ROOT / name, work / name)
        shutil.copytree(ROOT / "native", work / "native", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / "tests/fixtures", work / "tests/fixtures")
        (work / "common").mkdir()
        shutil.copy2(ROOT / "common/native.py", work / "common/native.py")

        source = (ROOT / "native/templates/format.rs").read_text()
        source = source.replace("example_frame", "extension_probe").replace("ExampleFrame", "ExtensionProbe")
        (work / "native/src/formats/extension_probe.rs").write_text(source)
        payload = b"a format added without editing a shared source file\n"
        for corrupt in (False, True):
            name = "extension_probe_corrupt" if corrupt else "extension_probe"
            fixture = work / "tests/fixtures" / name
            fixture.mkdir()
            sample = b"EXMP" + struct.pack("<I", len(payload)) + payload
            (fixture / "sample.bin").write_bytes(sample[:-1] if corrupt else sample)
            expected = {"sample": "sample.bin", "native_format": "extension_probe"}
            if corrupt:
                expected["expect_failure"] = True
            else:
                expected["children"] = {"payload.bin": {"length": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}}
            (fixture / "expected.json").write_text(json.dumps(expected))

        environment = dict(os.environ, CARGO_TARGET_DIR=str(cache))
        for command in (["cargo", "test", "--offline", "--locked", "--test", "fixtures"],
                        ["cargo", "build", "--offline", "--locked", "--release"]):
            subprocess.run(command, cwd=work, env=environment, check=True)
        filename = {"darwin": "libfirmware_unpack.dylib", "win32": "firmware_unpack.dll"}.get(sys.platform, "libfirmware_unpack.so")
        (work / "target/release").mkdir(parents=True)
        shutil.copy2(cache / "release" / filename, work / "target/release" / filename)
        spec = importlib.util.spec_from_file_location("extension_native", work / "common/native.py")
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        assert "extension_probe" in {info["id"] for info in native.formats()}
        sample = work / "tests/fixtures/extension_probe/sample.bin"
        assert native.detect(sample.read_bytes())["id"] == "extension_probe"
        with native.open_archive(None, sample.read_bytes()) as archive:
            assert archive.read("payload.bin") == payload
        executable = cache / "release" / ("firmware-unpack.exe" if sys.platform == "win32" else "firmware-unpack")
        subprocess.run([str(executable), str(sample), str(work / "extracted")], check=True)
        assert (work / "extracted/payload.bin").read_bytes() == payload
        print("PASS: one module + fixtures; generated inventory, fixture runner, Python bridge, and CLI all discover it")


if __name__ == "__main__":
    main()
