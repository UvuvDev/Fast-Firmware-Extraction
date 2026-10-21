#!/usr/bin/env python3
"""Generate official mkimage/dtc U-Boot fixtures and check their bytes.

Requires `mkimage` (u-boot-tools) and `dtc` on PATH. Their GPL-2.0 source is
not vendored in this repository -- only their CLI output is committed as
fixture bytes, the same pattern already used for the dtc-compiled DTBO
overlays under tests/fixture_sources/dtbo.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# mkimage stamps ih_time (legacy) and a devicetree "timestamp" property (FIT)
# with the current time by default; pin it so regenerated fixtures are
# byte-identical, as verified by this script's own --check mode.
REPRODUCIBLE_ENV = {**os.environ, "SOURCE_DATE_EPOCH": "1700000000"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(info):
    return (json.dumps(info, indent=2) + "\n").encode()


def tool_version(command, pattern):
    result = subprocess.run(command, capture_output=True, text=True)
    text = result.stdout + result.stderr
    match = re.search(pattern, text)
    return match.group(1) if match else text.strip().splitlines()[0]


def run(command, cwd):
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, env=REPRODUCIBLE_ENV
    )
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed: {result.stderr}")
    return result.stdout


def generate():
    for tool in ("mkimage", "dtc"):
        if shutil.which(tool) is None:
            raise SystemExit(f"{tool} not found on PATH; install u-boot-tools/dtc to regenerate fixtures")

    artifacts = {}
    commands = []
    with tempfile.TemporaryDirectory(prefix="ffe-uboot-fixtures-") as directory:
        work = Path(directory)

        def mkimage(arguments, out):
            command = ["mkimage", *arguments, out]
            run(command, work)
            commands.append(command)
            return (work / out).read_bytes()

        # --- legacy single-file kernel image ---
        kernel_payload = b"synthetic kernel payload\n" * 17
        (work / "kernel.bin").write_bytes(kernel_payload)
        legacy = mkimage(
            ["-A", "arm", "-O", "linux", "-T", "kernel", "-C", "none",
             "-a", "0x80008000", "-e", "0x80008000", "-n", "ffe-legacy-kernel",
             "-d", "kernel.bin"],
            "legacy.img",
        )
        base = ROOT / "tests/fixtures/uboot_legacy"
        artifacts[base / "sample.img"] = legacy
        artifacts[base / "expected.json"] = encoded({
            "sample": "sample.img",
            "native_format": "uboot_legacy",
            "children": {"kernel.bin": {"length": len(kernel_payload), "sha256": digest(kernel_payload)}},
        })

        # --- legacy multi-file image (exercises the sub-image size table and its padding) ---
        multi_inputs = [b"KERNEL-MULTI-0123456789", b"INITRD!", b"DTBDATA12"]
        for index, content in enumerate(multi_inputs):
            (work / f"multi{index}.bin").write_bytes(content)
        data_argument = ":".join(f"multi{index}.bin" for index in range(len(multi_inputs)))
        multi = mkimage(
            ["-A", "arm", "-O", "linux", "-T", "multi", "-C", "none",
             "-a", "0x0", "-e", "0x0", "-n", "ffe-legacy-multi", "-d", data_argument],
            "multi.img",
        )
        base = ROOT / "tests/fixtures/uboot_legacy_multi"
        artifacts[base / "sample.img"] = multi
        artifacts[base / "expected.json"] = encoded({
            "sample": "sample.img",
            "native_format": "uboot_legacy",
            "children": {
                f"data{index:02}.bin": {"length": len(content), "sha256": digest(content)}
                for index, content in enumerate(multi_inputs)
            },
        })

        # --- legacy corrupt: flip a data byte so the stored ih_dcrc no longer matches ---
        corrupt = bytearray(legacy)
        corrupt[64] ^= 0xFF
        base = ROOT / "tests/fixtures/uboot_legacy_corrupt"
        artifacts[base / "sample.img"] = bytes(corrupt)
        artifacts[base / "expected.json"] = encoded({
            "sample": "sample.img",
            "native_format": "uboot_legacy",
            "expect_failure": True,
        })

        # --- FIT image (devicetree-structured, kernel + fdt) ---
        fit_kernel = b"synthetic FIT kernel payload\n" * 13
        fit_fdt = b"synthetic FIT fdt payload\n" * 5
        (work / "fit_kernel.bin").write_bytes(fit_kernel)
        (work / "fit_fdt.bin").write_bytes(fit_fdt)
        its_source = """/dts-v1/;
/ {
    description = "FFE FIT fixture";
    images {
        kernel-1 {
            description = "kernel";
            data = /incbin/("fit_kernel.bin");
            type = "kernel";
            arch = "arm";
            os = "linux";
            compression = "none";
            load = <0x80008000>;
            entry = <0x80008000>;
        };
        fdt-1 {
            description = "fdt";
            data = /incbin/("fit_fdt.bin");
            type = "flat_dt";
            arch = "arm";
            compression = "none";
        };
    };
    configurations {
        default = "conf-1";
        conf-1 {
            description = "default";
            kernel = "kernel-1";
            fdt = "fdt-1";
        };
    };
};
"""
        (work / "fixture.its").write_text(its_source)
        command = ["mkimage", "-f", "fixture.its", "fit.itb"]
        run(command, work)
        commands.append(command)
        fit = (work / "fit.itb").read_bytes()
        base = ROOT / "tests/fixtures/uboot_fit"
        artifacts[base / "sample.itb"] = fit
        artifacts[base / "expected.json"] = encoded({
            "sample": "sample.itb",
            "native_format": "uboot_fit",
            "children": {
                "kernel-1": {"length": len(fit_kernel), "sha256": digest(fit_kernel)},
                "fdt-1": {"length": len(fit_fdt), "sha256": digest(fit_fdt)},
            },
        })

        # --- FIT corrupt: truncate before any embedded image data is reachable ---
        base = ROOT / "tests/fixtures/uboot_fit_corrupt"
        artifacts[base / "sample.itb"] = fit[:64]
        artifacts[base / "expected.json"] = encoded({
            "sample": "sample.itb",
            "native_format": "uboot_fit",
            "expect_failure": True,
        })

        artifacts[ROOT / "tests/fixture_sources/uboot/provenance.json"] = encoded({
            "source_date_epoch": REPRODUCIBLE_ENV["SOURCE_DATE_EPOCH"],
            "mkimage_version": tool_version(["mkimage", "-V"], r"mkimage version (\S+)"),
            "dtc_version": tool_version(["dtc", "-v"], r"Version: DTC (\S+)"),
            "commands": [[str(part) for part in command] for command in commands],
            "inputs": {
                "kernel.bin": digest(kernel_payload),
                **{f"multi{index}.bin": digest(content) for index, content in enumerate(multi_inputs)},
                "fit_kernel.bin": digest(fit_kernel),
                "fit_fdt.bin": digest(fit_fdt),
            },
            "its_source": its_source,
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
    print("Official mkimage/dtc U-Boot fixtures verified" if args.check else "Official mkimage/dtc U-Boot fixtures generated")


if __name__ == "__main__":
    main()
