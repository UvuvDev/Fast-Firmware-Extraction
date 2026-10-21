#!/usr/bin/env python3
"""Verify the researched R7000 image against Python lzma and upstream unsquashfs.

Example:
  python3 scripts/verify_r7000.py firmware.zip --unsquashfs /path/to/unsquashfs \
      --report /tmp/r7000-verification.json --disk-tree /tmp/extracted

Reads reference files with `unsquashfs -cat` so case-sensitive Linux filenames
are preserved even when validation runs on a case-insensitive host filesystem.
Requires cargo build --release first. No device firmware is executed.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
EXPECTED_SHA256 = "afb847c8772a8d59aabf026d01f0285ce14b03505d3a443e31afe6ba8ba8d379"
VENDOR_URL = "https://www.downloads.netgear.com/files/GDC/R7000/R7000-V1.0.9.88_10.2.88.zip"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--unsquashfs", default="unsquashfs")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--disk-tree", type=Path)
    args = parser.parse_args()
    if zipfile.is_zipfile(args.firmware):
        with zipfile.ZipFile(args.firmware) as archive:
            data = archive.read("R7000-V1.0.9.88_10.2.88.chk")
    else:
        data = args.firmware.read_bytes()
    if digest(data) != EXPECTED_SHA256:
        raise SystemExit("This verification targets exactly R7000-V1.0.9.88_10.2.88.chk; SHA-256 differs")
    spec = importlib.util.spec_from_file_location("ffe_native", ROOT / "common/native.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    chk = native.open_archive("netgear_chk", data)
    if chk is None:
        raise SystemExit("Build Rust first: cargo build --release")
    with chk:
        trx_data = chk.read("firmware.trx")
    assert trx_data == data[58:]
    with native.open_archive("trx", trx_data) as trx:
        kernel_lzma = trx.read("kernel.lzma")
        rootfs = trx.read("rootfs.squashfs")
    with native.open_archive("lzma_alone", kernel_lzma) as stream:
        kernel = stream.read("kernel.bin")
    assert kernel == lzma.decompress(kernel_lzma, format=lzma.FORMAT_ALONE)

    path_mapping = None
    filesystem_directory = None
    if args.disk_tree:
        def mapping(directory):
            rows = (directory / ".ffe-paths.tsv").read_text().splitlines()
            assert rows[0] == "original_path\textracted_path\tformat\tchildren_directory"
            return {row.split("\t")[0]: row.split("\t")[1:] for row in rows[1:]}

        outer = mapping(args.disk_tree)
        trx_path, trx_format, trx_directory = outer["firmware.trx"]
        assert trx_format == "trx"
        assert (args.disk_tree / trx_path).read_bytes() == trx_data
        trx_directory = args.disk_tree / trx_directory
        partitions = mapping(trx_directory)
        kernel_path, kernel_format, kernel_directory = partitions["kernel.lzma"]
        rootfs_path, rootfs_format, rootfs_directory = partitions["rootfs.squashfs"]
        assert kernel_format == "lzma_alone" and rootfs_format == "squashfs"
        assert (trx_directory / kernel_path).read_bytes() == kernel_lzma
        assert (trx_directory / rootfs_path).read_bytes() == rootfs
        kernel_directory = trx_directory / kernel_directory
        assert (kernel_directory / mapping(kernel_directory)["kernel.bin"][0]).read_bytes() == kernel
        filesystem_directory = trx_directory / rootfs_directory
        path_mapping = {name: info[0] for name, info in mapping(filesystem_directory).items()}

    with tempfile.TemporaryDirectory(prefix="ffe-r7000-verify-") as directory:
        squash_path = Path(directory) / "rootfs.squashfs"
        squash_path.write_bytes(rootfs)
        listing = subprocess.check_output([args.unsquashfs, "-lln", str(squash_path)], text=True)
        reference_names = {line.split(" squashfs-root/", 1)[1] for line in listing.splitlines()
                           if line.startswith("-") and " squashfs-root/" in line}
        with native.open_archive("squashfs", rootfs) as fs:
            assert set(fs.names) == reference_names, "regular file sets differ from unsquashfs"
            if path_mapping is not None:
                assert set(path_mapping) == set(fs.names)

            def verify(name):
                reference = subprocess.check_output([args.unsquashfs, "-cat", str(squash_path), name])
                content = fs.read(name)
                assert content == reference, f"reference mismatch: {name}"
                if path_mapping is not None:
                    assert (filesystem_directory / path_mapping[name]).read_bytes() == reference, name
                return name, {"length": len(content), "sha256": digest(content)}

            with ThreadPoolExecutor(max_workers=4) as workers:
                files = dict(workers.map(verify, sorted(fs.names)))

    report = {
        "firmware": "R7000-V1.0.9.88_10.2.88.chk", "source": VENDOR_URL,
        "sha256": digest(data), "bytes": len(data),
        "kernel_bytes": len(kernel), "kernel_sha256": digest(kernel),
        "regular_files_verified": len(files),
        # Upstream unsquashfs prints its version but exits with status 1.
        "reference_tool": subprocess.run([args.unsquashfs, "-version"], text=True,
                                         stdout=subprocess.PIPE, check=False).stdout.splitlines()[0],
        "symlinks_and_special_files": "not exported (Container Browser policy)",
        "disk_tree_verified": str(args.disk_tree) if args.disk_tree else None,
        "files": files,
    }
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Verified kernel and all {len(files)} regular files byte-for-byte; report: {args.report}")


if __name__ == "__main__":
    main()
