"""Optional full-image test; supply a local .chk via FFE_R7000_FIRMWARE.

An independent per-file report from scripts/verify_r7000.py can be supplied
via FFE_R7000_REPORT. Firmware is never downloaded during tests.
"""
import hashlib
import json
import os
from pathlib import Path

from binaryninja import TransformSession
import pytest


@pytest.mark.skipif(not os.environ.get("FFE_R7000_FIRMWARE"), reason="set FFE_R7000_FIRMWARE to test real R7000 firmware")
def test_real_r7000_container_chain():
    path = Path(os.environ["FFE_R7000_FIRMWARE"])
    assert hashlib.sha256(path.read_bytes()).hexdigest() == "afb847c8772a8d59aabf026d01f0285ce14b03505d3a443e31afe6ba8ba8d379"
    session = TransformSession(str(path))
    session.set_interactive(False)
    session.process()
    root = session.root_context
    assert [child.filename for child in root.children] == ["firmware.trx"]
    assert root.children[0].transform_name == "Trx"
    partitions = {child.filename: child for child in root.children[0].children}
    assert set(partitions) == {"kernel.lzma", "rootfs.squashfs"}
    assert partitions["kernel.lzma"].transform_name == "LzmaAlone"
    assert partitions["rootfs.squashfs"].transform_name == "Squashfs"
    decoded = partitions["kernel.lzma"].children
    assert len(decoded) == 1
    assert decoded[0].input.length == 5436480
    files = {child.filename: child for child in partitions["rootfs.squashfs"].children}
    assert len(files) == 1578
    if report_path := os.environ.get("FFE_R7000_REPORT"):
        expected = json.loads(Path(report_path).read_text())["files"]
        assert set(files) == set(expected)
        for name, info in expected.items():
            child = files[name]
            content = bytes(child.input.read(0, child.input.length))
            assert len(content) == info["length"], name
            assert hashlib.sha256(content).hexdigest() == info["sha256"], name
