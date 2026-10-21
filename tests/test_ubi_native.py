"""UBI native reassembly matches the existing Python reader."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.ubi import UbiFS


def test_ubi_native_matches_python():
    data = (Path(__file__).parent / "fixtures/ubi/sample.bin").read_bytes()
    fs = UbiFS(data)
    archive = open_archive("ubi", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    with archive:
        assert list(archive.names) == list(fs.names_by_id.values())
        for vol_id, name in fs.names_by_id.items():
            assert archive.read(name) == fs.read_volume(vol_id)
