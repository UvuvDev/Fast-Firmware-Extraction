"""Verify byte-exact fw-type carving and the legacy scan boundaries."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.fwtype_header import _find_payload_offset


@pytest.mark.parametrize("fixture", ["fwtype_header", "fwtype_header_ubi"])
def test_fwtype_native_matches_python(fixture):
    data = (Path(__file__).parent / "fixtures" / fixture / "sample.bin").read_bytes()
    archive = open_archive("fwtype_header", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    offset = _find_payload_offset(data[:1 << 16])
    assert offset is not None
    with archive:
        assert archive.names == ("payload.bin",)
        assert archive.read("payload.bin") == data[offset:]
