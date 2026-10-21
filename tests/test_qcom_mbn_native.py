"""MBN region boundaries agree with the legacy header reader."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.qcom_mbn import _Header


@pytest.mark.parametrize("fixture", ["qcom_mbn", "qcom_mbn_qcdt"])
def test_qcom_mbn_native_matches_python_regions(fixture):
    data = (Path(__file__).parent / "fixtures" / fixture / "sample.mbn").read_bytes()
    archive = open_archive("qcom_mbn", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    header = _Header.unpack_from(data, 0)
    assert header.sig_ptr > len(data) and header.cert_chain_ptr > len(data)
    start = _Header.size()
    with archive:
        for name, size in [("code", header.code_size), ("signature", header.sig_size), ("cert_chain", header.cert_chain_size)]:
            assert archive.read(name) == data[start:start + size]
            start += size
