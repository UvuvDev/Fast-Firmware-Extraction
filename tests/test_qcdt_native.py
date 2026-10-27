"""Native QCDT entries agree with the retained Python layouts for all versions."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.qcdt import _VERSION_PARSERS


@pytest.mark.parametrize("version", [1, 2, 3])
def test_qcdt_native_matches_python(version):
    data = (Path(__file__).parent / f"fixtures/qcdt_v{version}/sample.img").read_bytes()
    archive = open_archive("qcdt", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    entries = _VERSION_PARSERS[version](data)
    with archive:
        assert list(archive.names) == [entry.name for entry in entries]
        for entry in entries:
            assert archive.read(entry.name) == data[entry.offset:entry.offset + entry.size]
