"""Keep native FBPK extraction byte-for-byte compatible with the Python reader."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats import fbpack


@pytest.mark.parametrize("version", [1, 2])
def test_fbpack_native_matches_python(version):
    data = (Path(__file__).parent / f"fixtures/fbpack_v{version}/sample.bin").read_bytes()
    archive = open_archive("fbpack", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    entries = fbpack._VERSION_PARSERS[version](data)
    with archive:
        assert list(archive.names) == [entry.name for entry in entries]
        for entry in entries:
            assert archive.read(entry.name) == data[entry.offset:entry.offset + entry.size]
