"""Native UBIFS agrees with the Python reader on the committed namespace."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.ubifs import UbifsFS


@pytest.mark.parametrize("fixture", ["ubifs", "ubifs_multiblock"])
def test_ubifs_native_matches_python(fixture):
    data = (Path(__file__).parent / 'fixtures' / fixture / 'sample.ubifs').read_bytes()
    archive = open_archive('ubifs', data)
    if archive is None:
        pytest.skip('build the Rust backend')
    fs = UbifsFS(data)
    with archive:
        assert list(archive.names) == fs.walk()
        for name in archive.names:
            assert archive.read(name) == fs.read_file_content(name)
