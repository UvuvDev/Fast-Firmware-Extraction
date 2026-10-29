"""Native ext4 agrees with the existing reader on each supported fixture."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.ext4 import Ext4FS


@pytest.mark.parametrize("fixture", ["ext4", "ext4_offset0", "ext4_indirect"])
def test_ext4_native_matches_python(fixture):
    data = (Path(__file__).parent / "fixtures" / fixture / "sample.img").read_bytes()
    fs = Ext4FS(data)
    archive = open_archive("ext4", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    with archive:
        assert list(archive.names) == fs.walk()
        for name in archive.names:
            assert archive.read(name) == fs.read_file_content(fs.resolve(name))
