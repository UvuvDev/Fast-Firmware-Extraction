"""Native F2FS matches the corrected Python reader on its supported subset."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.f2fs import F2fsFS


@pytest.mark.parametrize('fixture', ['f2fs', 'f2fs_mapped', 'f2fs_secondary'])
def test_f2fs_native_matches_python(fixture):
    data = (Path(__file__).parent / 'fixtures' / fixture / 'sample.img').read_bytes()
    archive = open_archive('f2fs', data)
    if archive is None:
        pytest.skip('build the Rust backend')
    fs = F2fsFS(data)
    with archive:
        assert list(archive.names) == fs.walk()
        for name in archive.names:
            assert archive.read(name) == fs.read_file_content(fs.resolve(name))
