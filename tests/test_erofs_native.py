"""Native EROFS agrees with the existing reader across its supported layouts."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.erofs import ErofsFS


@pytest.mark.parametrize("fixture", ["erofs_flat_plain", "erofs_flat_inline", "erofs_chunk_based", "erofs_mapped"])
def test_erofs_native_matches_python(fixture):
    data = (Path(__file__).parent / "fixtures" / fixture / "sample.img").read_bytes()
    fs = ErofsFS(data)
    archive = open_archive("erofs", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    with archive:
        assert list(archive.names) == fs.walk()
        for name in archive.names:
            assert archive.read(name) == fs.read_file_content(fs.resolve(name))
