"""Native Shannon extraction retains virtual-region and BOOT-trimming behavior."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.shannon_toc import _parse_entries


@pytest.mark.parametrize("fixture", ["shannon_toc", "shannon_toc_nested", "shannon_toc_padded"])
def test_shannon_native_matches_python(fixture):
    data = (Path(__file__).parent / "fixtures" / fixture / "sample.bin").read_bytes()
    archive = open_archive("shannon_toc", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    entries = _parse_entries(data)
    with archive:
        assert list(archive.names) == [entry.name for entry in entries]
        for entry in entries:
            assert archive.read(entry.name) == data[entry.offset:entry.offset + entry.size]
