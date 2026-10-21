"""PIT raw descriptors match the existing Python reader."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.samsung_pit import SamsungPit


def test_samsung_pit_native_matches_python():
    data = (Path(__file__).parent / 'fixtures/samsung_pit/sample.pit').read_bytes()
    archive = open_archive('samsung_pit', data)
    if archive is None:
        pytest.skip('build the Rust backend')
    entries = SamsungPit.parse_entries(None, data)
    with archive:
        assert list(archive.names) == [entry.name for entry in entries]
        for entry in entries:
            assert archive.read(entry.name) == data[entry.offset:entry.offset + entry.size]
