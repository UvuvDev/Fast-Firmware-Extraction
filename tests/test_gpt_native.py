"""Native GPT partitions agree with the Python reader on its supported layout."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.gpt import Gpt


@pytest.mark.parametrize("fixture", ["gpt", "gpt_extended"])
def test_gpt_native_matches_python(fixture):
    data = (Path(__file__).parent / "fixtures" / fixture / "sample.img").read_bytes()
    archive = open_archive("gpt", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    # parse_entries does not depend on a registered Transform instance.
    entries = Gpt.parse_entries(None, data)
    with archive:
        assert list(archive.names) == [entry.name for entry in entries]
        for entry in entries:
            assert archive.read(entry.name) == data[entry.offset:entry.offset + entry.size]
