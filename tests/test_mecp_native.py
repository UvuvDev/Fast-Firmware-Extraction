"""Native MECP keeps embedded payloads and the forensic load-address report."""
from pathlib import Path
import pytest
from binaryninja import TransformSession
from easy_firmware_opening.common import native_container
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.mecp import _parse_entries


@pytest.mark.parametrize("fixture", ["mecp", "mecp_no_avb", "mecp_nested"])
def test_mecp_native_matches_python(fixture):
    data = (Path(__file__).parent / "fixtures" / fixture / "sample.img").read_bytes()
    archive = open_archive("mecp", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    entries = _parse_entries(data, log=False)
    with archive:
        assert list(archive.names) == [entry.name for entry in entries]
        for entry in entries:
            assert archive.read(entry.name) == data[entry.offset:entry.offset + entry.size]
        assert "modem child loads at 0x8b000600" in archive.diagnostics
        assert "gdsp" in archive.diagnostics and "gdsp" not in archive.names
        assert "cpcmdline" in archive.diagnostics and "cpcmdline" not in archive.names


def test_mecp_memory_map_is_logged_once_on_extraction(monkeypatch):
    messages = []
    monkeypatch.setattr(native_container, "log_info", messages.append)
    session = TransformSession(str(Path(__file__).parent / "fixtures/mecp/sample.img"))
    session.set_interactive(False)
    session.root_context.set_transform_name("UnisocMECP")
    session.process()
    assert len(messages) == 1
    assert "modem child loads at 0x8b000600" in messages[0]
    assert {child.filename for child in session.root_context.children} == {"modem", "cp_bootcode", "vbmeta"}
