"""Shannon-specific Python bridge cases beyond the shared fixture checks."""
import struct
from pathlib import Path
from easy_firmware_opening.common.native import open_archive


def test_empty_table():
    header = struct.pack("<12s5I", b"TOC", 0, 0, 32, 0, 0)
    with open_archive("shannon_toc", header) as archive:
        assert archive.names == ()


def test_more_than_one_hundred_entries():
    count = 101
    table_size = 32 * (count + 1)
    header = struct.pack("<12s5I", b"TOC", 0, 0, table_size, 0, 0)
    payloads = {f"PART{i}": bytes([i]) * (i % 7 + 1) for i in range(count)}
    records = []
    offset = table_size
    for name, payload in payloads.items():
        records.append(struct.pack("<12s5I", name.encode(), offset, 0, len(payload), 0, 0))
        offset += len(payload)
    data = header + b"".join(records) + b"".join(payloads.values())
    with open_archive("shannon_toc", data) as archive:
        assert archive.names == tuple(payloads)
        for name, payload in payloads.items():
            assert archive.read(name) == payload, name


def test_diagnostics_survive_archive_close():
    data = bytearray((Path(__file__).parent / "fixtures/shannon_toc/sample.bin").read_bytes())
    data[32:44] = b"../escape".ljust(12, b"\0")
    with open_archive("shannon_toc", data) as archive:
        assert archive.names == ("MAIN",)
        assert archive.read("MAIN") == b"MAIN_PAYLOAD_DATA"
        assert "../escape" in archive.diagnostics
        message = archive.diagnostics
    assert archive.diagnostics == message
