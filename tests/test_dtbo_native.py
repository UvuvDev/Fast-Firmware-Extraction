"""Compare the generic native adapter with the retained Python fallback."""
from pathlib import Path
import struct
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats import dtbo


@pytest.mark.parametrize("fixture", ["dtbo_aosp_v0", "dtbo_aosp_v1"])
def test_aosp_fixture_matches_original_overlays(fixture):
    tests = Path(__file__).parent
    data = (tests / "fixtures" / fixture / "sample.img").read_bytes()
    archive = open_archive("dtbo", data)
    if archive is None:
        pytest.skip("build the Rust library with cargo build --release")
    with archive:
        assert archive.names == ("dt00", "dt01")
        assert [archive.read(name) for name in archive.names] == [
            (tests / "fixture_sources/dtbo" / f"overlay{index}.dtbo").read_bytes()
            for index in range(2)
        ]
        assert [archive.read(entry.name) for entry in dtbo._parse_entries(data)] == [
            data[entry.offset:entry.offset + entry.size] for entry in dtbo._parse_entries(data)
        ]


@pytest.mark.parametrize("magic,version", [(b"\xd7\xb7\xab\x1e", 0), (b"\xd7\xb7\xab\x1e", 1), (b"ACPI", 0)])
def test_native_matches_python(magic, version):
    data = bytearray((Path(__file__).parent / "fixtures/dtbo/sample.img").read_bytes())
    data[:4] = magic
    struct.pack_into(">I", data, 28, version)
    archive = open_archive("dtbo", data)
    if archive is None:
        pytest.skip("build the Rust library with cargo build --release")
    with archive:
        assert {name: archive.read(name) for name in archive.names} == {
            entry.name: data[entry.offset:entry.offset + entry.size] for entry in dtbo._parse_entries(data)
        }
