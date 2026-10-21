"""Native extraction must agree with the independently vendored AOSP reader."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.boot_image import _unpack_to_children


@pytest.mark.parametrize("fixture", [*[f"boot_aosp_v{version}" for version in range(5)],
    "boot_aosp_v4_signature", "init_boot_aosp_v4", "vendor_boot_aosp_v3", "vendor_boot_aosp_v4"])
def test_boot_native_matches_aosp(fixture):
    data = (Path(__file__).parent / "fixtures" / fixture / "sample.img").read_bytes()
    archive = open_archive("boot_image", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    with archive:
        assert {name: archive.read(name) for name in archive.names} == _unpack_to_children(data)
