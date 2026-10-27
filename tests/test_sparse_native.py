"""Native sparse streams preserve Python bytes and the automatic child UI."""
from pathlib import Path
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats.sparse_image import _unsparse


def test_native_unsparse_matches_python():
    data = (Path(__file__).parent / "fixtures/sparse_image/sample.img").read_bytes()
    archive = open_archive("sparse_image", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    with archive:
        assert archive.is_stream
        assert archive.names == ("image.raw",)
        assert archive.read("image.raw") == _unsparse(data)
