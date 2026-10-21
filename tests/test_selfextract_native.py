"""Check legacy carving parity, long-banner discovery, and inert script bytes."""
from pathlib import Path
import pytest
from binaryninja import TransformSession
from easy_firmware_opening.common.native import detect, open_archive, probe_limit
from easy_firmware_opening.formats.android_selfextract import _find_payload_offset


@pytest.mark.parametrize("fixture", ["android_selfextract", "android_selfextract_tar", "android_selfextract_crlf"])
def test_selfextract_native_matches_python(fixture):
    data = (Path(__file__).parent / "fixtures" / fixture / "sample.sh").read_bytes()
    archive = open_archive("android_selfextract", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    offset = _find_payload_offset(data[:1 << 20])
    assert offset is not None
    with archive:
        assert archive.names == ("payload.gz",)
        assert archive.read("payload.gz") == data[offset:]


def test_long_banner_uses_backend_detection_limit(tmp_path):
    assert probe_limit() >= 1 << 20
    payload = (Path(__file__).parent / "fixtures/android_selfextract/sample.sh").read_bytes()[84:]
    data = b"#!/bin/sh\n#" + b"x" * 70_000 + b"\ntail -n +4 $0 | tar zxv\n" + payload
    assert detect(data)["id"] == "android_selfextract"
    path = tmp_path / "vendor.sh"
    path.write_bytes(data)
    session = TransformSession(str(path))
    session.set_interactive(False)
    session.process()
    assert [child.filename for child in session.root_context.children] == ["payload.gz"]
    child = session.root_context.children[0]
    assert bytes(child.input.read(0, child.input.length)) == payload


def test_extraction_does_not_execute_script(tmp_path):
    sentinel = tmp_path / "script-was-executed"
    payload = (Path(__file__).parent / "fixtures/android_selfextract/sample.sh").read_bytes()[84:]
    data = (f'#!/bin/sh\ntouch "{sentinel}"\ntail -n +4 $0 | tar zxv\n'.encode() + payload)
    archive = open_archive("android_selfextract", data)
    assert archive is not None
    with archive:
        assert archive.read("payload.gz") == payload
    assert not sentinel.exists()


def test_plain_scripts_are_not_claimed():
    assert detect(b"#!/bin/sh\necho ordinary script\n") is None
