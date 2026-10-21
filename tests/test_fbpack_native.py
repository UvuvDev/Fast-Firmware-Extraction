"""Keep native FBPK extraction byte-for-byte compatible with the Python reader."""
from pathlib import Path
import hashlib
import json
import os
from binaryninja import TransformResult, TransformSession, TransformSessionMode
import pytest
from easy_firmware_opening.common.native import open_archive
from easy_firmware_opening.formats import fbpack


@pytest.mark.parametrize("version", [1, 2])
def test_fbpack_native_matches_python(version):
    data = (Path(__file__).parent / f"fixtures/fbpack_v{version}/sample.bin").read_bytes()
    archive = open_archive("fbpack", data)
    if archive is None:
        pytest.skip("build the Rust backend")
    entries = fbpack._VERSION_PARSERS[version](data)
    with archive:
        assert list(archive.names) == [entry.name for entry in entries]
        for entry in entries:
            assert archive.read(entry.name) == data[entry.offset:entry.offset + entry.size]


def test_fbpack_variant_selection_in_interactive_browser():
    fixture = Path(__file__).parent / "fixtures/fbpack_variants"
    expected = json.loads((fixture / "expected.json").read_text())["children"]
    session = TransformSession(str(fixture / "sample.bin"),
                               mode=TransformSessionMode.TransformSessionModeInteractive)
    session.set_interactive(True)
    session.process()
    root = session.root_context
    assert root.transform_result != TransformResult.TransformFailure
    assert root.available_files == list(expected)
    # The browser creates empty placeholders for every discovered file.
    assert all(child.extraction_result == TransformResult.TransformNotAttempted for child in root.children)
    root.set_requested_files(["ufs~1", "abl"])
    session.process_from(root)
    extracted = [child for child in root.children if child.extraction_result == TransformResult.TransformSuccess]
    assert {child.filename for child in extracted} == {"ufs~1", "abl"}
    for child in extracted:
        assert hashlib.sha256(bytes(child.input.read(0, child.input.length))).hexdigest() == expected[child.filename]["sha256"]
    abl = root.get_child("abl")
    assert abl.transform_name == "Apbl"
    session.process_from(abl)
    assert abl.available_files == ["payload.bin"]
    abl.set_requested_files(["payload.bin"])
    session.process_from(abl)
    payload = abl.get_child("payload.bin")
    assert payload.transform_name == "Blfs"
    session.process_from(payload)
    assert {child.filename for child in payload.children} == {"Image", "Unpacked contents"}
    retained = payload.get_child("Image")
    assert retained.is_leaf and not retained.transform_name
    assert bytes(retained.input.read(0, retained.input.length)) == bytes(payload.input.read(0, payload.input.length))
    contents = payload.get_child("Unpacked contents")
    session.process_from(contents)
    assert set(contents.available_files) == {"Boot/test.bmp.lz4", "Fonts/test.txt"}
    contents.set_requested_files(["Boot/test.bmp.lz4"])
    session.process_from(contents)
    image = contents.get_child("Boot/test.bmp.lz4")
    session.process_from(image)
    assert len(image.children) == 1
    decoded = image.children[0]
    decoded_info = expected["abl"]["children"]["payload.bin"]["children"]["Boot/test.bmp.lz4"]["children"][""]
    assert hashlib.sha256(bytes(decoded.input.read(0, decoded.input.length))).hexdigest() == decoded_info["sha256"]


def test_real_cubs_bootloader_targets():
    filename = os.environ.get("FFE_CUBS_BOOTLOADER")
    if not filename:
        pytest.skip("set FFE_CUBS_BOOTLOADER to the original Cubs bootloader FBPK")
    data = Path(filename).read_bytes()
    entries = fbpack._parse_v2(data)
    assert len(entries) == 34
    with open_archive("fbpack", data) as archive:
        assert len(archive.names) == len(set(archive.names)) == len(entries)
        for index, entry in enumerate(entries):
            assert archive.read(archive.names[index]) == data[entry.offset:entry.offset + entry.size]
    session = TransformSession(filename)
    session.set_interactive(False)
    complete = session.process()
    assert session.root_context.transform_result != TransformResult.TransformFailure
    assert len(session.root_context.children) == 34
    pending = [session.root_context]
    failures = []
    while pending:
        context = pending.pop()
        if (context.transform_result == TransformResult.TransformFailure
                or context.extraction_result == TransformResult.TransformFailure):
            failures.append((context.filename, context.transform_name, context.extraction_message))
        pending.extend(context.children)
    assert not failures, f"failed nested components: {failures}"
    assert complete
    dram_report = json.loads((Path(__file__).parent / "fixture_sources/cubs_blfs/provenance.json").read_text())
    assert hashlib.sha256(data).hexdigest() == dram_report["sha256"]
    for component in dram_report["components"]:
        host = session.root_context.get_child(component["name"])
        host_bytes = bytes(host.input.read(0, host.input.length))
        assert hashlib.sha256(host_bytes).hexdigest() == component["sha256"]
        image, contents = host.get_child("Image"), host.get_child("Unpacked contents")
        assert image.is_leaf and not image.transform_name
        assert bytes(image.input.read(0, image.input.length)) == host_bytes
        assert len(contents.children) == component["member_count"]
        with open_archive("blfs", host_bytes) as archive:
            assert archive.embedded_range == (component["blfs_offset"],
                                               component["blfs_offset"] + component["blfs_length"])
            digest = hashlib.sha256()
            for name in archive.names:
                content = archive.read(name)
                digest.update(name.encode() + b"\0" + len(content).to_bytes(8, "little") + content)
                child = contents.get_child(name)
                assert bytes(child.input.read(0, child.input.length)) == content
            assert digest.hexdigest() == component["members_sha256"]
    abl = session.root_context.get_child("abl")
    report = json.loads((Path(__file__).parent / "fixture_sources/cubs_abl/provenance.json").read_text())
    assert hashlib.sha256(bytes(abl.input.read(0, abl.input.length))).hexdigest() == report["sha256"]
    payload = abl.get_child("payload.bin")
    image = payload.get_child("Image")
    assert image.is_leaf and not image.transform_name
    assert hashlib.sha256(bytes(image.input.read(0, image.input.length))).hexdigest() == report["payload_sha256"]
    contents = payload.get_child("Unpacked contents")
    assert len(contents.children) == len(report["members"]) == 28
    for info in report["members"]:
        child = contents.get_child(info["name"])
        assert hashlib.sha256(bytes(child.input.read(0, child.input.length))).hexdigest() == info["stored_sha256"]
        if "decoded_sha256" in info:
            assert len(child.children) == 1
            decoded = child.children[0]
            assert hashlib.sha256(bytes(decoded.input.read(0, decoded.input.length))).hexdigest() == info["decoded_sha256"]
