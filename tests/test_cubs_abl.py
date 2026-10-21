"""Optional real-image regression; vendor bytes are deliberately not committed."""
import hashlib
import json
import os
from pathlib import Path
import pytest
from binaryninja import TransformSession
from easy_firmware_opening.common.native import detect, open_archive


def test_real_cubs_abl_chain():
    filename = os.environ.get('FFE_CUBS_ABL')
    if not filename:
        pytest.skip('set FFE_CUBS_ABL to the independently inspected Cubs abl component')
    data = Path(filename).read_bytes()
    report = json.loads((Path(__file__).parent / 'fixture_sources/cubs_abl/provenance.json').read_text())
    assert hashlib.sha256(data).hexdigest() == report['sha256']
    assert detect(data)['id'] == 'apbl'
    with open_archive(None, data) as wrapped:
        assert wrapped.names == ('payload.bin',)
        payload = wrapped.read('payload.bin')
    assert hashlib.sha256(payload).hexdigest() == report['payload_sha256']
    assert detect(payload)['id'] == 'blfs'
    members = {entry['name']: entry for entry in report['members']}
    with open_archive(None, payload) as archive:
        assert set(archive.names) == set(members)
        for name, info in members.items():
            stored = archive.read(name)
            assert hashlib.sha256(stored).hexdigest() == info['stored_sha256']
            if 'decoded_sha256' in info:
                assert detect(stored)['id'] == 'lz4_frame'
                with open_archive(None, stored) as stream:
                    plain = stream.read(stream.names[0])
                    assert hashlib.sha256(plain).hexdigest() == info['decoded_sha256']
    # Exercise the actual Container Browser discovery/selection/recursion path.
    session = TransformSession(filename)
    session.set_interactive(False)
    session.process()
    assert [child.filename for child in session.root_context.children] == ['payload.bin']
    executable = session.root_context.children[0]
    resources = {child.filename: child for child in executable.children}
    assert set(resources) == set(members)
    for name, info in members.items():
        child = resources[name]
        assert hashlib.sha256(bytes(child.input.read(0, child.input.length))).hexdigest() == info['stored_sha256']
        if 'decoded_sha256' in info:
            assert len(child.children) == 1
            decoded = child.children[0]
            assert hashlib.sha256(bytes(decoded.input.read(0, decoded.input.length))).hexdigest() == info['decoded_sha256']
