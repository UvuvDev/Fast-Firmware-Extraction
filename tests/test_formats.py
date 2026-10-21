"""Generic, fixture-driven test runner.

Adding test coverage for a new format means adding a directory under
``fixtures/`` with a ``sample.*`` and an ``expected.json`` — not writing a
new test function. See ``docs/ADDING_A_FORMAT.md``.

``expected.json`` shape::

    {
        "sample": "sample.bin",
        "expect_failure": false,
        "children": {
            "child_name": {"sha256": "...", "length": 123}
        }
    }

Set ``expect_failure: true`` (and omit ``children``) for a fixture that
should fail to parse (corrupt header, truncated data, etc.) rather than
crash.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from binaryninja import TransformResult, TransformSession

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _fixture_dirs() -> list[Path]:
    if not FIXTURES_DIR.is_dir():
        return []
    return sorted(p for p in FIXTURES_DIR.iterdir() if p.is_dir() and (p / "expected.json").is_file())


@pytest.mark.parametrize("fixture_dir", _fixture_dirs(), ids=lambda p: p.name)
def test_format_fixture(fixture_dir: Path) -> None:
    expected = json.loads((fixture_dir / "expected.json").read_text())
    sample_path = fixture_dir / expected["sample"]

    session = TransformSession(str(sample_path))
    session.set_interactive(False)
    if transform := expected.get("transform"):
        session.root_context.set_transform_name(transform)
    session.process()
    root = session.root_context

    if expected.get("expect_failure"):
        assert root.transform_result == TransformResult.TransformFailure or not root.children, (
            f"{fixture_dir.name}: expected failure but got children {[c.filename for c in root.children]}"
        )
        return

    _check_children(root, expected["children"], fixture_dir.name)


def _check_children(root, expected_children, label):
    assert root.children, f"{label}: expected children but got none"

    by_name = {c.filename: c for c in root.children}
    assert set(by_name) == set(expected_children), (
        f"{label}: child set mismatch, got {sorted(by_name)}, want {sorted(expected_children)}"
    )

    for name, info in expected_children.items():
        child = by_name[name]
        content = bytes(child.input.read(0, child.input.length))
        if "length" in info:
            assert len(content) == info["length"], f"{label}/{name}: length mismatch"
        if "sha256" in info:
            assert hashlib.sha256(content).hexdigest() == info["sha256"], f"{label}/{name}: content mismatch"
        if "children" in info:
            _check_children(child, info["children"], f"{label}/{name}")
