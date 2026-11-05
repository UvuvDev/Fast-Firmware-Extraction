#!/usr/bin/env python3
"""Seed fuzz/corpus/ from every real, non-corrupt sample under tests/fixtures/.

Real samples give both fuzz targets a starting point that already clears
detection and header validation, so mutation spends its time past that
point instead of re-discovering it by chance. Safe to re-run any time new
fixtures land; it never removes anything, and re-seeds are deduplicated by
content hash (libFuzzer/afl corpus convention).

open_auto gets each sample byte-for-byte. open_format additionally needs a
leading selector byte picking that sample's own format out of whatever
`--list-formats` currently reports, so each seed is valid for that target's
input convention (see fuzz/fuzz_targets/open_format.rs) on day one rather
than only after the fuzzer rediscovers the convention from scratch.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests/fixtures"
CORPUS = ROOT / "fuzz/corpus"


def native_format_ids() -> list[str]:
    binary = ROOT / "target/release/firmware-unpack"
    if not binary.is_file():
        print("build the release binary first: cargo build --release", file=sys.stderr)
        sys.exit(1)
    output = subprocess.run([str(binary), "--list-formats"], capture_output=True, text=True, check=True).stdout
    ids = [line.split()[0] for line in output.splitlines() if line.strip()]
    if not ids:
        print("no formats registered; nothing to seed for open_format", file=sys.stderr)
    return ids


def add(target: str, name: str, data: bytes) -> None:
    out_dir = CORPUS / target
    out_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha1(data).hexdigest()
    (out_dir / f"{name}-{digest[:8]}").write_bytes(data)


def main() -> None:
    ids = native_format_ids()
    added = 0
    for expected_path in sorted(FIXTURES.glob("*/expected.json")):
        expected = json.loads(expected_path.read_text())
        if expected.get("expect_failure") or not (format_id := expected.get("native_format")):
            continue
        sample = expected_path.parent / expected["sample"]
        data = sample.read_bytes()
        add("open_auto", expected_path.parent.name, data)
        if format_id in ids:
            selector = ids.index(format_id) % 256
            add("open_format", expected_path.parent.name, bytes([selector]) + data)
        added += 1
    print(f"seeded corpus from {added} fixture(s)")


if __name__ == "__main__":
    main()
