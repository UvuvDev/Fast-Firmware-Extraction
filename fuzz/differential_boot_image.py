#!/usr/bin/env python3
"""Coverage-guided differential fuzzing for boot_image, via atheris.

Compares two independent implementations of the same format - unlike the
crash-only cargo-fuzz targets in fuzz/fuzz_targets/, this catches silent
wrong-output bugs, not just crashes:

- native/src/formats/boot_image.rs (via the C ABI, same bridge
  common/native.py and native/tests/test_bridge.py use)
- third_party/aosp_mkbootimg/unpack_bootimg.py (the real, unmodified AOSP
  tool formats/boot_image.py itself wraps for its own fallback - see that
  module's docstring)

Only works where an independent, Binary-Ninja-free reference exists to
diff against. Today that's boot_image and (not yet wired up) dtbo; most
formats have no such reference and can't be differentially fuzzed this
way at all.

Coverage guidance comes from instrumenting the reference parser
(unpack_bootimg.py): atheris only instruments Python bytecode, so the Rust
side contributes no coverage signal here, but exploring the reference
parser's branches (header versions, which optional sections are present,
size edge cases) is what actually drives interesting mutations - that's
the side with real conditional logic to find a path through.

Setup (needs Python 3.6-3.12; atheris doesn't support 3.13+):
    python3.12 -m venv .venv-atheris
    CLANG_BIN=$(brew --prefix llvm)/bin/clang .venv-atheris/bin/pip install atheris
    cargo build --release   # needed by this script

Usage:
    .venv-atheris/bin/python3 fuzz/differential_boot_image.py -runs=2000000
    # or any other libFuzzer flag, e.g. -max_total_time=120
Any disagreement is written to fuzz/differential_findings/ as a libFuzzer
crash artifact and reproduces by re-running the same command with that
file as an extra argument.
"""
import hashlib
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

import atheris

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native = _load("ffe_native", ROOT / "common/native.py")
aosp = _load("aosp_unpack_bootimg", ROOT / "third_party/aosp_mkbootimg/unpack_bootimg.py")

# Only these two have the branches worth coverage-guiding mutation toward
# (header version dispatch, which optional sections are present, sizes).
atheris.instrument_func(aosp.unpack_boot_image)
atheris.instrument_func(aosp.unpack_vendor_boot_image)

MAGICS = (b"ANDROID!", b"VNDRBOOT")

# unpack_bootimg.py's cstr() truncates a fixed-width string field at its
# first NUL *after* decoding the whole field as UTF-8 (see cstr()'s own
# docstring: "remove first NULL character and any character beyond" -
# applied to an already-decoded str, not the raw bytes). A garbage byte in
# the padding *after* a real cmdline/product_name string - which has
# nothing to do with whether kernel/ramdisk/etc. extraction would succeed -
# aborts the whole unpack before extraction is even attempted. Confirmed by
# reproducing the first disagreement this script found: Rust extracted
# vendor_ramdisk+dtb fine from an input whose vendor cmdline field's unused
# tail wasn't valid UTF-8. Treated as inconclusive, not "reference
# rejected", so this known reference-tool fragility doesn't drown out real
# findings.
INCONCLUSIVE = object()


def reference_result(data: bytes):
    """{name: bytes} on success, None on rejection, INCONCLUSIVE if the
    reference tool's own unrelated info-decoding failed first."""
    if data[:8] not in MAGICS:
        return None
    try:
        with tempfile.TemporaryDirectory(prefix="ffe_diff_") as tmp:
            buf = io.BytesIO(data)
            if data[:8] == b"ANDROID!":
                aosp.unpack_boot_image(buf, tmp)
            else:
                aosp.unpack_vendor_boot_image(buf, tmp)
            return {p.name: p.read_bytes() for p in Path(tmp).iterdir() if p.is_file()}
    except UnicodeDecodeError:
        return INCONCLUSIVE
    except Exception:
        return None


def native_result(data: bytes):
    try:
        with native.open_archive("boot_image", data) as archive:
            return {name: archive.read(name) for name in archive.names}
    except Exception:
        return None


def seed_corpus() -> list[bytes]:
    seeds = [
        sample.read_bytes()
        for sample in sorted(ROOT.glob("tests/fixtures/*/sample.img"))
        if sample.read_bytes()[:8] in MAGICS
    ]
    if not seeds:
        raise RuntimeError("no boot/vendor_boot fixtures found to seed from")
    return seeds


def test_one_input(data: bytes) -> None:
    ref = reference_result(data)
    if ref is INCONCLUSIVE:
        return
    rust = native_result(data)
    if (ref is None) != (rust is None):
        kind = "reference accepted, rust rejected" if rust is None else "rust accepted, reference rejected"
        raise AssertionError(kind)
    if ref is not None and rust is not None and ref != rust:
        raise AssertionError("both accepted, output differs")


def main() -> None:
    if native._load_library() is None:
        raise SystemExit("build the native library with cargo build --release first")

    here = Path(__file__).resolve().parent
    findings_dir = here / "differential_findings"
    corpus_dir = here / "differential_corpus" / "boot_image"
    findings_dir.mkdir(exist_ok=True)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    for seed in seed_corpus():
        digest = hashlib.sha1(seed).hexdigest()[:12]
        (corpus_dir / f"seed-{digest}").write_bytes(seed)

    atheris.Setup(
        [sys.argv[0], f"-artifact_prefix={findings_dir}/", *sys.argv[1:], str(corpus_dir)],
        test_one_input,
    )
    atheris.Fuzz()


if __name__ == "__main__":
    main()
