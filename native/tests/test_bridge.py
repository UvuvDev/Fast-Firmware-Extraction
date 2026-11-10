"""Test the generic C ABI without Binary Ninja; fixtures are auto-discovered."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ffe_native", ROOT / "common/native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class NativeBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if native._load_library() is None:
            raise RuntimeError("build the native library with cargo build --release first")
        cls.fixtures = []
        for path in sorted((ROOT / "tests/fixtures").glob("*/expected.json")):
            expected = json.loads(path.read_text())
            if expected.get("native_format"):
                cls.fixtures.append((path.parent, expected))
        valid = [(directory, expected) for directory, expected in cls.fixtures
                 if not expected.get("expect_failure") and expected.get("children")]
        if not valid:
            raise RuntimeError("native bridge tests require a valid nonempty fixture")
        directory, cls.expected = valid[0]
        cls.identifier = cls.expected["native_format"]
        cls.sample = (directory / cls.expected["sample"]).read_bytes()

    def check_children(self, archive, expected, embedded_range=None):
        self.assertEqual(archive.embedded_range, tuple(embedded_range) if embedded_range else None)
        self.assertEqual(set(("",) if archive.is_stream else archive.names), set(expected))
        for name, info in expected.items():
            data = archive.read(archive.names[0] if archive.is_stream else name)
            self.assertEqual(len(data), info["length"], name)
            self.assertEqual(hashlib.sha256(data).hexdigest(), info["sha256"], name)
            if "children" in info:
                with native.open_archive(None, data) as child:
                    self.check_children(child, info["children"], info.get("embedded_range"))

    def test_all_native_fixtures(self):
        covered = set()
        corrupt = set()
        for directory, expected in self.fixtures:
            identifier = expected["native_format"]
            with self.subTest(fixture=directory.name):
                data = (directory / expected["sample"]).read_bytes()
                if expected.get("expect_failure"):
                    with self.assertRaises(ValueError):
                        native.open_archive(identifier, data)
                    corrupt.add(identifier)
                else:
                    self.assertEqual(native.detect(data)["id"], identifier)
                    with native.open_archive(None, data) as archive:
                        self.check_children(archive, expected["children"], expected.get("embedded_range"))
                        if archive.embedded_range:
                            start, end = archive.embedded_range
                            with native.open_archive(None, data[start:end]) as standalone:
                                self.check_children(standalone, expected["children"])
                    covered.add(identifier)
        self.assertEqual(covered, {info["id"] for info in native.formats()})
        self.assertEqual(corrupt, covered)

    def test_absent_library(self):
        with patch.object(native, "_load_library", return_value=None):
            self.assertIsNone(native.open_archive(self.identifier, self.sample))
            self.assertIsNone(native.detect(self.sample))
            self.assertEqual(native.formats(), ())

    def test_incompatible_library_raises(self):
        native._load_library.cache_clear()
        try:
            with patch.object(native.Path, "is_file", return_value=True), patch.object(native.ctypes, "CDLL") as load:
                load.return_value.ffe_abi_version.return_value = 999
                with self.assertRaisesRegex(RuntimeError, "ABI"):
                    native.open_archive(self.identifier, self.sample)
        finally:
            native._load_library.cache_clear()

    def test_invalid_abi_arguments_are_rejected(self):
        library = native._load_library()
        handle = ctypes.c_void_p()
        error = ctypes.create_string_buffer(128)
        identifier = self.identifier.encode("utf-8")
        self.assertEqual(library.ffe_archive_open(identifier, len(identifier), None, 0, ctypes.byref(handle), error, len(error)), -1)
        self.assertEqual(library.ffe_archive_open(identifier, len(identifier), self.sample, len(self.sample), None, error, len(error)), -1)
        self.assertEqual(library.ffe_detect(None, 0), ctypes.c_size_t(-1).value)
        length = ctypes.c_size_t(999)
        self.assertFalse(library.ffe_format_info(999999, 0, ctypes.byref(length)))
        self.assertEqual(length.value, 0)

    def test_unknown_id_fails(self):
        with self.assertRaisesRegex(ValueError, "unknown native format"):
            native.open_archive("missing_format", self.sample)

    def test_lifecycle_and_read_buffer_ownership(self):
        with native.open_archive(self.identifier, self.sample) as archive:
            name = archive.names[0]
            first = archive.read(name)
            for member in archive.names:
                archive.read(member)
            with self.assertRaises(KeyError):
                archive.read("../../outside")
        info = self.expected["children"]["" if archive.is_stream else name]
        self.assertEqual(len(first), info["length"])
        self.assertEqual(hashlib.sha256(first).hexdigest(), info["sha256"])
        archive.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            archive.read(name)

    def test_detection_does_not_claim_elf(self):
        self.assertIsNone(native.detect(b"\x7fELF" + b"\0" * 100))

    def test_null_diagnostics_handle_is_safe(self):
        length = ctypes.c_size_t(999)
        self.assertFalse(native._load_library().ffe_archive_diagnostics(None, ctypes.byref(length)))
        self.assertEqual(length.value, 0)

    def test_null_embedded_extent_and_outputs(self):
        offset, length = ctypes.c_size_t(99), ctypes.c_size_t(99)
        function = native._load_library().ffe_archive_embedded_range
        self.assertEqual(function(None, ctypes.byref(offset), ctypes.byref(length)), 0)
        self.assertEqual((offset.value, length.value), (0, 0))
        self.assertEqual(function(None, None, ctypes.byref(length)), -1)
        self.assertEqual(function(None, ctypes.byref(offset), None), -1)


if __name__ == "__main__":
    unittest.main()
