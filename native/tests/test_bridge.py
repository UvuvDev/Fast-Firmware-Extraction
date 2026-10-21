"""Test the generic C ABI without Binary Ninja; fixtures are auto-discovered."""
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ffe_native", ROOT / "common/native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
SAMPLE = (ROOT / "tests/fixtures/dtbo/sample.img").read_bytes()


class NativeBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if native._load_library() is None:
            raise RuntimeError("build the native library with cargo build --release first")

    def check_children(self, archive, expected):
        self.assertEqual(set(archive.names), set(expected))
        for name, info in expected.items():
            data = archive.read(name)
            self.assertEqual(len(data), info["length"], name)
            self.assertEqual(hashlib.sha256(data).hexdigest(), info["sha256"], name)
            if "children" in info:
                with native.open_archive(None, data) as child:
                    self.check_children(child, info["children"])

    def test_all_native_fixtures(self):
        covered = set()
        for path in sorted((ROOT / "tests/fixtures").glob("*/expected.json")):
            expected = json.loads(path.read_text())
            if not (identifier := expected.get("native_format")):
                continue
            with self.subTest(fixture=path.parent.name):
                data = (path.parent / expected["sample"]).read_bytes()
                if expected.get("expect_failure"):
                    with self.assertRaises(ValueError):
                        native.open_archive(identifier, data)
                else:
                    self.assertEqual(native.detect(data)["id"], identifier)
                    with native.open_archive(None, data) as archive:
                        self.check_children(archive, expected["children"])
                    covered.add(identifier)
        self.assertEqual(covered, {info["id"] for info in native.formats()})

    def test_all_truncated_dtbo_prefixes_raise(self):
        for length in range(len(SAMPLE)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                native.open_archive("dtbo", SAMPLE[:length])

    def test_empty_table(self):
        data = bytearray(SAMPLE[:32])
        struct.pack_into(">I", data, 16, 0)
        with native.open_archive("dtbo", data) as archive:
            self.assertEqual(archive.names, ())

    def test_more_than_one_hundred_entries(self):
        count = 101
        offset = 32 + 32 * count
        header = struct.pack(">8I", 0xd7b7ab1e, offset + 4, 32, 32, count, 32, 4096, 0)
        record = struct.pack(">8I", 4, offset, 0, 0, 0, 0, 0, 0)
        with native.open_archive("dtbo", header + record * count + b"data") as archive:
            self.assertEqual(len(archive.names), count)
            self.assertTrue(all(archive.read(name) == b"data" for name in archive.names))

    def test_absent_library(self):
        with patch.object(native, "_load_library", return_value=None):
            self.assertIsNone(native.open_archive("dtbo", SAMPLE))
            self.assertIsNone(native.detect(SAMPLE))
            self.assertEqual(native.formats(), ())

    def test_incompatible_library_raises(self):
        native._load_library.cache_clear()
        try:
            with patch.object(native.Path, "is_file", return_value=True), patch.object(native.ctypes, "CDLL") as load:
                load.return_value.ffe_abi_version.return_value = 999
                with self.assertRaisesRegex(RuntimeError, "ABI"):
                    native.open_archive("dtbo", SAMPLE)
        finally:
            native._load_library.cache_clear()

    def test_invalid_abi_arguments_are_rejected(self):
        library = native._load_library()
        handle = ctypes.c_void_p()
        error = ctypes.create_string_buffer(128)
        self.assertEqual(library.ffe_archive_open(b"dtbo", 4, None, 0, ctypes.byref(handle), error, len(error)), -1)
        self.assertEqual(library.ffe_archive_open(b"dtbo", 4, SAMPLE, len(SAMPLE), None, error, len(error)), -1)
        self.assertEqual(library.ffe_detect(None, 0), ctypes.c_size_t(-1).value)
        length = ctypes.c_size_t(999)
        self.assertFalse(library.ffe_format_info(999999, 0, ctypes.byref(length)))
        self.assertEqual(length.value, 0)

    def test_unknown_id_fails(self):
        with self.assertRaisesRegex(ValueError, "unknown native format"):
            native.open_archive("missing_format", SAMPLE)

    def test_lifecycle_and_read_buffer_ownership(self):
        data = (ROOT / "tests/fixtures/trx/sample.bin").read_bytes()
        archive = native.open_archive("trx", data)
        first = archive.read("kernel.lzma")
        archive.read("rootfs.squashfs")
        self.assertEqual(first, (ROOT / "tests/fixtures/lzma_alone/sample.bin").read_bytes())
        with self.assertRaises(KeyError):
            archive.read("../../outside")
        archive.close()
        archive.close()
        with self.assertRaisesRegex(ValueError, "closed"):
            archive.read("kernel.lzma")

    def test_detection_does_not_claim_elf(self):
        self.assertIsNone(native.detect(b"\x7fELF" + b"\0" * 100))


if __name__ == "__main__":
    unittest.main()
