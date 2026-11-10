"""DTBO bridge regressions; enabled only when the DTBO reader is built."""
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("dtbo_native", ROOT / "common/native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def image(payloads):
    """Construct a big-endian DT table from independent payload bytes."""
    table_end = 32 + 32 * len(payloads)
    header = struct.pack(">8I", 0xD7B7AB1E, table_end + sum(map(len, payloads)),
                         32, 32, len(payloads), 32, 4096, 0)
    records = []
    offset = table_end
    for payload in payloads:
        records.append(struct.pack(">8I", len(payload), offset, 0, 0, 0, 0, 0, 0))
        offset += len(payload)
    return header + b"".join(records) + b"".join(payloads)


class DtboBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if native._load_library() is None:
            raise RuntimeError("build the native library with cargo build --release first")
        if not any(info["id"] == "dtbo" for info in native.formats()):
            raise unittest.SkipTest("DTBO reader is not included in this build")

    def test_all_truncated_prefixes_raise(self):
        sample = image([b"first overlay", b"second overlay bytes"])
        for length in range(len(sample)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                native.open_archive("dtbo", sample[:length])

    def test_empty_table(self):
        with native.open_archive("dtbo", image([])) as archive:
            self.assertEqual(archive.names, ())

    def test_more_than_one_hundred_entries(self):
        payloads = [bytes([index]) * (index % 7 + 1) for index in range(101)]
        with native.open_archive("dtbo", image(payloads)) as archive:
            names = tuple(f"dt{index:02}" for index in range(len(payloads)))
            self.assertEqual(archive.names, names)
            for name, payload in zip(names, payloads):
                with self.subTest(name=name):
                    self.assertEqual(archive.read(name), payload)


if __name__ == "__main__":
    unittest.main()
