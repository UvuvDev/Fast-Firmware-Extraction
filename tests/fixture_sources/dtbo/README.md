# Official-tool DTBO fixtures

`tests/fixtures/dtbo_aosp_v0/sample.img` and
`tests/fixtures/dtbo_aosp_v1/sample.img` were generated with the unmodified
AOSP `mkdtboimg.py` vendored under `third_party/aosp_mkdtboimg/`.

The tool is pinned to `platform/system/libufdt` commit
`7327a003b2588845698b0993c454719a1f7005dc` (`android-16.0.0_r1`). Its
source SHA-256 and the generation commands are recorded in `provenance.json`.

`overlay0.dts` and `overlay1.dts` are small, valid device-tree overlay sources
created for this repository. They were compiled with **dtc 1.8.1**, using
`dtc -@ -I dts -O dtb`. The resulting `overlay0.dtbo` (238 bytes) and
`overlay1.dtbo` (311 bytes) are committed as independent expected payloads.
Both images are 645 bytes, contain those two overlays, and use a page-size
metadata value of 4096. The v1 image includes nonzero flags on its second
entry with compression disabled.

The generator runs AOSP's `create` command and then its `dump --dtb` command,
and requires both extracted payloads to equal the compiled overlays byte for
byte. Each fixture's `official_dump.txt` records the official reader's
metadata output. `expected.json` lengths and SHA-256 hashes come from the
compiled inputs, independently of the Python/Rust parsers in this plugin.

Regenerate from the repository root (requires Python 3 and dtc on PATH):

```sh
python3 scripts/generate_dtbo_fixtures.py
```

Verify reproducibility without changing any artifacts:

```sh
python3 scripts/generate_dtbo_fixtures.py --check
```

Generation takes place in a temporary directory containing copies of the
DTS sources. Tool paths in the recorded commands are relative to the repo
root; the script supplies absolute paths when invoking AOSP from that
temporary directory. `--check` also compares the recorded dtc version.
The script verifies the vendored tool's SHA-256 before running it and uses
no network, Binary Ninja API, or plugin parser.

The older `tests/fixtures/dtbo/` fixture is retained for small mutation
tests. Its generator is unknown and its payloads contain placeholder bytes.
The new fixtures are generated test data, rather than device firmware dumps.
