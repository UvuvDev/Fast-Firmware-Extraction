# Vendored: AOSP `mkbootimg` — `unpack_bootimg.py`

Source: `platform/system/tools/mkbootimg`, `unpack_bootimg.py`
(https://android.googlesource.com/platform/system/tools/mkbootimg/), fetched
unmodified from the `main` branch.

License: Apache License, Version 2.0 (per the header embedded in the file
itself, per AOSP's standard per-file licensing convention — see
http://www.apache.org/licenses/LICENSE-2.0 for the full license text).

This is the authoritative AOSP reference implementation for parsing
`boot.img` and `vendor_boot.img` (all header versions 0–4, dispatched by
the `ANDROID!`/`VNDRBOOT` magic). The Python fallback `formats/boot_image.py`
calls `unpack_boot_image()` / `unpack_vendor_boot_image()` from this file
directly (via a temp directory, since the AOSP tool is designed to write
extracted segments to disk) rather than re-deriving the page-alignment and
per-header-version offset math independently — see PROPOSAL.md for why
this format was vendored rather than reimplemented from scratch.

Do not modify this file — if a newer AOSP version fixes something, re-fetch
it wholesale so the provenance stays exact and diffable.


## Fixture producer

`mkbootimg.py` and `gki/generate_gki_certificate.py` are vendored unmodified
from `platform/system/tools/mkbootimg` at tag `android-16.0.0_r1` (Apache-2.0,
per their embedded license headers). These are used only by
`scripts/generate_boot_fixtures.py`; firmware signatures are not generated.
The GKI import is needed by the producer even without signing options.
No signing tools or firmware code are executed when generating fixtures.

Sources and SHA-256:

- `mkbootimg.py`: `37d84b3d162e0bc62e36c1f4e1c63c85ea0caa9f29be023eb2f8efe006ad948c`
  https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/tags/android-16.0.0_r1/mkbootimg.py
- `gki/generate_gki_certificate.py`: `1bb1feec68a13da18d581aa2c631798f86f6bc10b55d587b2dd31446a0f8a203`
  https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/tags/android-16.0.0_r1/gki/generate_gki_certificate.py

The Rust boot reader is verified against the vendored independent AOSP
unpacker and the official producer. It extracts in memory; only the Python
fallback and fixture generation use temporary directories.
