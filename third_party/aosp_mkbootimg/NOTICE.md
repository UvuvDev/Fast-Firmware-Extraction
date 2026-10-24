# Vendored: AOSP `mkbootimg` — `unpack_bootimg.py`

Source: `platform/system/tools/mkbootimg`, `unpack_bootimg.py`
(https://android.googlesource.com/platform/system/tools/mkbootimg/), fetched
unmodified from the `main` branch.

License: Apache License, Version 2.0 (per the header embedded in the file
itself, per AOSP's standard per-file licensing convention — see
http://www.apache.org/licenses/LICENSE-2.0 for the full license text).

This is the authoritative AOSP reference implementation for parsing
`boot.img` and `vendor_boot.img` (all header versions 0–4, dispatched by
the `ANDROID!`/`VNDRBOOT` magic). `formats/boot_image.py` in this plugin
calls `unpack_boot_image()` / `unpack_vendor_boot_image()` from this file
directly (via a temp directory, since the AOSP tool is designed to write
extracted segments to disk) rather than re-deriving the page-alignment and
per-header-version offset math independently — see PROPOSAL.md for why
this format was vendored rather than reimplemented from scratch.

Do not modify this file — if a newer AOSP version fixes something, re-fetch
it wholesale so the provenance stays exact and diffable.
